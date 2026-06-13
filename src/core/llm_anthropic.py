"""
Anthropic Messages API adapter for the ModelClient Protocol.

`core.llm` intentionally remains dependency-free beyond pydantic. This
module is the first concrete backend that actually talks to a model.

Design points
-------------

- Synchronous. Matches the `ModelClient` Protocol. The agent loop runs
  one step at a time; streaming/async can be layered on later.
- Uses httpx directly rather than pulling in the `anthropic` SDK. The
  adapter surface is small (one POST, one response shape) so adding
  another transitive dependency is not worth it today.
- Retries transient failures (connection errors, HTTP 429, HTTP 5xx)
  with exponential backoff + small jitter. 429 `retry-after` headers
  are honored when present. 4xx other than 429 is surfaced immediately.
- Does NOT swallow errors into empty responses. The LLM-backed
  strategy layers (`LLMPlanner`, `LLMVerifier`, `LLMSelfCorrector`)
  already have defensive fallbacks against malformed/empty model
  output; transport/auth failures should be loud so operators can see
  them in the audit log.
- Token accounting from the API response is passed through verbatim
  into `ModelResponse.usage` (typically `{input_tokens, output_tokens,
  cache_read_input_tokens, cache_creation_input_tokens}`).

References
----------
- https://docs.anthropic.com/en/api/messages
- src/core/llm.py (ModelClient Protocol, ModelRequest/ModelResponse)
- docs/architecture/shared-brain.md
"""

from __future__ import annotations

import os
import random
import time
from collections.abc import Callable
from typing import Any

import httpx

from core.llm import (
    ModelRequest,
    ModelResponse,
    StopReason,
)

_DEFAULT_MODEL = "claude-sonnet-4-5-20250929"
_DEFAULT_BASE_URL = "https://api.anthropic.com"
_DEFAULT_VERSION = "2023-06-01"
_DEFAULT_TIMEOUT_S = 60.0
_DEFAULT_MAX_RETRIES = 3
_DEFAULT_BACKOFF_BASE_S = 0.5
_DEFAULT_BACKOFF_CAP_S = 30.0

_STOP_REASON_MAP: dict[str, StopReason] = {
    "end_turn": "end_turn",
    "max_tokens": "max_tokens",
    "stop_sequence": "stop_sequence",
}


# ---------------------------------------------------------------------------
# Error hierarchy
# ---------------------------------------------------------------------------


class AnthropicAdapterError(RuntimeError):
    """Base error raised by `AnthropicModelClient`."""


class AnthropicAuthError(AnthropicAdapterError):
    """Credentials missing or rejected (HTTP 401/403)."""


class AnthropicRateLimitError(AnthropicAdapterError):
    """Persistent HTTP 429 after retries exhausted."""


class AnthropicAPIError(AnthropicAdapterError):
    """Other 4xx (non-auth, non-rate-limit) or persistent 5xx."""


class AnthropicTransportError(AnthropicAdapterError):
    """Persistent connection error (DNS, reset, timeout) after retries."""


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class AnthropicModelClient:
    """Synchronous adapter over the Anthropic Messages API.

    Parameters
    ----------
    api_key
        Explicit API key. If omitted, falls back to the
        ``ANTHROPIC_API_KEY`` environment variable. If neither is set,
        construction raises ``AnthropicAuthError``.
    model
        Model identifier to send. Defaults to a recent Claude Sonnet.
    base_url
        Override for the API root (useful for proxies / staging).
    anthropic_version
        Value for the ``anthropic-version`` header. Pinned for
        reproducibility.
    timeout_s
        Per-request timeout (seconds). Applied to the internally-owned
        httpx.Client only; an externally-supplied client keeps its own
        timeout.
    max_retries
        Total number of attempts, not extra retries. ``max_retries=3``
        means: initial attempt + up to 2 retries.
    backoff_base_s
        Base delay for exponential backoff. Attempt N waits
        ``backoff_base_s * 2**N`` plus a small jitter, capped at
        ``_DEFAULT_BACKOFF_CAP_S``.
    http_client
        Optional pre-built ``httpx.Client`` (e.g. with a
        ``MockTransport`` for tests). When supplied, this class does
        not close it.
    sleep
        Override for ``time.sleep``. Tests inject a no-op.
    rng
        Optional ``random.Random`` for jitter. Tests inject a seeded
        one for determinism.
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str = _DEFAULT_MODEL,
        base_url: str = _DEFAULT_BASE_URL,
        anthropic_version: str = _DEFAULT_VERSION,
        timeout_s: float = _DEFAULT_TIMEOUT_S,
        max_retries: int = _DEFAULT_MAX_RETRIES,
        backoff_base_s: float = _DEFAULT_BACKOFF_BASE_S,
        http_client: httpx.Client | None = None,
        sleep: Callable[[float], None] | None = None,
        rng: random.Random | None = None,
    ) -> None:
        resolved = api_key if api_key is not None else os.environ.get("ANTHROPIC_API_KEY")
        if not resolved:
            raise AnthropicAuthError(
                "ANTHROPIC_API_KEY not provided "
                "(constructor arg or environment variable).",
            )
        self._api_key = resolved
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._anthropic_version = anthropic_version
        self._timeout_s = timeout_s
        self._max_retries = max(1, max_retries)
        self._backoff_base_s = max(0.0, backoff_base_s)
        self._owns_client = http_client is None
        self._http = http_client or httpx.Client(timeout=timeout_s)
        self._sleep = sleep or time.sleep
        self._rng = rng or random.Random()

    # ---- lifecycle -------------------------------------------------------

    def close(self) -> None:
        """Close the internally-owned httpx.Client, if any."""
        if self._owns_client:
            self._http.close()

    def __enter__(self) -> AnthropicModelClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # ---- ModelClient Protocol --------------------------------------------

    def complete(self, request: ModelRequest) -> ModelResponse:
        payload = self._build_payload(request)
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": self._anthropic_version,
            "content-type": "application/json",
        }
        url = f"{self._base_url}/v1/messages"

        for attempt in range(self._max_retries):
            try:
                resp = self._http.post(url, json=payload, headers=headers)
            except httpx.RequestError as exc:
                if attempt + 1 < self._max_retries:
                    self._sleep(self._backoff(attempt))
                    continue
                raise AnthropicTransportError(
                    f"Anthropic request failed after {self._max_retries} "
                    f"attempts: {exc!r}",
                ) from exc

            if resp.status_code == 200:
                return self._parse_response(resp.json())

            if resp.status_code in (401, 403):
                # Auth failures are never retried.
                raise AnthropicAuthError(
                    f"Anthropic auth rejected (HTTP {resp.status_code}): "
                    f"{_safe_body(resp)}",
                )

            if resp.status_code == 429:
                if attempt + 1 < self._max_retries:
                    delay = self._retry_after(resp)
                    if delay is None:
                        delay = self._backoff(attempt)
                    self._sleep(delay)
                    continue
                raise AnthropicRateLimitError(
                    f"Anthropic rate-limited (HTTP 429) after "
                    f"{self._max_retries} attempts: {_safe_body(resp)}",
                )

            if 500 <= resp.status_code < 600:
                if attempt + 1 < self._max_retries:
                    self._sleep(self._backoff(attempt))
                    continue
                raise AnthropicAPIError(
                    f"Anthropic server error (HTTP {resp.status_code}) "
                    f"after {self._max_retries} attempts: {_safe_body(resp)}",
                )

            # Any other 4xx: surface immediately.
            raise AnthropicAPIError(
                f"Anthropic API error (HTTP {resp.status_code}): "
                f"{_safe_body(resp)}",
            )

        # Unreachable: loop always returns or raises.
        raise AnthropicAdapterError(
            "Unreachable: retry loop exited without a terminal decision.",
        )

    # ---- helpers ---------------------------------------------------------

    def _build_payload(self, request: ModelRequest) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self._model,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "messages": [
                {"role": m.role, "content": m.content}
                for m in request.messages
                if m.role in ("user", "assistant")
            ],
        }
        if request.system:
            payload["system"] = request.system
        if request.stop_sequences:
            payload["stop_sequences"] = list(request.stop_sequences)
        return payload

    def _parse_response(self, data: dict[str, Any]) -> ModelResponse:
        content = _extract_text(data.get("content"))
        raw_stop = data.get("stop_reason")
        stop: StopReason = _STOP_REASON_MAP.get(
            raw_stop if isinstance(raw_stop, str) else "",
            "error",
        )
        usage = _extract_usage(data.get("usage"))
        model_name = data.get("model") if isinstance(data.get("model"), str) else None
        return ModelResponse(
            content=content,
            stop_reason=stop,
            usage=usage,
            model=model_name,
            raw=data,
        )

    def _backoff(self, attempt: int) -> float:
        if self._backoff_base_s <= 0:
            return 0.0
        base: float = self._backoff_base_s * (2 ** attempt)
        base = min(base, _DEFAULT_BACKOFF_CAP_S)
        jitter = self._rng.uniform(0.0, self._backoff_base_s)
        return base + jitter

    @staticmethod
    def _retry_after(resp: httpx.Response) -> float | None:
        value = resp.headers.get("retry-after")
        if not value:
            return None
        try:
            return max(0.0, float(value))
        except ValueError:
            # HTTP-date form not supported; fall back to exponential backoff.
            return None


# ---------------------------------------------------------------------------
# Module-private helpers
# ---------------------------------------------------------------------------


def _extract_text(blocks: Any) -> str:
    """Concatenate text from Anthropic's content block array."""
    if not isinstance(blocks, list):
        return ""
    parts: list[str] = []
    for b in blocks:
        if isinstance(b, dict) and b.get("type") == "text":
            t = b.get("text")
            if isinstance(t, str):
                parts.append(t)
    return "".join(parts)


def _extract_usage(usage_obj: Any) -> dict[str, int] | None:
    """Coerce usage payload to ``dict[str, int]`` or return None."""
    if not isinstance(usage_obj, dict):
        return None
    result: dict[str, int] = {}
    for k, v in usage_obj.items():
        if isinstance(k, str) and isinstance(v, (int, float)) and not isinstance(v, bool):
            result[k] = int(v)
    return result or None


def _safe_body(resp: httpx.Response) -> str:
    """Return the response body for error messages, truncated."""
    try:
        text = resp.text
    except Exception:  # noqa: BLE001 — diagnostic path only
        return "<unreadable body>"
    return text[:400]


__all__ = [
    "AnthropicAPIError",
    "AnthropicAdapterError",
    "AnthropicAuthError",
    "AnthropicModelClient",
    "AnthropicRateLimitError",
    "AnthropicTransportError",
]
