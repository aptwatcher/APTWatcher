"""
AptWatchProvider — Tier 1 intel adapter for the APTWatch curated REST API.

Clean-room original: this client is written from scratch against the public
APTWatch Intelligence REST API contract (``https://api.aptwatch.org/intel/v1``).
It conforms to that API's request/response shapes but copies no code from the
separate ``aptwatch-mcp`` gateway. The API is read-only and edge-gated; no
application-level auth is required (keyless).

Endpoint used for single-IOC verdicts:
    GET /ioc/lookup?value=<v>&type=<t>&min_confidence=<c>

The curated DB answers "is this IOC attributed to a tracked threat actor?".
Absence of a match is reported as ``unknown`` (not ``benign``) — the DB tracks
malicious infrastructure, so a miss means "no attribution", never "safe".
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

import httpx

from core.intel.base import IOCQuery, IOCTransportError
from core.intel.http_provider import HTTPIOCProviderBase
from core.types import IOCProviderResult, IOCType, Verdict

#: Module logger. Observability only — never used to alter control flow.
logger = logging.getLogger(__name__)

#: Default production base URL. Override via config ``intel.apt_watch.base_url``.
DEFAULT_BASE_URL = "https://api.aptwatch.org/intel/v1"

#: REST contract this wrapper was written and last verified against
#: (gateway-announced ``rest_contract``, confirmed live on 2026-06-13).
#: Used purely to flag silent server-side drift; it never gates a lookup.
EXPECTED_REST_CONTRACT = "v1.0.1"

#: Envelope keys that, if the server ever starts emitting one, carry the
#: declared REST contract version. Read opportunistically; never required.
#: The ``/ioc/lookup`` envelope is additive, so this stays forward-tolerant.
_CONTRACT_ENVELOPE_KEYS = ("rest_contract", "contract_version", "api_contract")

#: APTWatcher IOCType -> APTWatch REST ``type`` parameter.
_TYPE_MAP: dict[IOCType, str] = {
    "ipv4": "ip",
    "ipv6": "ip",
    "domain": "domain",
    "url": "url",
    "sha256": "hash",
    "sha1": "hash",
    "md5": "hash",
    "email": "email",
}

#: REST ``min_confidence`` string -> the verdict assigned when the strongest
#: match sits at that confidence band. A curated attribution is malicious;
#: weaker bands soften to suspicious.
_CONFIDENCE_VERDICT: dict[str, Verdict] = {
    "high": "malicious",
    "medium": "suspicious",
    "low": "suspicious",
}


class AptWatchProvider(HTTPIOCProviderBase):
    """Curated actor-attribution provider backed by the APTWatch REST API."""

    name = "apt_watch"
    supported_types = frozenset(_TYPE_MAP.keys())

    def __init__(
        self,
        *,
        base_url: str = DEFAULT_BASE_URL,
        min_confidence: str = "medium",
        timeout_s: float = 10.0,
        http_client: httpx.Client | None = None,
        user_agent: str = "aptwatcher-intel/1.0",
        probe_health_contract: bool = False,
    ) -> None:
        super().__init__(
            base_url=base_url,
            timeout_s=timeout_s,
            http_client=http_client,
            default_headers={"User-Agent": user_agent, "Accept": "application/json"},
        )
        self._min_confidence = min_confidence
        #: Drift is logged at most once per provider instance to avoid noise.
        self._contract_logged = False
        # Opt-in only: the common path issues no extra request, and the test
        # suite never enables this, so no network is touched by default.
        if probe_health_contract:
            self._probe_contract()

    def _build_request(
        self, request: IOCQuery
    ) -> tuple[str, str, Mapping[str, str] | None, Mapping[str, Any] | None, Any]:
        params = {
            "value": request.value,
            "type": _TYPE_MAP[request.ioc_type],
            "min_confidence": self._min_confidence,
        }
        return "GET", "/ioc/lookup", None, params, None

    def _parse_response(self, response: httpx.Response) -> IOCProviderResult:
        if response.status_code == 429:
            raise IOCTransportError(f"{self.name}: rate limited (HTTP 429)")
        if response.status_code >= 500:
            raise IOCTransportError(f"{self.name}: upstream {response.status_code}")
        try:
            data: dict[str, Any] = response.json()
        except ValueError as exc:
            raise IOCTransportError(f"{self.name}: non-JSON response") from exc

        # Observability only: flag REST contract drift if the envelope ever
        # starts declaring its version. Never alters the verdict below.
        self._note_contract(self._extract_contract(data))

        matches = data.get("matches") or []
        if not matches:
            # No curated attribution. The DB tracks malicious infra, so a miss
            # is "unknown", never "benign". Infrastructure context is kept in raw.
            return IOCProviderResult(name=self.name, verdict="unknown", score=None, raw=data)

        # Soft scoring degradation: a populated match set carrying neither
        # ``confidence`` nor ``confidence_score`` means the verdict can no
        # longer be trusted to its usual band. Flag it, but keep the existing
        # fallback behavior unchanged (Rule #1: note doubt, never block).
        if not any(
            m.get("confidence") is not None or m.get("confidence_score") is not None
            for m in matches
        ):
            logger.warning("apt_watch: scoring fields absent, verdict degraded")

        # Strongest match drives the verdict and score.
        best = max(matches, key=lambda m: m.get("confidence_score") or 0.0)
        band = str(best.get("confidence", "")).lower()
        verdict = _CONFIDENCE_VERDICT.get(band, "suspicious")
        raw_score = best.get("confidence_score")
        score = None
        if isinstance(raw_score, (int, float)):
            score = max(0.0, min(1.0, float(raw_score)))
        return IOCProviderResult(name=self.name, verdict=verdict, score=score, raw=data)

    # --- Contract-drift observability (non-blocking) ----------------------

    @staticmethod
    def _extract_contract(envelope: Mapping[str, Any]) -> str | None:
        """Pull a declared REST contract version out of a response envelope.

        Returns ``None`` when the envelope carries no contract field, which is
        the expected case today — the wrapper never depends on its presence.
        """
        for key in _CONTRACT_ENVELOPE_KEYS:
            value = envelope.get(key)
            if value:
                return str(value)
        return None

    def _note_contract(self, observed: str | None) -> None:
        """Log the observed REST contract once: debug if it matches the
        expected contract, warning if it has drifted. Never raises."""
        if observed is None or self._contract_logged:
            return
        self._contract_logged = True
        if observed == EXPECTED_REST_CONTRACT:
            logger.debug("apt_watch: REST contract %s as expected", observed)
        else:
            logger.warning(
                "apt_watch: REST contract drift: observed %s, expected %s",
                observed,
                EXPECTED_REST_CONTRACT,
            )

    def _probe_contract(self) -> None:
        """Opt-in ``/health`` probe to learn the server's declared contract.

        Disabled by default and never invoked by the test suite, so the
        common path and tests touch no network. Best-effort and fully
        swallowed: an observability probe must never break a lookup.
        """
        try:
            response = self._http.get(
                self._resolve_url("/health"),
                headers=self._default_headers,
                timeout=self._timeout_s,
            )
            data = response.json()
        except (httpx.HTTPError, ValueError):
            return
        if not isinstance(data, Mapping):
            return
        app_version = data.get("version")
        if app_version:
            # The app version (e.g. "1.0.0") is a distinct namespace from the
            # REST contract; record it for context but do not compare it.
            logger.debug("apt_watch: /health app version %s", app_version)
        self._note_contract(self._extract_contract(data))
