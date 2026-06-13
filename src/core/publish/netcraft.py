"""
Netcraft Report v3 publication adapter.

Submits `url`, `domain`, and `ipv4` IOCs to the Netcraft Report API v3
take-down queue. Other IOC types are filtered out silently (Netcraft
does not accept them on this endpoint).

Pattern adapted from the reference `netcraft_report.py` — clean-room,
no copied code. See `docs/design/analysis-output-pipeline.md`.

HTTP transport:
- Prefers `httpx` when available.
- Falls back to `urllib.request` from the stdlib if `httpx` is not
  installed (keeps the offline VM footprint small).
- `transport` can be injected to replace the HTTP call in tests.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any

from core.publish.protocol import (
    PublicationAdapter,
    PublicationError,
    PublicationResult,
)
from core.types import Finding, IOCVerdict

try:
    import httpx
except Exception:  # pragma: no cover - optional dep
    httpx = None  # type: ignore[assignment]


__all__ = ["NetcraftAdapter"]


_ACCEPTED_TYPES = frozenset({"url", "domain", "ipv4"})
_DEFAULT_BASE_URL = "https://report.netcraft.com/api/v3/"
_REPORT_PATH = "report/urls"


def _utc_iso_now() -> str:
    return datetime.now(tz=UTC).isoformat().replace("+00:00", "Z")


class NetcraftAdapter:
    """
    Submit URL / domain / ipv4 IOCs to Netcraft Report v3.

    See https://report.netcraft.com/api/v3/ for the live schema. The
    adapter POSTs to `<base_url>/report/urls` with the body shape:

        {
          "reason": "<human-readable reason>",
          "urls": [
            {"url": "<value>", "type": "<url|domain|ip>", "country": "..."},
            ...
          ]
        }

    Auth is `Authorization: Bearer <api_key>`.
    """

    name: str = "netcraft"

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str = _DEFAULT_BASE_URL,
        reason: str = "Confirmed malicious from APTWatcher incident triage",
        timeout: float = 30.0,
        transport: Callable[..., Any] | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("api_key is required")
        self._api_key = api_key
        self._base_url = base_url.rstrip("/") + "/"
        self._reason = reason
        self._timeout = timeout
        self._transport = transport

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def publish(
        self,
        *,
        findings: list[Finding],
        iocs: list[IOCVerdict],
        incident_id: str,
        campaign_tag: str,
        dry_run: bool = True,
    ) -> PublicationResult:
        filtered = [i for i in iocs if i.ioc_type in _ACCEPTED_TYPES]
        payload = self._build_payload(filtered, incident_id=incident_id, campaign_tag=campaign_tag)
        endpoint = self._endpoint()
        correlation_id = f"netcraft-{uuid.uuid4().hex}"

        if dry_run:
            return PublicationResult(
                adapter=self.name,
                target="netcraft-dry-run",
                submitted_at=_utc_iso_now(),
                correlation_id=correlation_id,
                status="dry_run",
                details={
                    "endpoint": endpoint,
                    "payload": payload,
                    "accepted_iocs": len(filtered),
                    "dropped_iocs": len(iocs) - len(filtered),
                },
            )

        if not filtered:
            # Nothing to submit; record a submitted no-op.
            return PublicationResult(
                adapter=self.name,
                target="netcraft-empty",
                submitted_at=_utc_iso_now(),
                correlation_id=correlation_id,
                status="submitted",
                details={"endpoint": endpoint, "payload": payload, "submitted_iocs": 0},
            )

        response_json = self._post(endpoint, payload)
        target = str(
            response_json.get("uuid")
            or response_json.get("id")
            or "netcraft-submitted"
        )
        return PublicationResult(
            adapter=self.name,
            target=target,
            submitted_at=_utc_iso_now(),
            correlation_id=correlation_id,
            status="submitted",
            details={
                "endpoint": endpoint,
                "submitted_iocs": len(filtered),
                "response": response_json,
            },
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _endpoint(self) -> str:
        return f"{self._base_url}{_REPORT_PATH}"

    def _build_payload(
        self,
        iocs: Iterable[IOCVerdict],
        *,
        incident_id: str,
        campaign_tag: str,
    ) -> dict[str, Any]:
        urls_payload: list[dict[str, str]] = []
        for ioc in iocs:
            urls_payload.append(
                {
                    "url": ioc.value,
                    "type": _netcraft_type(ioc.ioc_type),
                }
            )
        return {
            "reason": self._reason,
            "urls": urls_payload,
            "incident_id": incident_id,
            "campaign": campaign_tag,
        }

    def _post(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        if self._transport is not None:
            try:
                resp = self._transport(
                    method="POST",
                    url=url,
                    headers=headers,
                    json=payload,
                    timeout=self._timeout,
                )
            except PublicationError:
                raise
            except Exception as exc:  # noqa: BLE001
                raise PublicationError(f"netcraft transport failure: {exc}") from exc
            return _parse_transport_response(resp)

        if httpx is None:
            return _stdlib_post(url, headers, payload, timeout=self._timeout)

        try:
            response = httpx.post(url, headers=headers, json=payload, timeout=self._timeout)
        except Exception as exc:  # noqa: BLE001
            raise PublicationError(f"netcraft httpx error: {exc}") from exc

        status = getattr(response, "status_code", 0)
        if 200 <= status < 300:
            try:
                data: dict[str, Any] = response.json()
                return data
            except Exception:  # noqa: BLE001
                return {}
        text = getattr(response, "text", "")
        raise PublicationError(f"netcraft returned HTTP {status}: {text[:500]}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _netcraft_type(ioc_type: str) -> str:
    if ioc_type == "ipv4":
        return "ip"
    return ioc_type


def _parse_transport_response(resp: Any) -> dict[str, Any]:
    """Coerce a transport response (dict | object with status_code) into JSON."""
    # Dict-shaped response (what most test doubles use).
    if isinstance(resp, dict):
        status = int(resp.get("status_code", 200))
        body = resp.get("json", resp.get("body", {}))
        if 200 <= status < 300:
            return body if isinstance(body, dict) else {}
        raise PublicationError(f"netcraft returned HTTP {status}: {body!r}")

    status = int(getattr(resp, "status_code", 200))
    if 200 <= status < 300:
        json_fn = getattr(resp, "json", None)
        if callable(json_fn):
            try:
                data: dict[str, Any] = json_fn()
                return data
            except Exception:  # noqa: BLE001
                return {}
        return {}
    text = getattr(resp, "text", "")
    raise PublicationError(f"netcraft returned HTTP {status}: {text[:500]}")


def _stdlib_post(
    url: str,
    headers: dict[str, str],
    payload: dict[str, Any],
    *,
    timeout: float,
) -> dict[str, Any]:
    import urllib.error
    import urllib.request

    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            status = resp.getcode()
            raw = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        raise PublicationError(
            f"netcraft returned HTTP {exc.code}: {exc.reason}"
        ) from exc
    except urllib.error.URLError as exc:
        raise PublicationError(f"netcraft URL error: {exc.reason}") from exc

    if not (200 <= status < 300):
        raise PublicationError(f"netcraft returned HTTP {status}: {raw[:500]}")
    if not raw:
        return {}
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return decoded if isinstance(decoded, dict) else {}


# Protocol runtime check (structural typing sanity)
_PROTOCOL_CHECK: PublicationAdapter = NetcraftAdapter(api_key="placeholder")
del _PROTOCOL_CHECK
