"""
DShieldProvider — Tier 1 keyless reputation provider (SANS ISC DShield).

Clean-room original client against the public DShield IP reputation API
(``https://isc.sans.edu/api/ip/<ip>?json``). Keyless, read-only. Maps the
attack/threatfeed signals into a normalized verdict:

- listed in one or more threat feeds      -> malicious
- nonzero attack/report counts            -> suspicious
- known to the API but quiet              -> benign
- not present / unparseable               -> unknown
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx

from core.intel.base import IOCQuery, IOCTransportError
from core.intel.http_provider import HTTPIOCProviderBase
from core.types import IOCProviderResult, Verdict

#: Default API root. Override via config ``intel.dshield.base_url``.
DEFAULT_BASE_URL = "https://isc.sans.edu/api"


def _as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


class DShieldProvider(HTTPIOCProviderBase):
    """SANS ISC DShield IP reputation (keyless)."""

    name = "dshield"
    supported_types = frozenset({"ipv4", "ipv6"})

    def __init__(
        self,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout_s: float = 10.0,
        http_client: httpx.Client | None = None,
        user_agent: str = "aptwatcher-intel/1.0",
    ) -> None:
        super().__init__(
            base_url=base_url,
            timeout_s=timeout_s,
            http_client=http_client,
            default_headers={"User-Agent": user_agent, "Accept": "application/json"},
        )

    def _build_request(
        self, request: IOCQuery
    ) -> tuple[str, str, Mapping[str, str] | None, Mapping[str, Any] | None, Any]:
        # DShield expects a bare ``?json`` flag on the path.
        return "GET", f"/ip/{request.value}?json", None, None, None

    def _parse_response(self, response: httpx.Response) -> IOCProviderResult:
        if response.status_code == 429:
            raise IOCTransportError(f"{self.name}: rate limited (HTTP 429)")
        if response.status_code >= 500:
            raise IOCTransportError(f"{self.name}: upstream {response.status_code}")
        try:
            payload: Any = response.json()
        except ValueError as exc:
            raise IOCTransportError(f"{self.name}: non-JSON response") from exc

        info: Any = payload.get("ip", payload) if isinstance(payload, dict) else payload
        if isinstance(info, list) and info:
            info = info[0]
        if not isinstance(info, dict):
            return IOCProviderResult(name=self.name, verdict="unknown", score=None, raw={})

        threatfeeds = info.get("threatfeeds") or {}
        count = _as_int(info.get("count"))
        attacks = _as_int(info.get("attacks"))

        if threatfeeds:
            verdict: Verdict = "malicious"
        elif count > 0 or attacks > 0:
            verdict = "suspicious"
        elif info.get("asname") or info.get("network"):
            # Known to the API but no abuse signal.
            verdict = "benign"
        else:
            verdict = "unknown"
        return IOCProviderResult(name=self.name, verdict=verdict, score=None, raw=info)
