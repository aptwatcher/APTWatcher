"""
ShodanInternetDbProvider — Tier 1 keyless exposure provider (Shodan InternetDB).

Clean-room original client for the free, keyless InternetDB endpoint
(``https://internetdb.shodan.io/<ip>``). InternetDB reports *exposure*
(open ports, CVEs, tags), not reputation, so verdict mapping is conservative:

- a tag flags it as compromised/malware/botnet/c2  -> malicious
- known CVEs exposed                               -> suspicious
- indexed, no risk signal                          -> benign
- not indexed (HTTP 404)                           -> unknown
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx

from core.intel.base import IOCQuery, IOCTransportError
from core.intel.http_provider import HTTPIOCProviderBase
from core.types import IOCProviderResult, Verdict

DEFAULT_BASE_URL = "https://internetdb.shodan.io"

#: Tags that flip the verdict to malicious (case-insensitive substring match).
_MALICIOUS_TAGS = ("compromised", "malware", "botnet", "c2", "ransomware", "phishing")


class ShodanInternetDbProvider(HTTPIOCProviderBase):
    """Shodan InternetDB exposure lookup (keyless, IP only)."""

    name = "shodan_internetdb"
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
        return "GET", f"/{request.value}", None, None, None

    def _parse_response(self, response: httpx.Response) -> IOCProviderResult:
        if response.status_code == 404:
            # Not indexed -> no exposure data, not a judgement.
            return IOCProviderResult(name=self.name, verdict="unknown", score=None,
                                     raw={"not_indexed": True})
        if response.status_code == 429:
            raise IOCTransportError(f"{self.name}: rate limited (HTTP 429)")
        if response.status_code >= 500:
            raise IOCTransportError(f"{self.name}: upstream {response.status_code}")
        try:
            data: dict[str, Any] = response.json()
        except ValueError as exc:
            raise IOCTransportError(f"{self.name}: non-JSON response") from exc

        tags = [str(t).lower() for t in (data.get("tags") or [])]
        vulns = data.get("vulns") or []

        if any(bad in tag for tag in tags for bad in _MALICIOUS_TAGS):
            verdict: Verdict = "malicious"
        elif vulns:
            verdict = "suspicious"
        else:
            verdict = "benign"
        return IOCProviderResult(name=self.name, verdict=verdict, score=None, raw=data)
