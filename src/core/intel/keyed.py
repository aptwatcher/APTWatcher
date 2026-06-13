"""
Keyed Tier 1 providers — VirusTotal, AbuseIPDB, AlienVault OTX, Censys.

Clean-room original clients on `HTTPIOCProviderBase`. Each needs an API key,
supplied at construction (the factory reads it from the env var named in
config; the key never lives in the repo). A provider is only built when its
key is present, so these classes assume a non-empty key.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx

from core.intel.base import IOCQuery, IOCTransportError
from core.intel.http_provider import HTTPIOCProviderBase
from core.types import IOCProviderResult, Verdict

# Default env var names (config may override via api_key_env).
VIRUSTOTAL_KEY_ENV = "VIRUSTOTAL_API_KEY"
ABUSEIPDB_KEY_ENV = "ABUSEIPDB_API_KEY"
OTX_KEY_ENV = "OTX_API_KEY"
CENSYS_KEY_ENV = "CENSYS_API_TOKEN"


def _clamp(x: float) -> float:
    return max(0.0, min(1.0, x))


class VirusTotalProvider(HTTPIOCProviderBase):
    """VirusTotal v3 file/IP/domain reputation."""

    name = "virustotal"
    supported_types = frozenset({"ipv4", "ipv6", "domain", "sha256", "sha1", "md5"})
    _SEGMENT = {"ipv4": "ip_addresses", "ipv6": "ip_addresses", "domain": "domains",
                "sha256": "files", "sha1": "files", "md5": "files"}

    def __init__(self, *, api_key: str, base_url: str = "https://www.virustotal.com/api/v3",
                 timeout_s: float = 10.0, http_client: httpx.Client | None = None) -> None:
        super().__init__(base_url=base_url, timeout_s=timeout_s, http_client=http_client,
                         default_headers={"x-apikey": api_key, "Accept": "application/json"})

    def _build_request(self, request: IOCQuery) -> tuple[str, str, Mapping[str, str] | None, Mapping[str, Any] | None, Any]:
        seg = self._SEGMENT[request.ioc_type]
        return "GET", f"/{seg}/{request.value}", None, None, None

    def _parse_response(self, response: httpx.Response) -> IOCProviderResult:
        if response.status_code == 404:
            return IOCProviderResult(name=self.name, verdict="unknown", score=None, raw={"found": False})
        if response.status_code == 429:
            raise IOCTransportError(f"{self.name}: rate limited (HTTP 429)")
        if response.status_code >= 500:
            raise IOCTransportError(f"{self.name}: upstream {response.status_code}")
        try:
            data: dict[str, Any] = response.json()
        except ValueError as exc:
            raise IOCTransportError(f"{self.name}: non-JSON response") from exc
        attrs = (data.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        mal = int(stats.get("malicious", 0) or 0)
        susp = int(stats.get("suspicious", 0) or 0)
        harm = int(stats.get("harmless", 0) or 0)
        undet = int(stats.get("undetected", 0) or 0)
        total = mal + susp + harm + undet
        if mal > 0:
            verdict: Verdict = "malicious"
        elif susp > 0:
            verdict = "suspicious"
        elif harm > 0:
            verdict = "benign"
        else:
            verdict = "unknown"
        score = _clamp((mal + susp) / total) if total and (mal or susp) else None
        return IOCProviderResult(name=self.name, verdict=verdict, score=score, raw=attrs)


class AbuseIpdbProvider(HTTPIOCProviderBase):
    """AbuseIPDB community abuse confidence (IP only)."""

    name = "abuseipdb"
    supported_types = frozenset({"ipv4", "ipv6"})

    def __init__(self, *, api_key: str, base_url: str = "https://api.abuseipdb.com/api/v2",
                 max_age_days: int = 90, timeout_s: float = 10.0,
                 http_client: httpx.Client | None = None) -> None:
        super().__init__(base_url=base_url, timeout_s=timeout_s, http_client=http_client,
                         default_headers={"Key": api_key, "Accept": "application/json"})
        self._max_age = max(1, min(365, max_age_days))

    def _build_request(self, request: IOCQuery) -> tuple[str, str, Mapping[str, str] | None, Mapping[str, Any] | None, Any]:
        return "GET", "/check", None, {"ipAddress": request.value, "maxAgeInDays": str(self._max_age)}, None

    def _parse_response(self, response: httpx.Response) -> IOCProviderResult:
        if response.status_code == 429:
            raise IOCTransportError(f"{self.name}: rate limited (HTTP 429)")
        if response.status_code >= 500:
            raise IOCTransportError(f"{self.name}: upstream {response.status_code}")
        try:
            data: dict[str, Any] = response.json()
        except ValueError as exc:
            raise IOCTransportError(f"{self.name}: non-JSON response") from exc
        d = data.get("data") or {}
        conf = int(d.get("abuseConfidenceScore", 0) or 0)
        if conf >= 75:
            verdict: Verdict = "malicious"
        elif conf > 0:
            verdict = "suspicious"
        else:
            verdict = "benign"
        return IOCProviderResult(name=self.name, verdict=verdict, score=_clamp(conf / 100.0), raw=d)


class OtxProvider(HTTPIOCProviderBase):
    """AlienVault OTX pulse reputation (general endpoint)."""

    name = "otx"
    supported_types = frozenset({"ipv4", "domain", "sha256", "sha1", "md5"})
    _SECTION = {"ipv4": "IPv4", "domain": "domain", "sha256": "file", "sha1": "file", "md5": "file"}

    def __init__(self, *, api_key: str, base_url: str = "https://otx.alienvault.com/api/v1",
                 timeout_s: float = 10.0, http_client: httpx.Client | None = None) -> None:
        super().__init__(base_url=base_url, timeout_s=timeout_s, http_client=http_client,
                         default_headers={"X-OTX-API-KEY": api_key, "Accept": "application/json"})

    def _build_request(self, request: IOCQuery) -> tuple[str, str, Mapping[str, str] | None, Mapping[str, Any] | None, Any]:
        section = self._SECTION[request.ioc_type]
        return "GET", f"/indicators/{section}/{request.value}/general", None, None, None

    def _parse_response(self, response: httpx.Response) -> IOCProviderResult:
        if response.status_code == 429:
            raise IOCTransportError(f"{self.name}: rate limited (HTTP 429)")
        if response.status_code >= 500:
            raise IOCTransportError(f"{self.name}: upstream {response.status_code}")
        try:
            data: dict[str, Any] = response.json()
        except ValueError as exc:
            raise IOCTransportError(f"{self.name}: non-JSON response") from exc
        pulse_count = int((data.get("pulse_info") or {}).get("count", 0) or 0)
        if pulse_count >= 4:
            verdict: Verdict = "malicious"
        elif pulse_count >= 1:
            verdict = "suspicious"
        else:
            verdict = "unknown"
        return IOCProviderResult(name=self.name, verdict=verdict, score=None,
                                 raw={"pulse_count": pulse_count})


_CENSYS_MALICIOUS_LABELS = ("malicious", "c2", "compromised", "botnet", "malware")


class CensysProvider(HTTPIOCProviderBase):
    """Censys Platform v3 host exposure (IP only, Bearer token)."""

    name = "censys"
    supported_types = frozenset({"ipv4", "ipv6"})

    def __init__(self, *, api_key: str, base_url: str = "https://api.platform.censys.io/v3",
                 timeout_s: float = 10.0, http_client: httpx.Client | None = None) -> None:
        super().__init__(base_url=base_url, timeout_s=timeout_s, http_client=http_client,
                         default_headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"})

    def _build_request(self, request: IOCQuery) -> tuple[str, str, Mapping[str, str] | None, Mapping[str, Any] | None, Any]:
        return "GET", f"/global/asset/host/{request.value}", None, None, None

    def _parse_response(self, response: httpx.Response) -> IOCProviderResult:
        if response.status_code == 404:
            return IOCProviderResult(name=self.name, verdict="unknown", score=None, raw={"found": False})
        if response.status_code == 429:
            raise IOCTransportError(f"{self.name}: rate limited (HTTP 429)")
        if response.status_code >= 500:
            raise IOCTransportError(f"{self.name}: upstream {response.status_code}")
        try:
            data: dict[str, Any] = response.json()
        except ValueError as exc:
            raise IOCTransportError(f"{self.name}: non-JSON response") from exc
        res = data.get("result") or {}
        labels = [str(x).lower() for x in (res.get("labels") or [])]
        services = res.get("services") or []
        if any(bad in lab for lab in labels for bad in _CENSYS_MALICIOUS_LABELS):
            verdict: Verdict = "malicious"
        elif services:
            verdict = "benign"
        else:
            verdict = "unknown"
        return IOCProviderResult(name=self.name, verdict=verdict, score=None, raw=res)
