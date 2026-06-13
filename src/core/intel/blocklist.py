"""
Blocklist providers — Tier 1 keyless membership checks against public lists.

These differ from `HTTPIOCProviderBase`: instead of one HTTP call per IOC,
they download a blocklist once (lazily, on first query), parse it into an
in-memory index, and answer membership questions. A listed value is
`malicious`; a miss is `unknown` (absence of evidence, not innocence).

Concrete providers:
- FireholProvider     IPv4/CIDR netset (firehol_level1)
- IpsumProvider       IPv4 reputation list (stamparm/ipsum)
- StevenBlackProvider domain hosts blocklist (StevenBlack/hosts)

Clean-room original; downloads public lists at their canonical raw URLs.
"""

from __future__ import annotations

import contextlib
import ipaddress
from typing import Any

import httpx

from core.intel.base import (
    IOCProviderError,
    IOCQuery,
    IOCTimeoutError,
    IOCTransportError,
    IOCUnsupportedError,
)
from core.types import IOCProviderResult, IOCType, Verdict


class BlocklistProviderBase:
    """Structurally implements the `IOCProvider` Protocol via list membership."""

    name: str = "blocklist"
    supported_types: frozenset[IOCType] = frozenset()
    mode: str = "ip"          # "ip" or "domain"
    list_url: str = ""

    def __init__(
        self,
        *,
        list_url: str | None = None,
        timeout_s: float = 20.0,
        http_client: httpx.Client | None = None,
        user_agent: str = "aptwatcher-intel/1.0",
    ) -> None:
        self._list_url = list_url or self.list_url
        self._timeout_s = timeout_s
        self._headers = {"User-Agent": user_agent}
        self._owned = http_client is None
        self._http = http_client or httpx.Client(timeout=timeout_s)
        self._loaded = False
        self._closed = False
        self._ips: set[str] = set()
        self._nets: list[Any] = []
        self._domains: set[str] = set()

    # --- Protocol surface ------------------------------------------------

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in self.supported_types

    def query(self, request: IOCQuery) -> IOCProviderResult:
        if self._closed:
            raise IOCProviderError(f"{self.name} is closed")
        if not self.supports(request.ioc_type):
            raise IOCUnsupportedError(f"{self.name} does not support {request.ioc_type!r}")
        if not self._loaded:
            self._load()
        listed = self._is_listed(request.value)
        verdict: Verdict = "malicious" if listed else "unknown"
        return IOCProviderResult(
            name=self.name, verdict=verdict, score=None,
            raw={"listed": listed, "source": self._list_url},
        )

    def close(self) -> None:
        if self._closed:
            return
        if self._owned:
            # Shutdown must not raise.
            with contextlib.suppress(Exception):
                self._http.close()
        self._closed = True

    # --- Loading + membership -------------------------------------------

    def _load(self) -> None:
        try:
            r = self._http.get(self._list_url, headers=self._headers, timeout=self._timeout_s)
        except httpx.TimeoutException as exc:
            raise IOCTimeoutError(f"{self.name}: timed out fetching blocklist") from exc
        except httpx.TransportError as exc:
            raise IOCTransportError(f"{self.name}: transport error: {exc}") from exc
        if r.status_code == 429 or r.status_code >= 500:
            raise IOCTransportError(f"{self.name}: upstream {r.status_code}")
        for raw in r.text.splitlines():
            tok = self._parse_line(raw)
            if not tok:
                continue
            if self.mode == "ip":
                if "/" in tok:
                    try:
                        self._nets.append(ipaddress.ip_network(tok, strict=False))
                    except ValueError:
                        continue
                else:
                    self._ips.add(tok)
            else:
                self._domains.add(tok.lower())
        self._loaded = True

    def _is_listed(self, value: str) -> bool:
        if self.mode == "ip":
            if value in self._ips:
                return True
            try:
                ip = ipaddress.ip_address(value)
            except ValueError:
                return False
            return any(ip in net for net in self._nets)
        dom = value.lower().rstrip(".")
        if dom in self._domains:
            return True
        parts = dom.split(".")
        return any(".".join(parts[i:]) in self._domains for i in range(1, len(parts) - 1))

    def _parse_line(self, line: str) -> str | None:
        """Return the indexable token from a list line, or None to skip."""
        raise NotImplementedError


class FireholProvider(BlocklistProviderBase):
    name = "firehol"
    supported_types = frozenset({"ipv4"})
    mode = "ip"
    list_url = (
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/"
        "firehol_level1.netset"
    )

    def _parse_line(self, line: str) -> str | None:
        line = line.strip()
        if not line or line.startswith("#"):
            return None
        return line.split()[0]


class IpsumProvider(BlocklistProviderBase):
    name = "ipsum"
    supported_types = frozenset({"ipv4"})
    mode = "ip"
    list_url = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"

    def _parse_line(self, line: str) -> str | None:
        line = line.strip()
        if not line or line.startswith("#"):
            return None
        return line.split()[0]


_STEVENBLACK_SKIP = {
    "localhost", "localhost.localdomain", "local", "broadcasthost",
    "0.0.0.0", "::1", "ip6-localhost", "ip6-loopback",
}


class StevenBlackProvider(BlocklistProviderBase):
    name = "stevenblack"
    supported_types = frozenset({"domain"})
    mode = "domain"
    list_url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"

    def _parse_line(self, line: str) -> str | None:
        line = line.strip()
        if not line or line.startswith("#"):
            return None
        parts = line.split()
        if len(parts) < 2:
            return None
        host = parts[1]
        if host in _STEVENBLACK_SKIP:
            return None
        return host
