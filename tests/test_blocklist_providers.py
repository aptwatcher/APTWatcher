"""Unit tests for the keyless blocklist providers (FireHOL/IPsum/StevenBlack)."""

from __future__ import annotations

import httpx

from core.intel.base import IOCQuery
from core.intel.blocklist import FireholProvider, IpsumProvider, StevenBlackProvider

_NETSET = "# firehol level1\n1.2.3.4\n10.0.0.0/8\n203.0.113.7\n"
_IPSUM = "# ipsum\n1.2.3.4\t9\n198.51.100.5\t3\n"
_HOSTS = "# StevenBlack hosts\n0.0.0.0 localhost\n0.0.0.0 evil.example\n0.0.0.0 ads.tracker.net\n"


def _client(text: str) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, text=text)))


def test_firehol_exact_and_cidr() -> None:
    p = FireholProvider(http_client=_client(_NETSET))
    assert p.query(IOCQuery(value="1.2.3.4", ioc_type="ipv4")).verdict == "malicious"   # exact
    assert p.query(IOCQuery(value="10.5.6.7", ioc_type="ipv4")).verdict == "malicious"   # in 10.0.0.0/8
    assert p.query(IOCQuery(value="8.8.8.8", ioc_type="ipv4")).verdict == "unknown"      # miss
    p.close()


def test_firehol_only_supports_ipv4() -> None:
    p = FireholProvider(http_client=_client(_NETSET))
    assert p.supports("ipv4") and not p.supports("domain")
    p.close()


def test_ipsum_first_token() -> None:
    p = IpsumProvider(http_client=_client(_IPSUM))
    assert p.query(IOCQuery(value="198.51.100.5", ioc_type="ipv4")).verdict == "malicious"
    assert p.query(IOCQuery(value="9.9.9.9", ioc_type="ipv4")).verdict == "unknown"
    p.close()


def test_stevenblack_domain_and_parent() -> None:
    p = StevenBlackProvider(http_client=_client(_HOSTS))
    assert p.query(IOCQuery(value="evil.example", ioc_type="domain")).verdict == "malicious"
    assert p.query(IOCQuery(value="sub.ads.tracker.net", ioc_type="domain")).verdict == "malicious"  # parent
    assert p.query(IOCQuery(value="good.example", ioc_type="domain")).verdict == "unknown"
    assert p.query(IOCQuery(value="localhost", ioc_type="domain")).verdict == "unknown"  # skipped
    p.close()


def test_blocklist_loads_once() -> None:
    calls = {"n": 0}

    def handler(r: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, text=_NETSET)

    p = FireholProvider(http_client=httpx.Client(transport=httpx.MockTransport(handler)))
    p.query(IOCQuery(value="1.2.3.4", ioc_type="ipv4"))
    p.query(IOCQuery(value="5.5.5.5", ioc_type="ipv4"))
    assert calls["n"] == 1   # downloaded once, cached in memory
    p.close()
