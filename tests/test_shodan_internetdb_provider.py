"""Unit tests for the Shodan InternetDB keyless provider."""

from __future__ import annotations

import httpx
import pytest

from core.intel.base import IOCQuery, IOCTransportError
from core.intel.shodan_internetdb import ShodanInternetDbProvider


def _p(handler) -> ShodanInternetDbProvider:
    return ShodanInternetDbProvider(http_client=httpx.Client(transport=httpx.MockTransport(handler)))


def test_404_not_indexed_is_unknown() -> None:
    p = _p(lambda r: httpx.Response(404, json={}))
    res = p.query(IOCQuery(value="8.8.8.8", ioc_type="ipv4"))
    assert res.verdict == "unknown"
    assert res.raw["not_indexed"] is True
    p.close()


def test_malicious_tag_is_malicious() -> None:
    p = _p(lambda r: httpx.Response(200, json={"tags": ["compromised"], "vulns": []}))
    res = p.query(IOCQuery(value="1.2.3.4", ioc_type="ipv4"))
    assert res.verdict == "malicious"
    p.close()


def test_vulns_only_is_suspicious() -> None:
    p = _p(lambda r: httpx.Response(200, json={"tags": ["cloud"], "vulns": ["CVE-2024-1"]}))
    res = p.query(IOCQuery(value="1.2.3.4", ioc_type="ipv4"))
    assert res.verdict == "suspicious"
    p.close()


def test_clean_indexed_is_benign() -> None:
    p = _p(lambda r: httpx.Response(200, json={"tags": [], "vulns": [], "ports": [443]}))
    res = p.query(IOCQuery(value="1.1.1.1", ioc_type="ipv4"))
    assert res.verdict == "benign"
    p.close()


def test_only_supports_ip() -> None:
    p = _p(lambda r: httpx.Response(200, json={}))
    assert p.supports("ipv4") and p.supports("ipv6") and not p.supports("domain")
    p.close()


def test_500_raises() -> None:
    p = _p(lambda r: httpx.Response(502))
    with pytest.raises(IOCTransportError):
        p.query(IOCQuery(value="1.2.3.4", ioc_type="ipv4"))
    p.close()
