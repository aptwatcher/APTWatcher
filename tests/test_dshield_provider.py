"""Unit tests for the DShield (SANS ISC) keyless Tier 1 provider."""

from __future__ import annotations

import httpx
import pytest

from core.intel.aggregator import IOCAggregator
from core.intel.base import IOCQuery, IOCTransportError
from core.intel.dshield import DShieldProvider


def _provider(handler) -> DShieldProvider:
    return DShieldProvider(http_client=httpx.Client(transport=httpx.MockTransport(handler)))


def test_threatfeeds_present_is_malicious() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/ip/1.2.3.4"
        return httpx.Response(200, json={"ip": {"count": 12, "attacks": 4,
                                                 "threatfeeds": {"feodo": {}}, "asname": "EVIL"}})

    p = _provider(handler)
    r = p.query(IOCQuery(value="1.2.3.4", ioc_type="ipv4"))
    assert r.name == "dshield"
    assert r.verdict == "malicious"
    p.close()


def test_counts_only_is_suspicious() -> None:
    p = _provider(lambda req: httpx.Response(200, json={"ip": {"count": 5, "attacks": 0,
                                                               "threatfeeds": {}, "asname": "X"}}))
    r = p.query(IOCQuery(value="1.2.3.4", ioc_type="ipv4"))
    assert r.verdict == "suspicious"
    p.close()


def test_known_quiet_is_benign() -> None:
    p = _provider(lambda req: httpx.Response(200, json={"ip": {"count": 0, "attacks": 0,
                                                               "threatfeeds": {}, "asname": "CLOUDFLARE"}}))
    r = p.query(IOCQuery(value="1.1.1.1", ioc_type="ipv4"))
    assert r.verdict == "benign"
    p.close()


def test_empty_is_unknown() -> None:
    p = _provider(lambda req: httpx.Response(200, json={"ip": {}}))
    r = p.query(IOCQuery(value="9.9.9.9", ioc_type="ipv4"))
    assert r.verdict == "unknown"
    p.close()


def test_500_raises_transport_error() -> None:
    p = _provider(lambda req: httpx.Response(503))
    with pytest.raises(IOCTransportError):
        p.query(IOCQuery(value="1.2.3.4", ioc_type="ipv4"))
    p.close()


def test_only_supports_ip() -> None:
    p = _provider(lambda req: httpx.Response(200, json={"ip": {}}))
    assert p.supports("ipv4") and p.supports("ipv6")
    assert not p.supports("domain")
    p.close()


def test_two_providers_aggregate_malicious_wins() -> None:
    # DShield says malicious; a benign stub-like provider should not override.
    ds = _provider(lambda req: httpx.Response(200, json={"ip": {"threatfeeds": {"x": {}}}}))
    agg = IOCAggregator()
    agg.register(ds)
    verdict = agg.lookup(IOCQuery(value="1.2.3.4", ioc_type="ipv4"))
    assert verdict.verdict == "malicious"
    assert [s.name for s in verdict.sources] == ["dshield"]
    agg.close()
