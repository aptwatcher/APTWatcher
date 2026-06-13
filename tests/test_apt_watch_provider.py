"""Unit tests for the APTWatch curated Tier 1 provider.

Uses httpx.MockTransport so no network is touched. Covers request shaping
(IOC type mapping, endpoint, params), verdict/score mapping, the
no-match -> unknown rule, transport-error handling, and aggregator
integration.
"""

from __future__ import annotations

import logging

import httpx
import pytest

from core.intel.aggregator import IOCAggregator
from core.intel.apt_watch import AptWatchProvider
from core.intel.base import IOCQuery, IOCTransportError


def _provider(handler) -> AptWatchProvider:
    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)
    return AptWatchProvider(http_client=client, min_confidence="medium")


def test_lookup_ip_builds_correct_request() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["type"] = request.url.params.get("type")
        seen["value"] = request.url.params.get("value")
        seen["min_confidence"] = request.url.params.get("min_confidence")
        return httpx.Response(200, json={"matches": []})

    p = _provider(handler)
    p.query(IOCQuery(value="144.172.99.68", ioc_type="ipv4"))
    assert seen["path"] == "/intel/v1/ioc/lookup"
    assert seen["type"] == "ip"          # ipv4 -> ip
    assert seen["value"] == "144.172.99.68"
    assert seen["min_confidence"] == "medium"
    p.close()


def test_match_high_confidence_is_malicious() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "value": "kittiesmc.com",
                "matches": [
                    {"actor_id": "2", "name": "Forest Blizzard",
                     "confidence": "high", "confidence_score": 0.93},
                    {"actor_id": "9", "name": "Other",
                     "confidence": "low", "confidence_score": 0.2},
                ],
            },
        )

    p = _provider(handler)
    result = p.query(IOCQuery(value="kittiesmc.com", ioc_type="domain"))
    assert result.name == "apt_watch"
    assert result.verdict == "malicious"
    assert result.score == pytest.approx(0.93)   # strongest match wins
    p.close()


def test_no_match_is_unknown_not_benign() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"matches": [], "infrastructure": {"asn": 53667}})

    p = _provider(handler)
    result = p.query(IOCQuery(value="8.8.8.8", ioc_type="ipv4"))
    assert result.verdict == "unknown"
    assert result.score is None
    assert result.raw["infrastructure"]["asn"] == 53667
    p.close()


@pytest.mark.parametrize(
    "ioc_type,expected",
    [("ipv6", "ip"), ("sha256", "hash"), ("sha1", "hash"), ("md5", "hash"),
     ("url", "url"), ("email", "email")],
)
def test_type_mapping(ioc_type: str, expected: str) -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["type"] = request.url.params.get("type")
        return httpx.Response(200, json={"matches": []})

    p = _provider(handler)
    assert p.supports(ioc_type)            # provider supports every IOCType
    p.query(IOCQuery(value="x", ioc_type=ioc_type))
    assert seen["type"] == expected
    p.close()


def test_rate_limit_raises_transport_error() -> None:
    p = _provider(lambda r: httpx.Response(429, json={"error": "rate limited"}))
    with pytest.raises(IOCTransportError):
        p.query(IOCQuery(value="1.2.3.4", ioc_type="ipv4"))
    p.close()


def test_v1_0_1_envelope_additive_fields_are_ignored() -> None:
    # Live v1.0.1 envelope carries many additive top-level fields the wrapper
    # does not read. Parsing must still succeed, the verdict/score must come
    # only from matches, and every extra field must survive untouched in raw.
    envelope = {
        "query_id": "q-7f3a",
        "type": "domain",
        "value": "kittiesmc.com",
        "normalized": "kittiesmc.com",
        "result_count": 1,
        "first_observed": "2025-11-02T00:00:00Z",
        "last_observed": "2026-06-10T00:00:00Z",
        "lifecycle_state": "active",
        "infrastructure": {"asn": 64500, "country": "RU"},
        "scoring": {"model": "curated-v2", "weight": 0.8},
        "matches": [
            {"actor_id": "2", "name": "Forest Blizzard",
             "confidence": "high", "confidence_score": 0.91},
        ],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=envelope)

    p = _provider(handler)
    result = p.query(IOCQuery(value="kittiesmc.com", ioc_type="domain"))
    assert result.verdict == "malicious"
    assert result.score == pytest.approx(0.91)
    # Additive fields are ignored for the verdict but preserved verbatim in raw.
    assert result.raw["lifecycle_state"] == "active"
    assert result.raw["infrastructure"]["asn"] == 64500
    assert result.raw["scoring"]["model"] == "curated-v2"
    assert result.raw["query_id"] == "q-7f3a"
    p.close()


def test_matches_without_confidence_fields_warns_and_keeps_fallback(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # A populated match set with neither `confidence` nor `confidence_score`
    # must log a degradation warning WITHOUT changing the existing fallback
    # verdict (band "" -> suspicious, score None).
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "value": "kittiesmc.com",
                "matches": [
                    {"actor_id": "2", "name": "Forest Blizzard"},
                    {"actor_id": "9", "name": "Other"},
                ],
            },
        )

    p = _provider(handler)
    with caplog.at_level(logging.WARNING, logger="core.intel.apt_watch"):
        result = p.query(IOCQuery(value="kittiesmc.com", ioc_type="domain"))

    assert "apt_watch: scoring fields absent, verdict degraded" in caplog.text
    # Fallback verdict is unchanged: no usable band -> suspicious, no score.
    assert result.verdict == "suspicious"
    assert result.score is None
    p.close()


def test_aggregator_integration_abstains_on_transport_error() -> None:
    # A provider raising IOCProviderError counts as abstention -> unknown.
    p = _provider(lambda r: httpx.Response(503))
    agg = IOCAggregator()
    agg.register(p)
    verdict = agg.lookup(IOCQuery(value="1.2.3.4", ioc_type="ipv4"))
    assert verdict.verdict == "unknown"
    assert verdict.sources == []
    agg.close()
