"""
Tests for the Netcraft Report v3 publication adapter.

All HTTP traffic is intercepted via the `transport` injection — no real
network calls are ever made.
"""

from __future__ import annotations

from typing import Any

import pytest

from core.publish.netcraft import NetcraftAdapter
from core.publish.protocol import PublicationAdapter, PublicationError, PublicationResult
from core.types import IOCVerdict


def _ioc(value: str, ioc_type: str) -> IOCVerdict:
    return IOCVerdict(
        value=value,
        ioc_type=ioc_type,  # type: ignore[arg-type]
        verdict="malicious",
        confidence=0.9,
    )


def _sample_mixed_iocs() -> list[IOCVerdict]:
    return [
        _ioc("https://bad.example/path", "url"),
        _ioc("evil.example", "domain"),
        _ioc("203.0.113.10", "ipv4"),
        _ioc("a" * 64, "sha256"),        # dropped
        _ioc("attacker@bad.example", "email"),  # dropped
    ]


def test_netcraft_adapter_is_a_publication_adapter() -> None:
    adapter = NetcraftAdapter(api_key="fake")
    assert isinstance(adapter, PublicationAdapter)
    assert adapter.name == "netcraft"


def test_netcraft_rejects_empty_api_key() -> None:
    with pytest.raises(ValueError):
        NetcraftAdapter(api_key="")


def test_netcraft_dry_run_returns_serialized_payload() -> None:
    adapter = NetcraftAdapter(api_key="fake")
    result = adapter.publish(
        findings=[],
        iocs=_sample_mixed_iocs(),
        incident_id="INC-1",
        campaign_tag="CAMPAIGN-A",
        dry_run=True,
    )
    assert isinstance(result, PublicationResult)
    assert result.status == "dry_run"
    assert result.adapter == "netcraft"

    payload = result.details["payload"]
    assert payload["reason"].startswith("Confirmed malicious")
    assert payload["incident_id"] == "INC-1"
    assert payload["campaign"] == "CAMPAIGN-A"
    assert result.details["accepted_iocs"] == 3
    assert result.details["dropped_iocs"] == 2
    assert "report/urls" in result.details["endpoint"]


def test_netcraft_only_keeps_url_domain_ipv4() -> None:
    adapter = NetcraftAdapter(api_key="fake")
    result = adapter.publish(
        findings=[],
        iocs=_sample_mixed_iocs(),
        incident_id="INC-1",
        campaign_tag="CAMPAIGN-A",
        dry_run=True,
    )
    values = [u["url"] for u in result.details["payload"]["urls"]]
    types = [u["type"] for u in result.details["payload"]["urls"]]
    assert values == [
        "https://bad.example/path",
        "evil.example",
        "203.0.113.10",
    ]
    # ipv4 is normalized to "ip" for Netcraft.
    assert "ip" in types
    assert "sha256" not in types
    assert "email" not in types


def test_netcraft_submitted_with_2xx_mock() -> None:
    captured: dict[str, Any] = {}

    def fake_transport(**kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {"status_code": 201, "json": {"uuid": "abcd-1234"}}

    adapter = NetcraftAdapter(api_key="fake", transport=fake_transport)
    result = adapter.publish(
        findings=[],
        iocs=[_ioc("evil.example", "domain")],
        incident_id="INC-2",
        campaign_tag="C2",
        dry_run=False,
    )
    assert result.status == "submitted"
    assert result.target == "abcd-1234"
    assert captured["method"] == "POST"
    assert "report/urls" in captured["url"]
    assert captured["headers"]["Authorization"] == "Bearer fake"
    assert captured["json"]["urls"][0]["url"] == "evil.example"


def test_netcraft_4xx_raises_publication_error() -> None:
    def fake_transport(**_kwargs: Any) -> dict[str, Any]:
        return {"status_code": 403, "body": {"error": "forbidden"}}

    adapter = NetcraftAdapter(api_key="fake", transport=fake_transport)
    with pytest.raises(PublicationError) as exc_info:
        adapter.publish(
            findings=[],
            iocs=[_ioc("evil.example", "domain")],
            incident_id="INC-3",
            campaign_tag="C3",
            dry_run=False,
        )
    assert "403" in str(exc_info.value)


def test_netcraft_5xx_raises_publication_error() -> None:
    def fake_transport(**_kwargs: Any) -> dict[str, Any]:
        return {"status_code": 502, "body": "bad gateway"}

    adapter = NetcraftAdapter(api_key="fake", transport=fake_transport)
    with pytest.raises(PublicationError):
        adapter.publish(
            findings=[],
            iocs=[_ioc("evil.example", "domain")],
            incident_id="INC-4",
            campaign_tag="C4",
            dry_run=False,
        )


def test_netcraft_empty_filtered_submit_is_noop() -> None:
    """Submitting only non-accepted types in real mode yields an empty no-op."""
    calls: list[dict[str, Any]] = []

    def fake_transport(**kwargs: Any) -> dict[str, Any]:
        calls.append(kwargs)
        return {"status_code": 200, "json": {}}

    adapter = NetcraftAdapter(api_key="fake", transport=fake_transport)
    result = adapter.publish(
        findings=[],
        iocs=[_ioc("a" * 64, "sha256")],  # filtered out
        incident_id="INC-5",
        campaign_tag="C5",
        dry_run=False,
    )
    assert result.status == "submitted"
    assert result.target == "netcraft-empty"
    assert result.details["submitted_iocs"] == 0
    # No HTTP call should have been issued for an empty submission.
    assert calls == []
