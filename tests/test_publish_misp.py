"""
Tests for the MISP event push adapter.

HTTP is fully mocked via the `transport` injection.
"""

from __future__ import annotations

from typing import Any

import pytest

from core.publish.misp import MispAdapter
from core.publish.protocol import PublicationAdapter, PublicationError, PublicationResult
from core.types import Finding, FindingCitation, IOCVerdict


def _ioc(value: str, ioc_type: str) -> IOCVerdict:
    return IOCVerdict(
        value=value,
        ioc_type=ioc_type,  # type: ignore[arg-type]
        verdict="malicious",
        confidence=0.85,
    )


def _sample_finding() -> Finding:
    return Finding(
        finding_id="F-1",
        summary="Attacker beaconing to C2",
        mitre=["T1071.001"],
        confidence=0.9,
        evidence=[FindingCitation(source="Security.evtx", locator="event=4624")],
    )


def test_misp_adapter_is_a_publication_adapter() -> None:
    adapter = MispAdapter(api_key="fake", base_url="https://misp.example/")
    assert isinstance(adapter, PublicationAdapter)
    assert adapter.name == "misp"


def test_misp_rejects_invalid_tlp() -> None:
    with pytest.raises(ValueError):
        MispAdapter(api_key="fake", base_url="https://misp.example/", tlp="puce")


def test_misp_rejects_missing_credentials() -> None:
    with pytest.raises(ValueError):
        MispAdapter(api_key="", base_url="https://misp.example/")
    with pytest.raises(ValueError):
        MispAdapter(api_key="fake", base_url="")


def test_misp_dry_run_builds_event_shape() -> None:
    adapter = MispAdapter(
        api_key="fake", base_url="https://misp.example/", tlp="amber"
    )
    iocs = [
        _ioc("203.0.113.10", "ipv4"),
        _ioc("evil.example", "domain"),
        _ioc("https://bad.example/x", "url"),
        _ioc("a" * 64, "sha256"),
        _ioc("bad@evil.example", "email"),
    ]
    result = adapter.publish(
        findings=[_sample_finding()],
        iocs=iocs,
        incident_id="INC-1",
        campaign_tag="TESTCAMP",
        dry_run=True,
    )
    assert isinstance(result, PublicationResult)
    assert result.status == "dry_run"
    assert result.adapter == "misp"

    event = result.details["payload"]["Event"]
    assert event["info"] == "TESTCAMP"
    assert event["distribution"] == 1
    assert event["threat_level_id"] == 2
    assert event["analysis"] == 2

    tag_names = {tag["name"] for tag in event["Tag"]}
    assert "tlp:amber" in tag_names
    assert "aptwatcher:INC-1" in tag_names
    assert "campaign:TESTCAMP" in tag_names

    attribute_types = [a["type"] for a in event["Attribute"]]
    assert "ip-dst" in attribute_types
    assert "domain" in attribute_types
    assert "url" in attribute_types
    assert "sha256" in attribute_types
    assert "email-src" in attribute_types

    # Finding added as a comment attribute
    comments = [a for a in event["Attribute"] if a["type"] == "comment"]
    assert len(comments) >= 1
    assert "beaconing" in comments[0]["value"]


def test_misp_dry_run_drops_unknown_types() -> None:
    adapter = MispAdapter(api_key="fake", base_url="https://misp.example/")
    # cve isn't in the MISP map used here.
    iocs = [_ioc("evil.example", "domain")]
    result = adapter.publish(
        findings=[],
        iocs=iocs,
        incident_id="INC-2",
        campaign_tag="C2",
        dry_run=True,
    )
    event = result.details["payload"]["Event"]
    # Only the domain attribute should be present (no findings, no extras).
    ioc_attrs = [a for a in event["Attribute"] if a["type"] != "comment"]
    assert len(ioc_attrs) == 1
    assert ioc_attrs[0]["type"] == "domain"


def test_misp_submitted_path_extracts_event_id() -> None:
    captured: dict[str, Any] = {}

    def fake_transport(**kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {
            "status_code": 200,
            "json": {"Event": {"id": "123", "uuid": "abc"}},
        }

    adapter = MispAdapter(
        api_key="fake",
        base_url="https://misp.example/",
        transport=fake_transport,
    )
    result = adapter.publish(
        findings=[],
        iocs=[_ioc("evil.example", "domain")],
        incident_id="INC-3",
        campaign_tag="C3",
        dry_run=False,
    )
    assert result.status == "submitted"
    assert result.target == "123"
    assert captured["url"].endswith("events/add")
    assert captured["headers"]["Authorization"] == "fake"


def test_misp_http_error_raises_publication_error() -> None:
    def fake_transport(**_kwargs: Any) -> dict[str, Any]:
        return {"status_code": 401, "body": {"message": "Invalid authkey"}}

    adapter = MispAdapter(
        api_key="bad",
        base_url="https://misp.example/",
        transport=fake_transport,
    )
    with pytest.raises(PublicationError) as exc_info:
        adapter.publish(
            findings=[],
            iocs=[_ioc("evil.example", "domain")],
            incident_id="INC-4",
            campaign_tag="C4",
            dry_run=False,
        )
    assert "401" in str(exc_info.value)
