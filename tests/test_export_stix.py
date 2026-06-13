"""
Tests for the STIX 2.1 bundle exporter.

Coverage:
- Top-level bundle shape (``type``, ``id``, ``objects``).
- One indicator SDO per input IOC.
- Pattern shape matches the IOC type (ipv4, domain, url, sha256, email).
- UUIDs are deterministic — two runs produce identical IDs.
- ``IOCExportError`` is raised on hostile input (empty value, embedded quote).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from core.analysis.export_stix import IOCExportError, export_stix_bundle
from core.types import Finding, FindingCitation, IOCVerdict


def _ioc(value: str, ioc_type: str, **kwargs: object) -> IOCVerdict:
    return IOCVerdict(
        value=value,
        ioc_type=ioc_type,  # type: ignore[arg-type]
        verdict="malicious",
        confidence=0.9,
        **kwargs,  # type: ignore[arg-type]
    )


def _sample_iocs() -> list[IOCVerdict]:
    return [
        _ioc("203.0.113.10", "ipv4"),
        _ioc("evil.example", "domain"),
        _ioc("https://bad.example/path?q=1", "url"),
        _ioc("a" * 64, "sha256"),
        _ioc("attacker@bad.example", "email"),
    ]


def test_bundle_has_required_top_level_fields(tmp_path: Path) -> None:
    out = tmp_path / "bundle.stix.json"
    bundle = export_stix_bundle(
        iocs=_sample_iocs(),
        output_path=out,
        incident_id="s01-2026-04-19-1523",
    )
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    assert isinstance(bundle["objects"], list)
    assert out.exists()
    # The written file should round-trip through json.loads.
    on_disk = json.loads(out.read_text(encoding="utf-8"))
    assert on_disk["id"] == bundle["id"]


def test_one_indicator_per_input_ioc(tmp_path: Path) -> None:
    iocs = _sample_iocs()
    bundle = export_stix_bundle(
        iocs=iocs,
        output_path=tmp_path / "b.json",
        incident_id="inc-1",
    )
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(indicators) == len(iocs)
    # Also check the identity SDO is present.
    identities = [o for o in bundle["objects"] if o["type"] == "identity"]
    assert len(identities) == 1
    assert identities[0]["id"] == "identity--aptwatcher"


def test_pattern_matches_ioc_type(tmp_path: Path) -> None:
    iocs = [
        _ioc("203.0.113.10", "ipv4"),
        _ioc("evil.example", "domain"),
        _ioc("https://bad.example/path", "url"),
        _ioc("deadbeef" * 8, "sha256"),
        _ioc("attacker@bad.example", "email"),
    ]
    bundle = export_stix_bundle(
        iocs=iocs,
        output_path=tmp_path / "b.json",
        incident_id="inc-2",
    )
    patterns = {
        o["name"]: o["pattern"]
        for o in bundle["objects"]
        if o["type"] == "indicator"
    }
    assert patterns["ipv4: 203.0.113.10"] == "[ipv4-addr:value = '203.0.113.10']"
    assert patterns["domain: evil.example"] == "[domain-name:value = 'evil.example']"
    assert (
        patterns["url: https://bad.example/path"]
        == "[url:value = 'https://bad.example/path']"
    )
    sha_key = f"sha256: {'deadbeef' * 8}"
    assert patterns[sha_key] == f"[file:hashes.'SHA-256' = '{'deadbeef' * 8}']"
    assert (
        patterns["email: attacker@bad.example"]
        == "[email-addr:value = 'attacker@bad.example']"
    )
    # Every indicator must declare pattern_type=stix per STIX 2.1.
    for obj in bundle["objects"]:
        if obj["type"] == "indicator":
            assert obj["pattern_type"] == "stix"
            assert obj["labels"] == ["malicious-activity"]
            assert obj["spec_version"] == "2.1"


def test_deterministic_uuids_across_runs(tmp_path: Path) -> None:
    iocs = _sample_iocs()
    b1 = export_stix_bundle(
        iocs=iocs,
        output_path=tmp_path / "b1.json",
        incident_id="stable-id",
    )
    b2 = export_stix_bundle(
        iocs=iocs,
        output_path=tmp_path / "b2.json",
        incident_id="stable-id",
    )
    ids1 = [o["id"] for o in b1["objects"] if o["type"] == "indicator"]
    ids2 = [o["id"] for o in b2["objects"] if o["type"] == "indicator"]
    assert ids1 == ids2
    assert b1["id"] == b2["id"]


def test_raises_on_empty_value(tmp_path: Path) -> None:
    bad = IOCVerdict(value="   ", ioc_type="domain", verdict="malicious")
    with pytest.raises(IOCExportError):
        export_stix_bundle(
            iocs=[bad],
            output_path=tmp_path / "b.json",
            incident_id="inc-x",
        )


def test_raises_on_single_quote_in_value(tmp_path: Path) -> None:
    bad = IOCVerdict(value="evil'example.com", ioc_type="domain", verdict="malicious")
    with pytest.raises(IOCExportError):
        export_stix_bundle(
            iocs=[bad],
            output_path=tmp_path / "b.json",
            incident_id="inc-y",
        )


def test_raises_on_empty_ioc_list(tmp_path: Path) -> None:
    with pytest.raises(IOCExportError):
        export_stix_bundle(
            iocs=[],
            output_path=tmp_path / "b.json",
            incident_id="inc-z",
        )


def test_findings_accepted_but_bundle_remains_valid(tmp_path: Path) -> None:
    findings = [
        Finding(
            finding_id="F-1",
            summary="Indicator cluster",
            confidence=0.8,
            evidence=[FindingCitation(source="audit:x")],
        )
    ]
    bundle = export_stix_bundle(
        iocs=_sample_iocs(),
        findings=findings,
        output_path=tmp_path / "b.json",
        incident_id="inc-with-findings",
    )
    # Findings are accepted without raising; bundle still has indicators.
    assert any(o["type"] == "indicator" for o in bundle["objects"])


def test_valid_from_uses_first_seen_when_available(tmp_path: Path) -> None:
    seen = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    iocs = [
        IOCVerdict(
            value="10.0.0.1",
            ioc_type="ipv4",
            verdict="malicious",
            first_seen=seen,
        )
    ]
    bundle = export_stix_bundle(
        iocs=iocs,
        output_path=tmp_path / "b.json",
        incident_id="inc-ts",
    )
    indicator = next(o for o in bundle["objects"] if o["type"] == "indicator")
    assert indicator["valid_from"].startswith("2026-01-02T03:04:05")
