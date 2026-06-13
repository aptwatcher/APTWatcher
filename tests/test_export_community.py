"""
Tests for the community-feed YAML exporter.

Coverage:
- YAML file parses back through ``yaml.safe_load``.
- ``submission`` block carries ``campaign``, ``submitter``, ``submitted_at``.
- ``indicators`` list has one entry per input IOC with the expected keys.
- ``findings`` list preserves finding IDs and MITRE techniques.
- ``campaign_tag`` and ``submitter`` are required.
- Banner is prepended but the body remains parseable.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from core.analysis.export_community import export_community_yaml
from core.analysis.export_stix import IOCExportError
from core.types import Finding, FindingCitation, IOCVerdict


def _ioc(value: str, ioc_type: str, confidence: float | None = 0.8) -> IOCVerdict:
    return IOCVerdict(
        value=value,
        ioc_type=ioc_type,  # type: ignore[arg-type]
        verdict="malicious",
        confidence=confidence,
        first_seen=datetime(2026, 3, 1, tzinfo=UTC),
    )


def _findings() -> list[Finding]:
    return [
        Finding(
            finding_id="F-100",
            summary="C2 beaconing to evil.example",
            mitre=["T1071.001", "T1059"],
            confidence=0.9,
            evidence=[FindingCitation(source="pcap:conn-1")],
        ),
        Finding(
            finding_id="F-101",
            summary="Suspicious scheduled task",
            mitre=["T1053"],
            confidence=0.6,
            evidence=[FindingCitation(source="evtx:task")],
        ),
    ]


def test_yaml_parses_back_correctly(tmp_path: Path) -> None:
    out = tmp_path / "community-submission.yaml"
    doc = export_community_yaml(
        iocs=[_ioc("1.2.3.4", "ipv4"), _ioc("evil.example", "domain")],
        findings=_findings(),
        output_path=out,
        campaign_tag="OPERATION_TEST",
        submitter="apt-bot",
    )
    parsed = yaml.safe_load(out.read_text(encoding="utf-8"))
    assert parsed == doc


def test_submission_block_has_required_fields(tmp_path: Path) -> None:
    out = tmp_path / "c.yaml"
    export_community_yaml(
        iocs=[_ioc("1.2.3.4", "ipv4")],
        findings=_findings(),
        output_path=out,
        campaign_tag="OP_ALPHA",
        submitter="apt-bot",
    )
    parsed = yaml.safe_load(out.read_text(encoding="utf-8"))
    assert parsed["submission"]["campaign"] == "OP_ALPHA"
    assert parsed["submission"]["submitter"] == "apt-bot"
    assert "submitted_at" in parsed["submission"]


def test_indicator_fields_present(tmp_path: Path) -> None:
    out = tmp_path / "c.yaml"
    iocs = [
        _ioc("1.2.3.4", "ipv4", confidence=0.9),
        _ioc("evil.example", "domain", confidence=0.5),
        _ioc("a" * 64, "sha256", confidence=0.2),
    ]
    export_community_yaml(
        iocs=iocs,
        findings=[],
        output_path=out,
        campaign_tag="OP_BETA",
        submitter="bot",
    )
    parsed = yaml.safe_load(out.read_text(encoding="utf-8"))
    inds = parsed["indicators"]
    assert len(inds) == 3
    for entry in inds:
        assert "type" in entry
        assert "value" in entry
        assert "confidence" in entry
        assert "source" in entry
        assert entry["source"] == "APTWatcher"
    # Confidence bucketing: 0.9 -> high, 0.5 -> medium, 0.2 -> low.
    buckets = {e["value"]: e["confidence"] for e in inds}
    assert buckets["1.2.3.4"] == "high"
    assert buckets["evil.example"] == "medium"
    assert buckets["a" * 64] == "low"


def test_findings_preserve_id_and_techniques(tmp_path: Path) -> None:
    out = tmp_path / "c.yaml"
    export_community_yaml(
        iocs=[_ioc("1.2.3.4", "ipv4")],
        findings=_findings(),
        output_path=out,
        campaign_tag="OP_GAMMA",
        submitter="bot",
    )
    parsed = yaml.safe_load(out.read_text(encoding="utf-8"))
    f_by_id = {f["id"]: f for f in parsed["findings"]}
    assert set(f_by_id) == {"F-100", "F-101"}
    assert f_by_id["F-100"]["techniques"] == ["T1071.001", "T1059"]
    assert f_by_id["F-101"]["techniques"] == ["T1053"]


def test_campaign_tag_required(tmp_path: Path) -> None:
    with pytest.raises(IOCExportError):
        export_community_yaml(
            iocs=[_ioc("1.2.3.4", "ipv4")],
            findings=[],
            output_path=tmp_path / "c.yaml",
            campaign_tag="",
            submitter="bot",
        )


def test_submitter_required(tmp_path: Path) -> None:
    with pytest.raises(IOCExportError):
        export_community_yaml(
            iocs=[_ioc("1.2.3.4", "ipv4")],
            findings=[],
            output_path=tmp_path / "c.yaml",
            campaign_tag="OP_DELTA",
            submitter="",
        )


def test_empty_inputs_rejected(tmp_path: Path) -> None:
    with pytest.raises(IOCExportError):
        export_community_yaml(
            iocs=[],
            findings=[],
            output_path=tmp_path / "c.yaml",
            campaign_tag="OP_EPSILON",
            submitter="bot",
        )


def test_banner_present_and_yaml_still_valid(tmp_path: Path) -> None:
    out = tmp_path / "c.yaml"
    export_community_yaml(
        iocs=[_ioc("1.2.3.4", "ipv4")],
        findings=[],
        output_path=out,
        campaign_tag="OP_ZETA",
        submitter="bot",
    )
    text = out.read_text(encoding="utf-8")
    assert text.startswith("# DO NOT EDIT")
    # The body after the banner still parses.
    parsed = yaml.safe_load(text)
    assert parsed["submission"]["campaign"] == "OP_ZETA"
