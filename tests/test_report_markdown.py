"""
Tests for the Markdown analyst-narrative and TTP-assessment renderers.

Coverage:
- Narrative parses as valid Markdown (round-trips through a header
  parser) and carries exactly one H1.
- Summary section exists and contains the finding count.
- TTP assessment groups findings by MITRE technique.
- Empty finding list is handled cleanly.
- Refuses to overwrite.
- Findings without any MITRE technique land under the ``UNMAPPED`` key.
- Markdown table for IOCs preserves one row per IOC.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from core.analysis.report_docx import ReportRenderError
from core.analysis.report_markdown import (
    render_analyst_markdown,
    render_ttp_assessment,
)
from core.types import Finding, FindingCitation, IOCProviderResult, IOCVerdict


def _ioc(value: str, ioc_type: str, confidence: float | None = 0.8) -> IOCVerdict:
    return IOCVerdict(
        value=value,
        ioc_type=ioc_type,  # type: ignore[arg-type]
        verdict="malicious",
        confidence=confidence,
        sources=[IOCProviderResult(name="stub", verdict="malicious", score=confidence)],
    )


def _findings() -> list[Finding]:
    return [
        Finding(
            finding_id="F-200",
            summary="Credential dumping via lsass access",
            mitre=["T1003.001"],
            confidence=0.95,
            evidence=[FindingCitation(source="memory:volatility", locator="pid=632")],
        ),
        Finding(
            finding_id="F-201",
            summary="PowerShell encoded command",
            mitre=["T1059.001", "T1027"],
            confidence=0.7,
            evidence=[FindingCitation(source="Security.evtx", locator="event_id=4104")],
        ),
        Finding(
            finding_id="F-202",
            summary="Benign-looking anomaly",
            mitre=[],
            confidence=0.3,
            evidence=[FindingCitation(source="anomaly:score")],
        ),
    ]


def _iocs() -> list[IOCVerdict]:
    return [
        _ioc("10.0.0.5", "ipv4"),
        _ioc("evil.example", "domain"),
    ]


def _collect_headings(text: str) -> list[tuple[int, str]]:
    """Return (level, text) tuples for every ATX heading in ``text``."""
    out: list[tuple[int, str]] = []
    for line in text.splitlines():
        m = re.match(r"^(#+)\s+(.*)$", line)
        if m:
            out.append((len(m.group(1)), m.group(2)))
    return out


# ---------------------------------------------------------------------------
# Analyst narrative
# ---------------------------------------------------------------------------


def test_analyst_narrative_has_single_h1(tmp_path: Path) -> None:
    out = tmp_path / "ANALYSIS-inc.md"
    render_analyst_markdown(
        findings=_findings(),
        iocs=_iocs(),
        output_path=out,
        incident_id="inc-001",
        campaign_tag="S01_TEST",
    )
    text = out.read_text(encoding="utf-8")
    headings = _collect_headings(text)
    h1 = [h for h in headings if h[0] == 1]
    assert len(h1) == 1
    assert "S01_TEST" in h1[0][1]


def test_analyst_narrative_has_required_sections(tmp_path: Path) -> None:
    out = tmp_path / "ANALYSIS-inc.md"
    render_analyst_markdown(
        findings=_findings(),
        iocs=_iocs(),
        output_path=out,
        incident_id="inc-001",
        campaign_tag="S01_TEST",
        operator="daniel",
    )
    text = out.read_text(encoding="utf-8")
    h2 = [h[1] for h in _collect_headings(text) if h[0] == 2]
    assert "Summary" in h2
    assert "Findings" in h2
    assert "IOCs" in h2
    assert "Next steps" in h2


def test_analyst_narrative_finding_rows_match(tmp_path: Path) -> None:
    out = tmp_path / "ANALYSIS.md"
    findings = _findings()
    render_analyst_markdown(
        findings=findings,
        iocs=_iocs(),
        output_path=out,
        incident_id="inc",
        campaign_tag="C",
    )
    text = out.read_text(encoding="utf-8")
    # Each finding renders as an H3 block.
    h3 = [h[1] for h in _collect_headings(text) if h[0] == 3]
    assert len(h3) == len(findings)
    for f in findings:
        assert any(f.finding_id in h for h in h3), f"missing {f.finding_id}"


def test_analyst_narrative_empty_findings(tmp_path: Path) -> None:
    out = tmp_path / "empty.md"
    render_analyst_markdown(
        findings=[],
        iocs=[],
        output_path=out,
        incident_id="inc-empty",
        campaign_tag="EMPTY",
    )
    text = out.read_text(encoding="utf-8")
    assert "_No findings recorded._" in text
    assert "_No indicators recorded._" in text


def test_analyst_narrative_refuses_overwrite(tmp_path: Path) -> None:
    out = tmp_path / "ANALYSIS.md"
    render_analyst_markdown(
        findings=_findings(),
        iocs=_iocs(),
        output_path=out,
        incident_id="inc",
        campaign_tag="C",
    )
    with pytest.raises(ReportRenderError, match="refusing to overwrite"):
        render_analyst_markdown(
            findings=_findings(),
            iocs=_iocs(),
            output_path=out,
            incident_id="inc",
            campaign_tag="C",
        )


def test_ioc_table_rows_match(tmp_path: Path) -> None:
    out = tmp_path / "ANALYSIS.md"
    iocs = _iocs()
    render_analyst_markdown(
        findings=_findings(),
        iocs=iocs,
        output_path=out,
        incident_id="inc",
        campaign_tag="C",
    )
    text = out.read_text(encoding="utf-8")
    # Find the IOCs table. Count pipe-prefixed lines following the header
    # marker row ``|-----|``.
    lines = text.splitlines()
    in_table = False
    data_rows = 0
    for line in lines:
        if re.match(r"^\|[-\s|]+\|$", line):
            in_table = True
            continue
        if in_table:
            if not line.startswith("|"):
                break
            data_rows += 1
    assert data_rows == len(iocs)


# ---------------------------------------------------------------------------
# TTP assessment
# ---------------------------------------------------------------------------


def test_ttp_groups_by_technique(tmp_path: Path) -> None:
    out = tmp_path / "TTP.md"
    render_ttp_assessment(
        findings=_findings(),
        output_path=out,
        incident_id="inc-001",
        campaign_tag="S01_TEST",
    )
    text = out.read_text(encoding="utf-8")
    # T1003.001, T1059.001, T1027 should each appear as an H2 block.
    assert "## `T1003.001`" in text
    assert "## `T1059.001`" in text
    assert "## `T1027`" in text


def test_ttp_unmapped_grouping(tmp_path: Path) -> None:
    out = tmp_path / "TTP.md"
    render_ttp_assessment(
        findings=_findings(),
        output_path=out,
        incident_id="inc-001",
        campaign_tag="S01_TEST",
    )
    text = out.read_text(encoding="utf-8")
    assert "UNMAPPED" in text


def test_ttp_frequency_table_present(tmp_path: Path) -> None:
    out = tmp_path / "TTP.md"
    render_ttp_assessment(
        findings=_findings(),
        output_path=out,
        incident_id="inc-001",
        campaign_tag="S01_TEST",
    )
    text = out.read_text(encoding="utf-8")
    assert "## Technique Frequency" in text
    assert "| Technique | Count | Highest Severity |" in text


def test_ttp_empty_findings(tmp_path: Path) -> None:
    out = tmp_path / "TTP.md"
    render_ttp_assessment(
        findings=[],
        output_path=out,
        incident_id="inc-empty",
        campaign_tag="EMPTY",
    )
    text = out.read_text(encoding="utf-8")
    headings = _collect_headings(text)
    h1 = [h for h in headings if h[0] == 1]
    assert len(h1) == 1
    assert "_No findings available._" in text


def test_ttp_refuses_overwrite(tmp_path: Path) -> None:
    out = tmp_path / "TTP.md"
    render_ttp_assessment(
        findings=_findings(),
        output_path=out,
        incident_id="inc",
        campaign_tag="C",
    )
    with pytest.raises(ReportRenderError, match="refusing to overwrite"):
        render_ttp_assessment(
            findings=_findings(),
            output_path=out,
            incident_id="inc",
            campaign_tag="C",
        )


def test_ttp_empty_incident_id_raises(tmp_path: Path) -> None:
    with pytest.raises(ReportRenderError, match="incident_id"):
        render_ttp_assessment(
            findings=_findings(),
            output_path=tmp_path / "TTP.md",
            incident_id="",
            campaign_tag="C",
        )
