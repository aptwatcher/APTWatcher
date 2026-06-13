"""
Markdown analyst narrative and TTP assessment renderers.

Phase 3.8 task #63 companion to :mod:`core.analysis.report_docx`.

Two public functions:

- :func:`render_analyst_markdown` emits an ``ANALYSIS-<incident_id>.md``
  file -- the internal-facing research note.
- :func:`render_ttp_assessment` emits a ``TTP_<incident_id>.md`` file
  grouped by MITRE ATT&CK technique.

Both are English-only (the French twin is only produced for the
``.docx`` deliverable; analysts consume Markdown in English per the
design doc).

Reference:

- ``docs/design/analysis-output-pipeline.md`` -- "Markdown analyst
  narrative" and "TTP assessment" sections.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from core.analysis.report_docx import (
    ReportRenderError,
    _highest_severity,
    _severity_band,
)
from core.types import Finding, FindingCitation, IOCVerdict, utcnow

# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------


def _format_datetime(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    dt = dt.astimezone(UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _severity_badge(band: str) -> str:
    """Return a compact bracketed severity tag, e.g. ``[CRITICAL]``."""
    return f"[{band.upper()}]"


def _format_citation(c: FindingCitation) -> str:
    parts: list[str] = [f"source: `{c.source}`"]
    if c.locator:
        parts.append(f"locator: `{c.locator}`")
    if c.tool_call_id:
        parts.append(f"tool_call_id: `{c.tool_call_id}`")
    return "; ".join(parts)


def _auto_summary(findings: list[Finding], iocs: list[IOCVerdict]) -> str:
    """
    Produce a 2-3 sentence auto-generated executive summary.

    Uses only counts and the highest severity; never invents prose.
    """
    if not findings and not iocs:
        return "This run produced no findings or indicators."
    finding_count = len(findings)
    ioc_count = len(iocs)
    highest = _highest_severity(findings)
    sentences: list[str] = []
    if finding_count:
        sentences.append(
            f"This run surfaced {finding_count} finding"
            f"{'s' if finding_count != 1 else ''} "
            f"at highest severity {highest}.",
        )
    else:
        sentences.append("This run surfaced no findings.")
    if ioc_count:
        sentences.append(
            f"{ioc_count} indicator{'s' if ioc_count != 1 else ''} "
            "of compromise were extracted.",
        )
    else:
        sentences.append("No indicators of compromise were extracted.")
    sentences.append("See the sections below for the full breakdown.")
    return " ".join(sentences)


def _write(output_path: Path, text: str) -> Path:
    """Write ``text`` to ``output_path``, refusing to overwrite."""
    output_path = Path(output_path)
    if output_path.exists():
        msg = f"refusing to overwrite existing file: {output_path}"
        raise ReportRenderError(msg)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(text, encoding="utf-8")
    return output_path


# -----------------------------------------------------------------------
# Public API -- analyst narrative
# -----------------------------------------------------------------------


def render_analyst_markdown(
    *,
    findings: list[Finding],
    iocs: list[IOCVerdict],
    output_path: Path,
    incident_id: str,
    campaign_tag: str,
    operator: str | None = None,
) -> Path:
    """
    Produce an ``ANALYSIS-<incident_id>.md`` narrative document.

    Shape:

    - H1 title + metadata block
    - H2 "Summary" (auto-paragraph)
    - H2 "Findings" with one H3 per finding
    - H2 "IOCs" (table)
    - H2 "Next steps" (stubbed bullets)
    """
    if not incident_id:
        raise ReportRenderError("incident_id must be a non-empty string")
    if not campaign_tag:
        raise ReportRenderError("campaign_tag must be a non-empty string")

    output_path = Path(output_path)
    generated = _format_datetime(utcnow())
    operator_text = operator or "unknown"

    lines: list[str] = []
    lines.append(f"# Analyst Narrative: {campaign_tag}")
    lines.append("")
    lines.append(f"- **Incident:** `{incident_id}`")
    lines.append(f"- **Campaign:** `{campaign_tag}`")
    lines.append(f"- **Generated:** {generated}")
    lines.append(f"- **Operator:** {operator_text}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Summary
    lines.append("## Summary")
    lines.append("")
    lines.append(_auto_summary(findings, iocs))
    lines.append("")

    # Findings
    lines.append("## Findings")
    lines.append("")
    if not findings:
        lines.append("_No findings recorded._")
        lines.append("")
    else:
        for f in findings:
            band = _severity_band(f.confidence)
            lines.append(f"### {_severity_badge(band)} {f.finding_id} -- {f.summary}")
            lines.append("")
            lines.append(f"- **Confidence:** {f.confidence:.2f}")
            mitre_text = ", ".join(f"`{t}`" for t in f.mitre) if f.mitre else "_none_"
            lines.append(f"- **MITRE ATT&CK:** {mitre_text}")
            if f.reasoning:
                lines.append(f"- **Reasoning:** {f.reasoning}")
            if f.evidence:
                lines.append("- **Citations:**")
                for c in f.evidence:
                    lines.append(f"  - {_format_citation(c)}")
            else:
                lines.append("- **Citations:** _none_")
            lines.append("")

    # IOCs
    lines.append("## IOCs")
    lines.append("")
    if not iocs:
        lines.append("_No indicators recorded._")
        lines.append("")
    else:
        lines.append("| Type | Value | Verdict | Confidence |")
        lines.append("|------|-------|---------|------------|")
        for ioc in iocs:
            conf = f"{ioc.confidence:.2f}" if ioc.confidence is not None else "N/A"
            # Escape pipes inside IOC values to keep the Markdown table valid.
            value = ioc.value.replace("|", "\\|")
            lines.append(f"| {ioc.ioc_type} | `{value}` | {ioc.verdict} | {conf} |")
        lines.append("")

    # Next steps
    lines.append("## Next steps")
    lines.append("")
    lines.append("- Validate high-severity findings against additional artifacts.")
    lines.append("- Push verified IOCs to the community submission channel.")
    lines.append("- Review the TTP assessment companion document for pattern hits.")
    lines.append("")

    text = "\n".join(lines)
    return _write(output_path, text)


# -----------------------------------------------------------------------
# Public API -- TTP assessment
# -----------------------------------------------------------------------


def render_ttp_assessment(
    *,
    findings: list[Finding],
    output_path: Path,
    incident_id: str,
    campaign_tag: str,
) -> Path:
    """
    Produce a ``TTP_<incident_id>.md`` MITRE ATT&CK assessment.

    Findings without any MITRE technique are grouped under the
    ``UNMAPPED`` pseudo-technique so they still show up in the
    frequency table.
    """
    if not incident_id:
        raise ReportRenderError("incident_id must be a non-empty string")
    if not campaign_tag:
        raise ReportRenderError("campaign_tag must be a non-empty string")

    output_path = Path(output_path)
    generated = _format_datetime(utcnow())

    # Group findings by technique ID. One finding may appear under
    # multiple techniques; that is intentional -- the assessment
    # describes cross-cutting behavior.
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        keys = f.mitre or ["UNMAPPED"]
        for tech in keys:
            groups.setdefault(tech, []).append(f)

    # Sort techniques: UNMAPPED at the bottom, others by frequency desc,
    # then alphabetical for stability.
    def _sort_key(item: tuple[str, list[Finding]]) -> tuple[int, int, str]:
        tech, flist = item
        unmapped_rank = 1 if tech == "UNMAPPED" else 0
        return (unmapped_rank, -len(flist), tech)

    ordered = sorted(groups.items(), key=_sort_key)

    lines: list[str] = []
    lines.append(f"# TTP Assessment: {campaign_tag}")
    lines.append("")
    lines.append(f"- **Incident:** `{incident_id}`")
    lines.append(f"- **Campaign:** `{campaign_tag}`")
    lines.append(f"- **Generated:** {generated}")
    lines.append(f"- **Total findings:** {len(findings)}")
    lines.append(f"- **Distinct techniques:** {len(groups)}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Frequency table
    lines.append("## Technique Frequency")
    lines.append("")
    if not groups:
        lines.append("_No findings available._")
        lines.append("")
    else:
        lines.append("| Technique | Count | Highest Severity |")
        lines.append("|-----------|-------|------------------|")
        for tech, flist in ordered:
            highest = _highest_severity(flist)
            lines.append(f"| `{tech}` | {len(flist)} | {highest} |")
        lines.append("")

    # Per-technique sections
    for tech, flist in ordered:
        lines.append(f"## `{tech}`")
        lines.append("")
        lines.append(f"- **Count:** {len(flist)}")
        # Severity distribution
        dist: dict[str, int] = {}
        for f in flist:
            band = _severity_band(f.confidence)
            dist[band] = dist.get(band, 0) + 1
        dist_text = ", ".join(
            f"{band}: {count}" for band, count in sorted(dist.items())
        )
        lines.append(f"- **Severity distribution:** {dist_text}")
        lines.append(f"- **Finding IDs:** {', '.join(f.finding_id for f in flist)}")
        lines.append("")

    text = "\n".join(lines)
    return _write(output_path, text)


__all__ = [
    "render_analyst_markdown",
    "render_ttp_assessment",
]
