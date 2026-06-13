"""
Integration tests for the Phase 3.8 analysis pipeline fan-out wired into
``AgentLoop.finalize()``.

These tests exercise the opt-in ``emit_analysis_pipeline`` config flag
end-to-end: they drive the loop with the null strategies, pre-seed a
realistic finding + IOC set on state, call ``run()``, and assert that:

- With the flag off, the verdict is emitted and the output directory
  stays empty -- the fan-out is strictly additive.
- With the flag on and no sign key, rules / IOCs / reports / generation
  manifest land on disk and no incident bundle is written.
- With the flag on and a sign key, the same outputs land plus a signed
  :class:`IncidentBundle` whose ``import_bundle`` round-trip passes.
- A failure inside any one renderer is isolated: an ``analysis_error``
  audit event is logged, the verdict is still emitted, and the
  remaining pipeline steps continue.

Tests use the null strategies because the goal here is to exercise
finalize()'s fan-out, not the planner/verifier trio. A ``FakeModelClient``
is not required -- pre-seeded findings + IOCs are enough to drive the
analysis pipeline deterministically.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from core.agent_loop import AgentLoop
from core.audit import AuditLogger
from core.bundle import generate_keypair, import_bundle
from core.config import APTWatcherConfig
from core.types import Finding, FindingCitation, IOCVerdict

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_findings() -> list[Finding]:
    return [
        Finding(
            finding_id="F1",
            summary="Suspicious process creation observed in Security.evtx",
            mitre=["T1059"],
            confidence=0.85,
            evidence=[
                FindingCitation(
                    source="Security.evtx",
                    locator="event_id=4688 record=120",
                    tool_call_id="cid-1",
                ),
            ],
            reasoning="stub for pipeline test",
        ),
        Finding(
            finding_id="F2",
            summary="Shadow copy deletion attempted via vssadmin",
            mitre=["T1490"],
            confidence=0.9,
            evidence=[
                FindingCitation(
                    source="Security.evtx",
                    locator="event_id=4688 record=155",
                    tool_call_id="cid-2",
                ),
            ],
            reasoning="stub for pipeline test",
        ),
    ]


def _make_iocs() -> list[IOCVerdict]:
    return [
        IOCVerdict(
            value="203.0.113.10",
            ioc_type="ipv4",
            verdict="malicious",
            confidence=0.9,
        ),
        IOCVerdict(
            value="malicious.example.test",
            ioc_type="domain",
            verdict="malicious",
            confidence=0.85,
        ),
        IOCVerdict(
            value="a" * 64,  # synthetic sha256 hex
            ioc_type="sha256",
            verdict="malicious",
            confidence=0.8,
        ),
    ]


@pytest.fixture()
def analysis_output_dir(tmp_path: Path) -> Iterator[Path]:
    """Fresh output directory for the pipeline fan-out."""
    out = tmp_path / "analysis-out"
    # We intentionally do NOT create it -- emit_analysis_outputs must
    # create its own tree, and the "flag OFF" test wants to assert the
    # directory stays empty (never created).
    yield out


def _build_loop(
    *,
    audit_log_dir: Path,
    config: APTWatcherConfig,
    incident_id: str = "inc-analysis-emit",
) -> tuple[AgentLoop, AuditLogger]:
    audit = AuditLogger(incident_id=incident_id, log_dir=audit_log_dir)
    loop = AgentLoop(incident_id=incident_id, audit=audit, config=config)
    for f in _make_findings():
        loop.add_finding(f)
    for ioc in _make_iocs():
        loop.add_ioc(ioc)
    return loop, audit


def _read_log_events(audit: AuditLogger) -> list[dict]:
    """Read the raw audit JSONL -- robust against schema drift."""
    return [
        json.loads(raw)
        for raw in audit.log_path.read_text(encoding="utf-8").splitlines()
        if raw.strip()
    ]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_analysis_emit_flag_off_keeps_baseline_behavior(
    tmp_log_dir: Path, analysis_output_dir: Path,
) -> None:
    """Default config leaves finalize() untouched -- no files on disk."""
    config = APTWatcherConfig()
    # Sanity: the field exists and defaults to False.
    assert config.emit_analysis_pipeline is False

    loop, audit = _build_loop(audit_log_dir=tmp_log_dir, config=config)
    findings = loop.run()

    # Verdict still emitted as before.
    assert len(findings) == 2
    assert audit.has("report_emit")

    # No analysis_emit or analysis_error events were produced.
    assert not audit.has("analysis_emit")
    assert not audit.has("analysis_error")

    # The output directory was never even created.
    assert not analysis_output_dir.exists()


def test_analysis_emit_flag_on_without_sign_key(
    tmp_log_dir: Path, analysis_output_dir: Path,
) -> None:
    """Flag ON, no sign key -- pipeline fans out, no bundle produced."""
    config = APTWatcherConfig(
        emit_analysis_pipeline=True,
        analysis_output_dir=analysis_output_dir,
        analysis_campaign_tag="TEST-CAMPAIGN",
        analysis_languages=["en"],
    )

    loop, audit = _build_loop(audit_log_dir=tmp_log_dir, config=config)
    findings = loop.run()

    # Verdict still emitted.
    assert len(findings) == 2
    assert audit.has("report_emit")

    # Expected artifacts.
    rules_dir = analysis_output_dir / "rules"
    assert (rules_dir / "aptwatcher.yar").exists()
    assert (rules_dir / "aptwatcher.rules").exists()

    iocs_dir = analysis_output_dir / "iocs"
    assert (iocs_dir / "stix.json").exists()
    assert (iocs_dir / "community.yaml").exists()
    per_type_dir = iocs_dir / "per_type"
    assert per_type_dir.is_dir()
    # At least the ipv4, domain, sha256 per-type txts landed.
    per_type_files = {p.name for p in per_type_dir.glob("*.txt")}
    assert per_type_files, "per_type directory should contain at least one .txt"

    reports_dir = analysis_output_dir / "reports"
    assert (reports_dir / "analyst.md").exists()
    assert (reports_dir / "report_en.docx").exists()

    assert (analysis_output_dir / "generation_report.json").exists()

    # Bundle NOT produced.
    assert not (analysis_output_dir / "incident-bundle").exists()

    # At least one analysis_emit audit event was logged.
    assert audit.has("analysis_emit")


def test_analysis_emit_with_sign_key_produces_signed_bundle(
    tmp_log_dir: Path, analysis_output_dir: Path,
) -> None:
    """Flag ON + sign key -- a signed IncidentBundle round-trips."""
    private_bytes, _public_bytes = generate_keypair()
    key_hex = private_bytes.hex()

    config = APTWatcherConfig(
        emit_analysis_pipeline=True,
        analysis_output_dir=analysis_output_dir,
        analysis_campaign_tag="TEST-CAMPAIGN-SIGNED",
        analysis_sign_key_hex=key_hex,
        analysis_languages=["en"],
    )

    loop, audit = _build_loop(audit_log_dir=tmp_log_dir, config=config)
    findings = loop.run()

    # Verdict still emitted.
    assert len(findings) == 2
    assert audit.has("report_emit")

    bundle_dir = analysis_output_dir / "incident-bundle"
    assert bundle_dir.is_dir()
    # The four canonical payload files + signature.json must exist.
    for name in (
        "manifest.json",
        "findings.json",
        "iocs.json",
        "audit.jsonl",
        "signature.json",
    ):
        assert (bundle_dir / name).exists(), f"missing bundle file: {name}"

    # Round-trip: import_bundle must accept what export_bundle wrote.
    imported = import_bundle(bundle_dir=bundle_dir, verify=True)
    assert imported.manifest.incident_id == "inc-analysis-emit"
    assert len(imported.findings) == len(findings)
    assert len(imported.iocs) == len(_make_iocs())

    # An export_bundle analysis_emit event was logged. Read the JSONL
    # directly rather than via ``audit.find`` so this assertion is
    # robust against audit-record schema drift.
    log_lines = _read_log_events(audit)
    assert any(
        e.get("event_type") == "analysis_emit"
        and e.get("payload", {}).get("step") == "export_bundle"
        for e in log_lines
    )


def test_analysis_emit_graceful_degradation_on_renderer_failure(
    tmp_log_dir: Path,
    analysis_output_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One renderer raises -- verdict still emitted, other steps continue."""

    def _boom(*args: object, **kwargs: object) -> None:
        raise RuntimeError("synthetic analyst markdown failure")

    # Patch the analyst markdown renderer *before* the loop runs. The
    # emit_analysis_outputs method imports the symbol lazily inside
    # its body, so we must patch the module where the lookup happens.
    import core.analysis.report_markdown as report_markdown

    monkeypatch.setattr(
        report_markdown, "render_analyst_markdown", _boom,
    )

    config = APTWatcherConfig(
        emit_analysis_pipeline=True,
        analysis_output_dir=analysis_output_dir,
        analysis_campaign_tag="TEST-DEGRADE",
        analysis_languages=["en"],
    )

    loop, audit = _build_loop(audit_log_dir=tmp_log_dir, config=config)
    findings = loop.run()

    # Verdict still emitted despite the internal failure.
    assert len(findings) == 2
    assert audit.has("report_emit")

    # The failure was captured as an analysis_error audit event. Read
    # the JSONL directly for robustness against audit schema drift.
    assert audit.has("analysis_error")
    log_lines = _read_log_events(audit)
    errors = [e for e in log_lines if e.get("event_type") == "analysis_error"]
    assert any(
        e.get("payload", {}).get("step") == "render_analyst_markdown"
        and "synthetic analyst markdown failure"
        in (e.get("payload", {}).get("error") or "")
        for e in errors
    ), f"expected analyst markdown failure in: {[e.get('payload') for e in errors]}"

    # Downstream steps still ran: the rules + STIX bundle landed on disk.
    assert (analysis_output_dir / "rules" / "aptwatcher.yar").exists()
    assert (analysis_output_dir / "rules" / "aptwatcher.rules").exists()
    assert (analysis_output_dir / "iocs" / "stix.json").exists()
    # The .docx report still rendered -- it is independent of the analyst
    # markdown step.
    assert (analysis_output_dir / "reports" / "report_en.docx").exists()
    # The generation manifest must still be produced.
    assert (analysis_output_dir / "generation_report.json").exists()

    # Sanity: at least one analysis_emit event was also logged (the
    # pipeline didn't grind to a halt on the first failure).
    assert audit.has("analysis_emit")

    # generation_report.json is valid JSON with the expected shape.
    manifest = json.loads(
        (analysis_output_dir / "generation_report.json").read_text(encoding="utf-8"),
    )
    assert manifest["incident_id"] == "inc-analysis-emit"
    assert manifest["campaign_tag"] == "TEST-DEGRADE"
