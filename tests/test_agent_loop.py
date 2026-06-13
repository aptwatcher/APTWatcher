"""
Tests for core.agent_loop.

The loop is purely structural — no LLM calls. We drive it with custom
strategy stubs and verify the state transitions and audit-log shape.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.agent_loop import (
    AgentLoop,
    AgentState,
    ExecutionRecord,
    PlanStep,
    ReportEmitError,
    SelfCorrectionDecision,
    VerificationIssue,
)
from core.audit import AuditLogger
from core.types import Finding, FindingCitation

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _make_loop(tmp_log_dir: Path, **overrides: object) -> tuple[AgentLoop, AuditLogger]:
    audit = AuditLogger(incident_id="inc-test", log_dir=tmp_log_dir)
    loop = AgentLoop(incident_id="inc-test", audit=audit, **overrides)  # type: ignore[arg-type]
    return loop, audit


def _good_finding(fid: str = "f1") -> Finding:
    return Finding(
        finding_id=fid,
        summary="VSS deletion observed",
        mitre=["T1490"],
        confidence=0.8,
        evidence=[FindingCitation(source="Security.evtx", locator="event_id=4688 record=1")],
        reasoning="stub",
    )


def _bad_finding(fid: str = "f-bad") -> Finding:
    return Finding(
        finding_id=fid,
        summary="Unsubstantiated claim",
        mitre=[],
        confidence=0.5,
        evidence=[],
    )


# ---------------------------------------------------------------------------
# default (null) strategies
# ---------------------------------------------------------------------------


def test_null_loop_runs_empty_and_emits_report(tmp_log_dir: Path) -> None:
    loop, audit = _make_loop(tmp_log_dir)
    findings = loop.run()
    assert findings == []
    assert audit.has("self_correction")
    assert audit.has("report_emit")


def test_finalize_refused_without_self_correction(tmp_log_dir: Path) -> None:
    loop, _ = _make_loop(tmp_log_dir)
    # Add a finding but never invoke verify/correct — finalize must refuse.
    loop.add_finding(_good_finding())
    with pytest.raises(ReportEmitError):
        loop.finalize()


def test_null_verifier_drops_uncited_findings(tmp_log_dir: Path) -> None:
    loop, audit = _make_loop(tmp_log_dir)
    loop.add_finding(_good_finding("good-1"))
    loop.add_finding(_bad_finding("bad-1"))
    findings = loop.run()
    ids = {f.finding_id for f in findings}
    assert "good-1" in ids
    assert "bad-1" not in ids
    # The self_correction event carries the dropped id.
    sc_events = audit.find("self_correction")
    assert any("bad-1" in e.payload["dropped"] for e in sc_events)


# ---------------------------------------------------------------------------
# custom strategies
# ---------------------------------------------------------------------------


class _OneShotPlanner:
    """Plan once, then signal finalize."""

    def __init__(self) -> None:
        self.calls = 0

    def next_plan(self, state: AgentState) -> list[PlanStep]:
        self.calls += 1
        if self.calls == 1:
            return [PlanStep(step_id="s1", intent="stub-intent", tool="echo")]
        return []


class _RecordingExecutor:
    def __init__(self) -> None:
        self.calls: list[PlanStep] = []

    def execute(self, step: PlanStep, *, audit: AuditLogger) -> ExecutionRecord:
        self.calls.append(step)
        return ExecutionRecord(
            step_id=step.step_id,
            correlation_id=f"cid-{step.step_id}",
            summary=f"executed {step.step_id}",
        )


class _AlwaysPassVerifier:
    def verify(self, findings: list[Finding]) -> list[VerificationIssue]:
        return []


class _AlwaysPassSelfCorrector:
    def correct(
        self,
        *,
        findings: list[Finding],
        issues: list[VerificationIssue],
        iteration: int,
    ) -> SelfCorrectionDecision:
        return SelfCorrectionDecision(
            iteration=iteration,
            issues=issues,
            resolved=[],
            dropped=[],
            replan=False,
        )


def test_loop_drives_planner_executor_and_self_correct(tmp_log_dir: Path) -> None:
    planner = _OneShotPlanner()
    executor = _RecordingExecutor()
    loop, audit = _make_loop(
        tmp_log_dir,
        planner=planner,
        executor=executor,
        verifier=_AlwaysPassVerifier(),
        self_corrector=_AlwaysPassSelfCorrector(),
    )
    loop.add_finding(_good_finding("f-keep"))
    findings = loop.run()

    # planner called twice (once returning [s1], once returning [])
    assert planner.calls == 2
    # executor actually ran the single step
    assert [s.step_id for s in executor.calls] == ["s1"]
    # finding survived
    assert [f.finding_id for f in findings] == ["f-keep"]
    # exactly one report_emit and at least one self_correction
    assert len(audit.find("report_emit")) == 1
    assert len(audit.find("self_correction")) >= 1


def test_max_iterations_cap_is_enforced(tmp_log_dir: Path) -> None:
    class _ForeverPlanner:
        def next_plan(self, state: AgentState) -> list[PlanStep]:
            return [PlanStep(step_id=f"s{state.iterations}", intent="loop")]

    loop, audit = _make_loop(
        tmp_log_dir,
        planner=_ForeverPlanner(),
        verifier=_AlwaysPassVerifier(),
        self_corrector=_AlwaysPassSelfCorrector(),
    )
    loop.run()
    # Iterations capped at MAX_ITERATIONS.
    assert loop.state.iterations == AgentLoop.MAX_ITERATIONS
    assert audit.has("report_emit")


def test_add_finding_invalidates_self_correction_gate(tmp_log_dir: Path) -> None:
    loop, _ = _make_loop(
        tmp_log_dir,
        verifier=_AlwaysPassVerifier(),
        self_corrector=_AlwaysPassSelfCorrector(),
    )
    # Run the loop first — null planner finalizes immediately but verify runs.
    loop.run()
    # Adding a new finding after the fact invalidates the gate.
    loop.add_finding(_good_finding("f-late"))
    with pytest.raises(ReportEmitError):
        loop.finalize()
