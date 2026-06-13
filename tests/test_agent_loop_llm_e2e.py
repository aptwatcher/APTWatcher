"""
End-to-end integration test for AgentLoop driven by the three
LLM-backed strategies (LLMPlanner + LLMVerifier + LLMSelfCorrector).

Scenario (offline, FakeModelClient replay):

    Pre-run: two findings are injected into the loop's state —
             F1 with evidence, F2 without.
    iter 0:  LLMPlanner returns 1 step → loop executes (null executor
             records but does nothing); LLMVerifier's baseline check
             flags F2 (rule1_evidence_required, severity=block);
             LLMSelfCorrector drops F2.
    iter 1:  LLMPlanner returns finalize=true → loop breaks.
    finalize: report_emit fires with 1 finding remaining (F1).

Verified invariants:

- The `AgentLoop.finalize` gate (report cannot ship without a
  self-correction event for the current finding set) holds.
- F2 is removed before the report is emitted despite the loop never
  "seeing" F2 outside the verify/self-correct pass.
- The full audit trail contains exactly the expected event sequence
  in the expected order.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.agent_loop import AgentLoop
from core.audit import AuditLogger
from core.llm import FakeModelClient, ModelResponse
from core.strategies import LLMPlanner, LLMSelfCorrector, LLMVerifier
from core.types import Finding, FindingCitation

# ---------------------------------------------------------------------------
# Canned replies
# ---------------------------------------------------------------------------


PLANNER_ITER_0 = json.dumps(
    {
        "reasoning": "inventory + timeline first",
        "finalize": False,
        "steps": [
            {
                "step_id": "s1",
                "intent": "inventory evidence files",
                "tool": None,
                "tool_args": {},
            },
        ],
    },
)


PLANNER_ITER_1 = json.dumps(
    {"reasoning": "done, enough evidence", "finalize": True, "steps": []},
)


VERIFIER_REPLY = json.dumps(
    {"reasoning": "baseline catches F2", "issues": []},
)


SELF_CORRECTOR_REPLY = json.dumps(
    {
        "notes": "drop F2 (no citations)",
        "resolved": [],
        "dropped": ["F2"],
        "replan": False,
    },
)


def _fake(*contents: str) -> FakeModelClient:
    return FakeModelClient([ModelResponse(content=c) for c in contents])


def _read_events(log: AuditLogger) -> list[dict]:
    return [json.loads(line) for line in Path(log.log_path).read_text().splitlines()]


# ---------------------------------------------------------------------------
# The integration test
# ---------------------------------------------------------------------------


@pytest.fixture
def audit_log(tmp_path: Path) -> AuditLogger:
    return AuditLogger(incident_id="inc-e2e", log_dir=tmp_path)


def test_agent_loop_llm_strategies_compose(audit_log: AuditLogger) -> None:
    planner = LLMPlanner(
        client=_fake(PLANNER_ITER_0, PLANNER_ITER_1),
        audit=audit_log,
    )
    verifier = LLMVerifier(
        client=_fake(VERIFIER_REPLY),
        audit=audit_log,
    )
    self_corrector = LLMSelfCorrector(
        client=_fake(SELF_CORRECTOR_REPLY),
        audit=audit_log,
    )

    loop = AgentLoop(
        incident_id="inc-e2e",
        audit=audit_log,
        planner=planner,
        verifier=verifier,
        self_corrector=self_corrector,
        # executor defaults to _NullExecutor — fine for this trio test.
    )

    # Pre-populate findings: F1 survives, F2 must be dropped.
    f1 = Finding(
        finding_id="F1",
        summary="malfind hit pid=1234",
        confidence=0.7,
        evidence=[FindingCitation(source="volatility:malfind")],
    )
    f2 = Finding(
        finding_id="F2",
        summary="no evidence at all",
        confidence=0.5,
        evidence=[],  # will trip rule1_evidence_required
    )
    loop.add_finding(f1)
    loop.add_finding(f2)

    report = loop.run()

    # ---- post-run assertions -----------------------------------------
    assert [f.finding_id for f in report] == ["F1"]
    assert loop.state.iterations == 1  # only iter 0 performed real work
    assert loop.state.report_emitted is True

    events = _read_events(audit_log)
    by_type: dict[str, list[dict]] = {}
    for e in events:
        by_type.setdefault(e["event_type"], []).append(e)

    # Planner emitted twice (iter 0 + iter 1).
    # Verifier emitted once (only iter 0 had findings to review;
    # iter 1 broke out before verify).
    # Self-corrector emitted once (only iter 0's verify produced issues).
    llm_calls = by_type.get("llm_call", [])
    tools = [p["payload"]["tool"] for p in llm_calls]
    assert tools == [
        "llm_planner",      # iter 0 plan
        "llm_verifier",     # iter 0 verify
        "llm_self_corrector",  # iter 0 self_correct
        "llm_planner",      # iter 1 plan (finalize)
    ]

    # AgentLoop itself emits a tool_call (plan) per iteration.
    plan_events = [
        e for e in by_type.get("tool_call", []) if e["payload"].get("phase") == "plan"
    ]
    assert [e["payload"]["iteration"] for e in plan_events] == [0, 1]

    # Exactly one self_correction event — from iter 0.
    sc_events = by_type.get("self_correction", [])
    assert len(sc_events) == 1
    assert sc_events[0]["payload"]["dropped"] == ["F2"]
    assert sc_events[0]["payload"]["replan"] is False

    # Exactly one report_emit event — the finalize gate released.
    emit_events = by_type.get("report_emit", [])
    assert len(emit_events) == 1
    assert emit_events[0]["payload"]["finding_count"] == 1

    # Ordering sanity: every self_correction must precede report_emit,
    # per the architectural gate in docs/architecture/self-correction.md.
    sc_idx = events.index(sc_events[0])
    emit_idx = events.index(emit_events[0])
    assert sc_idx < emit_idx


def test_agent_loop_llm_fallback_when_planner_is_broken(
    audit_log: AuditLogger,
) -> None:
    """
    Planner returns garbage on iter 0 → LLMPlanner defensively
    returns []. Loop breaks immediately. Because there were no
    iterations, the tail-safety block in `AgentLoop.run` triggers a
    final verify_and_correct so that the self-correction gate can
    be satisfied before report_emit.

    With no pre-populated findings, the report is empty but the
    finalize gate still releases cleanly — the whole point of the
    defensive-fallback contract.
    """
    planner = LLMPlanner(client=_fake("garbage"), audit=audit_log)
    verifier = LLMVerifier(
        client=_fake(VERIFIER_REPLY),  # won't be called (empty findings)
        audit=audit_log,
    )
    self_corrector = LLMSelfCorrector(
        client=_fake(SELF_CORRECTOR_REPLY),  # won't be called (no issues)
        audit=audit_log,
    )

    loop = AgentLoop(
        incident_id="inc-e2e-fallback",
        audit=audit_log,
        planner=planner,
        verifier=verifier,
        self_corrector=self_corrector,
    )

    report = loop.run()

    assert report == []
    assert loop.state.report_emitted is True

    events = _read_events(audit_log)
    llm_calls = [
        e for e in events if e["event_type"] == "llm_call"
    ]
    planner_call = next(
        e for e in llm_calls if e["payload"]["tool"] == "llm_planner"
    )
    assert planner_call["payload"]["finalize"] is True
    assert "parse_error" in planner_call["payload"]

    # report_emit still fired because the tail-safety verify/correct
    # in AgentLoop.run satisfied the gate.
    assert any(e["event_type"] == "report_emit" for e in events)
