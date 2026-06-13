"""
Tests for core.strategies.llm_planner.LLMPlanner.

FakeModelClient drives every scenario offline. Audit behaviour is
checked against an in-memory AuditLogger fixture that reads the
JSONL file each wrapper writes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.agent_loop import AgentState, ExecutionRecord
from core.audit import AuditLogger
from core.llm import FakeModelClient, ModelResponse
from core.strategies.llm_planner import (
    MAX_STEPS_PER_BATCH,
    LLMPlanner,
    PlannerResponseError,
)
from core.types import Finding, FindingCitation, ProfileDefinition

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def audit_log(tmp_path: Path) -> AuditLogger:
    return AuditLogger(incident_id="inc-llm", log_dir=tmp_path)


@pytest.fixture
def state() -> AgentState:
    return AgentState(incident_id="inc-llm")


def _replies(*contents: str) -> FakeModelClient:
    return FakeModelClient([ModelResponse(content=c) for c in contents])


def _planner(client: FakeModelClient, **kw) -> LLMPlanner:
    return LLMPlanner(client=client, **kw)


def _read_events(log: AuditLogger) -> list[dict]:
    return [json.loads(line) for line in Path(log.log_path).read_text().splitlines()]


# ---------------------------------------------------------------------------
# Happy-path parsing
# ---------------------------------------------------------------------------


def test_next_plan_parses_two_steps(state: AgentState) -> None:
    reply = json.dumps(
        {
            "reasoning": "start with inventory then timeline",
            "finalize": False,
            "steps": [
                {
                    "step_id": "s1",
                    "intent": "inventory evidence files",
                    "tool": None,
                    "tool_args": {},
                },
                {
                    "step_id": "s2",
                    "intent": "build plaso timeline",
                    "tool": "run_log2timeline",
                    "tool_args": {"source": "/cases/image.dd"},
                },
            ],
        },
    )
    planner = _planner(_replies(reply))
    steps = planner.next_plan(state)

    assert len(steps) == 2
    assert steps[0].step_id == "s1"
    assert steps[0].tool is None
    assert steps[0].tool_args == {}
    assert steps[1].tool == "run_log2timeline"
    assert steps[1].tool_args == {"source": "/cases/image.dd"}


def test_next_plan_returns_empty_when_finalize_true(state: AgentState) -> None:
    reply = json.dumps(
        {"reasoning": "enough evidence", "finalize": True, "steps": []},
    )
    planner = _planner(_replies(reply))
    assert planner.next_plan(state) == []


def test_next_plan_finalize_wins_over_nonempty_steps(state: AgentState) -> None:
    reply = json.dumps(
        {
            "reasoning": "done",
            "finalize": True,
            "steps": [{"step_id": "s1", "intent": "ignored"}],
        },
    )
    planner = _planner(_replies(reply))
    assert planner.next_plan(state) == []


# ---------------------------------------------------------------------------
# Defensive parsing — every failure mode returns [] without raising
# ---------------------------------------------------------------------------


def test_next_plan_empty_response_returns_empty(
    state: AgentState, audit_log: AuditLogger,
) -> None:
    planner = _planner(_replies(""), audit=audit_log)
    assert planner.next_plan(state) == []
    events = _read_events(audit_log)
    assert events[-1]["payload"]["parse_error"].startswith("Model returned empty")
    assert events[-1]["payload"]["finalize"] is True


def test_next_plan_invalid_json_returns_empty(
    state: AgentState, audit_log: AuditLogger,
) -> None:
    planner = _planner(_replies("not json at all"), audit=audit_log)
    assert planner.next_plan(state) == []
    assert "not valid JSON" in _read_events(audit_log)[-1]["payload"]["parse_error"]


def test_next_plan_top_level_non_object_returns_empty(state: AgentState) -> None:
    planner = _planner(_replies(json.dumps([1, 2, 3])))
    assert planner.next_plan(state) == []


def test_next_plan_missing_step_id_returns_empty(state: AgentState) -> None:
    reply = json.dumps(
        {
            "reasoning": "bad step",
            "finalize": False,
            "steps": [{"intent": "no id"}],
        },
    )
    planner = _planner(_replies(reply))
    assert planner.next_plan(state) == []


def test_next_plan_missing_intent_returns_empty(state: AgentState) -> None:
    reply = json.dumps(
        {
            "reasoning": "bad step",
            "finalize": False,
            "steps": [{"step_id": "s1", "intent": ""}],
        },
    )
    planner = _planner(_replies(reply))
    assert planner.next_plan(state) == []


def test_next_plan_duplicate_step_ids_returns_empty(state: AgentState) -> None:
    reply = json.dumps(
        {
            "reasoning": "dups",
            "finalize": False,
            "steps": [
                {"step_id": "s1", "intent": "a"},
                {"step_id": "s1", "intent": "b"},
            ],
        },
    )
    planner = _planner(_replies(reply))
    assert planner.next_plan(state) == []


def test_next_plan_non_object_step_returns_empty(state: AgentState) -> None:
    reply = json.dumps(
        {"reasoning": "bad shape", "finalize": False, "steps": ["s1"]},
    )
    planner = _planner(_replies(reply))
    assert planner.next_plan(state) == []


def test_next_plan_empty_steps_no_finalize_defensive_finalize(
    state: AgentState,
) -> None:
    reply = json.dumps({"reasoning": "nothing", "finalize": False, "steps": []})
    planner = _planner(_replies(reply))
    assert planner.next_plan(state) == []


# ---------------------------------------------------------------------------
# Code-fence tolerance
# ---------------------------------------------------------------------------


def test_next_plan_tolerates_code_fence(state: AgentState) -> None:
    body = json.dumps(
        {
            "reasoning": "ok",
            "finalize": False,
            "steps": [{"step_id": "s1", "intent": "ok"}],
        },
    )
    fenced = f"```json\n{body}\n```"
    planner = _planner(_replies(fenced))
    steps = planner.next_plan(state)
    assert len(steps) == 1
    assert steps[0].step_id == "s1"


# ---------------------------------------------------------------------------
# Step-count clamp
# ---------------------------------------------------------------------------


def test_next_plan_clamps_to_max_steps(state: AgentState) -> None:
    too_many = [
        {"step_id": f"s{i}", "intent": f"step {i}"}
        for i in range(MAX_STEPS_PER_BATCH + 3)
    ]
    reply = json.dumps(
        {"reasoning": "too many", "finalize": False, "steps": too_many},
    )
    planner = _planner(_replies(reply))
    steps = planner.next_plan(state)
    assert len(steps) == MAX_STEPS_PER_BATCH


def test_next_plan_caller_max_steps_is_honoured(state: AgentState) -> None:
    reply = json.dumps(
        {
            "reasoning": "three",
            "finalize": False,
            "steps": [
                {"step_id": "s1", "intent": "a"},
                {"step_id": "s2", "intent": "b"},
                {"step_id": "s3", "intent": "c"},
            ],
        },
    )
    planner = _planner(_replies(reply), max_steps=2)
    steps = planner.next_plan(state)
    assert [s.step_id for s in steps] == ["s1", "s2"]


# ---------------------------------------------------------------------------
# Audit integration
# ---------------------------------------------------------------------------


def test_next_plan_emits_llm_call_audit(
    state: AgentState, audit_log: AuditLogger,
) -> None:
    reply = json.dumps(
        {
            "reasoning": "timeline-first",
            "finalize": False,
            "steps": [
                {"step_id": "s1", "intent": "inventory"},
                {"step_id": "s2", "intent": "timeline"},
            ],
        },
    )
    planner = _planner(_replies(reply), audit=audit_log)
    planner.next_plan(state)
    events = _read_events(audit_log)
    evt = events[-1]
    assert evt["event_type"] == "llm_call"
    p = evt["payload"]
    assert p["tool"] == "llm_planner"
    assert p["finalize"] is False
    assert p["step_ids"] == ["s1", "s2"]
    assert p["step_count"] == 2
    assert p["reasoning"] == "timeline-first"
    assert "parse_error" not in p


# ---------------------------------------------------------------------------
# Request construction
# ---------------------------------------------------------------------------


def test_request_includes_state_and_profile_context(state: AgentState) -> None:
    state.iterations = 2
    state.execution_log.append(
        ExecutionRecord(step_id="x1", correlation_id="c1", summary="done x1"),
    )
    state.findings.append(
        Finding(
            finding_id="F1",
            summary="malfind hit",
            confidence=0.8,
            evidence=[FindingCitation(source="volatility:malfind")],
        ),
    )
    profile = ProfileDefinition(
        name="host-triage",
        description="Standard host triage profile.",
        required_tools=["vol.py"],
    )
    client = _replies(
        json.dumps({"reasoning": "", "finalize": True, "steps": []}),
    )
    planner = _planner(
        client,
        profile=profile,
        preflight_summary="volatility3: OK, plaso: OK",
        kb_context="MITRE T1055 injection patterns ...",
    )
    planner.next_plan(state)

    assert len(client.calls) == 1
    user_msg = client.calls[0].messages[0].content
    assert "incident_id: inc-llm" in user_msg
    assert "iteration: 2" in user_msg
    assert "findings_accepted: 1" in user_msg
    assert "executions_so_far: 1" in user_msg
    assert "profile: host-triage" in user_msg
    assert "Standard host triage" in user_msg
    assert "preflight_summary:" in user_msg
    assert "volatility3: OK" in user_msg
    assert "kb_context:" in user_msg
    assert "T1055" in user_msg
    assert "F1: malfind hit" in user_msg
    assert "x1 :: done x1" in user_msg


def test_system_prompt_is_planner_md() -> None:
    planner = _planner(_replies(""))
    assert "APTWatcher — planner prompt" in planner._system_prompt
    assert "Output format" in planner._system_prompt


# ---------------------------------------------------------------------------
# Direct _parse_response unit tests
# ---------------------------------------------------------------------------


def test_parse_response_raises_on_invalid_json() -> None:
    planner = _planner(_replies(""))
    with pytest.raises(PlannerResponseError):
        planner._parse_response("not json")


def test_parse_response_raises_on_non_string_tool() -> None:
    planner = _planner(_replies(""))
    with pytest.raises(PlannerResponseError):
        planner._parse_response(
            json.dumps(
                {
                    "finalize": False,
                    "steps": [{"step_id": "s1", "intent": "x", "tool": 42}],
                },
            ),
        )


def test_parse_response_raises_on_non_object_tool_args() -> None:
    planner = _planner(_replies(""))
    with pytest.raises(PlannerResponseError):
        planner._parse_response(
            json.dumps(
                {
                    "finalize": False,
                    "steps": [
                        {"step_id": "s1", "intent": "x", "tool_args": [1, 2]},
                    ],
                },
            ),
        )
