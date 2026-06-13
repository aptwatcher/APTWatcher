"""
Tests for core.strategies.llm_self_corrector.LLMSelfCorrector.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.agent_loop import VerificationIssue
from core.audit import AuditLogger
from core.llm import FakeModelClient, ModelResponse
from core.strategies.llm_self_corrector import (
    LLMSelfCorrector,
    SelfCorrectorResponseError,
)
from core.types import Finding, FindingCitation

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def audit_log(tmp_path: Path) -> AuditLogger:
    return AuditLogger(incident_id="inc-sc", log_dir=tmp_path)


def _replies(*contents: str) -> FakeModelClient:
    return FakeModelClient([ModelResponse(content=c) for c in contents])


def _sc(client: FakeModelClient, **kw) -> LLMSelfCorrector:
    return LLMSelfCorrector(client=client, **kw)


def _finding(
    fid: str,
    *,
    summary: str = "finding",
    evidence: list[FindingCitation] | None = None,
    confidence: float = 0.5,
) -> Finding:
    return Finding(
        finding_id=fid,
        summary=summary,
        confidence=confidence,
        evidence=evidence or [],
    )


def _cite() -> FindingCitation:
    return FindingCitation(source="volatility:malfind")


def _issue(
    rule: str,
    finding_id: str | None = None,
    *,
    severity: str = "block",
    detail: str = "detail",
) -> VerificationIssue:
    return VerificationIssue(
        severity=severity,
        rule=rule,
        finding_id=finding_id,
        detail=detail,
    )


def _read_events(log: AuditLogger) -> list[dict]:
    return [json.loads(line) for line in Path(log.log_path).read_text().splitlines()]


# ---------------------------------------------------------------------------
# No-op paths
# ---------------------------------------------------------------------------


def test_no_issues_short_circuits_the_model() -> None:
    client = _replies()  # empty deck — would raise if called.
    sc = _sc(client)
    decision = sc.correct(
        findings=[_finding("F1", evidence=[_cite()])],
        issues=[],
        iteration=0,
    )
    assert decision.resolved == []
    assert decision.dropped == []
    assert decision.replan is False
    assert client.calls == []


def test_no_issues_emits_audit_and_skips_model(audit_log: AuditLogger) -> None:
    client = _replies()
    sc = _sc(client, audit=audit_log)
    sc.correct(findings=[], issues=[], iteration=3)
    evt = _read_events(audit_log)[-1]
    assert evt["payload"]["tool"] == "llm_self_corrector"
    assert evt["payload"]["used_fallback"] is False
    assert evt["payload"]["dropped"] == []


# ---------------------------------------------------------------------------
# Happy-path parsing
# ---------------------------------------------------------------------------


def test_correct_parses_drop_and_replan_false() -> None:
    reply = json.dumps(
        {
            "notes": "drop F1, keep F2",
            "resolved": [],
            "dropped": ["F1"],
            "replan": False,
        },
    )
    sc = _sc(_replies(reply))
    decision = sc.correct(
        findings=[_finding("F1"), _finding("F2", evidence=[_cite()])],
        issues=[_issue("rule1_evidence_required", "F1")],
        iteration=1,
    )
    assert decision.dropped == ["F1"]
    assert decision.resolved == []
    assert decision.replan is False
    assert decision.notes == "drop F1, keep F2"
    assert decision.iteration == 1


def test_correct_parses_resolved_and_replan_true() -> None:
    reply = json.dumps(
        {
            "notes": "add citation + replan",
            "resolved": ["F1"],
            "dropped": [],
            "replan": True,
        },
    )
    sc = _sc(_replies(reply))
    decision = sc.correct(
        findings=[_finding("F1", evidence=[_cite()])],
        issues=[_issue("rule6_missing_context", "F1", severity="info")],
        iteration=2,
    )
    assert decision.resolved == ["F1"]
    assert decision.replan is True


def test_overlap_between_resolved_and_dropped_drops_wins() -> None:
    reply = json.dumps(
        {
            "notes": "conflicted",
            "resolved": ["F1", "F2"],
            "dropped": ["F1"],
            "replan": False,
        },
    )
    sc = _sc(_replies(reply))
    decision = sc.correct(
        findings=[
            _finding("F1", evidence=[_cite()]),
            _finding("F2", evidence=[_cite()]),
        ],
        issues=[_issue("rule3_mitre_consistency", "F1", severity="warn")],
        iteration=0,
    )
    assert decision.dropped == ["F1"]
    assert decision.resolved == ["F2"]


def test_invented_ids_are_silently_dropped() -> None:
    reply = json.dumps(
        {
            "notes": "",
            "resolved": ["F999", "F1"],  # F999 does not exist
            "dropped": ["F_NOPE"],
            "replan": False,
        },
    )
    sc = _sc(_replies(reply))
    decision = sc.correct(
        findings=[_finding("F1", evidence=[_cite()])],
        issues=[_issue("rule3_mitre_consistency", "F1", severity="warn")],
        iteration=0,
    )
    assert decision.resolved == ["F1"]
    assert decision.dropped == []


def test_duplicate_ids_are_deduped() -> None:
    reply = json.dumps(
        {
            "notes": "",
            "resolved": [],
            "dropped": ["F1", "F1"],
            "replan": False,
        },
    )
    sc = _sc(_replies(reply))
    decision = sc.correct(
        findings=[_finding("F1")],
        issues=[_issue("rule1_evidence_required", "F1")],
        iteration=0,
    )
    assert decision.dropped == ["F1"]


# ---------------------------------------------------------------------------
# Defensive fallback — model output malformed → safe default
# ---------------------------------------------------------------------------


def test_invalid_json_falls_back_drops_blockers(audit_log: AuditLogger) -> None:
    sc = _sc(_replies("garbage"), audit=audit_log)
    decision = sc.correct(
        findings=[
            _finding("F1"),
            _finding("F2", evidence=[_cite()]),
        ],
        issues=[
            _issue("rule1_evidence_required", "F1"),  # block
            _issue("rule3_mitre_consistency", "F2", severity="warn"),
        ],
        iteration=4,
    )
    assert decision.dropped == ["F1"]
    assert decision.resolved == []
    assert decision.replan is False
    assert decision.notes and decision.notes.startswith("fallback:")
    evt = _read_events(audit_log)[-1]
    assert evt["payload"]["used_fallback"] is True
    assert "not valid JSON" in evt["payload"]["parse_error"]


def test_non_object_root_falls_back() -> None:
    sc = _sc(_replies(json.dumps(["not an object"])))
    decision = sc.correct(
        findings=[_finding("F1")],
        issues=[_issue("rule1_evidence_required", "F1")],
        iteration=0,
    )
    assert decision.dropped == ["F1"]


def test_non_bool_replan_falls_back() -> None:
    reply = json.dumps(
        {"notes": "", "resolved": [], "dropped": [], "replan": "yes"},
    )
    sc = _sc(_replies(reply))
    decision = sc.correct(
        findings=[_finding("F1")],
        issues=[_issue("rule1_evidence_required", "F1")],
        iteration=0,
    )
    assert decision.dropped == ["F1"]
    assert decision.replan is False


def test_non_list_resolved_falls_back() -> None:
    reply = json.dumps(
        {"notes": "", "resolved": "F1", "dropped": [], "replan": False},
    )
    sc = _sc(_replies(reply))
    decision = sc.correct(
        findings=[_finding("F1")],
        issues=[_issue("rule1_evidence_required", "F1")],
        iteration=0,
    )
    assert decision.dropped == ["F1"]


def test_non_string_id_in_resolved_falls_back() -> None:
    reply = json.dumps(
        {"notes": "", "resolved": [1], "dropped": [], "replan": False},
    )
    sc = _sc(_replies(reply))
    decision = sc.correct(
        findings=[_finding("F1")],
        issues=[_issue("rule1_evidence_required", "F1")],
        iteration=0,
    )
    assert decision.dropped == ["F1"]


def test_fallback_ignores_issues_with_null_finding_id() -> None:
    # A block-severity issue with finding_id=None should not fabricate
    # a drop target in the fallback path.
    sc = _sc(_replies("garbage"))
    decision = sc.correct(
        findings=[_finding("F1", evidence=[_cite()])],
        issues=[
            _issue("rule5_duplicate_findings", None, severity="block"),
        ],
        iteration=0,
    )
    assert decision.dropped == []
    assert decision.replan is False


def test_fallback_dedups_block_issues_for_same_finding() -> None:
    sc = _sc(_replies("garbage"))
    decision = sc.correct(
        findings=[_finding("F1")],
        issues=[
            _issue("rule1_evidence_required", "F1"),
            _issue("rule2_hallucination_check", "F1", severity="block"),
        ],
        iteration=0,
    )
    assert decision.dropped == ["F1"]


# ---------------------------------------------------------------------------
# Code-fence tolerance
# ---------------------------------------------------------------------------


def test_code_fence_response_is_tolerated() -> None:
    body = json.dumps(
        {
            "notes": "ok",
            "resolved": [],
            "dropped": ["F1"],
            "replan": False,
        },
    )
    fenced = f"```json\n{body}\n```"
    sc = _sc(_replies(fenced))
    decision = sc.correct(
        findings=[_finding("F1")],
        issues=[_issue("rule1_evidence_required", "F1")],
        iteration=0,
    )
    assert decision.dropped == ["F1"]


# ---------------------------------------------------------------------------
# Audit integration
# ---------------------------------------------------------------------------


def test_audit_event_has_expected_shape(audit_log: AuditLogger) -> None:
    reply = json.dumps(
        {
            "notes": "drop F1",
            "resolved": [],
            "dropped": ["F1"],
            "replan": False,
        },
    )
    sc = _sc(_replies(reply), audit=audit_log)
    sc.correct(
        findings=[_finding("F1")],
        issues=[_issue("rule1_evidence_required", "F1")],
        iteration=5,
    )
    evt = _read_events(audit_log)[-1]
    p = evt["payload"]
    assert evt["event_type"] == "llm_call"
    assert p["tool"] == "llm_self_corrector"
    assert p["iteration"] == 5
    assert p["resolved"] == []
    assert p["dropped"] == ["F1"]
    assert p["replan"] is False
    assert p["notes"] == "drop F1"
    assert p["used_fallback"] is False
    assert "parse_error" not in p


# ---------------------------------------------------------------------------
# Request construction
# ---------------------------------------------------------------------------


def test_request_renders_findings_and_issues() -> None:
    client = _replies(
        json.dumps(
            {
                "notes": "",
                "resolved": [],
                "dropped": [],
                "replan": False,
            },
        ),
    )
    sc = _sc(client)
    sc.correct(
        findings=[
            _finding("F1", summary="malfind hit", evidence=[_cite()]),
            _finding("F2", summary="no evidence", evidence=[]),
        ],
        issues=[
            _issue("rule1_evidence_required", "F2"),
            _issue("rule6_missing_context", None, severity="info"),
        ],
        iteration=7,
    )
    msg = client.calls[0].messages[0].content
    assert "iteration: 7" in msg
    assert "finding_count: 2" in msg
    assert "issue_count: 2" in msg
    assert "id: F1" in msg
    assert "summary: malfind hit" in msg
    assert "evidence: 1" in msg
    assert "id: F2" in msg
    assert "evidence: 0" in msg
    assert "rule: rule1_evidence_required" in msg
    assert "finding_id: None" in msg


def test_system_prompt_is_self_corrector_md() -> None:
    sc = _sc(_replies(""))
    assert "APTWatcher — self-corrector prompt" in sc._system_prompt
    assert "Never invent finding IDs" in sc._system_prompt


# ---------------------------------------------------------------------------
# Direct _parse_response unit tests
# ---------------------------------------------------------------------------


def test_parse_response_raises_on_non_bool_replan_directly() -> None:
    sc = _sc(_replies(""))
    with pytest.raises(SelfCorrectorResponseError):
        sc._parse_response(
            json.dumps(
                {"notes": "", "resolved": [], "dropped": [], "replan": 1},
            ),
            known_finding_ids=set(),
        )


def test_parse_response_empty_content_raises() -> None:
    sc = _sc(_replies(""))
    with pytest.raises(SelfCorrectorResponseError):
        sc._parse_response("   ", known_finding_ids=set())
