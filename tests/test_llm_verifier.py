"""
Tests for core.strategies.llm_verifier.LLMVerifier.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.audit import AuditLogger
from core.llm import FakeModelClient, ModelResponse
from core.strategies.llm_verifier import (
    ALLOWED_SEVERITIES,
    LLMVerifier,
    VerifierResponseError,
)
from core.types import Finding, FindingCitation

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def audit_log(tmp_path: Path) -> AuditLogger:
    return AuditLogger(incident_id="inc-ver", log_dir=tmp_path)


def _replies(*contents: str) -> FakeModelClient:
    return FakeModelClient([ModelResponse(content=c) for c in contents])


def _verifier(client: FakeModelClient, **kw) -> LLMVerifier:
    return LLMVerifier(client=client, **kw)


def _finding(
    fid: str,
    *,
    summary: str = "finding",
    evidence: list[FindingCitation] | None = None,
    confidence: float = 0.5,
    mitre: list[str] | None = None,
) -> Finding:
    return Finding(
        finding_id=fid,
        summary=summary,
        confidence=confidence,
        evidence=evidence or [],
        mitre=mitre or [],
    )


def _cite(source: str = "volatility:malfind") -> FindingCitation:
    return FindingCitation(source=source)


def _read_events(log: AuditLogger) -> list[dict]:
    return [json.loads(line) for line in Path(log.log_path).read_text().splitlines()]


# ---------------------------------------------------------------------------
# Baseline-only paths (no model call when findings is empty)
# ---------------------------------------------------------------------------


def test_verify_empty_findings_returns_empty_no_model_call() -> None:
    client = _replies()  # empty deck — would raise if called.
    verifier = _verifier(client)
    assert verifier.verify([]) == []
    assert client.calls == []


def test_baseline_blocks_finding_without_evidence() -> None:
    client = _replies(
        json.dumps({"reasoning": "no extra issues", "issues": []}),
    )
    verifier = _verifier(client)
    issues = verifier.verify([_finding("F1", evidence=[])])
    assert len(issues) == 1
    assert issues[0].severity == "block"
    assert issues[0].rule == "rule1_evidence_required"
    assert issues[0].finding_id == "F1"


def test_baseline_allows_finding_with_evidence() -> None:
    client = _replies(
        json.dumps({"reasoning": "ok", "issues": []}),
    )
    verifier = _verifier(client)
    issues = verifier.verify([_finding("F1", evidence=[_cite()])])
    assert issues == []


# ---------------------------------------------------------------------------
# Model-driven issues
# ---------------------------------------------------------------------------


def test_model_issues_are_merged_with_baseline() -> None:
    reply = json.dumps(
        {
            "reasoning": "mitre mismatch",
            "issues": [
                {
                    "severity": "warn",
                    "rule": "rule3_mitre_consistency",
                    "finding_id": "F1",
                    "detail": "T1055 tagged but behaviour is persistence.",
                },
            ],
        },
    )
    verifier = _verifier(_replies(reply))
    issues = verifier.verify(
        [_finding("F1", evidence=[_cite()], mitre=["T1055"])],
    )
    assert len(issues) == 1
    assert issues[0].severity == "warn"
    assert issues[0].rule == "rule3_mitre_consistency"


def test_model_issues_deduped_against_baseline() -> None:
    # Model produces the same rule1_evidence_required issue the baseline
    # produces. Merge should keep exactly one.
    reply = json.dumps(
        {
            "reasoning": "dup",
            "issues": [
                {
                    "severity": "block",
                    "rule": "rule1_evidence_required",
                    "finding_id": "F1",
                    "detail": "Duplicated by model.",
                },
            ],
        },
    )
    verifier = _verifier(_replies(reply))
    issues = verifier.verify([_finding("F1", evidence=[])])
    assert len(issues) == 1
    # Baseline wording wins on conflict.
    assert "report emitter will refuse" in issues[0].detail


def test_model_invented_finding_id_is_dropped_silently() -> None:
    reply = json.dumps(
        {
            "reasoning": "hallucinated id",
            "issues": [
                {
                    "severity": "warn",
                    "rule": "rule3_mitre_consistency",
                    "finding_id": "F999",
                    "detail": "No such finding.",
                },
                {
                    "severity": "info",
                    "rule": "rule6_missing_context",
                    "finding_id": "F1",
                    "detail": "Consider a bulk_extractor pass.",
                },
            ],
        },
    )
    verifier = _verifier(_replies(reply))
    issues = verifier.verify([_finding("F1", evidence=[_cite()])])
    # Only the F1 issue should survive.
    assert len(issues) == 1
    assert issues[0].finding_id == "F1"
    assert issues[0].rule == "rule6_missing_context"


def test_model_cross_finding_issue_with_null_id_passes() -> None:
    reply = json.dumps(
        {
            "reasoning": "dup findings",
            "issues": [
                {
                    "severity": "info",
                    "rule": "rule5_duplicate_findings",
                    "finding_id": None,
                    "detail": "F1 and F2 describe the same event.",
                },
            ],
        },
    )
    verifier = _verifier(_replies(reply))
    issues = verifier.verify(
        [
            _finding("F1", evidence=[_cite()]),
            _finding("F2", evidence=[_cite()]),
        ],
    )
    assert len(issues) == 1
    assert issues[0].finding_id is None


# ---------------------------------------------------------------------------
# Defensive parsing — malformed model output falls back to baseline
# ---------------------------------------------------------------------------


def test_invalid_json_falls_back_to_baseline(audit_log: AuditLogger) -> None:
    verifier = _verifier(_replies("garbage"), audit=audit_log)
    issues = verifier.verify([_finding("F1", evidence=[])])
    # Baseline still fired.
    assert len(issues) == 1
    assert issues[0].rule == "rule1_evidence_required"
    evt = _read_events(audit_log)[-1]
    assert "not valid JSON" in evt["payload"]["parse_error"]
    assert evt["payload"]["baseline_count"] == 1
    assert evt["payload"]["model_count"] == 0


def test_non_object_root_falls_back(audit_log: AuditLogger) -> None:
    verifier = _verifier(_replies(json.dumps([])), audit=audit_log)
    issues = verifier.verify([_finding("F1", evidence=[_cite()])])
    # Baseline empty, model output ignored → total 0.
    assert issues == []
    evt = _read_events(audit_log)[-1]
    assert "Top-level JSON" in evt["payload"]["parse_error"]


def test_invalid_severity_falls_back() -> None:
    reply = json.dumps(
        {
            "reasoning": "bad severity",
            "issues": [
                {
                    "severity": "CRITICAL",
                    "rule": "rule3_mitre_consistency",
                    "finding_id": "F1",
                    "detail": "...",
                },
            ],
        },
    )
    verifier = _verifier(_replies(reply))
    issues = verifier.verify([_finding("F1", evidence=[_cite()])])
    assert issues == []  # baseline only; model batch rejected


def test_missing_rule_falls_back() -> None:
    reply = json.dumps(
        {
            "reasoning": "no rule",
            "issues": [
                {"severity": "warn", "finding_id": "F1", "detail": "x"},
            ],
        },
    )
    verifier = _verifier(_replies(reply))
    issues = verifier.verify([_finding("F1", evidence=[_cite()])])
    assert issues == []


def test_missing_detail_falls_back() -> None:
    reply = json.dumps(
        {
            "reasoning": "no detail",
            "issues": [
                {"severity": "warn", "rule": "rule3_mitre_consistency", "finding_id": "F1"},
            ],
        },
    )
    verifier = _verifier(_replies(reply))
    issues = verifier.verify([_finding("F1", evidence=[_cite()])])
    assert issues == []


def test_issues_not_a_list_falls_back() -> None:
    reply = json.dumps({"reasoning": "bad", "issues": "oops"})
    verifier = _verifier(_replies(reply))
    issues = verifier.verify([_finding("F1", evidence=[_cite()])])
    assert issues == []


# ---------------------------------------------------------------------------
# Code-fence tolerance
# ---------------------------------------------------------------------------


def test_code_fence_response_is_tolerated() -> None:
    body = json.dumps(
        {
            "reasoning": "ok",
            "issues": [
                {
                    "severity": "info",
                    "rule": "rule6_missing_context",
                    "finding_id": "F1",
                    "detail": "follow up",
                },
            ],
        },
    )
    fenced = f"```json\n{body}\n```"
    verifier = _verifier(_replies(fenced))
    issues = verifier.verify([_finding("F1", evidence=[_cite()])])
    assert len(issues) == 1
    assert issues[0].rule == "rule6_missing_context"


# ---------------------------------------------------------------------------
# Audit integration
# ---------------------------------------------------------------------------


def test_audit_event_has_expected_shape(audit_log: AuditLogger) -> None:
    reply = json.dumps(
        {
            "reasoning": "short review",
            "issues": [
                {
                    "severity": "warn",
                    "rule": "rule3_mitre_consistency",
                    "finding_id": "F1",
                    "detail": "tag mismatch",
                },
            ],
        },
    )
    verifier = _verifier(_replies(reply), audit=audit_log)
    verifier.verify([_finding("F1", evidence=[_cite()], mitre=["T1055"])])
    evt = _read_events(audit_log)[-1]
    p = evt["payload"]
    assert evt["event_type"] == "llm_call"
    assert p["tool"] == "llm_verifier"
    assert p["baseline_count"] == 0
    assert p["model_count"] == 1
    assert p["issue_count"] == 1
    assert p["reasoning"] == "short review"
    assert "parse_error" not in p


def test_audit_on_empty_findings_skips_model(audit_log: AuditLogger) -> None:
    client = _replies()  # empty deck, would raise if called
    verifier = _verifier(client, audit=audit_log)
    verifier.verify([])
    evt = _read_events(audit_log)[-1]
    assert evt["payload"]["issue_count"] == 0
    assert client.calls == []


# ---------------------------------------------------------------------------
# Request construction
# ---------------------------------------------------------------------------


def test_request_includes_each_finding_with_evidence_listing() -> None:
    client = _replies(
        json.dumps({"reasoning": "", "issues": []}),
    )
    verifier = _verifier(client)
    verifier.verify(
        [
            _finding(
                "F1",
                summary="malfind hit",
                evidence=[
                    FindingCitation(
                        source="volatility:malfind",
                        locator="pid=1234",
                        tool_call_id="corr-abc",
                    ),
                ],
                mitre=["T1055"],
            ),
            _finding("F2", summary="no evidence", evidence=[]),
        ],
    )
    msg = client.calls[0].messages[0].content
    assert "finding_count: 2" in msg
    assert "id: F1" in msg
    assert "summary: malfind hit" in msg
    assert "mitre: T1055" in msg
    assert "source=volatility:malfind" in msg
    assert "locator=pid=1234" in msg
    assert "tool_call_id=corr-abc" in msg
    assert "id: F2" in msg
    assert "evidence: []" in msg


def test_system_prompt_is_verifier_md() -> None:
    verifier = _verifier(_replies(""))
    assert "APTWatcher — verifier prompt" in verifier._system_prompt
    assert "rule1_evidence_required" in verifier._system_prompt


# ---------------------------------------------------------------------------
# Direct _parse_response unit tests
# ---------------------------------------------------------------------------


def test_parse_response_rejects_unknown_severity_directly() -> None:
    verifier = _verifier(_replies(""))
    with pytest.raises(VerifierResponseError):
        verifier._parse_response(
            json.dumps(
                {
                    "reasoning": "",
                    "issues": [
                        {
                            "severity": "CRITICAL",
                            "rule": "x",
                            "finding_id": "F1",
                            "detail": "y",
                        },
                    ],
                },
            ),
            known_finding_ids={"F1"},
        )


def test_allowed_severities_constant_is_block_warn_info() -> None:
    assert frozenset({"block", "warn", "info"}) == ALLOWED_SEVERITIES
