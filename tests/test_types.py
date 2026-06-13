"""
Smoke tests for core.types.

We do not exhaustively test pydantic — pydantic tests itself. These assert
the contract we rely on in the rest of the codebase:
  - `extra="forbid"` on the shared base model
  - `Tier` is an int-enum and orders as we expect
  - `utcnow()` returns tz-aware UTC datetimes
  - Citation-free findings still validate (the self-correction pass
    enforces the citation rule; the type alone does not)
"""

from __future__ import annotations

from datetime import UTC

import pytest
from pydantic import ValidationError

from core.types import (
    AuditEvent,
    EvidenceFile,
    Finding,
    FindingCitation,
    IOCProviderResult,
    Tier,
    utcnow,
)


def test_tier_is_int_enum_and_ordered() -> None:
    assert int(Tier.CORE_TRIAGE) == 0
    assert Tier.CORE_TRIAGE < Tier.EXTERNAL_INTEL < Tier.IR_WORKFLOW
    assert Tier(4) == Tier.OFFENSIVE_CONTAINMENT


def test_utcnow_is_tzaware_utc() -> None:
    now = utcnow()
    assert now.tzinfo is not None
    assert now.utcoffset() == UTC.utcoffset(now)


def test_models_forbid_extra_fields() -> None:
    with pytest.raises(ValidationError):
        EvidenceFile(
            path="/evidence/mem.raw",
            sha256="a" * 64,
            size_bytes=1,
            kind="memory_image",
            bogus_field="nope",  # type: ignore[call-arg]
        )


def test_finding_accepts_empty_evidence_but_self_correction_will_reject() -> None:
    """
    A Finding with an empty `evidence` list is a valid pydantic instance —
    the self-correction pass, not the type, rejects un-cited findings. Keep
    this test as a reminder of where the constraint lives.
    """
    f = Finding(
        finding_id="F1",
        summary="placeholder",
        confidence=0.5,
    )
    assert f.evidence == []


def test_finding_with_citations() -> None:
    c = FindingCitation(source="Security.evtx", locator="event_id=4624")
    f = Finding(
        finding_id="F2",
        summary="Interactive logon for SYSTEM-equivalent account",
        mitre=["T1078"],
        confidence=0.7,
        evidence=[c],
    )
    assert f.mitre == ["T1078"]
    assert f.evidence[0].source == "Security.evtx"


def test_ioc_provider_result_score_bounds() -> None:
    with pytest.raises(ValidationError):
        IOCProviderResult(name="apt-watch", verdict="malicious", score=1.5)


def test_audit_event_roundtrip_json() -> None:
    ev = AuditEvent(
        event_type="run_start",
        incident_id="INC-0001",
        payload={"note": "hello"},
    )
    blob = ev.model_dump_json()
    reborn = AuditEvent.model_validate_json(blob)
    assert reborn.incident_id == "INC-0001"
    assert reborn.event_type == "run_start"
    assert reborn.payload == {"note": "hello"}
