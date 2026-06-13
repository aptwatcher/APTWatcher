"""
Tests for the publication adapter Protocol, result, and error types.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from core.publish.protocol import (
    PublicationAdapter,
    PublicationError,
    PublicationResult,
)
from core.publish.stub import StubPublicationAdapter
from core.types import IOCVerdict


def _ioc(value: str, ioc_type: str = "ipv4") -> IOCVerdict:
    return IOCVerdict(
        value=value,
        ioc_type=ioc_type,  # type: ignore[arg-type]
        verdict="malicious",
        confidence=0.9,
    )


def test_publication_error_is_a_runtime_error() -> None:
    assert issubclass(PublicationError, RuntimeError)
    with pytest.raises(RuntimeError):
        raise PublicationError("boom")


def test_publication_result_roundtrip() -> None:
    result = PublicationResult(
        adapter="stub",
        target="target-42",
        submitted_at="2026-04-19T12:00:00Z",
        correlation_id="corr-1",
        status="submitted",
        details={"note": "ok"},
    )
    assert result.adapter == "stub"
    assert result.target == "target-42"
    assert result.status == "submitted"
    assert result.details == {"note": "ok"}

    dumped = result.model_dump()
    again = PublicationResult.model_validate(dumped)
    assert again == result


def test_publication_result_forbids_extra_fields() -> None:
    with pytest.raises(ValidationError):
        PublicationResult(
            adapter="stub",
            target="t",
            submitted_at="2026-04-19T12:00:00Z",
            correlation_id="c",
            status="dry_run",
            surprise="nope",  # type: ignore[call-arg]
        )


def test_publication_result_rejects_unknown_status() -> None:
    with pytest.raises(ValidationError):
        PublicationResult(
            adapter="stub",
            target="t",
            submitted_at="2026-04-19T12:00:00Z",
            correlation_id="c",
            status="queued",  # type: ignore[arg-type]
        )


def test_stub_adapter_satisfies_protocol_at_runtime() -> None:
    stub = StubPublicationAdapter()
    assert isinstance(stub, PublicationAdapter)


def test_stub_adapter_records_publish_calls() -> None:
    stub = StubPublicationAdapter(name="recorder")
    iocs = [_ioc("203.0.113.10"), _ioc("198.51.100.7")]
    result = stub.publish(
        findings=[],
        iocs=iocs,
        incident_id="INC-1",
        campaign_tag="TESTCAMP",
        dry_run=True,
    )
    assert isinstance(result, PublicationResult)
    assert result.adapter == "recorder"
    assert result.status == "dry_run"
    assert len(stub.calls) == 1
    assert stub.calls[0]["iocs_count"] == 2
    assert stub.calls[0]["incident_id"] == "INC-1"
    assert stub.calls[0]["dry_run"] is True


def test_stub_adapter_can_force_failure() -> None:
    stub = StubPublicationAdapter(raise_on_publish=True)
    with pytest.raises(PublicationError):
        stub.publish(
            findings=[],
            iocs=[],
            incident_id="INC-2",
            campaign_tag="X",
            dry_run=False,
        )
    # Call is still recorded before the raise.
    assert len(stub.calls) == 1
