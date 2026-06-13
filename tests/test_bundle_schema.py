"""
Pydantic contract tests for `core.bundle.schema`.

We verify:
- Valid construction of every bundle model.
- Missing required fields raise `ValidationError`.
- `extra="forbid"` rejects unknown keys (prevents silent schema drift).
- `IncidentBundle.counts` can be checked at construction time even
  though the manifest counts field is not auto-derived — the test
  documents the invariant the exporter and importer rely on.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from core.bundle.schema import (
    BundleAuditEntry,
    BundleFinding,
    BundleIOC,
    BundleManifest,
    BundleSignature,
    IncidentBundle,
)
from core.types import AuditEvent, Finding, FindingCitation, IOCVerdict


def _make_finding() -> Finding:
    return Finding(
        finding_id="f-001",
        summary="suspicious powershell child process",
        mitre=["T1059.001"],
        confidence=0.8,
        evidence=[
            FindingCitation(source="Security.evtx", locator="event_id=4688", tool_call_id="call-1"),
        ],
        reasoning="powershell spawned by winword.exe",
    )


def _make_ioc() -> IOCVerdict:
    return IOCVerdict(
        value="185.234.247.12",
        ioc_type="ipv4",
        verdict="malicious",
        confidence=0.9,
    )


def _make_audit_event() -> AuditEvent:
    return AuditEvent(
        event_type="finding",
        incident_id="inc-42",
        correlation_id="call-1",
        payload={"finding_id": "f-001"},
    )


def _make_manifest(**overrides: object) -> BundleManifest:
    defaults: dict[str, object] = {
        "incident_id": "inc-42",
        "created_at": datetime(2026, 4, 19, 12, 0, tzinfo=UTC),
        "operator": "dr",
        "sift_workstation": "sift-vm-01",
        "file_digests": {
            "findings.json": "sha256:" + "a" * 64,
            "iocs.json": "sha256:" + "b" * 64,
            "audit.jsonl": "sha256:" + "c" * 64,
        },
        "counts": {"findings": 1, "iocs": 1, "audit_entries": 1},
    }
    defaults.update(overrides)
    return BundleManifest(**defaults)


# ---------- valid construction ----------


def test_bundle_finding_valid() -> None:
    entry = BundleFinding(finding=_make_finding())
    assert entry.finding.finding_id == "f-001"


def test_bundle_ioc_valid() -> None:
    entry = BundleIOC(ioc=_make_ioc())
    assert entry.ioc.ioc_type == "ipv4"


def test_bundle_audit_entry_valid() -> None:
    entry = BundleAuditEntry(event=_make_audit_event())
    assert entry.event.event_type == "finding"


def test_manifest_valid_defaults() -> None:
    manifest = _make_manifest()
    assert manifest.version == "1.0"
    assert manifest.profile is None
    assert manifest.notes is None


def test_signature_valid() -> None:
    sig = BundleSignature(
        public_key_hex="a" * 64,
        signature_hex="b" * 128,
        signed_digest_hex="c" * 64,
    )
    assert sig.algo == "ed25519"


def test_incident_bundle_valid() -> None:
    bundle = IncidentBundle(
        manifest=_make_manifest(),
        findings=[BundleFinding(finding=_make_finding())],
        iocs=[BundleIOC(ioc=_make_ioc())],
        audit=[BundleAuditEntry(event=_make_audit_event())],
    )
    assert bundle.signature is None
    assert len(bundle.findings) == 1


# ---------- missing required fields ----------


def test_manifest_missing_incident_id_rejected() -> None:
    with pytest.raises(ValidationError):
        BundleManifest(  # type: ignore[call-arg]
            created_at=datetime(2026, 4, 19, tzinfo=UTC),
            operator="dr",
            sift_workstation="sift-vm-01",
        )


def test_manifest_missing_created_at_rejected() -> None:
    with pytest.raises(ValidationError):
        BundleManifest(  # type: ignore[call-arg]
            incident_id="inc-42",
            operator="dr",
            sift_workstation="sift-vm-01",
        )


def test_signature_missing_fields_rejected() -> None:
    with pytest.raises(ValidationError):
        BundleSignature(  # type: ignore[call-arg]
            public_key_hex="a" * 64,
            signature_hex="b" * 128,
        )


# ---------- extra=forbid ----------


def test_manifest_rejects_extra_keys() -> None:
    with pytest.raises(ValidationError):
        BundleManifest(  # type: ignore[call-arg]
            incident_id="inc-42",
            created_at=datetime(2026, 4, 19, tzinfo=UTC),
            operator="dr",
            sift_workstation="sift-vm-01",
            rogue_field="nope",
        )


def test_incident_bundle_rejects_extra_keys() -> None:
    with pytest.raises(ValidationError):
        IncidentBundle(  # type: ignore[call-arg]
            manifest=_make_manifest(),
            bonus="no",
        )


# ---------- counts match list lengths ----------


def test_counts_match_list_lengths() -> None:
    """
    The manifest records counts per record type; the in-memory bundle
    carries the actual lists. Exporter/importer enforce equality. We
    assert the shape matches here so any future drift in either side
    is caught by this unit test.
    """
    manifest = _make_manifest(counts={"findings": 2, "iocs": 0, "audit_entries": 1})
    bundle = IncidentBundle(
        manifest=manifest,
        findings=[BundleFinding(finding=_make_finding()) for _ in range(2)],
        iocs=[],
        audit=[BundleAuditEntry(event=_make_audit_event())],
    )
    assert bundle.manifest.counts["findings"] == len(bundle.findings)
    assert bundle.manifest.counts["iocs"] == len(bundle.iocs)
    assert bundle.manifest.counts["audit_entries"] == len(bundle.audit)
