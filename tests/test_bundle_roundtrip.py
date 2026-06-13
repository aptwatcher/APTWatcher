"""
Full export -> import -> verify cycle for IncidentBundle.

Scenarios:
- Happy path: export to a tmpdir, re-import, verify counts / digests /
  signature all line up.
- Tamper a payload file after export: import must raise
  `BundleIntegrityError` because the sha256 no longer matches the
  manifest.
- Tamper the signature file after export: import must raise
  `BundleSignatureError`.
- `verify=False` lets a caller load a tampered bundle for inspection
  without raising.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.bundle import (
    BundleIntegrityError,
    BundleSignatureError,
    export_bundle,
    generate_keypair,
    import_bundle,
)
from core.bundle.exporter import (
    AUDIT_FILENAME,
    FINDINGS_FILENAME,
    IOCS_FILENAME,
    MANIFEST_FILENAME,
    SIGNATURE_FILENAME,
)
from core.types import (
    AuditEvent,
    Finding,
    FindingCitation,
    IOCVerdict,
)


def _findings() -> list[Finding]:
    return [
        Finding(
            finding_id="f-001",
            summary="suspicious powershell child process",
            mitre=["T1059.001"],
            confidence=0.8,
            evidence=[
                FindingCitation(
                    source="Security.evtx",
                    locator="event_id=4688",
                    tool_call_id="call-1",
                ),
            ],
            reasoning="winword spawned powershell",
        ),
        Finding(
            finding_id="f-002",
            summary="outbound beacon to known C2",
            mitre=["T1071.001"],
            confidence=0.9,
            evidence=[
                FindingCitation(source="volatility:netscan", tool_call_id="call-2"),
            ],
        ),
    ]


def _iocs() -> list[IOCVerdict]:
    return [
        IOCVerdict(
            value="185.234.247.12",
            ioc_type="ipv4",
            verdict="malicious",
            confidence=0.9,
        ),
    ]


def _events(incident_id: str) -> list[AuditEvent]:
    return [
        AuditEvent(
            event_type="run_start",
            incident_id=incident_id,
            payload={"incident_id": incident_id},
        ),
        AuditEvent(
            event_type="finding",
            incident_id=incident_id,
            correlation_id="call-1",
            payload={"finding_id": "f-001"},
        ),
        AuditEvent(
            event_type="run_end",
            incident_id=incident_id,
            payload={"incident_id": incident_id, "error": None},
        ),
    ]


def _export_fixture(tmp_path: Path) -> tuple[Path, bytes, bytes]:
    """Export a fresh bundle into tmp_path and return (dir, privkey, pubkey)."""
    private, public = generate_keypair()
    bundle_dir = tmp_path / "incident-bundle-inc-42"
    export_bundle(
        bundle_dir=bundle_dir,
        incident_id="inc-42",
        operator="dr",
        sift_workstation="sift-vm-01",
        findings=_findings(),
        iocs=_iocs(),
        audit_events=_events("inc-42"),
        private_key_bytes=private,
        profile="windows-host-triage",
        notes="pytest roundtrip",
    )
    return bundle_dir, private, public


# ---------- happy path ----------


def test_export_creates_expected_files(tmp_path: Path) -> None:
    bundle_dir, _, _ = _export_fixture(tmp_path)
    for name in (
        MANIFEST_FILENAME,
        FINDINGS_FILENAME,
        IOCS_FILENAME,
        AUDIT_FILENAME,
        SIGNATURE_FILENAME,
    ):
        assert (bundle_dir / name).exists(), f"missing {name}"


def test_roundtrip_preserves_counts_and_signature(tmp_path: Path) -> None:
    bundle_dir, _private, public = _export_fixture(tmp_path)

    loaded = import_bundle(bundle_dir=bundle_dir, verify=True)

    # Counts line up.
    assert loaded.manifest.counts == {
        "findings": 2,
        "iocs": 1,
        "audit_entries": 3,
    }
    assert len(loaded.findings) == 2
    assert len(loaded.iocs) == 1
    assert len(loaded.audit) == 3

    # Manifest metadata round-trips.
    assert loaded.manifest.incident_id == "inc-42"
    assert loaded.manifest.operator == "dr"
    assert loaded.manifest.sift_workstation == "sift-vm-01"
    assert loaded.manifest.profile == "windows-host-triage"

    # Signature round-trips and matches the generated public key.
    assert loaded.signature is not None
    assert loaded.signature.algo == "ed25519"
    assert loaded.signature.public_key_hex == public.hex()


def test_roundtrip_with_expected_pubkey(tmp_path: Path) -> None:
    bundle_dir, _private, public = _export_fixture(tmp_path)
    loaded = import_bundle(
        bundle_dir=bundle_dir,
        expected_public_key_hex=public.hex(),
        verify=True,
    )
    assert loaded.signature is not None
    assert loaded.signature.public_key_hex == public.hex()


def test_roundtrip_rejects_wrong_expected_pubkey(tmp_path: Path) -> None:
    bundle_dir, _, _ = _export_fixture(tmp_path)
    with pytest.raises(BundleSignatureError):
        import_bundle(
            bundle_dir=bundle_dir,
            expected_public_key_hex="de" * 32,
            verify=True,
        )


# ---------- tamper: payload ----------


def test_tampered_findings_file_raises_integrity(tmp_path: Path) -> None:
    bundle_dir, _, _ = _export_fixture(tmp_path)

    findings_path = bundle_dir / FINDINGS_FILENAME
    tampered = findings_path.read_text(encoding="utf-8").replace(
        "suspicious powershell",
        "benign process",
    )
    findings_path.write_text(tampered, encoding="utf-8")

    with pytest.raises(BundleIntegrityError):
        import_bundle(bundle_dir=bundle_dir, verify=True)


def test_tampered_audit_file_raises_integrity(tmp_path: Path) -> None:
    bundle_dir, _, _ = _export_fixture(tmp_path)

    audit_path = bundle_dir / AUDIT_FILENAME
    original = audit_path.read_bytes()
    # Append an extra valid-looking line — sha256 should change even if
    # the JSON still parses.
    extra = original + b'{"event":{"event_type":"finding","incident_id":"inc-42","payload":{}}}\n'
    audit_path.write_bytes(extra)

    with pytest.raises(BundleIntegrityError):
        import_bundle(bundle_dir=bundle_dir, verify=True)


def test_tampered_payload_accepted_when_verify_false(tmp_path: Path) -> None:
    bundle_dir, _, _ = _export_fixture(tmp_path)

    findings_path = bundle_dir / FINDINGS_FILENAME
    findings_path.write_text("[]", encoding="utf-8")

    # No exception: verify=False is the "load anyway" escape hatch.
    loaded = import_bundle(bundle_dir=bundle_dir, verify=False)
    assert loaded.findings == []


# ---------- tamper: signature ----------


def test_tampered_signature_raises_signature_error(tmp_path: Path) -> None:
    bundle_dir, _, _ = _export_fixture(tmp_path)

    sig_path = bundle_dir / SIGNATURE_FILENAME
    content = sig_path.read_text(encoding="utf-8")
    # Flip a single hex character inside the signature_hex field. We
    # pick a character that is certain to appear (all sig hex is 0-9a-f)
    # without hardcoding a position.
    assert '"signature_hex"' in content
    # Simple and robust: replace the first occurrence of an "a" in the
    # serialized signature with a "b", which keeps it valid hex but
    # invalidates the cryptographic check.
    idx = content.index('"signature_hex"')
    # Find the opening quote of the value.
    value_start = content.index('"', idx + len('"signature_hex"') + 1) + 1
    value_end = content.index('"', value_start)
    original_value = content[value_start:value_end]
    # Flip the first hex char: '0'<->'1', otherwise rotate by one.
    first = original_value[0]
    flipped = "1" if first == "0" else "0"
    new_value = flipped + original_value[1:]
    tampered = content[:value_start] + new_value + content[value_end:]
    sig_path.write_text(tampered, encoding="utf-8")

    with pytest.raises(BundleSignatureError):
        import_bundle(bundle_dir=bundle_dir, verify=True)


def test_missing_signature_file_raises_signature_error(tmp_path: Path) -> None:
    bundle_dir, _, _ = _export_fixture(tmp_path)
    (bundle_dir / SIGNATURE_FILENAME).unlink()

    with pytest.raises(BundleSignatureError):
        import_bundle(bundle_dir=bundle_dir, verify=True)


def test_missing_manifest_raises_integrity(tmp_path: Path) -> None:
    bundle_dir, _, _ = _export_fixture(tmp_path)
    (bundle_dir / MANIFEST_FILENAME).unlink()

    with pytest.raises(BundleIntegrityError):
        import_bundle(bundle_dir=bundle_dir, verify=True)
