"""
Build a signed IncidentBundle directory on disk.

`export_bundle()` takes findings, IOCs, and audit events from a
completed offline run and writes them to a fresh directory in the
layout documented in `schema.py`. After the payload files are on disk
the exporter computes one sha256 over their concatenation, signs the
digest with the operator's Ed25519 private key, and writes
`signature.json`.

The function is pure in the sense that it does not touch any global
state: the caller supplies every input including the destination path,
the incident id, and the private key bytes. A second call with the same
inputs into a fresh directory will produce byte-identical payload files
(Ed25519 signatures are deterministic so even the signature is stable).

References:
- docs/design/offline-to-online-handoff.md
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from core.bundle.schema import (
    BundleAuditEntry,
    BundleFinding,
    BundleIOC,
    BundleManifest,
    IncidentBundle,
)
from core.bundle.signer import sign_bundle
from core.types import AuditEvent, Finding, IOCVerdict, utcnow

# File names are fixed by the bundle spec. Order matters: the digest is
# computed over the concatenation in this exact sequence.
MANIFEST_FILENAME = "manifest.json"
FINDINGS_FILENAME = "findings.json"
IOCS_FILENAME = "iocs.json"
AUDIT_FILENAME = "audit.jsonl"
SIGNATURE_FILENAME = "signature.json"

PAYLOAD_FILES: tuple[str, ...] = (
    MANIFEST_FILENAME,
    FINDINGS_FILENAME,
    IOCS_FILENAME,
    AUDIT_FILENAME,
)


def _sha256_hex(data: bytes) -> str:
    """Return `sha256:<hex>` so digest strings are self-describing."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _findings_bytes(findings: list[Finding]) -> bytes:
    """Serialize findings as a JSON array of wrapped records."""
    wrapped = [BundleFinding(finding=f).model_dump(mode="json") for f in findings]
    return json.dumps(wrapped, indent=2, sort_keys=True).encode("utf-8")


def _iocs_bytes(iocs: list[IOCVerdict]) -> bytes:
    wrapped = [BundleIOC(ioc=i).model_dump(mode="json") for i in iocs]
    return json.dumps(wrapped, indent=2, sort_keys=True).encode("utf-8")


def _audit_bytes(events: list[AuditEvent]) -> bytes:
    """Serialize events as JSONL, one line per event, chronological order."""
    lines: list[str] = []
    for event in events:
        wrapped = BundleAuditEntry(event=event).model_dump(mode="json")
        lines.append(json.dumps(wrapped, sort_keys=True))
    body = "\n".join(lines)
    if body:
        body += "\n"
    return body.encode("utf-8")


def _manifest_bytes(manifest: BundleManifest) -> bytes:
    return json.dumps(
        manifest.model_dump(mode="json"),
        indent=2,
        sort_keys=True,
    ).encode("utf-8")


def _concat_digest(*, bundle_dir: Path) -> bytes:
    """
    Recompute the digest used for signing: sha256 of the raw bytes of
    the four payload files concatenated in PAYLOAD_FILES order.
    """
    hasher = hashlib.sha256()
    for name in PAYLOAD_FILES:
        hasher.update((bundle_dir / name).read_bytes())
    return hasher.digest()


def export_bundle(
    *,
    bundle_dir: Path,
    incident_id: str,
    operator: str,
    sift_workstation: str,
    findings: list[Finding],
    audit_events: list[AuditEvent],
    private_key_bytes: bytes,
    iocs: list[IOCVerdict] | None = None,
    profile: str | None = None,
    notes: str | None = None,
) -> IncidentBundle:
    """
    Write a signed bundle directory and return the in-memory aggregate.

    The destination directory is created if it does not already exist.
    Existing files with the canonical names are overwritten.

    Parameters
    ----------
    bundle_dir
        Target directory. Callers typically use
        ``<workspace>/incident-bundle-<incident_id>`` but the name is
        not enforced here.
    incident_id
        Stable id shared with the offline audit log.
    operator
        Human-readable identifier for the signing operator.
    sift_workstation
        Hostname / VM id the bundle was produced on.
    findings
        List of `core.types.Finding` to embed verbatim.
    audit_events
        Chronological list of `core.types.AuditEvent` to embed as JSONL.
    private_key_bytes
        Raw 32-byte Ed25519 private key seed. The caller is responsible
        for zeroing memory after the call if that is part of the threat
        model.
    iocs
        Optional list of `core.types.IOCVerdict`; defaults to empty.
    profile
        Optional profile name that produced the bundle.
    notes
        Optional free-form operator notes.
    """
    iocs = iocs or []

    bundle_dir = Path(bundle_dir)
    bundle_dir.mkdir(parents=True, exist_ok=True)

    # 1. Serialize payload files.
    findings_raw = _findings_bytes(findings)
    iocs_raw = _iocs_bytes(iocs)
    audit_raw = _audit_bytes(audit_events)

    # 2. Build the manifest. File digests and counts reference the raw
    #    bytes we are about to write, so a later integrity check has
    #    ground truth to compare against.
    file_digests = {
        FINDINGS_FILENAME: _sha256_hex(findings_raw),
        IOCS_FILENAME: _sha256_hex(iocs_raw),
        AUDIT_FILENAME: _sha256_hex(audit_raw),
    }
    counts = {
        "findings": len(findings),
        "iocs": len(iocs),
        "audit_entries": len(audit_events),
    }
    manifest = BundleManifest(
        version="1.0",
        incident_id=incident_id,
        created_at=utcnow(),
        operator=operator,
        sift_workstation=sift_workstation,
        file_digests=file_digests,
        counts=counts,
        profile=profile,
        notes=notes,
    )
    manifest_raw = _manifest_bytes(manifest)

    # 3. Write all four payload files.
    (bundle_dir / MANIFEST_FILENAME).write_bytes(manifest_raw)
    (bundle_dir / FINDINGS_FILENAME).write_bytes(findings_raw)
    (bundle_dir / IOCS_FILENAME).write_bytes(iocs_raw)
    (bundle_dir / AUDIT_FILENAME).write_bytes(audit_raw)

    # 4. Compute the signing digest from the bytes on disk (not the
    #    in-memory buffers) so any filesystem normalization is caught
    #    here rather than at verify time.
    digest = _concat_digest(bundle_dir=bundle_dir)
    signature = sign_bundle(private_key_bytes=private_key_bytes, digest=digest)

    # 5. Persist the signature.
    signature_raw = json.dumps(
        signature.model_dump(mode="json"),
        indent=2,
        sort_keys=True,
    ).encode("utf-8")
    (bundle_dir / SIGNATURE_FILENAME).write_bytes(signature_raw)

    return IncidentBundle(
        manifest=manifest,
        findings=[BundleFinding(finding=f) for f in findings],
        iocs=[BundleIOC(ioc=i) for i in iocs],
        audit=[BundleAuditEntry(event=e) for e in audit_events],
        signature=signature,
    )


__all__ = [
    "AUDIT_FILENAME",
    "FINDINGS_FILENAME",
    "IOCS_FILENAME",
    "MANIFEST_FILENAME",
    "PAYLOAD_FILES",
    "SIGNATURE_FILENAME",
    "export_bundle",
]
