"""
Load a bundle directory from disk and verify its signature.

`import_bundle()` is the only supported entry point for reading a
bundle back into memory. It performs three checks in order:

1. **Existence.** Every mandatory file is present on disk.
2. **Integrity.** Each file's sha256 matches the value recorded in
   the manifest's `file_digests` map. A mismatch raises
   `BundleIntegrityError` — the bundle has been tampered with.
3. **Signature.** When `verify=True` (default), the importer
   recomputes the sha256 over the concatenated payload bytes, loads
   `signature.json`, and calls `verify_bundle()`. A mismatch raises
   `BundleSignatureError`.

The importer never silently downgrades: any failure is a typed
exception, so a caller wiring this into a CLI can map each exception
to a distinct exit code.

References:
- docs/design/offline-to-online-handoff.md
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from core.bundle.exporter import (
    AUDIT_FILENAME,
    FINDINGS_FILENAME,
    IOCS_FILENAME,
    MANIFEST_FILENAME,
    PAYLOAD_FILES,
    SIGNATURE_FILENAME,
)
from core.bundle.schema import (
    BundleAuditEntry,
    BundleFinding,
    BundleIntegrityError,
    BundleIOC,
    BundleManifest,
    BundleSignature,
    BundleSignatureError,
    IncidentBundle,
)
from core.bundle.signer import verify_bundle


def _sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _load_manifest(bundle_dir: Path) -> BundleManifest:
    path = bundle_dir / MANIFEST_FILENAME
    if not path.exists():
        raise BundleIntegrityError(f"missing manifest: {path}")
    return BundleManifest.model_validate_json(path.read_bytes())


def _load_findings(bundle_dir: Path) -> list[BundleFinding]:
    path = bundle_dir / FINDINGS_FILENAME
    if not path.exists():
        raise BundleIntegrityError(f"missing findings file: {path}")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise BundleIntegrityError(f"{FINDINGS_FILENAME} must be a JSON array")
    return [BundleFinding.model_validate(item) for item in raw]


def _load_iocs(bundle_dir: Path) -> list[BundleIOC]:
    path = bundle_dir / IOCS_FILENAME
    if not path.exists():
        raise BundleIntegrityError(f"missing iocs file: {path}")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise BundleIntegrityError(f"{IOCS_FILENAME} must be a JSON array")
    return [BundleIOC.model_validate(item) for item in raw]


def _load_audit(bundle_dir: Path) -> list[BundleAuditEntry]:
    path = bundle_dir / AUDIT_FILENAME
    if not path.exists():
        raise BundleIntegrityError(f"missing audit file: {path}")
    entries: list[BundleAuditEntry] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        entries.append(BundleAuditEntry.model_validate_json(line))
    return entries


def _load_signature(bundle_dir: Path) -> BundleSignature:
    path = bundle_dir / SIGNATURE_FILENAME
    if not path.exists():
        raise BundleSignatureError(f"missing signature file: {path}")
    return BundleSignature.model_validate_json(path.read_bytes())


def _check_file_digests(bundle_dir: Path, manifest: BundleManifest) -> None:
    """
    Verify every file recorded in `manifest.file_digests` matches the
    bytes actually on disk. Raises `BundleIntegrityError` on mismatch.
    """
    for filename, expected in manifest.file_digests.items():
        path = bundle_dir / filename
        if not path.exists():
            raise BundleIntegrityError(f"file listed in manifest is missing: {path}")
        actual = _sha256_hex(path.read_bytes())
        if actual.lower() != expected.lower():
            raise BundleIntegrityError(
                f"sha256 mismatch for {filename}: "
                f"expected {expected}, got {actual}",
            )


def _check_counts(
    manifest: BundleManifest,
    findings: list[BundleFinding],
    iocs: list[BundleIOC],
    audit: list[BundleAuditEntry],
) -> None:
    """
    Verify the `counts` map matches the actual record-list lengths.

    This protects against a partial truncation that still happens to
    leave valid JSON behind (e.g. losing the last element of the
    findings array).
    """
    expected = {
        "findings": len(findings),
        "iocs": len(iocs),
        "audit_entries": len(audit),
    }
    for key, value in expected.items():
        if manifest.counts.get(key) != value:
            raise BundleIntegrityError(
                f"manifest counts mismatch for {key}: "
                f"manifest={manifest.counts.get(key)!r}, actual={value}",
            )


def _concat_payload_digest(bundle_dir: Path) -> bytes:
    """
    Recompute the signing digest: sha256 over the raw bytes of the
    four payload files concatenated in PAYLOAD_FILES order.
    """
    hasher = hashlib.sha256()
    for name in PAYLOAD_FILES:
        path = bundle_dir / name
        if not path.exists():
            raise BundleIntegrityError(f"payload file missing for signature check: {path}")
        hasher.update(path.read_bytes())
    return hasher.digest()


def import_bundle(
    *,
    bundle_dir: Path,
    expected_public_key_hex: str | None = None,
    verify: bool = True,
) -> IncidentBundle:
    """
    Load and optionally verify a bundle directory.

    Parameters
    ----------
    bundle_dir
        Directory written by `export_bundle()`.
    expected_public_key_hex
        If provided, the signature's public key must match this value
        or a `BundleSignatureError` is raised. Use this on the online
        host to pin the expected signer.
    verify
        When True (default) the file digests, counts, and Ed25519
        signature are all checked. Set to False only for offline
        inspection of a bundle whose signer key is not available.

    Raises
    ------
    BundleIntegrityError
        A payload file is missing, its sha256 does not match the
        manifest, or the manifest counts disagree with the record
        lists.
    BundleSignatureError
        The signature file is missing, its digest does not match the
        recomputed payload digest, the Ed25519 check fails, or the
        public key does not match `expected_public_key_hex`.
    """
    bundle_dir = Path(bundle_dir)
    if not bundle_dir.is_dir():
        raise BundleIntegrityError(f"bundle directory does not exist: {bundle_dir}")

    manifest = _load_manifest(bundle_dir)
    findings = _load_findings(bundle_dir)
    iocs = _load_iocs(bundle_dir)
    audit = _load_audit(bundle_dir)

    if verify:
        _check_file_digests(bundle_dir, manifest)
        _check_counts(manifest, findings, iocs, audit)

    signature: BundleSignature | None = None
    if verify:
        signature = _load_signature(bundle_dir)
        digest = _concat_payload_digest(bundle_dir)
        verify_bundle(
            digest=digest,
            signature=signature,
            expected_public_key_hex=expected_public_key_hex,
        )
    else:
        sig_path = bundle_dir / SIGNATURE_FILENAME
        if sig_path.exists():
            signature = BundleSignature.model_validate_json(sig_path.read_bytes())

    return IncidentBundle(
        manifest=manifest,
        findings=findings,
        iocs=iocs,
        audit=audit,
        signature=signature,
    )


__all__ = [
    "import_bundle",
]
