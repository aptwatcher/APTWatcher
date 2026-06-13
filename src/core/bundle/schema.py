"""
Pydantic models for the IncidentBundle on-disk layout.

An exported bundle is a directory with four payload files:

    incident-bundle-<incident_id>/
        manifest.json        BundleManifest
        findings.json        list[BundleFinding]
        iocs.json            list[BundleIOC]
        audit.jsonl          one BundleAuditEntry per line, chronological
        signature.json       BundleSignature

The `IncidentBundle` model is the in-memory aggregate returned by the
importer and accepted by the exporter; it mirrors the directory but
lives as one Python object.

Canonicalization for signing is deliberately simple: the signer hashes
the raw bytes of `manifest.json`, `findings.json`, `iocs.json`, and
`audit.jsonl` in that fixed order with SHA-256, then signs the digest.
A verifier re-reads the files, recomputes the digest, and checks the
signature. The signature covers the digest, not the files directly —
so only one hash pass is needed on the verify path.

References:
- docs/design/offline-to-online-handoff.md
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from core.types import AuditEvent, Finding, IOCVerdict

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class BundleSignatureError(Exception):
    """Raised when an Ed25519 signature does not verify against its digest."""


class BundleIntegrityError(Exception):
    """Raised when file_digests in the manifest disagree with file content."""


# ---------------------------------------------------------------------------
# Base model
# ---------------------------------------------------------------------------


class _BundleModel(BaseModel):
    """Shared pydantic config for every bundle value object."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
    )


# ---------------------------------------------------------------------------
# Payload records
# ---------------------------------------------------------------------------


class BundleFinding(_BundleModel):
    """
    One finding inside the bundle.

    Thin wrapper over `core.types.Finding` so the schema of the on-disk
    file is independent of internal refactors. Today it simply embeds
    the finding verbatim; future versions may add bundle-only metadata
    (e.g., redaction flags) without disturbing `core.types.Finding`.
    """

    finding: Finding


class BundleIOC(_BundleModel):
    """One IOC record inside the bundle."""

    ioc: IOCVerdict


class BundleAuditEntry(_BundleModel):
    """One audit event inside the bundle (one line of audit.jsonl)."""

    event: AuditEvent


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


class BundleManifest(_BundleModel):
    """
    Metadata describing a bundle directory.

    `file_digests` and `counts` are what makes the manifest trustworthy:
    every payload file is pinned by its sha256, and every record list
    has a checked length. A verifier rejects the bundle as soon as any
    of those disagree with the file contents.
    """

    version: str = "1.0"
    incident_id: str
    created_at: datetime
    operator: str
    sift_workstation: str
    file_digests: dict[str, str] = Field(default_factory=dict)
    counts: dict[str, int] = Field(default_factory=dict)
    profile: str | None = None
    notes: str | None = None


# ---------------------------------------------------------------------------
# Signature
# ---------------------------------------------------------------------------


class BundleSignature(_BundleModel):
    """
    Detached Ed25519 signature for a bundle directory.

    `signed_digest_hex` is the sha256 of the concatenation of the raw
    bytes of manifest.json + findings.json + iocs.json + audit.jsonl,
    in that fixed order. `signature_hex` is the 64-byte Ed25519
    signature over those 32 bytes.
    """

    algo: Literal["ed25519"] = "ed25519"
    public_key_hex: str
    signature_hex: str
    signed_digest_hex: str


# ---------------------------------------------------------------------------
# In-memory aggregate
# ---------------------------------------------------------------------------


class IncidentBundle(_BundleModel):
    """
    Full in-memory representation of a bundle.

    Returned by `import_bundle()` and produced by `export_bundle()`.
    The signature is optional on the in-memory object because the
    exporter builds the manifest + payload lists first, then signs,
    then attaches the signature.
    """

    manifest: BundleManifest
    findings: list[BundleFinding] = Field(default_factory=list)
    iocs: list[BundleIOC] = Field(default_factory=list)
    audit: list[BundleAuditEntry] = Field(default_factory=list)
    signature: BundleSignature | None = None


__all__ = [
    "BundleAuditEntry",
    "BundleFinding",
    "BundleIOC",
    "BundleIntegrityError",
    "BundleManifest",
    "BundleSignature",
    "BundleSignatureError",
    "IncidentBundle",
]
