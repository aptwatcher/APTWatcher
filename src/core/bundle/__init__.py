"""
IncidentBundle export / import / signing.

An IncidentBundle is the portable, signed payload APTWatcher produces on
the offline SIFT workstation and consumes on the online remediation
surface. The bundle is a directory of JSON / JSONL payload files plus a
manifest and a detached Ed25519 signature over the sha256 digest of the
concatenated payload bytes.

Layering:

- `schema.py`      Pydantic models: manifest, per-record shapes, bundle,
                   signature, typed errors.
- `signer.py`      Ed25519 keypair / sign / verify primitives (wraps
                   `cryptography.hazmat.primitives.asymmetric.ed25519`).
- `exporter.py`    Build a bundle directory from findings / IOCs / audit
                   events; sign it.
- `importer.py`    Load + verify a bundle directory from disk.

References:
- docs/design/offline-to-online-handoff.md
- docs/architecture/evidence-integrity.md
"""

from __future__ import annotations

from core.bundle.exporter import export_bundle
from core.bundle.importer import import_bundle
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
from core.bundle.signer import (
    generate_keypair,
    sign_bundle,
    sign_digest,
    verify_bundle,
    verify_signature,
)

__all__ = [
    "BundleAuditEntry",
    "BundleFinding",
    "BundleIOC",
    "BundleIntegrityError",
    "BundleManifest",
    "BundleSignature",
    "BundleSignatureError",
    "IncidentBundle",
    "export_bundle",
    "generate_keypair",
    "import_bundle",
    "sign_bundle",
    "sign_digest",
    "verify_bundle",
    "verify_signature",
]
