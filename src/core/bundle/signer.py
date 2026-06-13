"""
Ed25519 signing primitives for IncidentBundle.

Thin wrapper over `cryptography.hazmat.primitives.asymmetric.ed25519`.
All keys here are raw 32-byte seeds (private) and raw 32-byte points
(public), encoded as hex in the on-disk `BundleSignature`. We do NOT
use PEM / PKCS8 / OpenSSH formats: the bundle is self-contained and
operators carry the public key material out of band (or pull it from
a trust store keyed by fingerprint).

Two levels of helpers:

- `sign_digest` / `verify_signature` — raw bytes in, raw bytes out.
  The exporter calls `sign_digest(private, digest)`; the importer
  calls `verify_signature(public, digest, signature)`.
- `sign_bundle` / `verify_bundle` — convenience wrappers that accept a
  `BundleSignature` or produce one. These keep the exporter and
  importer code short without forcing callers to juggle hex / bytes.

No key persistence helpers live in this module — the exporter accepts
32 raw private-key bytes and the importer accepts a hex public key.
How operators store their keys (file, HSM, keyring) is out of scope
for Phase 3.7 and covered by a dedicated key-management module later.

References:
- docs/design/offline-to-online-handoff.md
- docs/design/evidence-integrity.md
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from core.bundle.schema import BundleSignature, BundleSignatureError

# Ed25519 byte lengths per RFC 8032.
PRIVATE_KEY_BYTES = 32
PUBLIC_KEY_BYTES = 32
SIGNATURE_BYTES = 64


def generate_keypair() -> tuple[bytes, bytes]:
    """
    Generate a fresh Ed25519 keypair.

    Returns
    -------
    (private_32_bytes, public_32_bytes)
        Raw seed + raw public point. No encoding; callers are responsible
        for storing them securely.
    """
    private = ed25519.Ed25519PrivateKey.generate()
    public = private.public_key()
    from cryptography.hazmat.primitives import serialization

    private_bytes = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_bytes, public_bytes


def public_from_private(private_key_bytes: bytes) -> bytes:
    """Derive the 32-byte public key from a 32-byte private seed."""
    if len(private_key_bytes) != PRIVATE_KEY_BYTES:
        raise ValueError(
            f"private_key_bytes must be {PRIVATE_KEY_BYTES} bytes, got {len(private_key_bytes)}",
        )
    from cryptography.hazmat.primitives import serialization

    private = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def sign_digest(private_key_bytes: bytes, digest: bytes) -> bytes:
    """
    Sign an arbitrary byte string (typically a sha256 digest).

    Ed25519 signs any payload in one shot — there is no separate hash
    step inside the primitive. We feed it a sha256 digest because the
    bundle already computes that digest to pin file integrity.
    """
    if len(private_key_bytes) != PRIVATE_KEY_BYTES:
        raise ValueError(
            f"private_key_bytes must be {PRIVATE_KEY_BYTES} bytes, got {len(private_key_bytes)}",
        )
    private = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    return private.sign(digest)


def verify_signature(
    public_key_bytes: bytes,
    digest: bytes,
    signature: bytes,
) -> bool:
    """
    Verify a detached Ed25519 signature.

    Returns True on success, False on any verification failure. Does
    not raise — callers that need an exception should wrap this in
    `verify_bundle` or raise `BundleSignatureError` themselves.
    """
    if len(public_key_bytes) != PUBLIC_KEY_BYTES:
        return False
    if len(signature) != SIGNATURE_BYTES:
        return False
    try:
        public = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public.verify(signature, digest)
    except InvalidSignature:
        return False
    except ValueError:
        return False
    return True


def sign_bundle(
    *,
    private_key_bytes: bytes,
    digest: bytes,
) -> BundleSignature:
    """
    Sign a bundle digest and return a `BundleSignature` ready to persist.

    The caller is responsible for computing `digest` — usually the
    sha256 of the concatenated payload files. We deliberately do not
    compute it here so that the exporter can keep file I/O centralized.
    """
    public_bytes = public_from_private(private_key_bytes)
    signature_bytes = sign_digest(private_key_bytes, digest)
    return BundleSignature(
        algo="ed25519",
        public_key_hex=public_bytes.hex(),
        signature_hex=signature_bytes.hex(),
        signed_digest_hex=digest.hex(),
    )


def verify_bundle(
    *,
    digest: bytes,
    signature: BundleSignature,
    expected_public_key_hex: str | None = None,
) -> None:
    """
    Validate a `BundleSignature` against a freshly computed digest.

    Raises
    ------
    BundleSignatureError
        If the algorithm is unknown, the digest in the signature does
        not match the recomputed digest, the public key does not match
        the expected value, or the Ed25519 check fails.
    """
    if signature.algo != "ed25519":
        raise BundleSignatureError(f"unsupported signature algo: {signature.algo!r}")

    if signature.signed_digest_hex.lower() != digest.hex().lower():
        raise BundleSignatureError(
            "signed digest does not match recomputed payload digest",
        )

    if expected_public_key_hex is not None and (
        signature.public_key_hex.lower() != expected_public_key_hex.lower()
    ):
        raise BundleSignatureError(
            "bundle public key does not match expected public key",
        )

    try:
        public_bytes = bytes.fromhex(signature.public_key_hex)
        signature_bytes = bytes.fromhex(signature.signature_hex)
    except ValueError as exc:
        raise BundleSignatureError(f"signature fields are not valid hex: {exc}") from exc

    if not verify_signature(public_bytes, digest, signature_bytes):
        raise BundleSignatureError("Ed25519 signature check failed")


__all__ = [
    "PRIVATE_KEY_BYTES",
    "PUBLIC_KEY_BYTES",
    "SIGNATURE_BYTES",
    "generate_keypair",
    "public_from_private",
    "sign_bundle",
    "sign_digest",
    "verify_bundle",
    "verify_signature",
]
