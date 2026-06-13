"""
Tests for `core.bundle.signer`.

Focus:
- `generate_keypair()` returns 32-byte private / 32-byte public blobs.
- `sign_digest` + `verify_signature` round-trip for a fresh keypair.
- `verify_signature` returns False (does not raise) on:
    * tampered signature bytes,
    * tampered digest bytes,
    * mismatched public key (a different keypair's public half).
- `verify_bundle` raises `BundleSignatureError` with a typed message on
  each failure mode the importer depends on.
"""

from __future__ import annotations

import hashlib

import pytest

from core.bundle.schema import BundleSignature, BundleSignatureError
from core.bundle.signer import (
    PRIVATE_KEY_BYTES,
    PUBLIC_KEY_BYTES,
    SIGNATURE_BYTES,
    generate_keypair,
    public_from_private,
    sign_bundle,
    sign_digest,
    verify_bundle,
    verify_signature,
)


def _digest(data: bytes = b"hello world") -> bytes:
    return hashlib.sha256(data).digest()


def test_generate_keypair_sizes() -> None:
    private, public = generate_keypair()
    assert isinstance(private, bytes)
    assert isinstance(public, bytes)
    assert len(private) == PRIVATE_KEY_BYTES == 32
    assert len(public) == PUBLIC_KEY_BYTES == 32


def test_public_from_private_matches_generated() -> None:
    private, public = generate_keypair()
    assert public_from_private(private) == public


def test_sign_verify_roundtrip() -> None:
    private, public = generate_keypair()
    digest = _digest()
    signature = sign_digest(private, digest)
    assert len(signature) == SIGNATURE_BYTES == 64
    assert verify_signature(public, digest, signature) is True


def test_verify_rejects_tampered_signature() -> None:
    private, public = generate_keypair()
    digest = _digest()
    signature = bytearray(sign_digest(private, digest))
    # Flip one bit to invalidate it.
    signature[0] ^= 0x01
    assert verify_signature(public, digest, bytes(signature)) is False


def test_verify_rejects_tampered_digest() -> None:
    private, public = generate_keypair()
    digest = _digest(b"original")
    signature = sign_digest(private, digest)
    tampered = _digest(b"different")
    assert verify_signature(public, tampered, signature) is False


def test_verify_rejects_wrong_pubkey() -> None:
    private, _public = generate_keypair()
    _, other_public = generate_keypair()
    digest = _digest()
    signature = sign_digest(private, digest)
    assert verify_signature(other_public, digest, signature) is False


def test_verify_rejects_wrong_length_inputs() -> None:
    # verify_signature is permissive — it must never raise, only return False.
    assert verify_signature(b"too short", _digest(), b"x" * 64) is False
    assert verify_signature(b"x" * 32, _digest(), b"too short") is False


def test_sign_bundle_produces_consistent_signature_object() -> None:
    private, public = generate_keypair()
    digest = _digest()
    sig = sign_bundle(private_key_bytes=private, digest=digest)

    assert isinstance(sig, BundleSignature)
    assert sig.algo == "ed25519"
    assert sig.public_key_hex == public.hex()
    assert sig.signed_digest_hex == digest.hex()
    # And the signature verifies against the digest that was signed.
    assert verify_signature(public, digest, bytes.fromhex(sig.signature_hex))


def test_verify_bundle_happy_path() -> None:
    private, _ = generate_keypair()
    digest = _digest()
    sig = sign_bundle(private_key_bytes=private, digest=digest)
    # Should not raise.
    verify_bundle(digest=digest, signature=sig)


def test_verify_bundle_raises_on_digest_mismatch() -> None:
    private, _ = generate_keypair()
    sig = sign_bundle(private_key_bytes=private, digest=_digest(b"a"))
    with pytest.raises(BundleSignatureError):
        verify_bundle(digest=_digest(b"b"), signature=sig)


def test_verify_bundle_raises_on_tampered_signature_bytes() -> None:
    private, _ = generate_keypair()
    digest = _digest()
    sig = sign_bundle(private_key_bytes=private, digest=digest)
    # Flip the last byte of the signature hex.
    last = sig.signature_hex[-1]
    flipped = "0" if last != "0" else "1"
    tampered = sig.model_copy(update={"signature_hex": sig.signature_hex[:-1] + flipped})
    with pytest.raises(BundleSignatureError):
        verify_bundle(digest=digest, signature=tampered)


def test_verify_bundle_raises_on_unexpected_pubkey() -> None:
    private, _public = generate_keypair()
    digest = _digest()
    sig = sign_bundle(private_key_bytes=private, digest=digest)
    with pytest.raises(BundleSignatureError):
        verify_bundle(
            digest=digest,
            signature=sig,
            expected_public_key_hex="de" * 32,
        )


def test_sign_digest_rejects_wrong_length_private_key() -> None:
    with pytest.raises(ValueError):
        sign_digest(b"short", _digest())
