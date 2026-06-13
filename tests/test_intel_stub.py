"""
Tests for StubIOCProvider — the in-memory reference provider.
"""

from __future__ import annotations

import pytest

from core.intel import IOCProvider, IOCQuery, IOCUnsupportedError, StubIOCProvider
from core.intel.stub import make_stub


def test_stub_is_an_iocprovider_at_runtime() -> None:
    stub = StubIOCProvider(name="unit")
    # isinstance works because IOCProvider is @runtime_checkable.
    assert isinstance(stub, IOCProvider)


def test_stub_returns_unknown_for_unseen_iocs() -> None:
    stub = StubIOCProvider(name="unit")
    r = stub.query(IOCQuery("1.2.3.4", "ipv4"))
    assert r.verdict == "unknown"
    assert r.score is None
    assert r.name == "unit"


def test_stub_returns_configured_verdict_and_score() -> None:
    stub = StubIOCProvider(
        name="vt-like",
        answers={("1.2.3.4", "ipv4"): ("malicious", 0.87)},
    )
    r = stub.query(IOCQuery("1.2.3.4", "ipv4"))
    assert r.verdict == "malicious"
    assert r.score == 0.87
    assert r.name == "vt-like"


def test_stub_raises_unsupported_for_out_of_scope_type() -> None:
    stub = StubIOCProvider(
        name="ipv4-only",
        supported_types=frozenset({"ipv4"}),
    )
    with pytest.raises(IOCUnsupportedError):
        stub.query(IOCQuery("evil.example", "domain"))


def test_stub_supports_all_types_by_default() -> None:
    stub = StubIOCProvider(name="default")
    for ioc_type in (
        "ipv4", "ipv6", "domain", "url", "sha256", "sha1", "md5", "email",
    ):
        assert stub.supports(ioc_type)


def test_stub_close_is_idempotent() -> None:
    stub = StubIOCProvider(name="u")
    stub.close()
    stub.close()  # must not raise
    assert stub._closed is True


def test_make_stub_helper() -> None:
    stub = make_stub(
        "helper",
        [
            ("1.2.3.4", "ipv4", "malicious", 0.9),
            ("bad.example", "domain", "suspicious", None),
        ],
    )
    assert stub.query(IOCQuery("1.2.3.4", "ipv4")).verdict == "malicious"
    assert stub.query(IOCQuery("bad.example", "domain")).score is None


def test_stub_raw_payload_is_copied_not_shared() -> None:
    shared = {"cache": "hit"}
    stub = StubIOCProvider(name="u", raw_payload=shared)
    r1 = stub.query(IOCQuery("x", "ipv4"))
    r1.raw["mutated"] = True
    r2 = stub.query(IOCQuery("y", "ipv4"))
    assert "mutated" not in r2.raw
