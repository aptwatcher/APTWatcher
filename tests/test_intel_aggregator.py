"""
Tests for IOCAggregator and the pure aggregate_results() function.

Focus areas:
- Verdict precedence (malicious > suspicious > benign > unknown).
- Score propagation — winning rank, max-score tie-break.
- Provider errors count as abstention, not global failure.
- Unsupported IOC types skip the provider silently.
- Sources preserved in provider-insertion order.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from core.intel import (
    DEFAULT_VERDICT_PRECEDENCE,
    IOCAggregator,
    IOCQuery,
    IOCTimeoutError,
    IOCTransportError,
    StubIOCProvider,
    aggregate_results,
)
from core.intel.base import IOCProviderError
from core.intel.stub import make_stub
from core.types import IOCProviderResult, IOCType

# ---------------------------------------------------------------------------
# aggregate_results — pure-function edge cases
# ---------------------------------------------------------------------------


def test_aggregate_no_results_is_unknown() -> None:
    v = aggregate_results(IOCQuery("x", "ipv4"), [])
    assert v.verdict == "unknown"
    assert v.confidence is None
    assert v.sources == []


def test_aggregate_malicious_beats_benign() -> None:
    results = [
        IOCProviderResult(name="a", verdict="benign", score=0.99),
        IOCProviderResult(name="b", verdict="malicious", score=0.7),
    ]
    v = aggregate_results(IOCQuery("x", "ipv4"), results)
    assert v.verdict == "malicious"
    assert v.confidence == 0.7


def test_aggregate_suspicious_beats_benign_and_unknown() -> None:
    results = [
        IOCProviderResult(name="a", verdict="benign", score=0.2),
        IOCProviderResult(name="b", verdict="suspicious", score=0.5),
        IOCProviderResult(name="c", verdict="unknown"),
    ]
    v = aggregate_results(IOCQuery("x", "ipv4"), results)
    assert v.verdict == "suspicious"
    assert v.confidence == 0.5


def test_aggregate_uses_max_score_among_winning_rank() -> None:
    results = [
        IOCProviderResult(name="a", verdict="malicious", score=0.5),
        IOCProviderResult(name="b", verdict="malicious", score=0.9),
        IOCProviderResult(name="c", verdict="malicious", score=0.8),
    ]
    v = aggregate_results(IOCQuery("x", "ipv4"), results)
    assert v.verdict == "malicious"
    assert v.confidence == 0.9


def test_aggregate_confidence_none_when_no_winning_score() -> None:
    results = [
        IOCProviderResult(name="a", verdict="malicious"),  # score None
        IOCProviderResult(name="b", verdict="benign", score=0.1),
    ]
    v = aggregate_results(IOCQuery("x", "ipv4"), results)
    assert v.verdict == "malicious"
    assert v.confidence is None


def test_aggregate_preserves_sources_in_order() -> None:
    a = IOCProviderResult(name="a", verdict="benign")
    b = IOCProviderResult(name="b", verdict="malicious")
    c = IOCProviderResult(name="c", verdict="suspicious")
    v = aggregate_results(IOCQuery("x", "ipv4"), [a, b, c])
    assert [s.name for s in v.sources] == ["a", "b", "c"]


def test_aggregate_custom_precedence_overrides_default() -> None:
    # Invert: benign beats malicious. Synthetic, just to prove it's honored.
    prec = dict(DEFAULT_VERDICT_PRECEDENCE)
    prec["benign"] = 10
    results = [
        IOCProviderResult(name="a", verdict="malicious", score=0.9),
        IOCProviderResult(name="b", verdict="benign", score=0.3),
    ]
    v = aggregate_results(IOCQuery("x", "ipv4"), results, precedence=prec)
    assert v.verdict == "benign"


# ---------------------------------------------------------------------------
# IOCAggregator — end-to-end with real stubs and fake providers
# ---------------------------------------------------------------------------


def test_aggregator_fans_out_to_all_supporting_providers() -> None:
    agg = IOCAggregator()
    agg.register(
        make_stub("p1", [("1.1.1.1", "ipv4", "malicious", 0.8)])
    )
    agg.register(
        make_stub("p2", [("1.1.1.1", "ipv4", "benign", 0.3)])
    )
    v = agg.lookup(IOCQuery("1.1.1.1", "ipv4"))
    assert v.verdict == "malicious"
    assert v.confidence == 0.8
    assert {s.name for s in v.sources} == {"p1", "p2"}


def test_aggregator_skips_unsupported_providers() -> None:
    agg = IOCAggregator()
    ipv4_only = StubIOCProvider(
        name="ipv4-only",
        supported_types=frozenset({"ipv4"}),
    )
    agg.register(ipv4_only)
    v = agg.lookup(IOCQuery("evil.example", "domain"))
    # Skipped silently → no sources, verdict unknown.
    assert v.verdict == "unknown"
    assert v.sources == []


@dataclass
class _FailingProvider:
    name: str
    supported_types: frozenset[IOCType] = frozenset({"ipv4"})
    exc: type[IOCProviderError] = IOCTimeoutError

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in self.supported_types

    def query(self, request: IOCQuery) -> IOCProviderResult:
        raise self.exc(f"{self.name} boom")

    def close(self) -> None: ...


def test_aggregator_treats_provider_timeout_as_abstention() -> None:
    agg = IOCAggregator()
    agg.register(_FailingProvider(name="flaky", exc=IOCTimeoutError))
    agg.register(
        make_stub("good", [("1.1.1.1", "ipv4", "suspicious", 0.5)])
    )
    v = agg.lookup(IOCQuery("1.1.1.1", "ipv4"))
    assert v.verdict == "suspicious"
    assert [s.name for s in v.sources] == ["good"]


def test_aggregator_treats_transport_error_as_abstention() -> None:
    agg = IOCAggregator()
    agg.register(_FailingProvider(name="flaky", exc=IOCTransportError))
    agg.register(
        make_stub("ok", [("1.1.1.1", "ipv4", "malicious", 0.9)])
    )
    v = agg.lookup(IOCQuery("1.1.1.1", "ipv4"))
    assert v.verdict == "malicious"


def test_aggregator_lets_non_provider_errors_propagate() -> None:
    class BustedProvider:
        name = "busted"
        def supports(self, ioc_type: IOCType) -> bool: return True
        def query(self, request: IOCQuery) -> IOCProviderResult:
            raise ValueError("not a provider error")
        def close(self) -> None: ...

    agg = IOCAggregator()
    agg.register(BustedProvider())  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        agg.lookup(IOCQuery("1.1.1.1", "ipv4"))


def test_aggregator_lookup_many() -> None:
    agg = IOCAggregator()
    agg.register(
        make_stub(
            "p",
            [
                ("1.1.1.1", "ipv4", "malicious", 0.9),
                ("2.2.2.2", "ipv4", "benign", 0.2),
            ],
        )
    )
    verdicts = agg.lookup_many(
        [IOCQuery("1.1.1.1", "ipv4"), IOCQuery("2.2.2.2", "ipv4")]
    )
    assert [v.verdict for v in verdicts] == ["malicious", "benign"]


def test_aggregator_close_calls_every_provider_and_swallows_errors() -> None:
    closed: list[str] = []

    class Recorder:
        name = "rec"
        def supports(self, ioc_type: IOCType) -> bool: return True
        def query(self, request: IOCQuery) -> IOCProviderResult:
            return IOCProviderResult(name="rec", verdict="unknown")
        def close(self) -> None:
            closed.append("rec")

    class Bad:
        name = "bad"
        def supports(self, ioc_type: IOCType) -> bool: return True
        def query(self, request: IOCQuery) -> IOCProviderResult:
            return IOCProviderResult(name="bad", verdict="unknown")
        def close(self) -> None:
            raise RuntimeError("close failure")

    agg = IOCAggregator()
    agg.register(Recorder())  # type: ignore[arg-type]
    agg.register(Bad())  # type: ignore[arg-type]
    agg.close()  # must not raise
    assert closed == ["rec"]


def test_aggregator_empty_has_no_sources() -> None:
    agg = IOCAggregator()
    v = agg.lookup(IOCQuery("x", "ipv4"))
    assert v.verdict == "unknown"
    assert v.sources == []
