"""
Cross-provider aggregator.

Fans out an `IOCQuery` to every registered provider that claims to
support the IOC type, collects `IOCProviderResult`s, and synthesizes
one `IOCVerdict`.

Design rules:

- Provider errors (`IOCProviderError` and subclasses) are swallowed and
  count as abstention. Any other exception propagates — those are
  programmer bugs, not provider failures.
- Unsupported IOC types never produce a result from that provider.
- Precedence: if *any* provider says "malicious", the verdict is
  "malicious". Else "suspicious" wins over "benign"/"unknown". Ties
  within a rank are broken by the highest-scoring result.
- Confidence on the aggregate is the max score seen among providers
  whose verdict matches the winning rank. `None` if no provider
  supplied a score.
- The aggregator never calls the same provider twice for one query
  and always returns the underlying `IOCProviderResult`s in the
  `sources` field, in provider-insertion order.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from core.intel.base import IOCProvider, IOCProviderError, IOCQuery
from core.types import IOCProviderResult, IOCVerdict, Verdict

# Higher rank wins.
DEFAULT_VERDICT_PRECEDENCE: dict[Verdict, int] = {
    "malicious": 3,
    "suspicious": 2,
    "benign": 1,
    "unknown": 0,
}


def _winning_verdict(
    results: list[IOCProviderResult],
    precedence: dict[Verdict, int],
) -> Verdict:
    if not results:
        return "unknown"
    best_rank = -1
    best: Verdict = "unknown"
    for r in results:
        rank = precedence.get(r.verdict, 0)
        if rank > best_rank:
            best_rank = rank
            best = r.verdict
    return best


def _winning_score(
    results: list[IOCProviderResult],
    winning: Verdict,
) -> float | None:
    best: float | None = None
    for r in results:
        if r.verdict != winning:
            continue
        if r.score is None:
            continue
        if best is None or r.score > best:
            best = r.score
    return best


def aggregate_results(
    query: IOCQuery,
    results: list[IOCProviderResult],
    *,
    precedence: dict[Verdict, int] | None = None,
) -> IOCVerdict:
    """Pure function: fold provider results into one IOCVerdict."""
    prec = precedence or DEFAULT_VERDICT_PRECEDENCE
    winning = _winning_verdict(results, prec)
    return IOCVerdict(
        value=query.value,
        ioc_type=query.ioc_type,
        verdict=winning,
        confidence=_winning_score(results, winning),
        sources=results,
    )


@dataclass
class IOCAggregator:
    """
    Orchestrates N providers. Stateless between queries apart from the
    provider list; safe to reuse across incidents.
    """

    providers: list[IOCProvider] = field(default_factory=list)
    precedence: dict[Verdict, int] = field(
        default_factory=lambda: dict(DEFAULT_VERDICT_PRECEDENCE)
    )

    def register(self, provider: IOCProvider) -> None:
        self.providers.append(provider)

    def lookup(self, query: IOCQuery) -> IOCVerdict:
        """Fan out to every supporting provider and aggregate."""
        collected: list[IOCProviderResult] = []
        for p in self.providers:
            if not p.supports(query.ioc_type):
                continue
            try:
                collected.append(p.query(query))
            except IOCProviderError:
                # Provider-side failure → abstention. Logged by callers.
                continue
        return aggregate_results(query, collected, precedence=self.precedence)

    def lookup_many(self, queries: Iterable[IOCQuery]) -> list[IOCVerdict]:
        return [self.lookup(q) for q in queries]

    def close(self) -> None:
        """Close every provider. Swallows per-provider close errors."""
        for p in self.providers:
            try:
                p.close()
            except Exception:  # noqa: BLE001 — defensive on shutdown
                continue
