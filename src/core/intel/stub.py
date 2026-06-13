"""
StubIOCProvider — deterministic in-memory provider for tests and offline demos.

The stub is populated with a dict keyed by `(value, ioc_type)`. Any miss
returns a "unknown" verdict. Supported IOC types default to all, but
can be restricted to simulate per-provider scope.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from core.intel.base import IOCProvider, IOCQuery, IOCUnsupportedError
from core.types import IOCProviderResult, IOCType


@dataclass
class StubIOCProvider:
    """
    In-memory provider. Satisfies `IOCProvider`.

    Example:
        stub = StubIOCProvider(
            name="stub-a",
            answers={("1.2.3.4", "ipv4"): ("malicious", 0.9)},
        )
        r = stub.query(IOCQuery("1.2.3.4", "ipv4"))
        # r.verdict == "malicious"
    """

    name: str
    answers: dict[tuple[str, str], tuple[str, float | None]] = field(
        default_factory=dict
    )
    supported_types: frozenset[IOCType] = field(
        default_factory=lambda: frozenset(
            {"ipv4", "ipv6", "domain", "url", "sha256", "sha1", "md5", "email"}
        )
    )
    raw_payload: dict[str, object] = field(default_factory=dict)
    _closed: bool = False

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in self.supported_types

    def query(self, request: IOCQuery) -> IOCProviderResult:
        if not self.supports(request.ioc_type):
            raise IOCUnsupportedError(
                f"{self.name} does not support ioc_type={request.ioc_type!r}"
            )
        key = (request.value, request.ioc_type)
        verdict, score = self.answers.get(key, ("unknown", None))
        return IOCProviderResult(
            name=self.name,
            verdict=verdict,  # type: ignore[arg-type]
            score=score,
            raw=dict(self.raw_payload),
        )

    def close(self) -> None:
        self._closed = True


def make_stub(
    name: str,
    answers: Iterable[tuple[str, IOCType, str, float | None]],
) -> StubIOCProvider:
    """Convenience: build a stub from a flat iterable of tuples."""
    mapping: dict[tuple[str, str], tuple[str, float | None]] = {}
    for value, ioc_type, verdict, score in answers:
        mapping[(value, ioc_type)] = (verdict, score)
    return StubIOCProvider(name=name, answers=mapping)


# Runtime check: make sure the Protocol is satisfied.
_PROTOCOL_CHECK: IOCProvider = StubIOCProvider(name="_")
del _PROTOCOL_CHECK
