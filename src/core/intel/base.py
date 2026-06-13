"""
IOC provider Protocol + shared error hierarchy.

A provider is anything that can answer the question "is this IOC
malicious?" and return a single `IOCProviderResult`. Providers are
allowed to fail in bounded ways (timeout, transport error, unsupported
IOC type); the aggregator treats those as "this provider abstained,"
not as global failure.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from core.types import IOCProviderResult, IOCType

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class IOCProviderError(RuntimeError):
    """Base class for provider-side failures."""


class IOCUnsupportedError(IOCProviderError):
    """The provider does not support this IOC type (e.g., no domain lookup)."""


class IOCTransportError(IOCProviderError):
    """Underlying HTTP/transport failure — network, DNS, TLS, etc."""


class IOCTimeoutError(IOCProviderError):
    """Provider took too long to answer; treated as abstain."""


# ---------------------------------------------------------------------------
# Query request
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IOCQuery:
    """Structured lookup request. Immutable."""

    value: str
    ioc_type: IOCType


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class IOCProvider(Protocol):
    """
    Minimal contract every intel adapter must satisfy.

    A provider answers one IOC at a time. Aggregation, parallelism, and
    caching are the aggregator's job — providers stay dumb.

    Implementations MUST:
    - Return an `IOCProviderResult` whose `name` matches `self.name`.
    - Raise `IOCUnsupportedError` when `query.ioc_type` is out of scope
      (cheaper than returning a synthetic "unknown" result).
    - Raise `IOCTimeoutError` or `IOCTransportError` for recoverable
      transport failures. Everything else propagates.
    - Be safe to reuse across queries; connection pooling is fine but
      internal state must not leak between queries.
    """

    name: str

    def supports(self, ioc_type: IOCType) -> bool:
        """Cheap check used by the aggregator to skip providers."""
        ...

    def query(self, request: IOCQuery) -> IOCProviderResult:
        """Return one normalized provider answer."""
        ...

    def close(self) -> None:
        """Release any connection pool / handle. Must be idempotent."""
        ...
