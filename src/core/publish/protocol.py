"""
Publication adapter protocol + common result / error models.

Every publication target (Netcraft, MISP, GLPI, ...) implements
`PublicationAdapter`. The Protocol is runtime-checkable so the
`aptwatcher publish` CLI can validate its registry of targets without
requiring a common ABC.

Design notes:
- `PublicationResult` is a Pydantic v2 model (extra="forbid"), so the
  publication ledger format stays stable across adapters.
- `dry_run=True` is the default on every adapter. A `status="dry_run"`
  result is *not* a failure — it carries the rendered payload back so
  the operator can eyeball what would have been sent.
- Never swallow an underlying transport exception; wrap into
  `PublicationError` and raise.
"""

from __future__ import annotations

from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from core.types import Finding, IOCVerdict

__all__ = [
    "PublicationAdapter",
    "PublicationError",
    "PublicationResult",
    "PublicationStatus",
]


class PublicationError(RuntimeError):
    """Raised when publication fails (network, auth, rate limit, etc.)."""


PublicationStatus = Literal["submitted", "dry_run", "failed"]


class PublicationResult(BaseModel):
    """
    Persisted to `publication_ledger.jsonl` and returned to the CLI.

    `adapter` is the short name (e.g. "netcraft"), `target` is the remote
    identifier the adapter got back (UUID, event id, ticket id...). For
    `dry_run` results, `target` is the adapter name with a `-dry-run`
    suffix so the ledger row is still unique.
    """

    model_config = ConfigDict(extra="forbid")

    adapter: str
    target: str
    submitted_at: str
    correlation_id: str
    status: PublicationStatus
    details: dict[str, Any] = Field(default_factory=dict)


@runtime_checkable
class PublicationAdapter(Protocol):
    """
    Contract every publication adapter must satisfy.

    Adapters MUST:
    - Expose a stable `name` attribute (short slug).
    - Accept `dry_run=True` as the default on `publish(...)`.
    - Filter IOCs they cannot consume silently (do not raise).
    - Raise `PublicationError` on transport / auth / 4xx / 5xx failures.
    - Never perform real network I/O when `dry_run=True`.
    """

    name: str

    def publish(
        self,
        *,
        findings: list[Finding],
        iocs: list[IOCVerdict],
        incident_id: str,
        campaign_tag: str,
        dry_run: bool = True,
    ) -> PublicationResult: ...
