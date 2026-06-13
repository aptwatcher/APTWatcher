"""
StubPublicationAdapter — in-memory recorder for unit tests + dry-run
demos. Never performs any network or subprocess I/O.

Every `publish(...)` call appends a record to `self.calls` so tests can
assert what would have been sent. The returned `PublicationResult`
mirrors what a real adapter would return, with `status` controlled by
the `force_status` constructor arg (default: honors `dry_run`).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from core.publish.protocol import (
    PublicationAdapter,
    PublicationError,
    PublicationResult,
    PublicationStatus,
)
from core.types import Finding, IOCVerdict

__all__ = ["StubPublicationAdapter"]


def _utc_iso_now() -> str:
    return datetime.now(tz=UTC).isoformat().replace("+00:00", "Z")


class StubPublicationAdapter:
    """In-memory recorder for tests. Never touches the network."""

    def __init__(
        self,
        name: str = "stub",
        *,
        force_status: PublicationStatus | None = None,
        raise_on_publish: bool = False,
    ) -> None:
        self.name: str = name
        self.calls: list[dict[str, Any]] = []
        self._force_status = force_status
        self._raise_on_publish = raise_on_publish

    def publish(
        self,
        *,
        findings: list[Finding],
        iocs: list[IOCVerdict],
        incident_id: str,
        campaign_tag: str,
        dry_run: bool = True,
    ) -> PublicationResult:
        call_record: dict[str, Any] = {
            "findings_count": len(findings),
            "iocs_count": len(iocs),
            "incident_id": incident_id,
            "campaign_tag": campaign_tag,
            "dry_run": dry_run,
            "ioc_values": [ioc.value for ioc in iocs],
        }
        self.calls.append(call_record)

        if self._raise_on_publish:
            raise PublicationError(
                f"stub adapter {self.name!r} was configured to raise"
            )

        status: PublicationStatus
        if self._force_status is not None:
            status = self._force_status
        else:
            status = "dry_run" if dry_run else "submitted"

        return PublicationResult(
            adapter=self.name,
            target="stub",
            submitted_at=_utc_iso_now(),
            correlation_id=f"stub-{uuid.uuid4().hex}",
            status=status,
            details={
                "call_index": len(self.calls) - 1,
                "findings_count": len(findings),
                "iocs_count": len(iocs),
            },
        )


# Protocol runtime check
_PROTOCOL_CHECK: PublicationAdapter = StubPublicationAdapter()
del _PROTOCOL_CHECK
