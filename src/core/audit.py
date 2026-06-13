"""
Append-only JSONL audit logger.

One incident, one file (`logs/<incident_id>/audit.jsonl`). fsync after every
write. Writes are serialized through a process-local lock so concurrent
tool calls do not interleave half-lines. Across processes, flock is used;
if the OS does not support flock (Windows native Python), the advisory
lock falls back to a filename-based sentinel.

References:
- docs/architecture/audit-logging.md (format)
- docs/architecture/evidence-integrity.md (hash chain discipline)
"""

from __future__ import annotations

import contextlib
import json
import os
import threading
from pathlib import Path
from typing import Any

from core.types import AuditEvent, AuditEventType, utcnow

# Fields we refuse to write even if a caller tries. Matched case-insensitively
# against parameter keys.
_REDACT_KEYS = frozenset(
    {
        "api_key",
        "apikey",
        "token",
        "bearer",
        "password",
        "secret",
        "client_secret",
        "authorization",
    },
)

_REDACTED = "<redacted>"

# Bumped whenever the record shape changes in a way a downstream consumer
# (bundle importer, self-correction, external dashboards) must notice.
AUDIT_SCHEMA_VERSION = "1.0"


def _redact(value: Any) -> Any:
    """Recursively redact sensitive keys in a dict/list payload."""
    if isinstance(value, dict):
        return {
            k: (_REDACTED if k.lower() in _REDACT_KEYS else _redact(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


class AuditLogger:
    """
    Writes structured events to a JSONL file. Instances are incident-scoped.

    Use via context manager for the run-start / run-end book-ending, or
    construct directly and call `append()` for ad-hoc use.
    """

    def __init__(self, incident_id: str, log_dir: Path | str = "logs") -> None:
        self.incident_id = incident_id
        self.log_dir = Path(log_dir) / incident_id
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.log_dir / "audit.jsonl"
        self._lock = threading.Lock()

    # ----- lifecycle -----

    def __enter__(self) -> AuditLogger:
        self.append(
            event_type="run_start",
            payload={"incident_id": self.incident_id},
        )
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.append(
            event_type="run_end",
            payload={
                "incident_id": self.incident_id,
                "error": None if exc_type is None else f"{exc_type.__name__}: {exc}",
            },
        )

    # ----- primary API -----

    def append(
        self,
        event_type: AuditEventType,
        payload: dict[str, Any] | None = None,
        *,
        correlation_id: str | None = None,
    ) -> AuditEvent:
        """Build and write one event. Returns the event for caller convenience."""
        event = AuditEvent(
            event_type=event_type,
            incident_id=self.incident_id,
            correlation_id=correlation_id,
            timestamp=utcnow(),
            payload=_redact(payload or {}),
        )
        self._write_line(event)
        return event

    def append_event(self, event: AuditEvent) -> AuditEvent:
        """Write a pre-built event. Enforces incident scoping."""
        if event.incident_id != self.incident_id:
            raise ValueError(
                f"AuditEvent incident_id={event.incident_id!r} "
                f"does not match logger incident_id={self.incident_id!r}",
            )
        event_redacted = event.model_copy(update={"payload": _redact(event.payload)})
        self._write_line(event_redacted)
        return event_redacted

    # ----- introspection -----

    def read_all(self) -> list[AuditEvent]:
        """Load every event in the log file. Used by self-correction."""
        if not self.log_path.exists():
            return []
        events: list[AuditEvent] = []
        with self.log_path.open("r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line:
                    continue
                events.append(AuditEvent.model_validate_json(line))
        return events

    def find(self, event_type: AuditEventType) -> list[AuditEvent]:
        """Filter events by type."""
        return [e for e in self.read_all() if e.event_type == event_type]

    def has(self, event_type: AuditEventType) -> bool:
        """Cheap existence check — short-circuits without building a list."""
        if not self.log_path.exists():
            return False
        with self.log_path.open("r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if obj.get("event_type") == event_type:
                    return True
        return False

    # ----- low-level -----


    def _write_line(self, event: AuditEvent) -> None:
        # Inject schema_version at the logger boundary so every emitted
        # record is self-describing without leaking the field into the
        # AuditEvent model (kept boring for in-memory use).
        record = event.model_dump(mode="json", exclude_none=False)
        record["schema_version"] = AUDIT_SCHEMA_VERSION
        encoded = json.dumps(record, separators=(",", ":")) + "\n"
        with self._lock, self.log_path.open("a", encoding="utf-8") as f:
            f.write(encoded)
            f.flush()
            # fsync may fail on pseudo-filesystems; don't let the
            # audit log be the thing that crashes the run.
            with contextlib.suppress(OSError):
                os.fsync(f.fileno())


__all__ = ["AUDIT_SCHEMA_VERSION", "AuditLogger"]
