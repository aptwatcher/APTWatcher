"""
Tests for core.audit.AuditLogger.

Covers: write/read round-trip, redaction of sensitive keys, context-manager
book-ending with run_start/run_end, incident scoping enforcement.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.audit import AuditLogger
from core.types import AuditEvent


def test_append_and_read(tmp_log_dir: Path) -> None:
    with AuditLogger("INC-0001", log_dir=tmp_log_dir) as log:
        log.append("tool_call", {"tool": "preflight"}, correlation_id="abc")

    events = AuditLogger("INC-0001", log_dir=tmp_log_dir).read_all()
    types = [e.event_type for e in events]
    assert types[0] == "run_start"
    assert "tool_call" in types
    assert types[-1] == "run_end"


def test_redacts_sensitive_keys(tmp_log_dir: Path) -> None:
    log = AuditLogger("INC-0002", log_dir=tmp_log_dir)
    log.append(
        "tool_call",
        {
            "tool": "check_ioc",
            "api_key": "SHOULD-NOT-APPEAR",
            "nested": {"Authorization": "Bearer XXX", "keep": "ok"},
            "list_of_dicts": [{"token": "t1"}, {"plain": "v"}],
        },
    )
    raw = (tmp_log_dir / "INC-0002" / "audit.jsonl").read_text(encoding="utf-8")
    assert "SHOULD-NOT-APPEAR" not in raw
    assert "Bearer XXX" not in raw
    assert "t1" not in raw
    assert "<redacted>" in raw
    assert '"keep":"ok"' in raw
    assert '"plain":"v"' in raw


def test_has_and_find(tmp_log_dir: Path) -> None:
    log = AuditLogger("INC-0003", log_dir=tmp_log_dir)
    log.append("preflight", {"ok": True})
    log.append("finding", {"summary": "one"})
    log.append("finding", {"summary": "two"})

    assert log.has("finding") is True
    assert log.has("run_start") is False
    findings = log.find("finding")
    assert len(findings) == 2


def test_incident_scoping_enforced(tmp_log_dir: Path) -> None:
    log = AuditLogger("INC-0004", log_dir=tmp_log_dir)
    wrong = AuditEvent(event_type="tool_call", incident_id="INC-other", payload={})
    with pytest.raises(ValueError, match="does not match logger"):
        log.append_event(wrong)


def test_context_manager_records_error(tmp_log_dir: Path) -> None:
    with pytest.raises(RuntimeError, match="boom"):
        with AuditLogger("INC-0005", log_dir=tmp_log_dir) as log:
            log.append("tool_call", {"x": 1})
            raise RuntimeError("boom")

    events = AuditLogger("INC-0005", log_dir=tmp_log_dir).read_all()
    run_end = next(e for e in events if e.event_type == "run_end")
    assert run_end.payload.get("error", "").startswith("RuntimeError")
