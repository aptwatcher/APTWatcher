"""
Tests for agent_extension.audit_render.

Covers:
  * empty-log rendering (both formats),
  * single-event rendering,
  * mixed token_input/token_output (some populated, some None) --
    footer must sum only the populated ones,
  * malformed JSONL lines are skipped with a stderr warning,
  * format='txt' path,
  * writing output to a file vs stdout,
  * total wall-clock computation,
  * self-correction counting,
  * unknown --format is a 2 exit code,
  * missing input is a 2 exit code.

We parse the real AuditEvent model (pydantic 2, extra='forbid') and
write JSONL that matches what core.audit.AuditLogger emits, including
the schema_version boundary field.
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from agent_extension.audit_render import (
    _aggregate,
    _parse_jsonl,
    _render_md,
    _render_txt,
    cmd_audit_render,
)
from core.audit import AUDIT_SCHEMA_VERSION
from core.types import AuditEvent

# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------


def _make_event(
    *,
    event_type: str,
    incident_id: str = "INC-TEST",
    ts: datetime,
    payload: dict | None = None,
    token_input: int | None = None,
    token_output: int | None = None,
    latency_ms: int | None = None,
) -> AuditEvent:
    return AuditEvent(
        event_type=event_type,
        incident_id=incident_id,
        timestamp=ts,
        payload=payload or {},
        token_input=token_input,
        token_output=token_output,
        latency_ms=latency_ms,
    )


def _write_jsonl(path: Path, events: list[AuditEvent]) -> None:
    lines: list[str] = []
    for e in events:
        record = e.model_dump(mode="json", exclude_none=False)
        record["schema_version"] = AUDIT_SCHEMA_VERSION
        lines.append(json.dumps(record))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_empty_log_markdown_has_headers_and_no_crash(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    log.write_text("", encoding="utf-8")
    out = _render_md([])
    assert "# Agent Execution Log" in out
    assert "No events recorded" in out


def test_empty_log_txt_variant(tmp_path: Path) -> None:
    out = _render_txt([])
    assert "(no events)" in out


def test_single_event_markdown_has_table_headers() -> None:
    t0 = datetime(2026, 4, 21, 12, 0, 0, tzinfo=UTC)
    events = [
        _make_event(
            event_type="run_start",
            ts=t0,
            payload={"summary": "kickoff"},
        ),
    ]
    out = _render_md(events)
    assert "| Timestamp (UTC) | Event | Actor | Summary" in out
    assert "run_start" in out
    assert "kickoff" in out
    assert "## Summary" in out
    assert "total events: 1" in out


def test_mixed_token_fields_sum_only_populated() -> None:
    t0 = datetime(2026, 4, 21, 12, 0, 0, tzinfo=UTC)
    events = [
        _make_event(event_type="run_start", ts=t0),
        _make_event(
            event_type="llm_call",
            ts=t0 + timedelta(seconds=2),
            token_input=100,
            token_output=50,
            latency_ms=400,
        ),
        _make_event(
            event_type="llm_call",
            ts=t0 + timedelta(seconds=5),
            token_input=200,
            token_output=None,
            latency_ms=250,
        ),
        _make_event(event_type="run_end", ts=t0 + timedelta(seconds=10)),
    ]
    agg = _aggregate(events)
    assert agg["total_events"] == 4
    assert agg["total_input_tokens"] == 300
    assert agg["total_output_tokens"] == 50
    assert agg["input_events"] == 2
    assert agg["output_events"] == 1
    assert agg["wall_seconds"] == 10.0


def test_malformed_line_skipped_others_rendered(tmp_path: Path, capsys) -> None:
    t0 = datetime(2026, 4, 21, 12, 0, 0, tzinfo=UTC)
    good = _make_event(event_type="run_start", ts=t0, payload={"summary": "ok"})
    log = tmp_path / "audit.jsonl"
    # Write one valid line, one empty line, one broken JSON line,
    # one valid-JSON but invalid-AuditEvent line.
    record = good.model_dump(mode="json", exclude_none=False)
    record["schema_version"] = AUDIT_SCHEMA_VERSION
    lines = [
        json.dumps(record),
        "",
        "{not-json",
        json.dumps({"event_type": "not_a_valid_literal", "incident_id": "X"}),
    ]
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    events = _parse_jsonl(log)
    assert len(events) == 1
    assert events[0].event_type == "run_start"

    captured = capsys.readouterr()
    assert "skipping malformed JSON" in captured.err
    assert "skipping invalid AuditEvent" in captured.err


def test_txt_format_inline_token_annotations() -> None:
    t0 = datetime(2026, 4, 21, 9, 30, 15, tzinfo=UTC)
    events = [
        _make_event(
            event_type="llm_call",
            ts=t0,
            payload={"summary": "planner call"},
            token_input=42,
            token_output=7,
            latency_ms=123,
        ),
    ]
    out = _render_txt(events)
    assert "[09:30:15] llm_call -- planner call" in out
    assert "tokens: 42 in / 7 out" in out
    assert "123ms" in out
    assert "--- summary ---" in out


def test_cmd_audit_render_stdout_default(tmp_path: Path, capsys) -> None:
    t0 = datetime(2026, 4, 21, 8, 0, 0, tzinfo=UTC)
    events = [_make_event(event_type="run_start", ts=t0, payload={"summary": "hi"})]
    log = tmp_path / "audit.jsonl"
    _write_jsonl(log, events)

    rc = cmd_audit_render(argparse.Namespace(input=log, output=None, format="md"))
    assert rc == 0
    out = capsys.readouterr().out
    assert "# Agent Execution Log" in out
    assert "run_start" in out


def test_cmd_audit_render_writes_to_file(tmp_path: Path) -> None:
    t0 = datetime(2026, 4, 21, 8, 0, 0, tzinfo=UTC)
    events = [
        _make_event(event_type="run_start", ts=t0, payload={"summary": "hi"}),
        _make_event(
            event_type="self_correction",
            ts=t0 + timedelta(seconds=1),
            payload={"summary": "retrying"},
            token_input=10,
            token_output=5,
            latency_ms=90,
        ),
    ]
    log = tmp_path / "audit.jsonl"
    _write_jsonl(log, events)

    out_path = tmp_path / "out" / "timeline.md"
    rc = cmd_audit_render(argparse.Namespace(input=log, output=out_path, format="md"))
    assert rc == 0
    assert out_path.exists()
    content = out_path.read_text(encoding="utf-8")
    assert "self_correction" in content
    assert "self-corrections: 1" in content
    assert "total input tokens: 10" in content


def test_cmd_audit_render_txt_file_output(tmp_path: Path) -> None:
    t0 = datetime(2026, 4, 21, 8, 0, 0, tzinfo=UTC)
    events = [_make_event(event_type="run_start", ts=t0, payload={"summary": "hi"})]
    log = tmp_path / "audit.jsonl"
    _write_jsonl(log, events)
    out_path = tmp_path / "timeline.txt"
    rc = cmd_audit_render(argparse.Namespace(input=log, output=out_path, format="txt"))
    assert rc == 0
    content = out_path.read_text(encoding="utf-8")
    assert "[08:00:00] run_start" in content
    assert "--- summary ---" in content


def test_cmd_audit_render_missing_input_returns_2(tmp_path: Path, capsys) -> None:
    rc = cmd_audit_render(
        argparse.Namespace(input=tmp_path / "nope.jsonl", output=None, format="md")
    )
    assert rc == 2
    assert "input not found" in capsys.readouterr().err


def test_cmd_audit_render_unknown_format_returns_2(tmp_path: Path, capsys) -> None:
    log = tmp_path / "audit.jsonl"
    log.write_text("", encoding="utf-8")
    rc = cmd_audit_render(
        argparse.Namespace(input=log, output=None, format="html")
    )
    assert rc == 2
    assert "unknown format" in capsys.readouterr().err


def test_total_wall_clock_across_minutes() -> None:
    t0 = datetime(2026, 4, 21, 12, 0, 0, tzinfo=UTC)
    events = [
        _make_event(event_type="run_start", ts=t0),
        _make_event(event_type="run_end", ts=t0 + timedelta(minutes=2, seconds=30)),
    ]
    agg = _aggregate(events)
    assert agg["wall_seconds"] == 150.0


def test_defensive_sort_handles_out_of_order_input(tmp_path: Path) -> None:
    t0 = datetime(2026, 4, 21, 12, 0, 0, tzinfo=UTC)
    later = _make_event(event_type="run_end", ts=t0 + timedelta(seconds=5))
    earlier = _make_event(event_type="run_start", ts=t0)
    log = tmp_path / "audit.jsonl"
    _write_jsonl(log, [later, earlier])  # deliberately reversed
    events = _parse_jsonl(log)
    assert [e.event_type for e in events] == ["run_start", "run_end"]


def test_round_trip_with_token_fields_preserves_values(tmp_path: Path) -> None:
    """Regression guard for extra='forbid' + new token fields."""
    t0 = datetime(2026, 4, 21, 12, 0, 0, tzinfo=UTC)
    ev = _make_event(
        event_type="llm_call",
        ts=t0,
        token_input=111,
        token_output=222,
        latency_ms=333,
    )
    blob = ev.model_dump_json()
    reborn = AuditEvent.model_validate_json(blob)
    assert reborn.token_input == 111
    assert reborn.token_output == 222
    assert reborn.latency_ms == 333
