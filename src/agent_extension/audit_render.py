"""
Judge-friendly renderer for the Ed25519-signed JSONL audit log.

Converts an `audit.jsonl` file into either a Markdown table (the default;
good for reviewers who want columns with timestamp / actor / token counts)
or a plain ASCII timeline (good for copy-paste into a terminal transcript).

The signed audit log is the source of truth; this module is a pure
presentation layer with zero side effects on the log itself. It reads
JSONL line by line, parses each line into an ``AuditEvent`` (tolerant of
blank lines and malformed lines), sorts defensively by timestamp, and
then emits the rendered timeline plus a summary footer.

Invoked in two ways:
  * directly: ``cmd_audit_render(argparse.Namespace(...))``
  * through Typer: ``aptwatcher audit-render --input ... --format md``

Summary footer fields:
  * total events
  * total input tokens  (sum over events where ``token_input`` is set)
  * total output tokens (sum over events where ``token_output`` is set)
  * total wall clock    (last timestamp minus first timestamp)
  * self-correction count (events with ``event_type == "self_correction"``)
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from pydantic import ValidationError

from core.types import AuditEvent

# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def _parse_jsonl(path: Path) -> list[AuditEvent]:
    """Return AuditEvents parsed from ``path``.

    Tolerant of:
      * blank lines (skipped silently),
      * malformed JSON (skipped with a warning on stderr),
      * lines that are valid JSON but fail AuditEvent validation
        (skipped with a warning on stderr).

    Never raises for a per-line problem. A missing file is a hard error.
    """
    text = path.read_text(encoding="utf-8")
    events: list[AuditEvent] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            print(
                f"audit-render: skipping malformed JSON at line {lineno}: {exc}",
                file=sys.stderr,
            )
            continue
        try:
            events.append(AuditEvent.model_validate(obj))
        except ValidationError as exc:
            print(
                f"audit-render: skipping invalid AuditEvent at line {lineno}: {exc.errors()[0].get('msg', exc)}",
                file=sys.stderr,
            )
            continue
    # Defensive sort: the log writer already appends in order, but a
    # renderer should not rely on that contract for correctness.
    events.sort(key=lambda e: e.timestamp)
    return events


# ---------------------------------------------------------------------------
# Summary helpers
# ---------------------------------------------------------------------------


def _actor_for(event: AuditEvent) -> str:
    """Short actor tag derived from event_type.

    LLM-flavored events collapse to ``llm``; tool and workflow events
    map to their own buckets. Keeps the rendered table narrow.
    """
    et = event.event_type
    if et in ("llm_call", "analysis_emit", "analysis_error", "self_correction", "claim_verification"):
        return "llm"
    if et == "tool_call":
        return "tool"
    if et in ("run_start", "run_end"):
        return "runtime"
    if et == "preflight":
        return "preflight"
    if et in ("sift_update_consent", "timesketch_upload_consent"):
        return "operator"
    if et in ("finding", "report_emit"):
        return "agent"
    return "agent"


def _summary_for(event: AuditEvent) -> str:
    """One-line summary from the payload. Truncated for table width."""
    payload = event.payload or {}
    # Prefer an explicit summary-like key when the emitter supplied one.
    for key in ("summary", "message", "note", "description", "title", "tool", "finding_id"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            text = value
            break
    else:
        if payload:
            # Fall back to the first string-valued entry.
            for value in payload.values():
                if isinstance(value, str) and value:
                    text = value
                    break
            else:
                text = ""
        else:
            text = ""
    text = text.replace("\n", " ").replace("|", "/")
    if len(text) > 80:
        text = text[:79] + "..."
    return text


def _fmt_ts_md(ts: datetime) -> str:
    """Human-friendly timestamp for the markdown column. UTC."""
    return ts.strftime("%Y-%m-%d %H:%M:%S")


def _fmt_ts_txt(ts: datetime) -> str:
    """Compact HH:MM:SS timestamp for the txt timeline."""
    return ts.strftime("%H:%M:%S")


def _aggregate(events: list[AuditEvent]) -> dict[str, object]:
    """Compute summary-footer numbers in a single pass."""
    total_in = 0
    total_out = 0
    in_count = 0
    out_count = 0
    self_corrections = 0
    for e in events:
        if e.token_input is not None:
            total_in += e.token_input
            in_count += 1
        if e.token_output is not None:
            total_out += e.token_output
            out_count += 1
        if e.event_type == "self_correction":
            self_corrections += 1
    if events:
        first_ts = events[0].timestamp
        last_ts = events[-1].timestamp
        wall_seconds = (last_ts - first_ts).total_seconds()
    else:
        first_ts = None
        last_ts = None
        wall_seconds = 0.0
    return {
        "total_events": len(events),
        "total_input_tokens": total_in,
        "total_output_tokens": total_out,
        "input_events": in_count,
        "output_events": out_count,
        "self_corrections": self_corrections,
        "first_ts": first_ts,
        "last_ts": last_ts,
        "wall_seconds": wall_seconds,
    }


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------


def _render_md(events: list[AuditEvent]) -> str:
    """Render events as a GitHub-flavored markdown table plus footer."""
    lines: list[str] = []
    lines.append("# Agent Execution Log")
    lines.append("")
    if not events:
        lines.append("_No events recorded._")
        lines.append("")
        return "\n".join(lines) + "\n"
    lines.append(
        "| Timestamp (UTC) | Event | Actor | Summary | token_input | token_output | latency_ms |"
    )
    lines.append("|---|---|---|---|---:|---:|---:|")
    for e in events:
        ti = "" if e.token_input is None else str(e.token_input)
        to = "" if e.token_output is None else str(e.token_output)
        lat = "" if e.latency_ms is None else str(e.latency_ms)
        lines.append(
            f"| {_fmt_ts_md(e.timestamp)} | {e.event_type} | {_actor_for(e)} "
            f"| {_summary_for(e)} | {ti} | {to} | {lat} |"
        )
    agg = _aggregate(events)
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- total events: {agg['total_events']}")
    lines.append(
        f"- total input tokens: {agg['total_input_tokens']} "
        f"(across {agg['input_events']} event(s))"
    )
    lines.append(
        f"- total output tokens: {agg['total_output_tokens']} "
        f"(across {agg['output_events']} event(s))"
    )
    lines.append(f"- total wall clock: {agg['wall_seconds']:.3f}s")
    lines.append(f"- self-corrections: {agg['self_corrections']}")
    lines.append("")
    return "\n".join(lines) + "\n"


def _render_txt(events: list[AuditEvent]) -> str:
    """Render events as a plain ASCII timeline plus footer."""
    lines: list[str] = []
    if not events:
        lines.append("(no events)")
        lines.append("")
        return "\n".join(lines) + "\n"
    for e in events:
        parts: list[str] = []
        summary = _summary_for(e)
        head = f"[{_fmt_ts_txt(e.timestamp)}] {e.event_type}"
        if summary:
            head = f"{head} -- {summary}"
        parts.append(head)
        tail_bits: list[str] = []
        if e.token_input is not None or e.token_output is not None:
            ti = e.token_input if e.token_input is not None else 0
            to = e.token_output if e.token_output is not None else 0
            tail_bits.append(f"tokens: {ti} in / {to} out")
        if e.latency_ms is not None:
            tail_bits.append(f"{e.latency_ms}ms")
        if tail_bits:
            parts.append(f"({', '.join(tail_bits)})")
        lines.append(" ".join(parts))
    agg = _aggregate(events)
    lines.append("")
    lines.append("--- summary ---")
    lines.append(f"total events:        {agg['total_events']}")
    lines.append(f"total input tokens:  {agg['total_input_tokens']}")
    lines.append(f"total output tokens: {agg['total_output_tokens']}")
    lines.append(f"total wall clock:    {agg['wall_seconds']:.3f}s")
    lines.append(f"self-corrections:    {agg['self_corrections']}")
    lines.append("")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def cmd_audit_render(args: argparse.Namespace) -> int:
    """Render ``args.input`` to stdout or to ``args.output``.

    ``args`` must expose:
      * ``input``: ``pathlib.Path`` to a JSONL audit log (must exist).
      * ``output``: ``pathlib.Path`` or ``None``. If None, writes stdout.
      * ``format``: ``"md"`` or ``"txt"`` (default ``"md"``).

    Returns an integer exit code:
      * 0 on success,
      * 2 when the input file is missing or the format is unknown.
    """
    input_path: Path = args.input
    output_path: Path | None = getattr(args, "output", None)
    fmt: str = getattr(args, "format", "md") or "md"

    if not input_path.exists() or not input_path.is_file():
        print(f"audit-render: input not found: {input_path}", file=sys.stderr)
        return 2
    if fmt not in ("md", "txt"):
        print(f"audit-render: unknown format: {fmt!r} (expected md|txt)", file=sys.stderr)
        return 2

    events = _parse_jsonl(input_path)
    rendered = _render_md(events) if fmt == "md" else _render_txt(events)

    if output_path is None:
        sys.stdout.write(rendered)
    else:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
    return 0


__all__ = ["cmd_audit_render"]
