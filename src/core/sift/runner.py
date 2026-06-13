"""
Generic subprocess runner used by every Tier 0 SIFT wrapper.

Keep this file boring. All cleverness lives in the per-tool wrappers that
build the argv and interpret stdout. This module does three things:

1. Run a given argv with a timeout, capturing stdout/stderr.
2. Write before/after `tool_call` events to the audit log if a logger is
   supplied.
3. Return a structured `ToolRunResult` the caller can cite.

The runner refuses to execute if the first argv element is not already
resolved on disk (the caller is expected to have called `probe_tool` or
`shutil.which` before handing argv over). This keeps the tool allow-list
policy at the wrapper boundary where it belongs.
"""

from __future__ import annotations

import subprocess  # nosec: B404 — argv built by allow-listed wrappers
import uuid
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from core.audit import AuditLogger
from core.types import utcnow


class ToolRunError(RuntimeError):
    """Raised for structural / precondition failures (not non-zero exits)."""


class ToolRunResult(BaseModel):
    """
    Structured result of one SIFT tool invocation. Emitted verbatim as the
    payload of the closing `tool_call` audit event.
    """

    model_config = ConfigDict(extra="forbid")

    tool: str
    argv: list[str]
    correlation_id: str
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    started_at: str
    ended_at: str
    notes: str | None = None

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def run_tool(
    argv: list[str],
    *,
    tool_name: str,
    audit: AuditLogger | None = None,
    timeout: float = 120.0,
    stdin: str | None = None,
    cwd: Path | None = None,
    extra_audit_payload: dict[str, Any] | None = None,
) -> ToolRunResult:
    """
    Execute one allow-listed tool. Returns a `ToolRunResult` whether the
    process exited 0, non-zero, or timed out. Raises `ToolRunError` only
    for structural problems (empty argv, missing binary path).

    Callers must pre-resolve the binary (argv[0] should be an absolute path
    on disk, typically obtained from `probe_tool(name).path`).
    """
    if not argv:
        raise ToolRunError("argv must be non-empty")
    binary = Path(argv[0])
    if not binary.is_absolute() or not binary.exists():
        raise ToolRunError(
            f"Binary not resolved: {argv[0]!r}. "
            "Wrappers must pre-resolve with probe_tool() / shutil.which().",
        )

    correlation_id = uuid.uuid4().hex
    started = utcnow()
    if audit is not None:
        audit.append(
            event_type="tool_call",
            correlation_id=correlation_id,
            payload={
                "phase": "start",
                "tool": tool_name,
                "argv": argv,
                "cwd": str(cwd) if cwd else None,
                **(extra_audit_payload or {}),
            },
        )

    timed_out = False
    try:
        proc = subprocess.run(  # nosec: B603 — argv is pre-built allow-listed
            argv,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
            check=False,
        )
        returncode = proc.returncode
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        returncode = -1
        stdout = (exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else exc.stdout) or ""
        stderr = (exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else exc.stderr) or ""

    ended = utcnow()
    result = ToolRunResult(
        tool=tool_name,
        argv=argv,
        correlation_id=correlation_id,
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=(ended - started).total_seconds(),
        timed_out=timed_out,
        started_at=started.isoformat(),
        ended_at=ended.isoformat(),
    )

    if audit is not None:
        audit.append(
            event_type="tool_call",
            correlation_id=correlation_id,
            payload={
                "phase": "end",
                "tool": tool_name,
                "returncode": result.returncode,
                "duration_seconds": result.duration_seconds,
                "timed_out": result.timed_out,
                "stdout_bytes": len(result.stdout),
                "stderr_bytes": len(result.stderr),
            },
        )

    return result


__all__ = ["ToolRunError", "ToolRunResult", "run_tool"]


# Silence linters on unused Field (reserved for future fields).
_ = Field
