"""
Tier 0 -- Hayabusa wrapper.

Hayabusa (Yamato Security) is a Windows EVTX hunting tool: it ingests
Windows event logs (``*.evtx``) and applies a built-in ruleset derived
from Sigma rules to surface suspicious activity -- credential access,
lateral movement, persistence, execution, defense evasion, and so on.
Its outputs are forensic timelines: one row per detection, with a
severity level, rule id, channel, event id, computer, and contextual
event fields. It is read-only with respect to the evidence: it opens
the EVTX files, parses them, and writes results to a caller-supplied
output path. It never modifies the input.

Design:

- Subcommands are allow-listed. Hayabusa exposes many subcommands
  (profile management, rule updates, pivot tables, metrics, ...); the
  Tier 0 wrapper only exposes those that are defensive-IR-relevant and
  safe to invoke without operator prompts:
    * ``csv-timeline`` / ``json-timeline`` (wrapped via
      ``run_hayabusa_timeline``) for the primary detection timeline.
    * ``logon-summary`` (wrapped via ``run_hayabusa_logon_summary``)
      for a compact logon-event report useful at triage time.
  The rule-update subcommand (``update-rules``) is consent-gated and
  lives in ``core.sift.update`` style wiring; it is NOT surfaced here
  because it mutates the host's rule repository.
- Output format for the timeline is restricted to ``csv`` or ``json``
  via ``HAYABUSA_OUTPUT_FORMATS``. The wrapper maps these to the
  correct subcommand so the caller cannot confuse the two.
- ``min_level`` is validated against Hayabusa's documented severity
  vocabulary (informational, low, medium, high, critical). An invalid
  level raises ``HayabusaSubcommandError`` before we ever fork.
- Evidence is treated as read-only. ``evidence_readonly_assumed=True`` is
  emitted to the audit log so any downstream reviewer can verify the
  assumption at the wrapper boundary.
- Output paths must not already exist. The wrapper refuses to
  overwrite a previous run's timeline so we never silently destroy a
  prior artefact.

argv shape:

    hayabusa <csv-timeline|json-timeline> [-q]
             [-d <dir> | -f <file>]
             -o <output_path>
             [--min-level <level>]
             [-p <profile>]

    hayabusa logon-summary
             [-d <dir> | -f <file>]
             [-o <output_path>]

We pick ``-d`` (directory) when ``evtx_source`` is a directory and
``-f`` (file) when it is a single EVTX file. ``-o`` is always emitted
for the timeline subcommands; for ``logon-summary`` we only emit
``-o`` when the caller supplies an output path (otherwise Hayabusa
prints the summary to stdout, which is what the caller asked for).

References:
- docs/reference/sift-tools.md
- docs/design/tier0-sift-lifecycle.md
"""

from __future__ import annotations

import shutil
from pathlib import Path

from core.audit import AuditLogger
from core.sift.runner import ToolRunError, ToolRunResult, run_tool

# Output format -> Hayabusa subcommand. The Tier 0 wrapper only allows
# these two; the key is what the caller passes as ``output_format``,
# the value is the concrete Hayabusa subcommand we invoke.
HAYABUSA_OUTPUT_FORMATS: dict[str, str] = {
    "csv": "csv-timeline",
    "json": "json-timeline",
}

# Severity vocabulary accepted by ``--min-level``. Taken from
# Hayabusa's documented level filter values.
_HAYABUSA_MIN_LEVELS: frozenset[str] = frozenset(
    {"informational", "low", "medium", "high", "critical"},
)


class HayabusaSubcommandError(ValueError):
    """Raised for disallowed output formats or invalid level/profile inputs."""


def _resolve_binary(name: str = "hayabusa") -> Path:
    """Find the hayabusa binary. SIFT ships it on PATH."""
    found = shutil.which(name)
    if found:
        return Path(found)
    raise ToolRunError(
        f"{name} not found on PATH. Preflight should have caught this.",
    )


def _evtx_source_flag(evtx_source: Path) -> list[str]:
    """
    Pick ``-d`` when the source is a directory, ``-f`` when it is a
    single EVTX file. The caller already validated that the path
    exists.
    """
    if evtx_source.is_dir():
        return ["-d", str(evtx_source)]
    return ["-f", str(evtx_source)]


def run_hayabusa_timeline(
    *,
    evtx_source: Path,
    output_path: Path,
    output_format: str = "csv",
    min_level: str = "medium",
    profile: str | None = None,
    quiet: bool = True,
    audit: AuditLogger | None = None,
    timeout: float = 3600.0,
    hayabusa_binary: Path | None = None,
) -> ToolRunResult:
    """
    Run a Hayabusa Sigma-backed detection timeline.

    ``evtx_source`` is either a directory of ``*.evtx`` files or a
    single ``*.evtx`` file; both must exist. The source is treated as
    read-only. ``output_path`` must NOT already exist -- we refuse to
    overwrite. ``output_format`` must be one of
    ``HAYABUSA_OUTPUT_FORMATS``; ``min_level`` must be one of the
    documented Hayabusa severities.
    """
    if output_format not in HAYABUSA_OUTPUT_FORMATS:
        raise HayabusaSubcommandError(
            f"Unsupported output_format: {output_format!r}. "
            f"Supported: {', '.join(sorted(HAYABUSA_OUTPUT_FORMATS))}",
        )
    if min_level not in _HAYABUSA_MIN_LEVELS:
        raise HayabusaSubcommandError(
            f"Unsupported min_level: {min_level!r}. "
            f"Supported: {', '.join(sorted(_HAYABUSA_MIN_LEVELS))}",
        )
    if not evtx_source.exists():
        raise ToolRunError(f"EVTX source not found: {evtx_source}")
    if not output_path.parent.exists():
        raise ToolRunError(
            f"Output parent directory does not exist: {output_path.parent}",
        )
    if output_path.exists():
        raise ToolRunError(
            f"Output path already exists: {output_path}. "
            "Refusing to overwrite Hayabusa timeline; pick a new path.",
        )

    subcommand = HAYABUSA_OUTPUT_FORMATS[output_format]
    binary = hayabusa_binary or _resolve_binary()
    argv: list[str] = [str(binary), subcommand]
    if quiet:
        argv.append("-q")
    argv.extend(_evtx_source_flag(evtx_source))
    argv.extend(["-o", str(output_path)])
    argv.extend(["--min-level", min_level])
    if profile:
        argv.extend(["-p", profile])

    return run_tool(
        argv,
        tool_name="hayabusa",
        audit=audit,
        timeout=timeout,
        extra_audit_payload={
            "subcommand": subcommand,
            "output_format": output_format,
            "evtx_source": str(evtx_source),
            "evidence_readonly_assumed": True,
            "output_path": str(output_path),
            "min_level": min_level,
            "profile": profile,
        },
    )


def run_hayabusa_logon_summary(
    *,
    evtx_source: Path,
    output_path: Path | None = None,
    audit: AuditLogger | None = None,
    timeout: float = 1800.0,
    hayabusa_binary: Path | None = None,
) -> ToolRunResult:
    """
    Run Hayabusa's ``logon-summary`` subcommand.

    Produces a compact summary of successful / failed logon events
    across the supplied EVTX source. When ``output_path`` is ``None``,
    Hayabusa prints the summary to stdout (captured by the runner).
    When supplied, ``output_path`` must not already exist.
    """
    if not evtx_source.exists():
        raise ToolRunError(f"EVTX source not found: {evtx_source}")
    if output_path is not None:
        if not output_path.parent.exists():
            raise ToolRunError(
                f"Output parent directory does not exist: {output_path.parent}",
            )
        if output_path.exists():
            raise ToolRunError(
                f"Output path already exists: {output_path}. "
                "Refusing to overwrite Hayabusa logon-summary; pick a new path.",
            )

    binary = hayabusa_binary or _resolve_binary()
    argv: list[str] = [str(binary), "logon-summary"]
    argv.extend(_evtx_source_flag(evtx_source))
    if output_path is not None:
        argv.extend(["-o", str(output_path)])

    return run_tool(
        argv,
        tool_name="hayabusa",
        audit=audit,
        timeout=timeout,
        extra_audit_payload={
            "subcommand": "logon-summary",
            "evtx_source": str(evtx_source),
            "evidence_readonly_assumed": True,
            "output_path": str(output_path) if output_path is not None else None,
            "min_level": None,
            "profile": None,
        },
    )


__all__ = [
    "HAYABUSA_OUTPUT_FORMATS",
    "HayabusaSubcommandError",
    "run_hayabusa_logon_summary",
    "run_hayabusa_timeline",
]
