"""
Tier 0 -- plaso wrapper (log2timeline.py + psort.py).

plaso is the super-timeline engine. For APTWatcher it is the single
most valuable Tier 0 wrapper after volatility3: a plaso timeline
correlates disk, registry, event log, and filesystem mtime data into
one ordered stream that downstream analysis can cite by timestamp +
source.

Design:

- Two-stage pipeline matches plaso's own split. `run_log2timeline()`
  takes a source (disk image, mount directory, or a single file) plus
  an allow-listed parser preset and writes a `.plaso` storage file.
  `run_psort()` converts that storage file to CSV or JSON for
  downstream tools to read.
- Parser presets (the `--parsers` argument to log2timeline) are
  allow-listed. We refuse free-form parser strings because a wrong
  preset on a hostile input can blow RAM + runtime through the roof,
  and because the self-correction pass needs determinism.
- Output paths are caller-provided and must NOT be inside the
  evidence tree. The wrapper records the declared output location in
  the audit log so the reviewer can verify that after the fact; it
  does not itself police the evidence boundary (that belongs at a
  higher layer where `EvidenceFile` metadata is visible).
- Source is treated as read-only and that assumption is emitted to
  the audit log. Callers who need write-side operations (timeline
  tagging via `psteal`) must not use this wrapper.

References:
- docs/reference/sift-tools.md
- docs/design/tier0-sift-lifecycle.md
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Literal

from core.audit import AuditLogger
from core.sift.runner import ToolRunError, ToolRunResult, run_tool

# Plaso ships dozens of "parser presets" (see `log2timeline.py --parsers
# list`). We allow-list the ones that match our use-case profiles and
# that do not pull in expensive-to-parse third-party sources.
PLASO_PARSER_PRESETS: dict[str, str] = {
    "win7": "Windows 7+ triage preset (evtx, registry, prefetch, lnk, $MFT).",
    "win_gen": "Windows-generic preset; broader than win7, still read-only.",
    "winxp": "Windows XP preset. Legacy; kept for vintage images.",
    "linux": "Linux preset (syslog, auth.log, cron, dpkg, utmp, bash).",
    "macos": "macOS preset (plist, biome, unified log, safari history).",
    "webhist": "Web history preset (chrome, firefox, safari, edge).",
}

# psort output formats we support. Free-form format strings are refused
# for the same determinism reasons as parser presets.
PlasoOutputFormat = Literal["l2tcsv", "dynamic", "json_line"]
_OUTPUT_FORMAT_NOTES: dict[str, str] = {
    "l2tcsv": "Legacy log2timeline CSV; one row per event.",
    "dynamic": "Configurable columns; APTWatcher default.",
    "json_line": "One JSON object per line; easiest for programmatic parsing.",
}


class PlasoParserPresetError(ValueError):
    """Raised when a parser preset is not in the allow-list."""


class PlasoOutputFormatError(ValueError):
    """Raised when an output format is not in the allow-list."""


def _resolve_binary(name: str) -> Path:
    """Find a plaso binary. SIFT ships `log2timeline.py` / `psort.py`."""
    found = shutil.which(name)
    if found:
        return Path(found)
    # Some SIFT installs drop plaso under a venv; fall back to the
    # canonical `.py` suffix variant.
    alt = shutil.which(f"{name}.py")
    if alt:
        return Path(alt)
    raise ToolRunError(
        f"{name} not found on PATH. Preflight should have caught this.",
    )


def run_log2timeline(
    *,
    source: Path,
    storage_file: Path,
    parsers: str,
    audit: AuditLogger | None = None,
    timeout: float = 3600.0,
    log2timeline_binary: Path | None = None,
) -> ToolRunResult:
    """
    Extract a plaso storage file from an image or directory.

    `source` must exist; the wrapper treats it as read-only. `storage_file`
    is the output path and must NOT be under the evidence tree. `parsers`
    is an allow-listed preset (see `PLASO_PARSER_PRESETS`).
    """
    if parsers not in PLASO_PARSER_PRESETS:
        raise PlasoParserPresetError(
            f"Parser preset {parsers!r} is not in the Tier 0 allow-list. "
            f"Supported: {', '.join(sorted(PLASO_PARSER_PRESETS))}",
        )
    if not source.exists():
        raise ToolRunError(f"Source not found: {source}")
    if storage_file.exists():
        raise ToolRunError(
            f"Storage file already exists: {storage_file}. "
            "Refusing to overwrite; pick a new output path.",
        )

    binary = log2timeline_binary or _resolve_binary("log2timeline")
    argv: list[str] = [
        str(binary),
        "--quiet",
        "--status_view", "none",
        "--parsers", parsers,
        "--storage_file", str(storage_file),
        str(source),
    ]

    return run_tool(
        argv,
        tool_name="log2timeline",
        audit=audit,
        timeout=timeout,
        extra_audit_payload={
            "parsers": parsers,
            "parsers_reason": PLASO_PARSER_PRESETS[parsers],
            "source": str(source),
            "evidence_readonly_assumed": True,
            "storage_file": str(storage_file),
        },
    )


def run_psort(
    *,
    storage_file: Path,
    output_file: Path,
    output_format: PlasoOutputFormat = "dynamic",
    time_filter: str | None = None,
    audit: AuditLogger | None = None,
    timeout: float = 1800.0,
    psort_binary: Path | None = None,
) -> ToolRunResult:
    """
    Convert a plaso storage file to a human-readable timeline.

    `storage_file` must exist. `output_file` is the result and must NOT be
    under the evidence tree. `output_format` is allow-listed. `time_filter`
    is passed verbatim to psort's `-z` / `--slice` equivalent and is the
    caller's responsibility to keep to ISO-8601 ranges.
    """
    if output_format not in _OUTPUT_FORMAT_NOTES:
        raise PlasoOutputFormatError(
            f"Output format {output_format!r} is not allow-listed. "
            f"Supported: {', '.join(sorted(_OUTPUT_FORMAT_NOTES))}",
        )
    if not storage_file.exists() or not storage_file.is_file():
        raise ToolRunError(f"Storage file not found: {storage_file}")
    if output_file.exists():
        raise ToolRunError(
            f"Output file already exists: {output_file}. "
            "Refusing to overwrite; pick a new output path.",
        )

    binary = psort_binary or _resolve_binary("psort")
    argv: list[str] = [
        str(binary),
        "--quiet",
        "-o", output_format,
        "-w", str(output_file),
        str(storage_file),
    ]
    if time_filter:
        argv.extend(["--slice", time_filter])

    return run_tool(
        argv,
        tool_name="psort",
        audit=audit,
        timeout=timeout,
        extra_audit_payload={
            "output_format": output_format,
            "output_format_note": _OUTPUT_FORMAT_NOTES[output_format],
            "storage_file": str(storage_file),
            "evidence_readonly_assumed": True,
            "output_file": str(output_file),
            "time_filter": time_filter,
        },
    )


__all__ = [
    "PLASO_PARSER_PRESETS",
    "PlasoOutputFormat",
    "PlasoOutputFormatError",
    "PlasoParserPresetError",
    "run_log2timeline",
    "run_psort",
]
