"""
Tier 0 — volatility3 wrapper.

Exposes an allow-listed plugin runner. The agent is not permitted to pass
arbitrary vol3 plugin strings; each plugin supported here is explicitly
reviewed for:

- Read-only semantics against the memory image.
- Bounded output (we reject plugins whose `--dump` flag is the only
  valuable mode; those need their own wrapper with cwd + retention rules).
- Deterministic-enough output that the self-correction pass can re-run
  the same argv and diff.

References:
- docs/reference/sift-tools.md
- docs/design/tier0-sift-lifecycle.md
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from core.audit import AuditLogger
from core.sift.runner import ToolRunError, ToolRunResult, run_tool

# Allow-list. Maps plugin name → short reason it's allowed. The reason is
# surfaced in the audit log so after-the-fact review can see why each
# plugin made the cut.
VOLATILITY_PLUGINS: dict[str, str] = {
    "windows.pslist.PsList": "Read-only process list from PsActiveProcessHead.",
    "windows.pstree.PsTree": "Read-only process tree, parent/child relationships.",
    "windows.cmdline.CmdLine": "Read-only process command-line recovery.",
    "windows.netscan.NetScan": "Read-only scanner for _TCPE/UDPE structures.",
    "windows.dlllist.DllList": "Read-only loaded-DLL enumeration.",
    "windows.malfind.Malfind": "Read-only detection of suspected injected code.",
    "windows.svcscan.SvcScan": "Read-only service enumeration.",
    "windows.registry.hivelist.HiveList": "Read-only registry hive enumeration.",
    "linux.pslist.PsList": "Read-only Linux task list.",
    "linux.bash.Bash": "Read-only recovery of bash history from memory.",
}


class VolatilityPluginError(ValueError):
    """Raised when a plugin name is not in the allow-list."""


def _resolve_vol_binary() -> Path:
    """Find Volatility 3.

    Honors an `APTW_VOLATILITY3_BIN` override, then tries the SIFT names and
    the venv path (`/opt/volatility3/bin/vol`). A bare `vol` is deliberately
    never resolved: on SIFT that is Volatility 2 and would crash on a modern
    Windows dump (CLAUDE.md tool-invocation contract).
    """
    override = os.environ.get("APTW_VOLATILITY3_BIN")
    candidates = (
        (override,)
        if override
        else ("vol3", "vol.py", "volatility3", "/opt/volatility3/bin/vol")
    )
    for candidate in candidates:
        if not candidate:
            continue
        found = shutil.which(candidate)
        if found:
            return Path(found)
    raise ToolRunError(
        "volatility3 not found on PATH. Preflight should have caught this — "
        "the wrapper must not be reachable without passing preflight.",
    )


def run_volatility(
    *,
    memory_image: Path,
    plugin: str,
    plugin_args: list[str] | None = None,
    audit: AuditLogger | None = None,
    timeout: float = 600.0,
    vol_binary: Path | None = None,
) -> ToolRunResult:
    """
    Run one allow-listed volatility3 plugin against a memory image.

    `memory_image` must exist and be a regular file; the wrapper treats it
    as read-only. `plugin_args` are appended verbatim after the plugin name
    and are the caller's responsibility to keep side-effect-free (no
    `--dump`, no `--output-dir` pointing into evidence, etc.).
    """
    if plugin not in VOLATILITY_PLUGINS:
        raise VolatilityPluginError(
            f"Plugin {plugin!r} is not in the Tier 0 allow-list. "
            f"Supported: {', '.join(sorted(VOLATILITY_PLUGINS))}",
        )
    if not memory_image.exists() or not memory_image.is_file():
        raise ToolRunError(f"Memory image not found: {memory_image}")

    binary = vol_binary or _resolve_vol_binary()
    argv: list[str] = [
        str(binary),
        "-f",
        str(memory_image),
        "-q",  # quiet: suppress progress chatter so stdout is the table
        plugin,
    ]
    if plugin_args:
        argv.extend(plugin_args)

    return run_tool(
        argv,
        tool_name="volatility3",
        audit=audit,
        timeout=timeout,
        extra_audit_payload={
            "plugin": plugin,
            "plugin_reason": VOLATILITY_PLUGINS[plugin],
            "memory_image": str(memory_image),
            "evidence_readonly_assumed": True,
        },
    )


__all__ = [
    "VOLATILITY_PLUGINS",
    "VolatilityPluginError",
    "run_volatility",
]
