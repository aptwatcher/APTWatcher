"""
Tier 0 -- RegRipper wrapper.

RegRipper (Harlan Carvey) is a Windows registry triage tool: given an
offline registry hive (SOFTWARE, SYSTEM, NTUSER.DAT, SAM, SECURITY, or
a restored hive from a VSC / image), it runs a focused plugin or a
whole hive profile to extract defensively-relevant keys -- persistence
entries (Run / RunOnce / Services), execution evidence (AppCompatCache
/ ShimCache / Amcache), user activity (UserAssist, MUICache,
ShellBags), removable-media history (USB, MountPoints2), logging
policy (AuditPol), and host metadata (ComputerName, Windows version,
TimeZone). It is read-only with respect to the hive: RegRipper opens
the file, walks key structures, and prints to stdout. It never writes
back into the hive.

Design:

- Plugins are allow-listed. RegRipper ships hundreds of plugins; the
  Tier 0 wrapper exposes only the ones that are defensive-IR-relevant
  and safe to invoke without operator prompts. Anything outside that
  list raises ``RegRipperPluginError`` before we fork.
- Profiles (``-f software`` / ``system`` / ``ntuser`` / ``sam`` /
  ``security``) are likewise allow-listed. An unknown profile raises
  ``RegRipperProfileError``.
- Evidence is treated as read-only. ``evidence_readonly_assumed=True``
  is emitted to the audit log so any downstream reviewer can verify
  the assumption at the wrapper boundary. The hive path must point at
  an existing regular file; the wrapper refuses to open a directory or
  a missing path.
- Binary resolution prefers ``rip.pl`` (the Perl script ships on the
  SIFT Workstation) and falls back to ``rip`` if the Perl script is
  not on PATH. If neither resolves, ``_resolve_binary`` raises
  ``ToolRunError``.
- Output goes to stdout. The runner captures stdout into the
  ``ToolRunResult`` so callers can persist or parse it without the
  wrapper touching the filesystem.

argv shape:

    rip.pl -r <hive> -p <plugin>
    rip.pl -r <hive> -f <profile>

We never emit ``-l`` (list plugins) or any write-mode flag from this
wrapper; the plugin / profile allow-lists are the only documented
dispatch surface.

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

# Defensive-IR plugin allow-list. The key is the RegRipper plugin name
# (the ``-p`` argument value); the value is a short reason / coverage
# summary used in audit payloads and the MCP tool listing. Categories:
# system-hive triage, persistence, user activity, execution evidence,
# removable media, logging policy.
REGRIPPER_PLUGINS: dict[str, str] = {
    # System hive triage.
    "compname": "Computer name from the SYSTEM hive; anchors host identity.",
    "winver": "Windows product name, build, install date (SOFTWARE hive).",
    "timezone": "Active TimeZone bias; anchors all event correlation.",
    # Persistence.
    "run": "HKLM/HKCU Run keys; classic user-mode persistence vector.",
    "runonce": "RunOnce keys; one-shot persistence used by installers and malware.",
    "services": "Service definitions from SYSTEM hive; service-based persistence.",
    # User activity.
    "userassist": "UserAssist ROT13 entries; GUI program execution per-user.",
    "muicache": "MUICache launched-binary list; user-context execution evidence.",
    "shellbags": "ShellBags folder-view history; directory traversal per-user.",
    # Execution evidence.
    "appcompatcache": "AppCompatCache (Shimcache) execution evidence from SYSTEM.",
    "shimcache": "Alias for appcompatcache on some RegRipper builds.",
    "amcache": "Amcache.hve program execution / first-observed timestamps.",
    # Removable media.
    "usb": "USBSTOR device history; removable-media attachment record.",
    "mountpoints2": "HKCU MountPoints2; per-user drive mount history.",
    # Logging policy.
    "auditpol": "Audit policy from SECURITY hive; what the host was logging.",
}

# Profile-file allow-list. Each key is a RegRipper profile (``-f``)
# that corresponds to a classic hive-family triage sweep. Values are
# short reasons used in audit payloads and the MCP tool listing.
REGRIPPER_PROFILES: dict[str, str] = {
    "software": "HKLM\\SOFTWARE triage profile; install / run / uninstall keys.",
    "system": "HKLM\\SYSTEM triage profile; services, devices, timezone, controlset.",
    "ntuser": "Per-user NTUSER.DAT triage profile; user activity and persistence.",
    "sam": "SAM hive triage profile; local account metadata.",
    "security": "SECURITY hive triage profile; audit policy and privileges.",
}


class RegRipperPluginError(ValueError):
    """Raised when a requested plugin is not in the Tier 0 allow-list."""


class RegRipperProfileError(ValueError):
    """Raised when a requested profile is not in the Tier 0 allow-list."""


def _resolve_binary(name: str | None = None) -> Path:
    """
    Find the RegRipper binary on PATH.

    SIFT Workstation installs the Perl script as ``rip.pl``; some
    packaged builds also ship ``regripper`` or a ``rip`` wrapper. The
    Tier 0 wrapper honors an ``APTW_REGRIPPER_BIN`` override, then tries
    ``rip.pl``, ``regripper``, and ``rip`` so all layouts work. When
    ``name`` is supplied we probe that exact name only.
    """
    if name:
        candidates = [name]
    else:
        override = os.environ.get("APTW_REGRIPPER_BIN")
        candidates = [override] if override else ["rip.pl", "regripper", "rip"]
    for candidate in candidates:
        if candidate is None:
            continue
        found = shutil.which(candidate)
        if found:
            return Path(found)
    attempted = ", ".join(c for c in candidates if c)
    raise ToolRunError(
        f"RegRipper binary not found on PATH (tried: {attempted}). "
        "Preflight should have caught this.",
    )


def _assert_hive_is_file(hive: Path) -> None:
    """Hive must exist and be a regular file; reject directories / missing paths."""
    if not hive.exists():
        raise ToolRunError(f"Registry hive not found: {hive}")
    if not hive.is_file():
        raise ToolRunError(
            f"Registry hive path is not a regular file: {hive}. "
            "RegRipper operates on a single offline hive, not a directory.",
        )


def run_regripper_plugin(
    *,
    hive: Path,
    plugin: str,
    audit: AuditLogger | None = None,
    timeout: float = 300.0,
    regripper_binary: Path | None = None,
) -> ToolRunResult:
    """
    Run one RegRipper plugin against an offline registry hive.

    ``hive`` must exist and must be a regular file; it is treated as
    read-only. ``plugin`` must be a key in ``REGRIPPER_PLUGINS`` --
    anything else raises ``RegRipperPluginError`` before we fork.
    """
    if plugin not in REGRIPPER_PLUGINS:
        raise RegRipperPluginError(
            f"Plugin not in Tier 0 allow-list: {plugin!r}. "
            f"Supported: {', '.join(sorted(REGRIPPER_PLUGINS))}",
        )
    _assert_hive_is_file(hive)

    binary = regripper_binary or _resolve_binary()
    argv: list[str] = [str(binary), "-r", str(hive), "-p", plugin]

    return run_tool(
        argv,
        tool_name="regripper",
        audit=audit,
        timeout=timeout,
        extra_audit_payload={
            "mode": "plugin",
            "plugin": plugin,
            "plugin_reason": REGRIPPER_PLUGINS[plugin],
            "hive": str(hive),
            "evidence_readonly_assumed": True,
        },
    )


def run_regripper_profile(
    *,
    hive: Path,
    profile: str,
    audit: AuditLogger | None = None,
    timeout: float = 600.0,
    regripper_binary: Path | None = None,
) -> ToolRunResult:
    """
    Run a RegRipper hive profile against an offline registry hive.

    ``hive`` must exist and must be a regular file; it is treated as
    read-only. ``profile`` must be a key in ``REGRIPPER_PROFILES`` --
    anything else raises ``RegRipperProfileError`` before we fork.
    """
    if profile not in REGRIPPER_PROFILES:
        raise RegRipperProfileError(
            f"Profile not in Tier 0 allow-list: {profile!r}. "
            f"Supported: {', '.join(sorted(REGRIPPER_PROFILES))}",
        )
    _assert_hive_is_file(hive)

    binary = regripper_binary or _resolve_binary()
    argv: list[str] = [str(binary), "-r", str(hive), "-f", profile]

    return run_tool(
        argv,
        tool_name="regripper",
        audit=audit,
        timeout=timeout,
        extra_audit_payload={
            "mode": "profile",
            "profile": profile,
            "profile_reason": REGRIPPER_PROFILES[profile],
            "hive": str(hive),
            "evidence_readonly_assumed": True,
        },
    )


__all__ = [
    "REGRIPPER_PLUGINS",
    "REGRIPPER_PROFILES",
    "RegRipperPluginError",
    "RegRipperProfileError",
    "run_regripper_plugin",
    "run_regripper_profile",
]
