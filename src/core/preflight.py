"""
Tier 0 preflight probe.

Walks the declared profile's required/optional tool list, resolves each
tool against PATH, extracts its version, and compares against minimums
declared in `_MIN_VERSIONS`. Produces a `PreflightReport` the agent reads
before accepting any triage task.

References:
- docs/design/tier0-sift-lifecycle.md
- docs/reference/sift-tools.md
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess  # nosec: B404 — we invoke known tools with explicit argv
from collections.abc import Callable
from pathlib import Path
from typing import Literal

from core.profiles import get_profile
from core.types import EvidenceFile, PreflightReport, ToolVersion

# Minimum versions per docs/reference/sift-tools.md. Version strings are
# compared lexicographically after normalization in `_version_meets_minimum`.
_MIN_VERSIONS: dict[str, str] = {
    "volatility3": "2.4",
    "log2timeline.py": "20240504",
    "psort.py": "20240504",
    "bulk_extractor": "2.0",
    "yara": "4.3",
    "RegRipper": "4.0",
    "evtx_dump": "0.8",
    "chkrootkit": "0.58",
    "chainsaw": "2.8",
    "hayabusa": "2.17",
    "zeek": "6.0",
    "tshark": "4.0",
    "suricata": "7.0",
    "rita": "5.0",
    "jq": "1.6",
}

# Known argv invocations for version extraction. Each callable returns
# the version string (or None if not parseable).
_VersionExtractor = Callable[[Path], str | None]


def _run_for_version(cmd: list[str], timeout: float = 5.0) -> str | None:
    """Run a version command and return stdout+stderr as a single string."""
    try:
        proc = subprocess.run(  # nosec: B603 — argv is built from allow-list
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return (proc.stdout or "") + "\n" + (proc.stderr or "")


def _default_extractor(path: Path) -> str | None:
    """Try `--version`, then `-V`, then `-v`. First match wins."""
    for flag in ("--version", "-V", "-v"):
        out = _run_for_version([str(path), flag])
        if out is None:
            continue
        # Typical patterns: "tool 1.2.3", "tool version 1.2.3", "v1.2.3"
        match = re.search(r"v?(\d+(?:\.\d+){0,3})", out)
        if match:
            return match.group(1)
    return None


def _version_meets_minimum(got: str | None, minimum: str) -> bool:
    """Loose numeric-component comparison. None = we couldn't read it."""
    if got is None:
        return True  # present but unparseable; don't fail preflight on a parse miss
    got_parts = [int(p) for p in re.findall(r"\d+", got)]
    min_parts = [int(p) for p in re.findall(r"\d+", minimum)]
    # Pad to equal length
    width = max(len(got_parts), len(min_parts))
    got_parts += [0] * (width - len(got_parts))
    min_parts += [0] * (width - len(min_parts))
    return got_parts >= min_parts


# Canonical profile tool name -> ordered executable candidates to resolve on
# PATH. This bridges the gap between the name a profile declares and the name
# the SIFT Workstation actually installs: RegRipper ships as `rip.pl`, and
# Volatility 3 lives in a venv at /opt/volatility3/bin/vol. Ambiguous names are
# deliberately excluded — a bare `vol` on SIFT is Volatility 2 and must never
# satisfy a `volatility3` probe (see CLAUDE.md, tool-invocation contract).
_TOOL_ALIASES: dict[str, tuple[str, ...]] = {
    "volatility3": ("volatility3", "vol3", "vol.py", "/opt/volatility3/bin/vol"),
    "RegRipper": ("RegRipper", "rip.pl", "regripper", "rip"),
}


def _env_override(name: str) -> str | None:
    """An explicit operator override via `APTW_<NAME>_BIN` (path or PATH name)."""
    key = "APTW_" + re.sub(r"[^A-Za-z0-9]", "_", name).upper() + "_BIN"
    return os.environ.get(key)


def _resolve_tool_path(name: str) -> Path | None:
    """Resolve a canonical tool name to an executable path, or None.

    Order: an `APTW_<NAME>_BIN` override, then the tool's alias candidates,
    then the canonical name itself. `shutil.which` handles both bare names
    (PATH search) and absolute paths (executable check).
    """
    override = _env_override(name)
    candidates: tuple[str, ...] = (
        (override,) if override else _TOOL_ALIASES.get(name, (name,))
    )
    for candidate in candidates:
        if not candidate:
            continue
        found = shutil.which(candidate)
        if found:
            return Path(found)
    return None


def probe_tool(name: str) -> ToolVersion | None:
    """Locate one tool and extract its version. None if not found.

    Resolution honors an `APTW_<NAME>_BIN` env override and the SIFT alias
    table (`_TOOL_ALIASES`) before falling back to the canonical name.
    """
    resolved = _resolve_tool_path(name)
    if resolved is None:
        return None
    version = _default_extractor(resolved)
    minimum = _MIN_VERSIONS.get(name)
    meets_min = True if minimum is None else _version_meets_minimum(version, minimum)
    return ToolVersion(
        name=name,
        version=version,
        path=str(resolved),
        meets_minimum=meets_min,
    )


def hash_evidence_file(path: Path, *, chunk_size: int = 1 << 20) -> str:
    """SHA-256 of an evidence file. Chunked so multi-GB images don't OOM."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def build_evidence_manifest(paths: list[Path]) -> list[EvidenceFile]:
    """
    Hash and classify every provided evidence path. Classification is naive
    (by extension / filename heuristics); callers can override by passing
    pre-built `EvidenceFile` records in instead.
    """
    manifest: list[EvidenceFile] = []
    for p in paths:
        if not p.exists() or not p.is_file():
            raise FileNotFoundError(f"Evidence file not found: {p}")
        kind = _classify_evidence(p)
        manifest.append(
            EvidenceFile(
                path=str(p),
                sha256=hash_evidence_file(p),
                size_bytes=p.stat().st_size,
                kind=kind,
            ),
        )
    return manifest


def _classify_evidence(
    p: Path,
) -> Literal["disk_image", "memory_image", "triage_bundle", "pcap", "log_bundle", "other"]:
    """Heuristic evidence-file classification."""
    suffix = p.suffix.lower()
    name = p.name.lower()
    if suffix in {".e01", ".aff4", ".dd", ".raw", ".img"} and ("mem" in name or "memory" in name):
        return "memory_image"
    if suffix in {".e01", ".aff4", ".dd", ".img"}:
        return "disk_image"
    if suffix in {".vmem", ".lime"}:
        return "memory_image"
    if suffix in {".pcap", ".pcapng"}:
        return "pcap"
    if suffix in {".zip", ".tar", ".tgz", ".gz"} and "triage" in name:
        return "triage_bundle"
    if suffix in {".evtx", ".log"} or "log" in name:
        return "log_bundle"
    return "other"


def preflight(
    profile_name: str,
    *,
    evidence_paths: list[Path] | None = None,
    tier_config: dict[str, bool] | None = None,
) -> PreflightReport:
    """
    Produce a `PreflightReport` for a given profile.

    This is a pure probe — it does NOT run the triage, does NOT modify any
    evidence, and does NOT require elevated privileges. Caller is
    responsible for persisting the returned report to the audit log.
    """
    profile = get_profile(profile_name)
    inventory: list[ToolVersion] = []
    missing_required: list[str] = []
    missing_optional: list[str] = []
    warnings: list[str] = []

    for tool in profile.required_tools:
        probed = probe_tool(tool)
        if probed is None:
            missing_required.append(tool)
        else:
            inventory.append(probed)
            if not probed.meets_minimum:
                warnings.append(
                    f"{tool}: version {probed.version} below minimum {_MIN_VERSIONS.get(tool, '?')}",
                )

    for tool in profile.optional_tools:
        probed = probe_tool(tool)
        if probed is None:
            missing_optional.append(tool)
        else:
            inventory.append(probed)

    manifest = build_evidence_manifest(evidence_paths) if evidence_paths else []

    return PreflightReport(
        profile=profile.name,
        tool_inventory=inventory,
        missing_required=missing_required,
        missing_optional=missing_optional,
        evidence_manifest=manifest,
        tier_config=tier_config or {"tier_0": True},
        warnings=warnings,
        ok=not missing_required,
    )


__all__ = [
    "build_evidence_manifest",
    "hash_evidence_file",
    "preflight",
    "probe_tool",
]
