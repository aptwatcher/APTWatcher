"""
Tier 0 -- YARA scan wrapper.

YARA is a signature-matching tool: given a ruleset (a text file of
`rule` declarations or a compiled `.yarc`), it scans a target file,
directory, or memory dump and emits one line per match on stdout in
the canonical form::

    <rule> <path>

Optional prefixes extend this: `-g` prepends `[tag1,tag2]` tags, and
`-m` prepends `[key=value,...]` meta fields. `-s` additionally prints
matching strings inline. YARA itself is strictly read-only with
respect to the target -- no file writes, no timestamp touches, no
metadata changes -- so we always record `evidence_readonly_assumed=True`
in the audit log.

Policy:

- The wrapper is deliberately thin. It does not embed a rule allow-list
  the way bulk_extractor / volatility3 do, because YARA rulesets are
  themselves the unit of review. Instead, a higher layer is expected to
  allow-list which directories can host rulesets (the `rules_root`
  must live inside a configured "rulesets" tree). This wrapper enforces
  only that `rules_path` exists, is a regular file, and is non-empty;
  compiled rules (`.yarc`) are acceptable.
- Target path must exist (file or directory). Recursion into a directory
  is gated by `recursive=True` so an operator cannot accidentally walk a
  whole disk.
- `print_strings` defaults to False. Matched strings can balloon audit
  payload sizes and leak secrets into the log; the caller opts in.

argv shape::

    yara [-s] [-m] [-g] [-f] [-r] [-a <timeout_per_rule>]
         <rules_path> <target>

References:
- docs/reference/sift-tools.md
- docs/design/tier0-sift-lifecycle.md
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Any

from core.audit import AuditLogger
from core.sift.runner import ToolRunError, ToolRunResult, run_tool


class YaraScanError(ValueError):
    """Raised for YARA wrapper policy errors."""


def _resolve_binary(name: str = "yara") -> Path:
    """Find the yara binary. SIFT ships it on PATH."""
    found = shutil.which(name)
    if found:
        return Path(found)
    raise ToolRunError(
        f"{name} not found on PATH. Preflight should have caught this.",
    )


def run_yara_scan(
    *,
    rules_path: Path,
    target: Path,
    recursive: bool = False,
    print_meta: bool = True,
    print_tags: bool = True,
    print_strings: bool = False,  # off by default to keep audit payloads small
    timeout_per_rule: int | None = None,
    fast_mode: bool = True,
    audit: AuditLogger | None = None,
    timeout: float = 1800.0,
    yara_binary: Path | None = None,
) -> ToolRunResult:
    """
    Run `yara` with a ruleset against a file or directory target.

    `rules_path` must exist and be a regular file (`.yar`, `.yara`, or
    compiled `.yarc`) with non-zero size. `target` must exist -- a file
    or directory -- and is treated as read-only. Pass `recursive=True`
    to descend into a directory target.

    Defaults favour small, reviewable output: `print_meta` and
    `print_tags` on, `print_strings` off, `fast_mode` on.
    """
    if not rules_path.exists() or not rules_path.is_file():
        raise ToolRunError(f"YARA rules file not found: {rules_path}")
    if rules_path.stat().st_size == 0:
        raise ToolRunError(f"YARA rules file is empty: {rules_path}")
    if not target.exists():
        raise ToolRunError(f"YARA target not found: {target}")

    binary = yara_binary or _resolve_binary()
    argv: list[str] = [str(binary)]
    if print_strings:
        argv.append("-s")
    if print_meta:
        argv.append("-m")
    if print_tags:
        argv.append("-g")
    if fast_mode:
        argv.append("-f")
    if recursive:
        argv.append("-r")
    if timeout_per_rule is not None:
        argv.extend(["-a", str(timeout_per_rule)])
    argv.extend([str(rules_path), str(target)])

    return run_tool(
        argv,
        tool_name="yara",
        audit=audit,
        timeout=timeout,
        extra_audit_payload={
            "rules_path": str(rules_path),
            "target": str(target),
            "recursive": recursive,
            "fast_mode": fast_mode,
            "print_strings": print_strings,
            "print_meta": print_meta,
            "print_tags": print_tags,
            "timeout_per_rule": timeout_per_rule,
            "evidence_readonly_assumed": True,
        },
    )


# ---------------------------------------------------------------------------
# stdout parser
# ---------------------------------------------------------------------------

# Bracketed segments look like `[a,b,c]` or `[k=v,k2=v2]`. A meta segment
# is recognised by the presence of `=` inside the brackets; anything else
# is treated as a tag segment.
_BRACKET_RE = re.compile(r"^\[([^\]]*)\]$")


def _parse_bracket_segment(segment: str) -> tuple[list[str] | None, dict[str, str] | None]:
    """
    Classify a `[...]` segment as tags, meta, or neither.

    Returns `(tags, meta)`; at most one is non-None.
    """
    m = _BRACKET_RE.match(segment)
    if not m:
        return None, None
    inner = m.group(1).strip()
    if not inner:
        return [], None
    parts = [p.strip() for p in inner.split(",") if p.strip()]
    if all("=" in p for p in parts):
        meta: dict[str, str] = {}
        for p in parts:
            k, _, v = p.partition("=")
            meta[k.strip()] = v.strip()
        return None, meta
    return parts, None


def parse_yara_output(stdout: str) -> list[dict[str, Any]]:
    """
    Parse `yara` stdout into a list of match dicts.

    Each non-blank, non-error line is expected to conform to one of::

        RULENAME /path/to/file
        [tag1,tag2] RULENAME /path/to/file
        [k=v,k2=v2] RULENAME /path/to/file
        [tag1,tag2] [k=v,k2=v2] RULENAME /path/to/file
        k=v,k2=v2 RULENAME /path/to/file

    Blank lines and lines starting with `warning:` or `error:` are
    ignored. Unparseable lines are also skipped rather than raising --
    this is a best-effort reporter, not a validator.
    """
    if not stdout:
        return []

    results: list[dict[str, Any]] = []
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        lowered = line.lower()
        if lowered.startswith("warning:") or lowered.startswith("error:"):
            continue

        tags: list[str] | None = None
        meta: dict[str, str] | None = None
        remainder = line

        # Consume leading `[...]` segments (tags / meta bracket form).
        while remainder.startswith("["):
            close = remainder.find("]")
            if close == -1:
                break
            segment = remainder[: close + 1]
            maybe_tags, maybe_meta = _parse_bracket_segment(segment)
            if maybe_tags is None and maybe_meta is None:
                break
            if maybe_tags is not None and tags is None:
                tags = maybe_tags
            if maybe_meta is not None and meta is None:
                meta = maybe_meta
            remainder = remainder[close + 1 :].lstrip()

        # Unbracketed meta form: `k=v,k2=v2 RULENAME /path`.
        # Detect when the first whitespace-delimited token contains `=`.
        if meta is None and remainder:
            head, sep, rest = remainder.partition(" ")
            if sep and "=" in head and "/" not in head:
                parts = [p for p in head.split(",") if p]
                if parts and all("=" in p for p in parts):
                    meta = {}
                    for p in parts:
                        k, _, v = p.partition("=")
                        meta[k.strip()] = v.strip()
                    remainder = rest.lstrip()

        # What's left must be `<rule> <path>`.
        rule, sep, path = remainder.partition(" ")
        if not sep or not rule or not path:
            continue
        entry: dict[str, Any] = {"rule": rule, "path": path.strip()}
        if tags is not None:
            entry["tags"] = tags
        if meta is not None:
            entry["meta"] = meta
        results.append(entry)

    return results


__all__ = [
    "YaraScanError",
    "parse_yara_output",
    "run_yara_scan",
]
