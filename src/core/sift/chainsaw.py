"""
Tier 0 -- Chainsaw wrapper.

Chainsaw (WithSecure Labs) is a Windows EVTX hunting tool: like
Hayabusa, it ingests Windows event logs (``*.evtx``) and applies a
Sigma ruleset to surface suspicious activity. Unlike Hayabusa,
Chainsaw consumes Sigma rules directly (rather than a precompiled
internal ruleset) and requires an explicit field-mapping YAML to
translate Sigma's generic fields to the concrete EVTX channels.
That makes it complementary to Hayabusa: the same EVTX source can be
hunted with two independently maintained rulesets.

Chainsaw is read-only with respect to the evidence: it opens the
EVTX files, parses them, and writes results to a caller-supplied
output path. It never modifies the input.

Design:

- Subcommands are allow-listed (``CHAINSAW_SUBCOMMANDS``). Chainsaw
  ships many subcommands (``hunt``, ``search``, ``dump``, ``lint``,
  ``analyse``, ...); the Tier 0 wrapper only exposes:
    * ``hunt`` (wrapped via ``run_chainsaw_hunt``) -- Sigma detections
      against an EVTX source.
    * ``search`` (wrapped via ``run_chainsaw_search``) -- full-text
      search over EVTX records, useful for IOC pivots.
- Output format is restricted to ``json`` or ``csv`` via
  ``CHAINSAW_OUTPUT_FORMATS``. The default is ``json`` for agent
  consumption.
- Evidence is treated as read-only. ``evidence_readonly_assumed=True``
  is emitted to the audit log so any downstream reviewer can verify
  the assumption at the wrapper boundary.
- Output paths must not already exist with content. For directory
  outputs we allow an empty directory (matching the bulk_extractor
  rule); for file outputs we refuse if the file exists with non-zero
  size.
- ``search_term`` is restricted to a conservative character set
  (``[A-Za-z0-9_\\-.\\s]+``) to keep the argv composable and avoid
  accidental shell-metacharacter smuggling. Callers that need richer
  patterns must wrap at a higher layer.

argv shape:

    chainsaw hunt <evtx_source> -s <sigma_rules_dir>
             --mapping <mapping.yml>
             -o <output_path>
             --<output_format>

    chainsaw search <evtx_source> <search_term>
             -o <output_path>
             --<output_format>

``evtx_source`` can be a single ``.evtx`` file or a directory of
``.evtx`` files; Chainsaw handles both with the same positional arg.

References:
- docs/reference/sift-tools.md
- docs/design/tier0-sift-lifecycle.md
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

from core.audit import AuditLogger
from core.sift.runner import ToolRunError, ToolRunResult, run_tool

# Tier 0 Chainsaw subcommand allow-list. Key is the subcommand string
# passed as argv[1]; value is a short reason used in docs and audit.
CHAINSAW_SUBCOMMANDS: dict[str, str] = {
    "hunt": "Run a Sigma rule set against an EVTX source.",
    "search": "Full-text search over EVTX records.",
}

# Tier 0 Chainsaw output-format allow-list. Key is the caller-facing
# ``output_format`` value; the wrapper maps each to the appropriate
# Chainsaw CLI flag (``--json`` / ``--csv``).
CHAINSAW_OUTPUT_FORMATS: dict[str, str] = {
    "json": "Machine-readable JSON array. Default for agent consumption.",
    "csv": "CSV for analyst review.",
}

# Permissive-but-safe character class for free-text EVTX search terms.
# Refuses shell metacharacters, quotes, pipes, semicolons, and
# redirection operators so a caller cannot accidentally smuggle
# argv-breaking content through this parameter.
_SEARCH_TERM_RE = re.compile(r"^[A-Za-z0-9_\-\.\s]+$")


class ChainsawSubcommandError(ValueError):
    """Raised when a requested subcommand is not in the allow-list."""


class ChainsawOutputFormatError(ValueError):
    """Raised when a requested output format is not in the allow-list."""


class ChainsawSearchError(ValueError):
    """Raised when a search term fails the conservative safety check."""


def _resolve_binary(name: str = "chainsaw") -> Path:
    """Find the chainsaw binary. SIFT ships it on PATH."""
    found = shutil.which(name)
    if found:
        return Path(found)
    raise ToolRunError(
        f"{name} not found on PATH. Preflight should have caught this.",
    )


def _validate_output_format(output_format: str) -> str:
    if output_format not in CHAINSAW_OUTPUT_FORMATS:
        raise ChainsawOutputFormatError(
            f"Unsupported output_format: {output_format!r}. "
            f"Supported: {', '.join(sorted(CHAINSAW_OUTPUT_FORMATS))}",
        )
    return output_format


def _validate_output_path(output_path: Path) -> None:
    """
    Refuse to clobber a prior run.

    - If ``output_path`` exists and is a regular file with non-zero size,
      refuse.
    - If ``output_path`` exists and is a directory, require it to be
      empty (matches bulk_extractor's policy).
    - If ``output_path`` does not exist, the parent directory must.
    """
    if output_path.exists():
        if output_path.is_dir():
            if any(output_path.iterdir()):
                raise ToolRunError(
                    f"Output directory is not empty: {output_path}. "
                    "Refusing to overwrite Chainsaw results; "
                    "pick a new output path.",
                )
            return
        if output_path.is_file():
            if output_path.stat().st_size > 0:
                raise ToolRunError(
                    f"Output path already exists and is non-empty: {output_path}. "
                    "Refusing to overwrite Chainsaw results; "
                    "pick a new output path.",
                )
            return
        raise ToolRunError(
            f"Output path exists and is neither file nor directory: {output_path}",
        )
    if not output_path.parent.exists():
        raise ToolRunError(
            f"Output parent directory does not exist: {output_path.parent}",
        )


def _validate_search_term(search_term: str) -> str:
    if not search_term or not search_term.strip():
        raise ChainsawSearchError("search_term must be a non-empty string.")
    if not _SEARCH_TERM_RE.match(search_term):
        raise ChainsawSearchError(
            "search_term contains characters outside the safe set "
            "[A-Za-z0-9_\\-.\\s]. Shell metacharacters are rejected by policy.",
        )
    return search_term


def run_chainsaw_hunt(
    *,
    evtx_source: Path,
    sigma_rules_dir: Path,
    mapping: Path,
    output_path: Path,
    output_format: str = "json",
    audit: AuditLogger | None = None,
    timeout: float = 3600.0,
    chainsaw_binary: Path | None = None,
) -> ToolRunResult:
    """
    Run ``chainsaw hunt`` against an EVTX source with a Sigma ruleset.

    ``evtx_source`` is either a directory of ``*.evtx`` files or a
    single ``*.evtx`` file; both must exist. The source is treated as
    read-only. ``sigma_rules_dir`` must exist and be a directory.
    ``mapping`` must exist and be a regular file. ``output_path`` must
    not already hold content (empty directories are allowed).
    ``output_format`` must be one of ``CHAINSAW_OUTPUT_FORMATS``.
    """
    fmt = _validate_output_format(output_format)
    if not evtx_source.exists():
        raise ToolRunError(f"EVTX source not found: {evtx_source}")
    if not sigma_rules_dir.exists() or not sigma_rules_dir.is_dir():
        raise ToolRunError(
            f"Sigma rules directory not found or not a directory: {sigma_rules_dir}",
        )
    if not mapping.exists() or not mapping.is_file():
        raise ToolRunError(f"Chainsaw mapping file not found: {mapping}")
    _validate_output_path(output_path)

    binary = chainsaw_binary or _resolve_binary()
    argv: list[str] = [
        str(binary),
        "hunt",
        str(evtx_source),
        "-s",
        str(sigma_rules_dir),
        "--mapping",
        str(mapping),
        "-o",
        str(output_path),
        f"--{fmt}",
    ]

    return run_tool(
        argv,
        tool_name="chainsaw",
        audit=audit,
        timeout=timeout,
        extra_audit_payload={
            "subcommand": "hunt",
            "evtx_source": str(evtx_source),
            "evidence_readonly_assumed": True,
            "output_format": fmt,
            "output_path": str(output_path),
            "sigma_rules_dir": str(sigma_rules_dir),
            "mapping": str(mapping),
        },
    )


def run_chainsaw_search(
    *,
    evtx_source: Path,
    search_term: str,
    output_path: Path,
    output_format: str = "json",
    audit: AuditLogger | None = None,
    timeout: float = 1800.0,
    chainsaw_binary: Path | None = None,
) -> ToolRunResult:
    """
    Run ``chainsaw search`` against an EVTX source with a free-text term.

    ``evtx_source`` is either a directory of ``*.evtx`` files or a
    single ``*.evtx`` file; both must exist. The source is treated as
    read-only. ``search_term`` must be non-empty and match the safe
    character set ``[A-Za-z0-9_\\-.\\s]+``. ``output_path`` must not
    already hold content. ``output_format`` must be one of
    ``CHAINSAW_OUTPUT_FORMATS``.
    """
    fmt = _validate_output_format(output_format)
    term = _validate_search_term(search_term)
    if not evtx_source.exists():
        raise ToolRunError(f"EVTX source not found: {evtx_source}")
    _validate_output_path(output_path)

    binary = chainsaw_binary or _resolve_binary()
    argv: list[str] = [
        str(binary),
        "search",
        str(evtx_source),
        term,
        "-o",
        str(output_path),
        f"--{fmt}",
    ]

    return run_tool(
        argv,
        tool_name="chainsaw",
        audit=audit,
        timeout=timeout,
        extra_audit_payload={
            "subcommand": "search",
            "evtx_source": str(evtx_source),
            "evidence_readonly_assumed": True,
            "output_format": fmt,
            "output_path": str(output_path),
            "search_term": term,
        },
    )


__all__ = [
    "CHAINSAW_OUTPUT_FORMATS",
    "CHAINSAW_SUBCOMMANDS",
    "ChainsawOutputFormatError",
    "ChainsawSearchError",
    "ChainsawSubcommandError",
    "run_chainsaw_hunt",
    "run_chainsaw_search",
]
