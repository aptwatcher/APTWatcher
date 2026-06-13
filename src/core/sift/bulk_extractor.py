"""
Tier 0 -- bulk_extractor wrapper.

bulk_extractor is a stream-forensics tool: it scans an image (disk,
memory, file tree) for feature artefacts -- email addresses, URLs,
domains, IPs, credit-card numbers, EXIF tags, Windows prefetch / LNK
fragments, and so on -- without decoding the filesystem. That makes
it fast, deterministic, and cheap to rerun under self-correction.

Design:

- Scanner names are allow-listed. bulk_extractor ships many scanners;
  we only expose the ones we can defend as defensive-IR-relevant
  (IOC surfacing, not broad PII discovery). Scanners that surface
  payment data (`ccn`, `aes`) are deliberately NOT in the allow-list
  for Tier 0 -- they belong in a separate compliance tier.
- Output directory (`-o <outdir>`) must not already contain results.
  The wrapper refuses to overwrite a populated output dir and refuses
  to write under the evidence tree (policed at a higher layer; the
  wrapper records the declared path in the audit log so that layer
  can verify).
- Source is treated as read-only and that assumption is emitted to
  the audit log.

argv shape:

    bulk_extractor [-q] -E <scanner> [-E <scanner> ...] -o <outdir> <source>

We use `-E` (enable-only-this) rather than `-e` (add-to-defaults) so
that the invocation is deterministic: only the requested scanners
run, nothing else.

References:
- docs/reference/sift-tools.md
- docs/design/tier0-sift-lifecycle.md
"""

from __future__ import annotations

import shutil
from pathlib import Path

from core.audit import AuditLogger
from core.sift.runner import ToolRunError, ToolRunResult, run_tool

# Defensive-IR scanner allow-list. The key is the bulk_extractor
# scanner name (the `-E` argument value); the value is a short reason
# / coverage summary used in audit payloads and the MCP tool listing.
BULK_EXTRACTOR_SCANNERS: dict[str, str] = {
    "email": "RFC822 email addresses; correlates with phishing / account IOCs.",
    "url": "HTTP/HTTPS URLs; feeds beaconing and exfil investigation.",
    "domain": "Domain names (separate from url for higher recall).",
    "net": "IPv4 / IPv6 addresses extracted from any stream.",
    "exif": "EXIF metadata from embedded images (geolocation, device).",
    "winprefetch": "Windows Prefetch fragments (.pf) carved from the stream.",
    "winlnk": "Windows LNK shortcut fragments (target paths, UNC refs).",
    "httplogs": "HTTP request/response log lines carved from memory or disk.",
    "json": "JSON blobs; surfaces config and tooling artefacts.",
}


class BulkExtractorScannerError(ValueError):
    """Raised when a requested scanner is not in the allow-list."""


def _resolve_binary(name: str = "bulk_extractor") -> Path:
    """Find the bulk_extractor binary. SIFT ships it on PATH."""
    found = shutil.which(name)
    if found:
        return Path(found)
    raise ToolRunError(
        f"{name} not found on PATH. Preflight should have caught this.",
    )


def run_bulk_extractor(
    *,
    source: Path,
    output_dir: Path,
    scanners: list[str],
    audit: AuditLogger | None = None,
    timeout: float = 3600.0,
    bulk_extractor_binary: Path | None = None,
) -> ToolRunResult:
    """
    Run bulk_extractor against a source with a specific scanner set.

    `source` must exist; treated as read-only. `output_dir` must NOT
    already contain results (we refuse to overwrite any populated
    directory). `scanners` must be a non-empty list of names from
    `BULK_EXTRACTOR_SCANNERS`; anything else raises
    `BulkExtractorScannerError`.
    """
    if not scanners:
        raise BulkExtractorScannerError(
            "At least one scanner must be requested. "
            f"Supported: {', '.join(sorted(BULK_EXTRACTOR_SCANNERS))}",
        )
    unknown = [s for s in scanners if s not in BULK_EXTRACTOR_SCANNERS]
    if unknown:
        raise BulkExtractorScannerError(
            f"Scanners not in Tier 0 allow-list: {', '.join(unknown)}. "
            f"Supported: {', '.join(sorted(BULK_EXTRACTOR_SCANNERS))}",
        )
    if not source.exists():
        raise ToolRunError(f"Source not found: {source}")
    # Output dir must be either absent or empty. Anything else is an
    # overwrite, which the wrapper refuses.
    if output_dir.exists():
        if not output_dir.is_dir():
            raise ToolRunError(
                f"Output path exists and is not a directory: {output_dir}",
            )
        if any(output_dir.iterdir()):
            raise ToolRunError(
                f"Output directory is not empty: {output_dir}. "
                "Refusing to overwrite bulk_extractor results; "
                "pick a new output directory.",
            )

    binary = bulk_extractor_binary or _resolve_binary()
    argv: list[str] = [str(binary), "-q"]
    for scanner in scanners:
        argv.extend(["-E", scanner])
    argv.extend(["-o", str(output_dir), str(source)])

    return run_tool(
        argv,
        tool_name="bulk_extractor",
        audit=audit,
        timeout=timeout,
        extra_audit_payload={
            "scanners": scanners,
            "scanner_reasons": {s: BULK_EXTRACTOR_SCANNERS[s] for s in scanners},
            "source": str(source),
            "evidence_readonly_assumed": True,
            "output_dir": str(output_dir),
        },
    )


__all__ = [
    "BULK_EXTRACTOR_SCANNERS",
    "BulkExtractorScannerError",
    "run_bulk_extractor",
]
