"""
Tier 0 -- SIFT package update wrapper (user-consent gated).

SIFT ships with a defined forensic toolchain (plaso, volatility3,
yara, bulk_extractor, sleuthkit, ...). Preflight can discover that
one of these is stale or missing. This wrapper lets the agent
request an update, but ONLY after the caller supplies a non-empty
consent token. The token is recorded to the audit log as a
`sift_update_consent` event before the apt-get invocation, so that
any downstream reviewer can verify consent was obtained.

Safety rails:

- Package set is allow-listed. We do NOT upgrade arbitrary packages
  -- that is a system-administration action, not a forensic tooling
  refresh.
- Default mode is `dry_run=True` -> `apt-get install --only-upgrade -s`
  (simulate). The caller must set `dry_run=False` explicitly to mutate
  the VM.
- The wrapper refuses when `consent_token` is empty or whitespace.
  A richer production deployment can verify the token against a
  previously emitted consent event; the MVP just records it.
- argv uses `install --only-upgrade`, not `upgrade`, so it only
  touches packages already installed. It will not pull in new
  dependencies or remove anything.

References:
- docs/reference/sift-tools.md
- docs/design/tier0-sift-lifecycle.md
"""

from __future__ import annotations

import shutil
from pathlib import Path

from core.audit import AuditLogger
from core.sift.runner import ToolRunError, ToolRunResult, run_tool

# Allow-listed forensic packages. Key = Debian package name as
# shipped on SIFT (Ubuntu 22.04 base at time of writing); value =
# short human-readable reason used in audit payloads and MCP
# tool listings.
SIFT_UPDATE_PACKAGES: dict[str, str] = {
    "python3-plaso": "plaso timeline toolkit (log2timeline + psort).",
    "python3-volatility3": "volatility3 memory forensics framework.",
    "yara": "YARA pattern scanner for carving and IOC matching.",
    "bulk-extractor": "bulk_extractor stream-forensics scanner.",
    "sleuthkit": "The Sleuth Kit (fls, mmls, icat, ...).",
    "plaso-tools": "plaso auxiliary CLI tools (pinfo, psteal).",
}


class SiftUpdateConsentError(PermissionError):
    """Raised when sift_update is invoked without a valid consent token."""


class SiftUpdatePackageError(ValueError):
    """Raised when a requested package is not in the allow-list."""


def _resolve_binary(name: str = "apt-get") -> Path:
    """Find apt-get. Present on every Debian/Ubuntu-derived SIFT image."""
    found = shutil.which(name)
    if found:
        return Path(found)
    raise ToolRunError(
        f"{name} not found on PATH. SIFT requires apt-get for updates.",
    )


def run_sift_update(
    *,
    consent_token: str,
    packages: list[str] | None = None,
    audit: AuditLogger | None = None,
    timeout: float = 1800.0,
    apt_get_binary: Path | None = None,
    use_sudo: bool = True,
    dry_run: bool = True,
) -> ToolRunResult:
    """
    Update the SIFT forensic toolchain, after consent, within an allow-list.

    `consent_token` must be a non-empty, non-whitespace string. It is
    emitted to the audit log as a `sift_update_consent` event BEFORE
    the apt-get invocation.

    `packages` defaults to the full allow-list. If the caller passes a
    subset, every entry must be in `SIFT_UPDATE_PACKAGES`; anything
    else raises `SiftUpdatePackageError`.

    `dry_run=True` (the default) emits `-s` (simulate) so the SIFT
    image is untouched. A real upgrade requires an explicit
    `dry_run=False`.
    """
    if not consent_token or not consent_token.strip():
        raise SiftUpdateConsentError(
            "sift_update requires a non-empty consent_token. "
            "The caller must explicitly acknowledge that this "
            "action mutates the SIFT VM's forensic toolchain.",
        )

    if packages is None:
        requested = sorted(SIFT_UPDATE_PACKAGES)
    else:
        requested = list(packages)
        if not requested:
            raise SiftUpdatePackageError(
                "Package list was provided but is empty. "
                "Pass None to request the full allow-list, or supply "
                "at least one package. "
                f"Supported: {', '.join(sorted(SIFT_UPDATE_PACKAGES))}",
            )
    unknown = [p for p in requested if p not in SIFT_UPDATE_PACKAGES]
    if unknown:
        raise SiftUpdatePackageError(
            f"Packages not in SIFT update allow-list: {', '.join(unknown)}. "
            f"Supported: {', '.join(sorted(SIFT_UPDATE_PACKAGES))}",
        )

    if audit is not None:
        audit.append(
            event_type="sift_update_consent",
            payload={
                "consent_token_present": True,
                "consent_token_length": len(consent_token),
                "packages": requested,
                "dry_run": dry_run,
            },
        )

    binary = apt_get_binary or _resolve_binary()
    argv: list[str] = []
    if use_sudo:
        sudo = shutil.which("sudo") or "/usr/bin/sudo"
        argv.append(sudo)
    argv.extend([str(binary), "install", "--only-upgrade", "-y"])
    if dry_run:
        argv.append("-s")  # simulate
    argv.extend(requested)

    return run_tool(
        argv,
        tool_name="sift_update",
        audit=audit,
        timeout=timeout,
        extra_audit_payload={
            "packages": requested,
            "package_reasons": {p: SIFT_UPDATE_PACKAGES[p] for p in requested},
            "dry_run": dry_run,
            "use_sudo": use_sudo,
            "mutates_sift_vm": not dry_run,
        },
    )


__all__ = [
    "SIFT_UPDATE_PACKAGES",
    "SiftUpdateConsentError",
    "SiftUpdatePackageError",
    "run_sift_update",
]
