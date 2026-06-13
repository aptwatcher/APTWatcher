"""
Tier 0 -- sleuthkit wrapper.

The Sleuth Kit (TSK) is a classic filesystem-forensics toolbox. This
wrapper exposes four of its CLI tools that are useful during the
enumeration / triage phase of a Tier 0 run:

- `mmls`   -- list partitions in a disk image (find the right offset).
- `fsstat` -- print filesystem metadata (type, block size, mount info)
              for the partition at a given offset.
- `fls`    -- list files from a filesystem image; optionally recursive
              and/or rooted at a specific inode.
- `icat`   -- extract the contents of a file by inode, writing them to
              a caller-supplied `output_path`.

Design:

- Every tool treats the disk image as read-only. That assumption is
  emitted to the audit log (`evidence_readonly_assumed=True`).
- `offset`, when supplied, is validated to be non-negative. TSK uses
  the offset in sectors (`-o N`) to locate the target partition inside
  a whole-disk image; negative values would be meaningless.
- `icat` is the only tool here that produces extracted content rather
  than a text report. We route its output through `run_tool` (which
  captures stdout as text), then write the captured stdout to
  `output_path` via `surrogateescape` encoding. This preserves byte
  fidelity for most text-like streams but is NOT safe for arbitrary
  binary carving -- a future iteration should switch to a bytes-mode
  runner. The wrapper refuses to overwrite an existing `output_path`.

argv shapes:

    mmls   -B <image>
    fsstat [-o <offset>] <image>
    fls    [-o <offset>] [-r] <image> [inode]
    icat   [-o <offset>] <image> <inode>        # stdout -> output_path

References:
- docs/reference/sift-tools.md
- docs/design/tier0-sift-lifecycle.md
"""

from __future__ import annotations

import shutil
from pathlib import Path

from core.audit import AuditLogger
from core.sift.runner import ToolRunError, ToolRunResult, run_tool


def _resolve_binary(name: str) -> Path:
    """Find a sleuthkit binary by name. SIFT ships TSK on PATH."""
    found = shutil.which(name)
    if found:
        return Path(found)
    raise ToolRunError(
        f"{name} not found on PATH. Preflight should have caught this.",
    )


def _check_offset(offset: int | None) -> None:
    """Reject negative offsets. `None` means 'no -o flag'."""
    if offset is not None and offset < 0:
        raise ToolRunError(
            f"Offset must be non-negative, got {offset}.",
        )


def run_mmls(
    *,
    image: Path,
    audit: AuditLogger | None = None,
    timeout: float = 300.0,
    mmls_binary: Path | None = None,
) -> ToolRunResult:
    """
    List partitions in a disk image via `mmls -B <image>`.

    The `-B` flag asks mmls to print verbose block-unit information.
    `image` must exist; it is treated as read-only.
    """
    if not image.exists():
        raise ToolRunError(f"Image not found: {image}")

    binary = mmls_binary or _resolve_binary("mmls")
    argv: list[str] = [str(binary), "-B", str(image)]

    return run_tool(
        argv,
        tool_name="mmls",
        audit=audit,
        timeout=timeout,
        extra_audit_payload={
            "image": str(image),
            "evidence_readonly_assumed": True,
        },
    )


def run_fsstat(
    *,
    image: Path,
    offset: int | None = None,
    audit: AuditLogger | None = None,
    timeout: float = 300.0,
    fsstat_binary: Path | None = None,
) -> ToolRunResult:
    """
    Run `fsstat [-o <offset>] <image>` to print filesystem metadata.

    `image` must exist; it is treated as read-only. `offset`, if
    supplied, must be non-negative (sector offset into the disk image).
    """
    if not image.exists():
        raise ToolRunError(f"Image not found: {image}")
    _check_offset(offset)

    binary = fsstat_binary or _resolve_binary("fsstat")
    argv: list[str] = [str(binary)]
    if offset is not None:
        argv.extend(["-o", str(offset)])
    argv.append(str(image))

    return run_tool(
        argv,
        tool_name="fsstat",
        audit=audit,
        timeout=timeout,
        extra_audit_payload={
            "image": str(image),
            "offset": offset,
            "evidence_readonly_assumed": True,
        },
    )


def run_fls(
    *,
    image: Path,
    offset: int | None = None,
    inode: str | None = None,
    recursive: bool = False,
    audit: AuditLogger | None = None,
    timeout: float = 600.0,
    fls_binary: Path | None = None,
) -> ToolRunResult:
    """
    List files from a filesystem image via
    `fls [-o <offset>] [-r] <image> [inode]`.

    - `offset`: sector offset to the target partition (optional).
    - `recursive`: include `-r` to walk directories recursively.
    - `inode`: starting directory inode; omitted means the root.
    `image` must exist and is treated as read-only.
    """
    if not image.exists():
        raise ToolRunError(f"Image not found: {image}")
    _check_offset(offset)

    binary = fls_binary or _resolve_binary("fls")
    argv: list[str] = [str(binary)]
    if offset is not None:
        argv.extend(["-o", str(offset)])
    if recursive:
        argv.append("-r")
    argv.append(str(image))
    if inode is not None:
        argv.append(inode)

    return run_tool(
        argv,
        tool_name="fls",
        audit=audit,
        timeout=timeout,
        extra_audit_payload={
            "image": str(image),
            "offset": offset,
            "inode": inode,
            "recursive": recursive,
            "evidence_readonly_assumed": True,
        },
    )


def run_icat(
    *,
    image: Path,
    inode: str,
    output_path: Path,
    offset: int | None = None,
    audit: AuditLogger | None = None,
    timeout: float = 300.0,
    icat_binary: Path | None = None,
) -> ToolRunResult:
    """
    Extract a file by inode via `icat [-o <offset>] <image> <inode>`
    and write the captured stdout to `output_path`.

    Preconditions:
    - `image` must exist (read-only).
    - `output_path`'s parent directory must already exist.
    - `output_path` must NOT already exist; the wrapper refuses to
      overwrite.
    - `offset`, if provided, must be non-negative.

    NOTE ON BINARY FIDELITY: the shared `run_tool` captures stdout as
    text (`text=True`). We therefore re-encode the captured string with
    `errors="surrogateescape"` to round-trip bytes that are not valid
    UTF-8. This is acceptable for text carving and small artefacts but
    is NOT a general-purpose binary extraction path. A future iteration
    will add a bytes-mode runner for true binary fidelity.
    """
    if not image.exists():
        raise ToolRunError(f"Image not found: {image}")
    _check_offset(offset)
    if not output_path.parent.exists():
        raise ToolRunError(
            f"Output parent directory does not exist: {output_path.parent}",
        )
    if output_path.exists():
        raise ToolRunError(
            f"Output path already exists: {output_path}. "
            "Refusing to overwrite an existing icat extraction.",
        )

    binary = icat_binary or _resolve_binary("icat")
    argv: list[str] = [str(binary)]
    if offset is not None:
        argv.extend(["-o", str(offset)])
    argv.extend([str(image), inode])

    result = run_tool(
        argv,
        tool_name="icat",
        audit=audit,
        timeout=timeout,
        extra_audit_payload={
            "image": str(image),
            "offset": offset,
            "inode": inode,
            "output_path": str(output_path),
            "evidence_readonly_assumed": True,
        },
    )

    # Persist captured stdout to disk. See NOTE above about binary
    # fidelity limitations of the text-mode runner.
    output_path.write_bytes(
        result.stdout.encode("utf-8", errors="surrogateescape"),
    )

    return result


__all__ = [
    "ToolRunError",
    "run_fls",
    "run_fsstat",
    "run_icat",
    "run_mmls",
]
