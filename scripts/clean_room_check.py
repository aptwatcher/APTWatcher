#!/usr/bin/env python3
"""Clean-room forbidden-string gate for APTWatcher.

Enforces the policy documented in ``docs/POLICY.md``. Scans the scoped
content areas (KB entry bodies and judge-facing submission docs) for a
fixed list of forbidden strings that signal non-redistributable upstream
material. Skips declared carve-out paths.

Run standalone from the repository root::

    python3 scripts/clean_room_check.py

Exit codes:
    0 -- no violations.
    1 -- one or more violations. Each violation is printed as
         ``file:line: string`` on stderr before exit.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Forbidden strings. Matched case-sensitively against each line of
# scoped content. This list is the machine-readable mirror of the
# policy declaration in ``docs/POLICY.md`` and ``knowledge/README.md``.
FORBIDDEN: tuple[str, ...] = (
    "SANS",
    "GCIH",
    "GCFA",
    "FOR500",
    "FOR508",
    "NoStarch",
    "Syngress",
    "DFIR Report",
)

# Judge-facing submission docs. Paths are repo-relative.
SUBMISSION_DOCS: tuple[str, ...] = (
    "docs/DATASET.md",
    "docs/DEVPOST.md",
    "docs/TRY-IT-OUT.md",
)

# KB paths that are declared carve-outs and must be skipped during the
# KB body walk.
KB_CARVE_OUTS: frozenset[str] = frozenset({"README.md"})


def _repo_root() -> Path:
    """Return the repository root (parent of ``scripts/``)."""
    return Path(__file__).resolve().parent.parent


def _strip_frontmatter(text: str) -> tuple[str, int]:
    """Strip a leading YAML frontmatter block from ``text``.

    Returns a ``(body, offset)`` tuple where ``offset`` is the 1-based
    line number at which ``body`` begins in the original file. If no
    frontmatter is present, ``body`` equals ``text`` and ``offset`` is
    ``1``.
    """
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return text, 1
    for idx in range(1, len(lines)):
        if lines[idx].strip() == "---":
            body = "\n".join(lines[idx + 1:])
            return body, idx + 2
    # Unterminated frontmatter -- be conservative and scan the whole
    # file as body starting at line 1.
    return text, 1


def _scan_lines(
    body: str, line_offset: int, rel_path: str
) -> list[tuple[str, int, str]]:
    """Return a list of ``(rel_path, line_no, needle)`` violations."""
    hits: list[tuple[str, int, str]] = []
    for i, line in enumerate(body.splitlines()):
        for needle in FORBIDDEN:
            if needle in line:
                hits.append((rel_path, line_offset + i, needle))
    return hits


def main() -> int:
    root = _repo_root()
    violations: list[tuple[str, int, str]] = []

    # KB body walk: every ``knowledge/**/*.md`` except carve-outs, with
    # YAML frontmatter stripped before scanning.
    kb_root = root / "knowledge"
    kb_files_scanned = 0
    if kb_root.is_dir():
        for md in sorted(kb_root.rglob("*.md")):
            rel = md.relative_to(root).as_posix()
            # Carve-outs are matched by basename under ``knowledge/`` so
            # that nested READMEs (if any are added later) are also
            # treated as policy declarations rather than KB prose.
            if md.name in KB_CARVE_OUTS:
                continue
            text = md.read_text(encoding="utf-8")
            body, offset = _strip_frontmatter(text)
            violations.extend(_scan_lines(body, offset, rel))
            kb_files_scanned += 1

    # Submission docs walk: whole-file scan, no frontmatter stripping
    # (these are prose narratives, not KB entries).
    submission_scanned = 0
    for rel in SUBMISSION_DOCS:
        path = root / rel
        if not path.is_file():
            # A missing submission doc is itself a policy problem but
            # not the kind this gate enforces -- surface it and keep
            # going so the full violation picture is reported in one
            # pass.
            print(
                f"clean_room_check: warning: submission doc missing: {rel}",
                file=sys.stderr,
            )
            continue
        text = path.read_text(encoding="utf-8")
        violations.extend(_scan_lines(text, 1, rel))
        submission_scanned += 1

    if violations:
        for rel, line_no, needle in violations:
            print(f"{rel}:{line_no}: forbidden string {needle!r}", file=sys.stderr)
        print(
            f"clean_room_check: {len(violations)} violation(s) across "
            f"{kb_files_scanned} KB files + {submission_scanned} submission docs",
            file=sys.stderr,
        )
        return 1

    print(
        f"clean_room_check: 0 violations across {kb_files_scanned} KB files "
        f"+ {submission_scanned} submission docs"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
