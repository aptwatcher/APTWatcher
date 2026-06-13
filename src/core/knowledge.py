"""
Knowledge-base loader and search.

Reads every Markdown file under `knowledge/` (excluding `README.md`),
parses YAML front-matter per `knowledge/README.md`, and returns typed
`KBEntry` records. Search is intentionally simple (case-insensitive
keyword match with a small ranking heuristic); the agent's real grounding
comes from the returned content, not from search-layer cleverness.

References:
- knowledge/README.md (entry format + source_type enum)
- docs/reference/knowledge-index.md (target KB scope)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from core.types import KBEntry, SourceType

_FRONT_MATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n(.*)\Z", re.DOTALL)

# Allowed source_type values. Mirror of Literal in types.py; kept here so
# we can validate without a round-trip through pydantic.
_ALLOWED_SOURCE_TYPES: set[str] = {
    "author-original",
    "llm-synthesis",
    "mitre-attack",
    "nist",
    "public-blog-summary",
    "dfir-report-cc",
}


@dataclass(slots=True)
class KBLoadError(Exception):
    """Raised when a KB file's front-matter is malformed."""

    path: Path
    reason: str

    def __str__(self) -> str:  # pragma: no cover — trivial
        return f"{self.path}: {self.reason}"


def _parse_entry(path: Path, repo_root: Path) -> KBEntry:
    """Parse one Markdown file into a KBEntry. Raises on malformed entries."""
    text = path.read_text(encoding="utf-8")
    match = _FRONT_MATTER_RE.match(text)
    if match is None:
        raise KBLoadError(path=path, reason="missing YAML front-matter")

    raw_fm, body = match.group(1), match.group(2)
    try:
        fm = yaml.safe_load(raw_fm) or {}
    except yaml.YAMLError as exc:
        raise KBLoadError(path=path, reason=f"YAML parse error: {exc}") from exc

    if not isinstance(fm, dict):
        raise KBLoadError(path=path, reason="front-matter must be a mapping")

    source_type = fm.get("source_type")
    if source_type not in _ALLOWED_SOURCE_TYPES:
        raise KBLoadError(
            path=path,
            reason=f"invalid source_type: {source_type!r}",
        )

    for required in ("id", "title", "attribution", "last_updated"):
        if not fm.get(required):
            raise KBLoadError(path=path, reason=f"missing required field: {required}")

    try:
        repo_relative = str(path.relative_to(repo_root))
    except ValueError:
        repo_relative = str(path)

    return KBEntry(
        id=str(fm["id"]),
        title=str(fm["title"]),
        source_type=source_type,  # validated above
        attribution=str(fm["attribution"]),
        mitre_techniques=[str(t) for t in fm.get("mitre_techniques") or []],
        artifact_types=[str(a) for a in fm.get("artifact_types") or []],
        tools=[str(t) for t in fm.get("tools") or []],
        last_updated=str(fm["last_updated"]),
        body=body,
        path=repo_relative,
    )


class KnowledgeBase:
    """
    In-memory KB snapshot. Loaded eagerly on construction so the agent sees
    a stable index for the duration of a run. Rebuild by constructing a new
    `KnowledgeBase` — we do not mutate in place.
    """

    def __init__(self, root: Path | str, *, repo_root: Path | str | None = None) -> None:
        self.root = Path(root)
        self.repo_root = Path(repo_root) if repo_root is not None else self.root.parent
        self._entries: list[KBEntry] = []
        self._errors: list[KBLoadError] = []
        self._load()

    # ---- loading ----

    def _load(self) -> None:
        if not self.root.exists():
            return
        for md in sorted(self.root.rglob("*.md")):
            if md.name.lower() == "readme.md":
                continue
            try:
                self._entries.append(_parse_entry(md, self.repo_root))
            except KBLoadError as err:
                self._errors.append(err)

    # ---- inspection ----

    @property
    def entries(self) -> list[KBEntry]:
        return list(self._entries)

    @property
    def load_errors(self) -> list[KBLoadError]:
        return list(self._errors)

    def by_id(self, entry_id: str) -> KBEntry | None:
        return next((e for e in self._entries if e.id == entry_id), None)

    # ---- search ----

    def search(self, query: str, *, top_k: int = 5) -> list[KBEntry]:
        """
        Simple case-insensitive ranked keyword search.

        Ranking: +3 per query-token match in title, +2 per match in MITRE
        techniques / artifact types / tools, +1 per match in body. Ties
        break on entry id for determinism.
        """
        tokens = [t for t in re.split(r"\W+", query.lower()) if t]
        if not tokens or not self._entries:
            return []

        scored: list[tuple[int, str, KBEntry]] = []
        for entry in self._entries:
            title = entry.title.lower()
            body = entry.body.lower()
            meta = " ".join(
                [*entry.mitre_techniques, *entry.artifact_types, *entry.tools],
            ).lower()

            score = 0
            for tok in tokens:
                if tok in title:
                    score += 3
                if tok in meta:
                    score += 2
                if tok in body:
                    score += 1
            if score > 0:
                scored.append((score, entry.id, entry))

        scored.sort(key=lambda t: (-t[0], t[1]))
        return [e for _, _, e in scored[:top_k]]

    def filter_by_mitre(self, technique_id: str) -> list[KBEntry]:
        """All entries claiming coverage of a MITRE technique."""
        return [e for e in self._entries if technique_id in e.mitre_techniques]

    def filter_by_source_type(self, source_type: SourceType) -> list[KBEntry]:
        return [e for e in self._entries if e.source_type == source_type]


__all__ = ["KBLoadError", "KnowledgeBase"]
