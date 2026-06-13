"""
Tests for core.knowledge.KnowledgeBase.

Uses the tmp_kb_root fixture to populate a tiny KB on disk, then exercises
front-matter parsing, search ranking, and filter helpers.
"""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from core.knowledge import KnowledgeBase


def _write_entry(
    root: Path,
    filename: str,
    *,
    entry_id: str,
    title: str,
    source_type: str = "author-original",
    attribution: str = "APTWatcher",
    mitre: list[str] | None = None,
    artifact_types: list[str] | None = None,
    tools: list[str] | None = None,
    body: str = "placeholder body",
    last_updated: str = "2026-04-19",
) -> Path:
    fm_lines = [
        "---",
        f"id: {entry_id}",
        f'title: "{title}"',
        f"source_type: {source_type}",
        f'attribution: "{attribution}"',
        f"mitre_techniques: {mitre or []}",
        f"artifact_types: {artifact_types or []}",
        f"tools: {tools or []}",
        f"last_updated: {last_updated}",
        "---",
    ]
    content = "\n".join(fm_lines) + "\n" + body + "\n"
    path = root / filename
    path.write_text(content, encoding="utf-8")
    return path


def test_empty_kb_returns_no_entries(tmp_kb_root: Path) -> None:
    kb = KnowledgeBase(tmp_kb_root)
    assert kb.entries == []
    assert kb.search("anything") == []


def test_loads_valid_entry(tmp_kb_root: Path) -> None:
    _write_entry(
        tmp_kb_root,
        "dcsync.md",
        entry_id="kb-001",
        title="DCSync — T1003.006",
        mitre=["T1003.006"],
        tools=["volatility3"],
        body="DCSync happens when a non-DC account replicates secrets.",
    )
    kb = KnowledgeBase(tmp_kb_root)
    assert len(kb.entries) == 1
    entry = kb.entries[0]
    assert entry.id == "kb-001"
    assert entry.mitre_techniques == ["T1003.006"]
    assert entry.body.startswith("DCSync happens")


def test_malformed_entry_is_recorded_as_load_error(tmp_kb_root: Path) -> None:
    (tmp_kb_root / "bad.md").write_text("no front-matter here\n", encoding="utf-8")
    kb = KnowledgeBase(tmp_kb_root)
    assert kb.entries == []
    assert len(kb.load_errors) == 1


def test_invalid_source_type_rejected(tmp_kb_root: Path) -> None:
    _write_entry(
        tmp_kb_root,
        "weird.md",
        entry_id="kb-002",
        title="X",
        source_type="something-made-up",
    )
    kb = KnowledgeBase(tmp_kb_root)
    assert kb.entries == []
    assert any("invalid source_type" in str(err.reason) for err in kb.load_errors)


def test_search_ranks_title_highest(tmp_kb_root: Path) -> None:
    _write_entry(
        tmp_kb_root,
        "a.md",
        entry_id="a",
        title="Kerberoast basics",
        body="unrelated body",
    )
    _write_entry(
        tmp_kb_root,
        "b.md",
        entry_id="b",
        title="Unrelated",
        body="the word kerberoast appears exactly once in the body",
    )
    kb = KnowledgeBase(tmp_kb_root)
    hits = kb.search("kerberoast")
    assert [h.id for h in hits] == ["a", "b"]


def test_filter_by_mitre(tmp_kb_root: Path) -> None:
    _write_entry(tmp_kb_root, "a.md", entry_id="a", title="A", mitre=["T1059.001"])
    _write_entry(tmp_kb_root, "b.md", entry_id="b", title="B", mitre=["T1003.006"])
    kb = KnowledgeBase(tmp_kb_root)
    assert [e.id for e in kb.filter_by_mitre("T1003.006")] == ["b"]


def test_readme_is_skipped(tmp_kb_root: Path) -> None:
    (tmp_kb_root / "README.md").write_text("not an entry", encoding="utf-8")
    _write_entry(tmp_kb_root, "real.md", entry_id="real", title="Real")
    kb = KnowledgeBase(tmp_kb_root)
    assert [e.id for e in kb.entries] == ["real"]
    assert kb.load_errors == []


def test_readme_case_insensitive(tmp_kb_root: Path) -> None:
    (tmp_kb_root / "readme.md").write_text("also skipped", encoding="utf-8")
    _write_entry(tmp_kb_root, "r.md", entry_id="r", title="R")
    kb = KnowledgeBase(tmp_kb_root)
    assert [e.id for e in kb.entries] == ["r"]


def test_nested_entries_loaded_recursively(tmp_kb_root: Path) -> None:
    nested = tmp_kb_root / "techniques" / "credential-access"
    nested.mkdir(parents=True)
    _write_entry(nested, "kerberoast.md", entry_id="nested", title="Nested")
    kb = KnowledgeBase(tmp_kb_root)
    assert [e.id for e in kb.entries] == ["nested"]


def test_body_preserves_code_blocks(tmp_kb_root: Path) -> None:
    body = dedent(
        """
        ## Pattern

        ```bash
        echo hello
        ```
        """,
    ).strip()
    _write_entry(tmp_kb_root, "code.md", entry_id="c", title="C", body=body)
    kb = KnowledgeBase(tmp_kb_root)
    assert "```bash" in kb.entries[0].body
