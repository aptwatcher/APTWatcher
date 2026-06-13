"""
Shared pytest fixtures.

Scoped to tests that need a temp workspace (audit log, knowledge root).
Nothing here depends on a live SIFT VM; CI runs these against plain Python.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture()
def tmp_log_dir(tmp_path: Path) -> Iterator[Path]:
    """Isolated logs directory for the AuditLogger."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    yield log_dir


@pytest.fixture()
def tmp_kb_root(tmp_path: Path) -> Iterator[Path]:
    """Empty knowledge base root. Tests add Markdown files as needed."""
    kb_root = tmp_path / "knowledge"
    kb_root.mkdir()
    yield kb_root
