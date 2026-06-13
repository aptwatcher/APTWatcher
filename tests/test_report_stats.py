"""
Tests for the generation_report.json manifest writer.

Coverage:
- Top-level schema shape (``schema_version``, ``incident_id``, etc.).
- ``sid_range`` serializes to ``{"start": N, "end": M}`` or ``null``.
- ``file_digests`` keys/values are preserved byte-for-byte.
- Refuses to overwrite.
- ``counts`` with a non-int value is rejected.
- Bad ``sid_range`` (start > end) raises.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from core.analysis.report_docx import ReportRenderError
from core.analysis.report_stats import SCHEMA_VERSION, render_generation_report


def test_basic_schema_shape(tmp_path: Path) -> None:
    out = tmp_path / "generation_report.json"
    render_generation_report(
        output_path=out,
        incident_id="inc-123",
        campaign_tag="S01_TEST",
        counts={"findings": 3, "iocs": 7, "yara_rules": 2},
        sid_range=(2026000001, 2026000012),
        file_digests={"yara/a.yar": "sha256:abc", "suricata/b.rules": "sha256:def"},
        generated_at=datetime(2026, 4, 19, 12, 0, 0, tzinfo=UTC),
    )
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["schema_version"] == SCHEMA_VERSION
    assert data["incident_id"] == "inc-123"
    assert data["campaign_tag"] == "S01_TEST"
    assert data["generated_at"] == "2026-04-19T12:00:00Z"


def test_counts_are_sorted_and_preserved(tmp_path: Path) -> None:
    out = tmp_path / "gen.json"
    counts = {"iocs": 5, "findings": 2, "yara_rules": 1}
    render_generation_report(
        output_path=out,
        incident_id="i",
        campaign_tag="c",
        counts=counts,
        sid_range=None,
        file_digests={},
    )
    data = json.loads(out.read_text(encoding="utf-8"))
    # Sorted alphabetically in the on-disk JSON for determinism.
    assert list(data["counts"].keys()) == sorted(counts.keys())
    # Values preserved.
    for k, v in counts.items():
        assert data["counts"][k] == v


def test_sid_range_serialization(tmp_path: Path) -> None:
    out = tmp_path / "gen.json"
    render_generation_report(
        output_path=out,
        incident_id="i",
        campaign_tag="c",
        counts={},
        sid_range=(100, 200),
        file_digests={},
    )
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["sid_range"] == {"start": 100, "end": 200}


def test_sid_range_none_serializes_to_null(tmp_path: Path) -> None:
    out = tmp_path / "gen.json"
    render_generation_report(
        output_path=out,
        incident_id="i",
        campaign_tag="c",
        counts={},
        sid_range=None,
        file_digests={},
    )
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["sid_range"] is None


def test_file_digests_preserved(tmp_path: Path) -> None:
    out = tmp_path / "gen.json"
    digests = {
        "yara/family.yar": "sha256:" + "a" * 64,
        "suricata/auto.rules": "sha256:" + "b" * 64,
        "reports/Campaign_Report.docx": "sha256:" + "c" * 64,
    }
    render_generation_report(
        output_path=out,
        incident_id="i",
        campaign_tag="c",
        counts={},
        sid_range=None,
        file_digests=digests,
    )
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["file_digests"] == digests


def test_refuses_overwrite(tmp_path: Path) -> None:
    out = tmp_path / "gen.json"
    render_generation_report(
        output_path=out,
        incident_id="i",
        campaign_tag="c",
        counts={},
        sid_range=None,
        file_digests={},
    )
    with pytest.raises(ReportRenderError, match="refusing to overwrite"):
        render_generation_report(
            output_path=out,
            incident_id="i",
            campaign_tag="c",
            counts={},
            sid_range=None,
            file_digests={},
        )


def test_bad_count_value_rejected(tmp_path: Path) -> None:
    out = tmp_path / "gen.json"
    with pytest.raises(ReportRenderError, match="must be int"):
        render_generation_report(
            output_path=out,
            incident_id="i",
            campaign_tag="c",
            counts={"findings": "three"},  # type: ignore[dict-item]
            sid_range=None,
            file_digests={},
        )


def test_bad_sid_range_rejected(tmp_path: Path) -> None:
    out = tmp_path / "gen.json"
    with pytest.raises(ReportRenderError, match="start .* must be <= end"):
        render_generation_report(
            output_path=out,
            incident_id="i",
            campaign_tag="c",
            counts={},
            sid_range=(500, 100),
            file_digests={},
        )


def test_empty_incident_id_rejected(tmp_path: Path) -> None:
    with pytest.raises(ReportRenderError, match="incident_id"):
        render_generation_report(
            output_path=tmp_path / "gen.json",
            incident_id="",
            campaign_tag="c",
            counts={},
            sid_range=None,
            file_digests={},
        )
