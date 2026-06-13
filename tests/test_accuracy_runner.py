"""
Integration test for `tests.accuracy.runner`.

Loads the committed `s_phishing_beacon` fixture, runs the accuracy
harness, and asserts the scorecard hits a calibrated F1 threshold.
This is the smoke test that guards the pipeline wiring; the scoring
math itself is covered by `tests.test_accuracy_scoring`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.accuracy.runner import (
    aggregate,
    discover_manifests,
    load_golden,
    load_manifest,
    run_batch,
    run_scenario,
    write_report,
)

pytestmark = pytest.mark.accuracy


FIXTURES_DIR = Path(__file__).parent / "accuracy" / "fixtures"


# ---------------------------------------------------------------------------
# Individual loaders
# ---------------------------------------------------------------------------


def test_load_manifest_reads_required_fields() -> None:
    manifest = load_manifest(FIXTURES_DIR / "s_phishing_beacon" / "manifest.yaml")
    assert manifest.id == "s_phishing_beacon"
    assert manifest.profile == "windows-host-triage"
    assert manifest.transcript_path.name == "transcript.json"
    assert manifest.golden_path.name == "golden.json"
    assert manifest.seed_findings_path is not None
    assert manifest.seed_iocs_path is not None


def test_load_golden_has_findings_and_iocs() -> None:
    golden = load_golden(FIXTURES_DIR / "s_phishing_beacon" / "golden.json")
    assert len(golden["findings"]) == 2
    assert len(golden["iocs"]) == 2


# ---------------------------------------------------------------------------
# Runner integration
# ---------------------------------------------------------------------------


def test_run_scenario_phishing_beacon_high_f1(tmp_path: Path) -> None:
    manifest = load_manifest(FIXTURES_DIR / "s_phishing_beacon" / "manifest.yaml")
    card = run_scenario(manifest, output_dir=tmp_path)

    assert card.errors == [], f"scenario errors: {card.errors}"
    assert card.findings_tp == 2
    assert card.findings_fp == 0
    assert card.findings_fn == 0
    assert card.f1 > 0.7, f"findings F1 unexpectedly low: {card.f1}"

    # IOC surface: both seed IOCs land in the audit log and match the
    # golden exactly.
    assert card.ioc_tp == 2
    assert card.ioc_fp == 0
    assert card.ioc_fn == 0
    assert card.ioc_f1 == 1.0


def test_run_scenario_credential_dump_high_f1(tmp_path: Path) -> None:
    manifest = load_manifest(FIXTURES_DIR / "s_credential_dump" / "manifest.yaml")
    card = run_scenario(manifest, output_dir=tmp_path)

    assert card.errors == [], f"scenario errors: {card.errors}"
    assert card.findings_tp == 2
    assert card.findings_fp == 0
    assert card.findings_fn == 0
    assert card.f1 > 0.7


# ---------------------------------------------------------------------------
# Batch discovery + report writing
# ---------------------------------------------------------------------------


def test_discover_manifests_finds_both_seeded_scenarios() -> None:
    manifests = discover_manifests(FIXTURES_DIR)
    ids = {m.id for m in manifests}
    assert {"s_phishing_beacon", "s_credential_dump"}.issubset(ids)


def test_run_batch_writes_both_report_files(tmp_path: Path) -> None:
    scorecards, agg, json_path, md_path = run_batch(
        fixtures_dir=FIXTURES_DIR,
        output_dir=tmp_path,
    )
    assert len(scorecards) >= 2
    assert agg["scenario_count"] >= 2
    assert agg["mean_f1"] > 0.7
    assert json_path.exists()
    assert md_path.exists()
    # Sanity check the markdown surface.
    md = md_path.read_text(encoding="utf-8")
    assert "# Accuracy report" in md
    assert "Per-scenario" in md


def test_write_report_handles_empty_batch(tmp_path: Path) -> None:
    json_path, md_path = write_report([], tmp_path)
    assert json_path.exists() and md_path.exists()


def test_aggregate_empty_is_zero() -> None:
    agg = aggregate([])
    assert agg["scenario_count"] == 0
    assert agg["mean_f1"] == 0.0
