"""
Tests for `aptwatcher analyze` -- the fan-out command that turns a
triage output JSON into the full analysis bundle (rules / IOCs /
reports / generation manifest / optional signed incident bundle).

All generator/exporter/renderer calls are patched so no subprocesses,
no network, and no `.docx` binary stamping happen in the test suite.
Only filesystem writes inside `tmp_path` are real.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from agent_extension.analyze import (
    _auto_incident_id,
    _load_input_bundle,
    _slugify_campaign,
    cmd_analyze,
)
from agent_extension.cli import app

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _minimal_finding() -> dict:
    return {
        "finding_id": "f-001",
        "summary": "Suspicious outbound beacon to evil.example",
        "mitre": ["T1071.001"],
        "confidence": 0.9,
        "evidence": [
            {"source": "Security.evtx", "locator": "event_id=4624", "tool_call_id": "c-001"},
        ],
        "reasoning": None,
    }


def _minimal_ioc() -> dict:
    return {
        "value": "evil.example",
        "ioc_type": "domain",
        "verdict": "malicious",
        "confidence": 0.95,
        "sources": [],
        "attributions": [],
        "notes": None,
    }


def _write_input(tmp_path: Path) -> Path:
    path = tmp_path / "triage.json"
    payload = {
        "findings": [_minimal_finding()],
        "iocs": [_minimal_ioc()],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Subparser / CLI registration
# ---------------------------------------------------------------------------


def test_analyze_subcommand_is_registered_in_cli() -> None:
    """`aptwatcher --help` mentions the analyze subcommand."""
    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    combined = result.stdout + (result.stderr or "")
    assert "analyze" in combined


def test_analyze_requires_input_flag(tmp_path: Path) -> None:
    """Missing --input should fail with a non-zero exit (argparse-level)."""
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["analyze", "--output-dir", str(tmp_path / "out")],
    )
    assert result.exit_code != 0
    combined = result.stdout + (result.stderr or "")
    assert "--input" in combined or "Missing option" in combined or "required" in combined.lower()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_slugify_campaign_produces_kebab() -> None:
    assert _slugify_campaign("APTWATCHER") == "aptwatcher"
    assert _slugify_campaign("Hostkey DEDIK") == "hostkey-dedik"
    assert _slugify_campaign("  ") == "aptwatcher"


def test_auto_incident_id_has_expected_shape() -> None:
    iid = _auto_incident_id()
    assert iid.startswith("INC-")
    assert len(iid.split("-")) == 3


def test_load_input_bundle_parses_typed_records(tmp_path: Path) -> None:
    path = _write_input(tmp_path)
    findings, iocs = _load_input_bundle(path)
    assert len(findings) == 1
    assert findings[0].finding_id == "f-001"
    assert len(iocs) == 1
    assert iocs[0].value == "evil.example"


def test_load_input_bundle_raises_on_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        _load_input_bundle(tmp_path / "nope.json")


def test_load_input_bundle_raises_on_malformed_json(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("not-json", encoding="utf-8")
    with pytest.raises(ValueError):
        _load_input_bundle(path)


# ---------------------------------------------------------------------------
# cmd_analyze exit codes
# ---------------------------------------------------------------------------


def _base_args(input_path: Path, output_dir: Path, **overrides) -> argparse.Namespace:
    defaults = {
        "input": input_path,
        "output_dir": output_dir,
        "campaign_tag": "APTWATCHER",
        "incident_id": "INC-TEST-0001",
        "operator": None,
        "language": "both",
        "sid_start": 3_000_000,
        "skip_rules": False,
        "skip_reports": False,
        "skip_iocs": False,
        "sign": False,
        "private_key_path": None,
        "sift_workstation": "test-sift",
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def test_cmd_analyze_missing_input_returns_1(tmp_path: Path, capsys) -> None:
    args = _base_args(
        input_path=tmp_path / "does-not-exist.json",
        output_dir=tmp_path / "out",
    )
    code = cmd_analyze(args)
    assert code == 1
    err = capsys.readouterr().err
    assert "not found" in err.lower()


def test_cmd_analyze_sign_without_private_key_returns_1(
    tmp_path: Path, capsys,
) -> None:
    input_path = _write_input(tmp_path)
    args = _base_args(
        input_path=input_path,
        output_dir=tmp_path / "out",
        sign=True,
        operator="APTWatcher",
        private_key_path=None,
    )
    code = cmd_analyze(args)
    assert code == 1
    err = capsys.readouterr().err
    assert "private-key-path" in err


def test_cmd_analyze_sign_without_operator_returns_1(
    tmp_path: Path, capsys,
) -> None:
    input_path = _write_input(tmp_path)
    key_path = tmp_path / "key.bin"
    key_path.write_bytes(b"x" * 32)
    args = _base_args(
        input_path=input_path,
        output_dir=tmp_path / "out",
        sign=True,
        operator=None,
        private_key_path=key_path,
    )
    code = cmd_analyze(args)
    assert code == 1
    err = capsys.readouterr().err
    assert "operator" in err.lower()


def test_cmd_analyze_happy_path_returns_0_with_all_stages_mocked(
    tmp_path: Path,
) -> None:
    """All fan-out stages stubbed so we only verify orchestration + exit code."""
    input_path = _write_input(tmp_path)
    output_dir = tmp_path / "out"
    args = _base_args(input_path=input_path, output_dir=output_dir)

    with patch("agent_extension.analyze._write_rules", return_value={"yara": output_dir / "rules" / "x.yar"}), \
         patch("agent_extension.analyze._write_iocs", return_value={"stix": output_dir / "iocs" / "bundle.stix.json"}), \
         patch("agent_extension.analyze._write_reports", return_value={"md_analysis": output_dir / "reports" / "a.md"}):
        code = cmd_analyze(args)

    assert code == 0
    # Sibling staging files the publish command relies on are present.
    assert (output_dir / "findings.json").exists()
    assert (output_dir / "iocs.json").exists()
    assert (output_dir / "manifest.json").exists()
    assert (output_dir / "generation_report.json").exists()


def test_cmd_analyze_honours_skip_rules_flag(tmp_path: Path) -> None:
    input_path = _write_input(tmp_path)
    output_dir = tmp_path / "out"
    args = _base_args(
        input_path=input_path, output_dir=output_dir, skip_rules=True,
    )
    rules_mock = MagicMock()
    iocs_mock = MagicMock(return_value={})
    reports_mock = MagicMock(return_value={})
    with patch("agent_extension.analyze._write_rules", rules_mock), \
         patch("agent_extension.analyze._write_iocs", iocs_mock), \
         patch("agent_extension.analyze._write_reports", reports_mock):
        code = cmd_analyze(args)
    assert code == 0
    rules_mock.assert_not_called()
    iocs_mock.assert_called_once()
    reports_mock.assert_called_once()


def test_cmd_analyze_honours_skip_reports_flag(tmp_path: Path) -> None:
    input_path = _write_input(tmp_path)
    output_dir = tmp_path / "out"
    args = _base_args(
        input_path=input_path, output_dir=output_dir, skip_reports=True,
    )
    rules_mock = MagicMock(return_value={})
    iocs_mock = MagicMock(return_value={})
    reports_mock = MagicMock()
    with patch("agent_extension.analyze._write_rules", rules_mock), \
         patch("agent_extension.analyze._write_iocs", iocs_mock), \
         patch("agent_extension.analyze._write_reports", reports_mock):
        code = cmd_analyze(args)
    assert code == 0
    rules_mock.assert_called_once()
    iocs_mock.assert_called_once()
    reports_mock.assert_not_called()


def test_cmd_analyze_honours_skip_iocs_flag(tmp_path: Path) -> None:
    input_path = _write_input(tmp_path)
    output_dir = tmp_path / "out"
    args = _base_args(
        input_path=input_path, output_dir=output_dir, skip_iocs=True,
    )
    rules_mock = MagicMock(return_value={})
    iocs_mock = MagicMock()
    reports_mock = MagicMock(return_value={})
    with patch("agent_extension.analyze._write_rules", rules_mock), \
         patch("agent_extension.analyze._write_iocs", iocs_mock), \
         patch("agent_extension.analyze._write_reports", reports_mock):
        code = cmd_analyze(args)
    assert code == 0
    rules_mock.assert_called_once()
    iocs_mock.assert_not_called()
    reports_mock.assert_called_once()


def test_cmd_analyze_all_skip_flags_skips_every_stage(tmp_path: Path) -> None:
    input_path = _write_input(tmp_path)
    output_dir = tmp_path / "out"
    args = _base_args(
        input_path=input_path,
        output_dir=output_dir,
        skip_rules=True,
        skip_reports=True,
        skip_iocs=True,
    )
    rules_mock = MagicMock()
    iocs_mock = MagicMock()
    reports_mock = MagicMock()
    with patch("agent_extension.analyze._write_rules", rules_mock), \
         patch("agent_extension.analyze._write_iocs", iocs_mock), \
         patch("agent_extension.analyze._write_reports", reports_mock):
        code = cmd_analyze(args)
    assert code == 0
    rules_mock.assert_not_called()
    iocs_mock.assert_not_called()
    reports_mock.assert_not_called()
    # generation_report still written even with everything skipped.
    assert (output_dir / "generation_report.json").exists()


def test_cmd_analyze_generator_failure_returns_2(tmp_path: Path, capsys) -> None:
    """A raised generator error must translate to exit code 2."""
    input_path = _write_input(tmp_path)
    output_dir = tmp_path / "out"
    args = _base_args(input_path=input_path, output_dir=output_dir)

    def boom(**kwargs):
        raise RuntimeError("yara synthesis exploded")

    with patch("agent_extension.analyze._write_rules", side_effect=boom), \
         patch("agent_extension.analyze._write_iocs", return_value={}), \
         patch("agent_extension.analyze._write_reports", return_value={}):
        code = cmd_analyze(args)
    assert code == 2
    err = capsys.readouterr().err
    assert "pipeline" in err.lower() or "yara" in err.lower()


def test_cmd_analyze_sign_invokes_bundle_exporter(tmp_path: Path) -> None:
    """With --sign + operator + private-key-path, export_bundle is called."""
    input_path = _write_input(tmp_path)
    output_dir = tmp_path / "out"
    key_path = tmp_path / "key.bin"
    key_path.write_bytes(b"x" * 32)
    args = _base_args(
        input_path=input_path,
        output_dir=output_dir,
        sign=True,
        operator="APTWatcher",
        private_key_path=key_path,
    )
    with patch("agent_extension.analyze._write_rules", return_value={}), \
         patch("agent_extension.analyze._write_iocs", return_value={}), \
         patch("agent_extension.analyze._write_reports", return_value={}), \
         patch("agent_extension.analyze._write_signed_bundle") as signed:
        signed.return_value = output_dir / "incident-bundle"
        code = cmd_analyze(args)
    assert code == 0
    signed.assert_called_once()
    kw = signed.call_args.kwargs
    assert kw["operator"] == "APTWatcher"
    assert kw["private_key_path"] == key_path
