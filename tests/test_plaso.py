"""
Tests for core.sift.plaso -- Tier 0 plaso wrappers (log2timeline + psort).

Mocks subprocess.run so the suite runs on any host. Verifies:
- parser preset / output format allow-lists
- refuse-to-overwrite semantics on storage_file and output_file
- argv shape matches plaso's CLI contract
- audit payload carries preset reason + readonly_assumed markers
"""

from __future__ import annotations

from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from core.audit import AuditLogger
from core.sift.plaso import (
    PLASO_PARSER_PRESETS,
    PlasoOutputFormatError,
    PlasoParserPresetError,
    run_log2timeline,
    run_psort,
)
from core.sift.runner import ToolRunError

# ---------------------------------------------------------------------------
# parser preset allow-list
# ---------------------------------------------------------------------------


def test_parser_preset_allow_list_has_expected_entries() -> None:
    # Guard against silent removals.
    assert "win7" in PLASO_PARSER_PRESETS
    assert "linux" in PLASO_PARSER_PRESETS
    assert "macos" in PLASO_PARSER_PRESETS
    assert "webhist" in PLASO_PARSER_PRESETS
    # Every preset must carry a human-readable reason.
    for preset, reason in PLASO_PARSER_PRESETS.items():
        assert isinstance(preset, str) and preset
        assert isinstance(reason, str) and reason


# ---------------------------------------------------------------------------
# log2timeline wrapper
# ---------------------------------------------------------------------------


def test_run_log2timeline_rejects_unknown_preset(tmp_path: Path) -> None:
    src = tmp_path / "image.dd"
    src.write_bytes(b"FAKEIMG")
    storage = tmp_path / "out.plaso"
    with pytest.raises(PlasoParserPresetError):
        run_log2timeline(source=src, storage_file=storage, parsers="not_a_preset")


def test_run_log2timeline_rejects_missing_source(tmp_path: Path) -> None:
    storage = tmp_path / "out.plaso"
    with pytest.raises(ToolRunError):
        run_log2timeline(
            source=tmp_path / "does-not-exist.dd",
            storage_file=storage,
            parsers="win7",
        )


def test_run_log2timeline_refuses_to_overwrite_storage(tmp_path: Path) -> None:
    src = tmp_path / "image.dd"
    src.write_bytes(b"FAKEIMG")
    storage = tmp_path / "already.plaso"
    storage.write_bytes(b"EXISTING")
    with pytest.raises(ToolRunError):
        run_log2timeline(source=src, storage_file=storage, parsers="win7")


def test_run_log2timeline_builds_expected_argv(tmp_path: Path) -> None:
    src = tmp_path / "image.dd"
    src.write_bytes(b"FAKEIMG")
    storage = tmp_path / "out.plaso"
    fake_bin = tmp_path / "log2timeline"
    fake_bin.write_text("#!/bin/sh\nexit 0\n")
    fake_bin.chmod(0o755)

    fake_proc = CompletedProcess(args=["log2timeline"], returncode=0, stdout="", stderr="")
    with patch("core.sift.runner.subprocess.run", return_value=fake_proc) as mock_run:
        result = run_log2timeline(
            source=src,
            storage_file=storage,
            parsers="win7",
            log2timeline_binary=fake_bin,
        )
    assert result.ok is True
    argv = mock_run.call_args.args[0]
    assert argv[0] == str(fake_bin)
    assert "--parsers" in argv
    assert "win7" in argv
    assert "--storage_file" in argv
    assert str(storage) in argv
    assert str(src) in argv
    # Source path must come AFTER --storage_file (positional tail).
    assert argv.index(str(src)) > argv.index("--storage_file")


def test_run_log2timeline_audit_payload_includes_preset_reason(
    tmp_path: Path,
    tmp_log_dir: Path,
) -> None:
    src = tmp_path / "image.dd"
    src.write_bytes(b"FAKEIMG")
    storage = tmp_path / "out.plaso"
    fake_bin = tmp_path / "log2timeline"
    fake_bin.write_text("#!/bin/sh\nexit 0\n")
    fake_bin.chmod(0o755)

    fake_proc = CompletedProcess(args=["log2timeline"], returncode=0, stdout="", stderr="")
    audit = AuditLogger(incident_id="incident-plaso-l2t", log_dir=tmp_log_dir)
    with patch("core.sift.runner.subprocess.run", return_value=fake_proc):
        run_log2timeline(
            source=src,
            storage_file=storage,
            parsers="linux",
            audit=audit,
            log2timeline_binary=fake_bin,
        )
    start_events = [e for e in audit.find("tool_call") if e.payload.get("phase") == "start"]
    assert len(start_events) == 1
    payload = start_events[0].payload
    assert payload["parsers"] == "linux"
    assert "parsers_reason" in payload
    assert payload["source"] == str(src)
    assert payload["evidence_readonly_assumed"] is True
    assert payload["storage_file"] == str(storage)


# ---------------------------------------------------------------------------
# psort wrapper
# ---------------------------------------------------------------------------


def test_run_psort_rejects_unknown_output_format(tmp_path: Path) -> None:
    storage = tmp_path / "in.plaso"
    storage.write_bytes(b"FAKEPLASO")
    output = tmp_path / "out.csv"
    with pytest.raises(PlasoOutputFormatError):
        run_psort(
            storage_file=storage,
            output_file=output,
            output_format="yaml",  # type: ignore[arg-type]
        )


def test_run_psort_rejects_missing_storage(tmp_path: Path) -> None:
    output = tmp_path / "out.csv"
    with pytest.raises(ToolRunError):
        run_psort(
            storage_file=tmp_path / "does-not-exist.plaso",
            output_file=output,
        )


def test_run_psort_refuses_to_overwrite_output(tmp_path: Path) -> None:
    storage = tmp_path / "in.plaso"
    storage.write_bytes(b"FAKEPLASO")
    output = tmp_path / "already.csv"
    output.write_text("pre-existing")
    with pytest.raises(ToolRunError):
        run_psort(storage_file=storage, output_file=output)


def test_run_psort_builds_expected_argv(tmp_path: Path) -> None:
    storage = tmp_path / "in.plaso"
    storage.write_bytes(b"FAKEPLASO")
    output = tmp_path / "out.csv"
    fake_bin = tmp_path / "psort"
    fake_bin.write_text("#!/bin/sh\nexit 0\n")
    fake_bin.chmod(0o755)

    fake_proc = CompletedProcess(args=["psort"], returncode=0, stdout="", stderr="")
    with patch("core.sift.runner.subprocess.run", return_value=fake_proc) as mock_run:
        result = run_psort(
            storage_file=storage,
            output_file=output,
            output_format="dynamic",
            psort_binary=fake_bin,
        )
    assert result.ok is True
    argv = mock_run.call_args.args[0]
    assert argv[0] == str(fake_bin)
    assert "-o" in argv
    assert "dynamic" in argv
    assert "-w" in argv
    assert str(output) in argv
    assert str(storage) in argv
    # No --slice when no time filter was requested.
    assert "--slice" not in argv


def test_run_psort_appends_time_filter_slice(tmp_path: Path) -> None:
    storage = tmp_path / "in.plaso"
    storage.write_bytes(b"FAKEPLASO")
    output = tmp_path / "out.json"
    fake_bin = tmp_path / "psort"
    fake_bin.write_text("#!/bin/sh\nexit 0\n")
    fake_bin.chmod(0o755)

    fake_proc = CompletedProcess(args=["psort"], returncode=0, stdout="", stderr="")
    with patch("core.sift.runner.subprocess.run", return_value=fake_proc) as mock_run:
        run_psort(
            storage_file=storage,
            output_file=output,
            output_format="json_line",
            time_filter="2026-01-01T00:00:00..2026-01-02T00:00:00",
            psort_binary=fake_bin,
        )
    argv = mock_run.call_args.args[0]
    assert "--slice" in argv
    assert "2026-01-01T00:00:00..2026-01-02T00:00:00" in argv
    assert "json_line" in argv


def test_run_psort_audit_payload_includes_format_note(
    tmp_path: Path,
    tmp_log_dir: Path,
) -> None:
    storage = tmp_path / "in.plaso"
    storage.write_bytes(b"FAKEPLASO")
    output = tmp_path / "out.csv"
    fake_bin = tmp_path / "psort"
    fake_bin.write_text("#!/bin/sh\nexit 0\n")
    fake_bin.chmod(0o755)

    fake_proc = CompletedProcess(args=["psort"], returncode=0, stdout="", stderr="")
    audit = AuditLogger(incident_id="incident-plaso-psort", log_dir=tmp_log_dir)
    with patch("core.sift.runner.subprocess.run", return_value=fake_proc):
        run_psort(
            storage_file=storage,
            output_file=output,
            output_format="l2tcsv",
            audit=audit,
            psort_binary=fake_bin,
        )
    start_events = [e for e in audit.find("tool_call") if e.payload.get("phase") == "start"]
    assert len(start_events) == 1
    payload = start_events[0].payload
    assert payload["output_format"] == "l2tcsv"
    assert "output_format_note" in payload
    assert payload["storage_file"] == str(storage)
    assert payload["evidence_readonly_assumed"] is True
    assert payload["output_file"] == str(output)
    assert payload["time_filter"] is None
