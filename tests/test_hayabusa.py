"""
Tests for core.sift.hayabusa -- Tier 0 EVTX Sigma-hunt wrapper.

Mocks subprocess.run so the suite runs on any host. Verifies:
- argv shape for csv-timeline and json-timeline with both directory
  and single-file evtx sources
- argv shape for logon-summary with and without an output path
- precondition errors: missing evtx_source, existing output_path,
  unsupported output_format, unsupported min_level
- audit payload carries ``evidence_readonly_assumed=True`` plus the core
  metadata (subcommand, output_format, min_level, profile, paths)
- the module's ``__all__`` lists the documented public surface
"""

from __future__ import annotations

from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from core.audit import AuditLogger
from core.sift import hayabusa as hayabusa_mod
from core.sift.hayabusa import (
    HAYABUSA_OUTPUT_FORMATS,
    HayabusaSubcommandError,
    run_hayabusa_logon_summary,
    run_hayabusa_timeline,
)
from core.sift.runner import ToolRunError

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _fake_binary(tmp_path: Path, name: str = "hayabusa") -> Path:
    fake_bin = tmp_path / name
    fake_bin.write_text("#!/bin/sh\nexit 0\n")
    fake_bin.chmod(0o755)
    return fake_bin


def _fake_proc() -> CompletedProcess[str]:
    return CompletedProcess(args=["hayabusa"], returncode=0, stdout="", stderr="")


def _evtx_dir(tmp_path: Path) -> Path:
    evtx_dir = tmp_path / "evtx"
    evtx_dir.mkdir()
    (evtx_dir / "Security.evtx").write_bytes(b"ELFF")
    return evtx_dir


def _evtx_file(tmp_path: Path) -> Path:
    evtx = tmp_path / "Security.evtx"
    evtx.write_bytes(b"ELFF")
    return evtx


# ---------------------------------------------------------------------------
# public surface
# ---------------------------------------------------------------------------


def test_module_exports_documented_public_surface() -> None:
    assert set(hayabusa_mod.__all__) == {
        "HAYABUSA_OUTPUT_FORMATS",
        "HayabusaSubcommandError",
        "run_hayabusa_logon_summary",
        "run_hayabusa_timeline",
    }


def test_output_formats_allow_list_shape() -> None:
    # csv and json must map to the two documented subcommands.
    assert HAYABUSA_OUTPUT_FORMATS["csv"] == "csv-timeline"
    assert HAYABUSA_OUTPUT_FORMATS["json"] == "json-timeline"
    # Nothing else is allowed.
    assert set(HAYABUSA_OUTPUT_FORMATS) == {"csv", "json"}


# ---------------------------------------------------------------------------
# timeline -- argv shape
# ---------------------------------------------------------------------------


def test_csv_timeline_argv_with_directory_source(tmp_path: Path) -> None:
    src = _evtx_dir(tmp_path)
    out = tmp_path / "timeline.csv"
    fake_bin = _fake_binary(tmp_path)

    with patch(
        "core.sift.runner.subprocess.run", return_value=_fake_proc()
    ) as mock_run:
        result = run_hayabusa_timeline(
            evtx_source=src,
            output_path=out,
            output_format="csv",
            hayabusa_binary=fake_bin,
        )
    assert result.ok is True
    argv = mock_run.call_args.args[0]
    assert argv[0] == str(fake_bin)
    assert argv[1] == "csv-timeline"
    assert "-q" in argv
    # Directory source -> -d
    assert "-d" in argv
    assert str(src) in argv
    assert "-f" not in argv
    # Output path always emitted.
    assert "-o" in argv
    assert str(out) in argv
    # Default min-level is medium.
    assert "--min-level" in argv
    idx = argv.index("--min-level")
    assert argv[idx + 1] == "medium"
    # No profile by default.
    assert "-p" not in argv


def test_json_timeline_argv_with_file_source_and_profile(tmp_path: Path) -> None:
    src = _evtx_file(tmp_path)
    out = tmp_path / "timeline.jsonl"
    fake_bin = _fake_binary(tmp_path)

    with patch(
        "core.sift.runner.subprocess.run", return_value=_fake_proc()
    ) as mock_run:
        run_hayabusa_timeline(
            evtx_source=src,
            output_path=out,
            output_format="json",
            min_level="high",
            profile="timesketch",
            hayabusa_binary=fake_bin,
        )
    argv = mock_run.call_args.args[0]
    assert argv[1] == "json-timeline"
    # Single-file source -> -f
    assert "-f" in argv
    assert str(src) in argv
    assert "-d" not in argv
    assert "-o" in argv
    assert str(out) in argv
    # Custom min-level propagates.
    idx = argv.index("--min-level")
    assert argv[idx + 1] == "high"
    # Profile propagates via -p.
    assert "-p" in argv
    p_idx = argv.index("-p")
    assert argv[p_idx + 1] == "timesketch"


def test_timeline_quiet_flag_suppressed_when_requested(tmp_path: Path) -> None:
    src = _evtx_dir(tmp_path)
    out = tmp_path / "timeline.csv"
    fake_bin = _fake_binary(tmp_path)

    with patch(
        "core.sift.runner.subprocess.run", return_value=_fake_proc()
    ) as mock_run:
        run_hayabusa_timeline(
            evtx_source=src,
            output_path=out,
            quiet=False,
            hayabusa_binary=fake_bin,
        )
    argv = mock_run.call_args.args[0]
    assert "-q" not in argv


# ---------------------------------------------------------------------------
# timeline -- rejection paths
# ---------------------------------------------------------------------------


def test_timeline_rejects_missing_evtx_source(tmp_path: Path) -> None:
    out = tmp_path / "timeline.csv"
    with pytest.raises(ToolRunError):
        run_hayabusa_timeline(
            evtx_source=tmp_path / "does-not-exist",
            output_path=out,
        )


def test_timeline_refuses_to_overwrite_existing_output(tmp_path: Path) -> None:
    src = _evtx_dir(tmp_path)
    out = tmp_path / "timeline.csv"
    out.write_text("prior run")
    fake_bin = _fake_binary(tmp_path)
    with pytest.raises(ToolRunError):
        run_hayabusa_timeline(
            evtx_source=src,
            output_path=out,
            hayabusa_binary=fake_bin,
        )


def test_timeline_rejects_missing_output_parent(tmp_path: Path) -> None:
    src = _evtx_dir(tmp_path)
    out = tmp_path / "nope" / "timeline.csv"
    fake_bin = _fake_binary(tmp_path)
    with pytest.raises(ToolRunError):
        run_hayabusa_timeline(
            evtx_source=src,
            output_path=out,
            hayabusa_binary=fake_bin,
        )


def test_timeline_rejects_unknown_output_format(tmp_path: Path) -> None:
    src = _evtx_dir(tmp_path)
    out = tmp_path / "timeline.xml"
    with pytest.raises(HayabusaSubcommandError):
        run_hayabusa_timeline(
            evtx_source=src,
            output_path=out,
            output_format="xml",
        )


def test_timeline_rejects_unknown_min_level(tmp_path: Path) -> None:
    src = _evtx_dir(tmp_path)
    out = tmp_path / "timeline.csv"
    with pytest.raises(HayabusaSubcommandError):
        run_hayabusa_timeline(
            evtx_source=src,
            output_path=out,
            min_level="urgent",
        )


# ---------------------------------------------------------------------------
# logon-summary
# ---------------------------------------------------------------------------


def test_logon_summary_argv_stdout_mode(tmp_path: Path) -> None:
    src = _evtx_dir(tmp_path)
    fake_bin = _fake_binary(tmp_path)

    with patch(
        "core.sift.runner.subprocess.run", return_value=_fake_proc()
    ) as mock_run:
        run_hayabusa_logon_summary(
            evtx_source=src,
            hayabusa_binary=fake_bin,
        )
    argv = mock_run.call_args.args[0]
    assert argv[0] == str(fake_bin)
    assert argv[1] == "logon-summary"
    assert "-d" in argv
    assert str(src) in argv
    # stdout mode -> no -o flag.
    assert "-o" not in argv


def test_logon_summary_argv_with_output_path_and_file_source(
    tmp_path: Path,
) -> None:
    src = _evtx_file(tmp_path)
    out = tmp_path / "logon-summary.txt"
    fake_bin = _fake_binary(tmp_path)

    with patch(
        "core.sift.runner.subprocess.run", return_value=_fake_proc()
    ) as mock_run:
        run_hayabusa_logon_summary(
            evtx_source=src,
            output_path=out,
            hayabusa_binary=fake_bin,
        )
    argv = mock_run.call_args.args[0]
    assert argv[1] == "logon-summary"
    # Single-file source -> -f
    assert "-f" in argv
    assert str(src) in argv
    assert "-o" in argv
    assert str(out) in argv


def test_logon_summary_rejects_missing_evtx_source(tmp_path: Path) -> None:
    with pytest.raises(ToolRunError):
        run_hayabusa_logon_summary(evtx_source=tmp_path / "nope")


def test_logon_summary_refuses_to_overwrite_existing_output(
    tmp_path: Path,
) -> None:
    src = _evtx_dir(tmp_path)
    out = tmp_path / "logon.txt"
    out.write_text("prior run")
    fake_bin = _fake_binary(tmp_path)
    with pytest.raises(ToolRunError):
        run_hayabusa_logon_summary(
            evtx_source=src,
            output_path=out,
            hayabusa_binary=fake_bin,
        )


# ---------------------------------------------------------------------------
# audit payload
# ---------------------------------------------------------------------------


def test_timeline_audit_payload_shape(
    tmp_path: Path,
    tmp_log_dir: Path,
) -> None:
    src = _evtx_dir(tmp_path)
    out = tmp_path / "timeline.csv"
    fake_bin = _fake_binary(tmp_path)
    audit = AuditLogger(incident_id="incident-hayabusa", log_dir=tmp_log_dir)

    with patch("core.sift.runner.subprocess.run", return_value=_fake_proc()):
        run_hayabusa_timeline(
            evtx_source=src,
            output_path=out,
            output_format="csv",
            min_level="high",
            profile="standard",
            audit=audit,
            hayabusa_binary=fake_bin,
        )
    start_events = [
        e for e in audit.find("tool_call") if e.payload.get("phase") == "start"
    ]
    assert len(start_events) == 1
    payload = start_events[0].payload
    assert payload["tool"] == "hayabusa"
    assert payload["subcommand"] == "csv-timeline"
    assert payload["output_format"] == "csv"
    assert payload["evtx_source"] == str(src)
    assert payload["evidence_readonly_assumed"] is True
    assert payload["output_path"] == str(out)
    assert payload["min_level"] == "high"
    assert payload["profile"] == "standard"


def test_logon_summary_audit_payload_marks_evidence_readonly(
    tmp_path: Path,
    tmp_log_dir: Path,
) -> None:
    src = _evtx_file(tmp_path)
    fake_bin = _fake_binary(tmp_path)
    audit = AuditLogger(
        incident_id="incident-hayabusa-logon", log_dir=tmp_log_dir
    )

    with patch("core.sift.runner.subprocess.run", return_value=_fake_proc()):
        run_hayabusa_logon_summary(
            evtx_source=src,
            audit=audit,
            hayabusa_binary=fake_bin,
        )
    start_events = [
        e for e in audit.find("tool_call") if e.payload.get("phase") == "start"
    ]
    assert len(start_events) == 1
    payload = start_events[0].payload
    assert payload["subcommand"] == "logon-summary"
    assert payload["evtx_source"] == str(src)
    assert payload["evidence_readonly_assumed"] is True
    assert payload["output_path"] is None
