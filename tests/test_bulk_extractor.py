"""
Tests for core.sift.bulk_extractor -- Tier 0 stream-forensics wrapper.

Mocks subprocess.run so the suite runs on any host. Verifies:
- scanner allow-list rejection (empty list, unknown scanner)
- missing-source rejection
- refuse-to-overwrite semantics on the output directory
- argv shape (-q quiet, per-scanner -E, -o <outdir>, positional source last)
- audit payload includes scanners list + scanner_reasons dict
  + evidence_readonly_assumed=True
"""

from __future__ import annotations

from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from core.audit import AuditLogger
from core.sift.bulk_extractor import (
    BULK_EXTRACTOR_SCANNERS,
    BulkExtractorScannerError,
    run_bulk_extractor,
)
from core.sift.runner import ToolRunError

# ---------------------------------------------------------------------------
# scanner allow-list
# ---------------------------------------------------------------------------


def test_scanner_allow_list_has_expected_entries() -> None:
    # Guard against silent removals.
    for name in ("email", "url", "domain", "net", "exif", "winprefetch", "winlnk"):
        assert name in BULK_EXTRACTOR_SCANNERS
    # Every scanner must carry a human-readable reason.
    for name, reason in BULK_EXTRACTOR_SCANNERS.items():
        assert isinstance(name, str) and name
        assert isinstance(reason, str) and reason


def test_scanner_allow_list_excludes_payment_and_crypto() -> None:
    # Deliberate exclusions: these belong in a compliance tier, not Tier 0.
    assert "ccn" not in BULK_EXTRACTOR_SCANNERS
    assert "aes" not in BULK_EXTRACTOR_SCANNERS


# ---------------------------------------------------------------------------
# bulk_extractor wrapper -- rejection paths
# ---------------------------------------------------------------------------


def test_run_bulk_extractor_rejects_empty_scanner_list(tmp_path: Path) -> None:
    src = tmp_path / "image.dd"
    src.write_bytes(b"FAKEIMG")
    out = tmp_path / "be-out"
    with pytest.raises(BulkExtractorScannerError):
        run_bulk_extractor(source=src, output_dir=out, scanners=[])


def test_run_bulk_extractor_rejects_unknown_scanner(tmp_path: Path) -> None:
    src = tmp_path / "image.dd"
    src.write_bytes(b"FAKEIMG")
    out = tmp_path / "be-out"
    with pytest.raises(BulkExtractorScannerError):
        run_bulk_extractor(
            source=src,
            output_dir=out,
            scanners=["email", "not_a_scanner"],
        )


def test_run_bulk_extractor_rejects_missing_source(tmp_path: Path) -> None:
    out = tmp_path / "be-out"
    with pytest.raises(ToolRunError):
        run_bulk_extractor(
            source=tmp_path / "does-not-exist.dd",
            output_dir=out,
            scanners=["email"],
        )


def test_run_bulk_extractor_refuses_output_dir_that_is_a_file(
    tmp_path: Path,
) -> None:
    src = tmp_path / "image.dd"
    src.write_bytes(b"FAKEIMG")
    out = tmp_path / "already-a-file"
    out.write_text("i am a file, not a dir")
    with pytest.raises(ToolRunError):
        run_bulk_extractor(source=src, output_dir=out, scanners=["email"])


def test_run_bulk_extractor_refuses_non_empty_output_dir(tmp_path: Path) -> None:
    src = tmp_path / "image.dd"
    src.write_bytes(b"FAKEIMG")
    out = tmp_path / "be-out"
    out.mkdir()
    (out / "prior-run.txt").write_text("leftover from earlier")
    with pytest.raises(ToolRunError):
        run_bulk_extractor(source=src, output_dir=out, scanners=["email"])


def test_run_bulk_extractor_accepts_empty_existing_output_dir(
    tmp_path: Path,
) -> None:
    src = tmp_path / "image.dd"
    src.write_bytes(b"FAKEIMG")
    out = tmp_path / "be-out"
    out.mkdir()  # exists but empty -- should be fine
    fake_bin = tmp_path / "bulk_extractor"
    fake_bin.write_text("#!/bin/sh\nexit 0\n")
    fake_bin.chmod(0o755)

    fake_proc = CompletedProcess(
        args=["bulk_extractor"], returncode=0, stdout="", stderr=""
    )
    with patch("core.sift.runner.subprocess.run", return_value=fake_proc):
        result = run_bulk_extractor(
            source=src,
            output_dir=out,
            scanners=["email"],
            bulk_extractor_binary=fake_bin,
        )
    assert result.ok is True


# ---------------------------------------------------------------------------
# bulk_extractor wrapper -- argv shape
# ---------------------------------------------------------------------------


def test_run_bulk_extractor_builds_expected_argv(tmp_path: Path) -> None:
    src = tmp_path / "image.dd"
    src.write_bytes(b"FAKEIMG")
    out = tmp_path / "be-out"
    fake_bin = tmp_path / "bulk_extractor"
    fake_bin.write_text("#!/bin/sh\nexit 0\n")
    fake_bin.chmod(0o755)

    fake_proc = CompletedProcess(
        args=["bulk_extractor"], returncode=0, stdout="", stderr=""
    )
    with patch("core.sift.runner.subprocess.run", return_value=fake_proc) as mock_run:
        result = run_bulk_extractor(
            source=src,
            output_dir=out,
            scanners=["email", "url", "domain"],
            bulk_extractor_binary=fake_bin,
        )
    assert result.ok is True
    argv = mock_run.call_args.args[0]
    assert argv[0] == str(fake_bin)
    # -q (quiet) must appear so we do not flood the audit log with
    # per-sector progress.
    assert "-q" in argv
    # Each scanner must get its own -E (enable-only-this) pair.
    assert argv.count("-E") == 3
    for scanner in ("email", "url", "domain"):
        assert scanner in argv
    # -o <outdir> must be present.
    assert "-o" in argv
    assert str(out) in argv
    # Source path is the final positional argument.
    assert argv[-1] == str(src)


def test_run_bulk_extractor_preserves_scanner_order(tmp_path: Path) -> None:
    src = tmp_path / "image.dd"
    src.write_bytes(b"FAKEIMG")
    out = tmp_path / "be-out"
    fake_bin = tmp_path / "bulk_extractor"
    fake_bin.write_text("#!/bin/sh\nexit 0\n")
    fake_bin.chmod(0o755)

    fake_proc = CompletedProcess(
        args=["bulk_extractor"], returncode=0, stdout="", stderr=""
    )
    ordered = ["winprefetch", "winlnk", "exif"]
    with patch("core.sift.runner.subprocess.run", return_value=fake_proc) as mock_run:
        run_bulk_extractor(
            source=src,
            output_dir=out,
            scanners=ordered,
            bulk_extractor_binary=fake_bin,
        )
    argv = mock_run.call_args.args[0]
    # Pull out the scanners in the order they appear after each -E.
    e_indices = [i for i, v in enumerate(argv) if v == "-E"]
    emitted = [argv[i + 1] for i in e_indices]
    assert emitted == ordered


# ---------------------------------------------------------------------------
# audit payload
# ---------------------------------------------------------------------------


def test_run_bulk_extractor_audit_payload_shape(
    tmp_path: Path,
    tmp_log_dir: Path,
) -> None:
    src = tmp_path / "image.dd"
    src.write_bytes(b"FAKEIMG")
    out = tmp_path / "be-out"
    fake_bin = tmp_path / "bulk_extractor"
    fake_bin.write_text("#!/bin/sh\nexit 0\n")
    fake_bin.chmod(0o755)

    fake_proc = CompletedProcess(
        args=["bulk_extractor"], returncode=0, stdout="", stderr=""
    )
    audit = AuditLogger(incident_id="incident-bulk-ext", log_dir=tmp_log_dir)
    with patch("core.sift.runner.subprocess.run", return_value=fake_proc):
        run_bulk_extractor(
            source=src,
            output_dir=out,
            scanners=["email", "url"],
            audit=audit,
            bulk_extractor_binary=fake_bin,
        )
    start_events = [
        e for e in audit.find("tool_call") if e.payload.get("phase") == "start"
    ]
    assert len(start_events) == 1
    payload = start_events[0].payload
    assert payload["scanners"] == ["email", "url"]
    # scanner_reasons must mirror the requested set, keyed by scanner name.
    reasons = payload["scanner_reasons"]
    assert set(reasons) == {"email", "url"}
    assert reasons["email"] == BULK_EXTRACTOR_SCANNERS["email"]
    assert reasons["url"] == BULK_EXTRACTOR_SCANNERS["url"]
    assert payload["source"] == str(src)
    assert payload["evidence_readonly_assumed"] is True
    assert payload["output_dir"] == str(out)
