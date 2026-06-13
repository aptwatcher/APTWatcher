"""
Tests for core.sift.update -- consent-gated SIFT toolchain refresh.

Mocks subprocess.run so the suite runs on any host. Verifies:
- consent_token rejection (empty, whitespace)
- package allow-list enforcement (unknown package, empty list)
- default package set = full allow-list (sorted)
- dry_run=True (default) emits `-s` (simulate); dry_run=False does not
- argv shape with/without sudo; `install --only-upgrade` contract
- `sift_update_consent` audit event is emitted BEFORE the tool_call,
  with consent_token_present + length but WITHOUT the raw token
- tool_call audit payload mirrors consent (mutates_sift_vm, dry_run)
"""

from __future__ import annotations

from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from core.audit import AuditLogger
from core.sift.update import (
    SIFT_UPDATE_PACKAGES,
    SiftUpdateConsentError,
    SiftUpdatePackageError,
    run_sift_update,
)

# ---------------------------------------------------------------------------
# package allow-list
# ---------------------------------------------------------------------------


def test_package_allow_list_has_expected_entries() -> None:
    for name in (
        "python3-plaso",
        "python3-volatility3",
        "yara",
        "bulk-extractor",
        "sleuthkit",
    ):
        assert name in SIFT_UPDATE_PACKAGES
    for name, reason in SIFT_UPDATE_PACKAGES.items():
        assert isinstance(name, str) and name
        assert isinstance(reason, str) and reason


# ---------------------------------------------------------------------------
# consent gate
# ---------------------------------------------------------------------------


def test_run_sift_update_rejects_empty_consent_token(tmp_path: Path) -> None:
    fake_bin = tmp_path / "apt-get"
    fake_bin.write_text("#!/bin/sh\nexit 0\n")
    fake_bin.chmod(0o755)
    with pytest.raises(SiftUpdateConsentError):
        run_sift_update(
            consent_token="",
            apt_get_binary=fake_bin,
            use_sudo=False,
        )


def test_run_sift_update_rejects_whitespace_consent_token(tmp_path: Path) -> None:
    fake_bin = tmp_path / "apt-get"
    fake_bin.write_text("#!/bin/sh\nexit 0\n")
    fake_bin.chmod(0o755)
    with pytest.raises(SiftUpdateConsentError):
        run_sift_update(
            consent_token="   \t\n  ",
            apt_get_binary=fake_bin,
            use_sudo=False,
        )


# ---------------------------------------------------------------------------
# package allow-list enforcement at call time
# ---------------------------------------------------------------------------


def test_run_sift_update_rejects_unknown_package(tmp_path: Path) -> None:
    fake_bin = tmp_path / "apt-get"
    fake_bin.write_text("#!/bin/sh\nexit 0\n")
    fake_bin.chmod(0o755)
    with pytest.raises(SiftUpdatePackageError):
        run_sift_update(
            consent_token="I-consent",
            packages=["yara", "nmap"],  # nmap is not in the allow-list
            apt_get_binary=fake_bin,
            use_sudo=False,
        )


def test_run_sift_update_rejects_empty_package_list(tmp_path: Path) -> None:
    fake_bin = tmp_path / "apt-get"
    fake_bin.write_text("#!/bin/sh\nexit 0\n")
    fake_bin.chmod(0o755)
    with pytest.raises(SiftUpdatePackageError):
        run_sift_update(
            consent_token="I-consent",
            packages=[],
            apt_get_binary=fake_bin,
            use_sudo=False,
        )


# ---------------------------------------------------------------------------
# argv shape
# ---------------------------------------------------------------------------


def test_run_sift_update_default_dry_run_includes_simulate_flag(
    tmp_path: Path,
) -> None:
    fake_bin = tmp_path / "apt-get"
    fake_bin.write_text("#!/bin/sh\nexit 0\n")
    fake_bin.chmod(0o755)

    fake_proc = CompletedProcess(args=["apt-get"], returncode=0, stdout="", stderr="")
    with patch("core.sift.runner.subprocess.run", return_value=fake_proc) as mock_run:
        run_sift_update(
            consent_token="I-consent",
            packages=["yara"],
            apt_get_binary=fake_bin,
            use_sudo=False,
        )
    argv = mock_run.call_args.args[0]
    # Default: dry_run=True -> `-s` simulate must be present.
    assert "-s" in argv
    assert "install" in argv
    assert "--only-upgrade" in argv
    assert "yara" in argv
    # No sudo when use_sudo=False.
    assert argv[0] == str(fake_bin)


def test_run_sift_update_dry_run_false_omits_simulate_flag(
    tmp_path: Path,
) -> None:
    fake_bin = tmp_path / "apt-get"
    fake_bin.write_text("#!/bin/sh\nexit 0\n")
    fake_bin.chmod(0o755)

    fake_proc = CompletedProcess(args=["apt-get"], returncode=0, stdout="", stderr="")
    with patch("core.sift.runner.subprocess.run", return_value=fake_proc) as mock_run:
        run_sift_update(
            consent_token="I-consent",
            packages=["yara"],
            dry_run=False,
            apt_get_binary=fake_bin,
            use_sudo=False,
        )
    argv = mock_run.call_args.args[0]
    # dry_run=False -> `-s` must NOT be present; this is the "real"
    # upgrade path.
    assert "-s" not in argv
    assert "install" in argv
    assert "--only-upgrade" in argv
    assert "yara" in argv


def test_run_sift_update_default_packages_is_full_allow_list(
    tmp_path: Path,
) -> None:
    fake_bin = tmp_path / "apt-get"
    fake_bin.write_text("#!/bin/sh\nexit 0\n")
    fake_bin.chmod(0o755)

    fake_proc = CompletedProcess(args=["apt-get"], returncode=0, stdout="", stderr="")
    with patch("core.sift.runner.subprocess.run", return_value=fake_proc) as mock_run:
        run_sift_update(
            consent_token="I-consent",
            apt_get_binary=fake_bin,
            use_sudo=False,
        )
    argv = mock_run.call_args.args[0]
    for pkg in SIFT_UPDATE_PACKAGES:
        assert pkg in argv


def test_run_sift_update_prepends_sudo_when_requested(tmp_path: Path) -> None:
    fake_bin = tmp_path / "apt-get"
    fake_bin.write_text("#!/bin/sh\nexit 0\n")
    fake_bin.chmod(0o755)

    fake_proc = CompletedProcess(args=["apt-get"], returncode=0, stdout="", stderr="")
    with patch("core.sift.runner.subprocess.run", return_value=fake_proc) as mock_run:
        run_sift_update(
            consent_token="I-consent",
            packages=["yara"],
            apt_get_binary=fake_bin,
            use_sudo=True,
        )
    argv = mock_run.call_args.args[0]
    # argv[0] is sudo path, argv[1] is apt-get path.
    assert argv[0].endswith("sudo")
    assert argv[1] == str(fake_bin)


# ---------------------------------------------------------------------------
# audit trail
# ---------------------------------------------------------------------------


def test_run_sift_update_emits_consent_event_before_tool_call(
    tmp_path: Path,
    tmp_log_dir: Path,
) -> None:
    fake_bin = tmp_path / "apt-get"
    fake_bin.write_text("#!/bin/sh\nexit 0\n")
    fake_bin.chmod(0o755)

    fake_proc = CompletedProcess(args=["apt-get"], returncode=0, stdout="", stderr="")
    audit = AuditLogger(incident_id="incident-sift-update", log_dir=tmp_log_dir)
    with patch("core.sift.runner.subprocess.run", return_value=fake_proc):
        run_sift_update(
            consent_token="i-understand",
            packages=["yara", "sleuthkit"],
            audit=audit,
            apt_get_binary=fake_bin,
            use_sudo=False,
        )
    # Consent event must be present.
    consent_events = audit.find("sift_update_consent")
    assert len(consent_events) == 1
    consent = consent_events[0].payload
    assert consent["consent_token_present"] is True
    assert consent["consent_token_length"] == len("i-understand")
    # The raw token must NOT be in the payload.
    assert "i-understand" not in str(consent)
    assert consent["packages"] == ["yara", "sleuthkit"]
    assert consent["dry_run"] is True

    # tool_call start event must come AFTER the consent event.
    all_events = audit.read_all()
    consent_idx = next(
        i
        for i, e in enumerate(all_events)
        if e.event_type == "sift_update_consent"
    )
    tool_call_start_idx = next(
        i
        for i, e in enumerate(all_events)
        if e.event_type == "tool_call" and e.payload.get("phase") == "start"
    )
    assert consent_idx < tool_call_start_idx


def test_run_sift_update_tool_call_payload_mirrors_mode(
    tmp_path: Path,
    tmp_log_dir: Path,
) -> None:
    fake_bin = tmp_path / "apt-get"
    fake_bin.write_text("#!/bin/sh\nexit 0\n")
    fake_bin.chmod(0o755)

    fake_proc = CompletedProcess(args=["apt-get"], returncode=0, stdout="", stderr="")
    audit = AuditLogger(incident_id="incident-sift-update-mode", log_dir=tmp_log_dir)
    with patch("core.sift.runner.subprocess.run", return_value=fake_proc):
        run_sift_update(
            consent_token="i-understand",
            packages=["yara"],
            dry_run=False,
            audit=audit,
            apt_get_binary=fake_bin,
            use_sudo=False,
        )
    start_events = [
        e for e in audit.find("tool_call") if e.payload.get("phase") == "start"
    ]
    assert len(start_events) == 1
    payload = start_events[0].payload
    assert payload["packages"] == ["yara"]
    assert payload["package_reasons"]["yara"] == SIFT_UPDATE_PACKAGES["yara"]
    assert payload["dry_run"] is False
    assert payload["mutates_sift_vm"] is True
    assert payload["use_sudo"] is False
