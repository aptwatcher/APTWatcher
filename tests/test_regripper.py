"""
Tests for core.sift.regripper -- Tier 0 Windows registry triage wrapper.

Mocks ``subprocess.run`` so the suite runs on any host. Verifies:

- argv shape for plugin and profile invocations
- plugin allow-list enforcement (known-good plugins accepted, unknown
  plugins rejected with ``RegRipperPluginError``)
- profile allow-list enforcement (known-good profiles accepted,
  unknown profiles rejected with ``RegRipperProfileError``)
- hive-missing and hive-is-a-directory precondition failures
  (``ToolRunError``)
- binary resolution: ``rip.pl`` preferred, ``rip`` fallback, neither
  present raises ``ToolRunError``
- audit payload carries ``evidence_readonly_assumed=True`` plus the
  mode (plugin/profile), hive path, and the plugin/profile name
- timeout value propagates to the underlying ``subprocess.run`` call
- module ``__all__`` lists the documented public surface
"""

from __future__ import annotations

from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from core.audit import AuditLogger
from core.sift import regripper as regripper_mod
from core.sift.regripper import (
    REGRIPPER_PLUGINS,
    REGRIPPER_PROFILES,
    RegRipperPluginError,
    RegRipperProfileError,
    _resolve_binary,
    run_regripper_plugin,
    run_regripper_profile,
)
from core.sift.runner import ToolRunError

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _fake_binary(tmp_path: Path, name: str = "rip.pl") -> Path:
    """Materialize a pretend RegRipper binary so the runner's exists() check passes."""
    fake_bin = tmp_path / name
    fake_bin.write_text("#!/bin/sh\nexit 0\n")
    fake_bin.chmod(0o755)
    return fake_bin


def _fake_proc() -> CompletedProcess[str]:
    return CompletedProcess(args=["rip.pl"], returncode=0, stdout="", stderr="")


def _hive(tmp_path: Path, name: str = "SYSTEM") -> Path:
    """Create a placeholder regular file that plays the role of a registry hive."""
    hive = tmp_path / name
    hive.write_bytes(b"regf")
    return hive


# ---------------------------------------------------------------------------
# public surface
# ---------------------------------------------------------------------------


def test_module_exports_documented_public_surface() -> None:
    assert set(regripper_mod.__all__) == {
        "REGRIPPER_PLUGINS",
        "REGRIPPER_PROFILES",
        "RegRipperPluginError",
        "RegRipperProfileError",
        "run_regripper_plugin",
        "run_regripper_profile",
    }


def test_plugins_allow_list_covers_required_categories() -> None:
    # Spot-check: every documented category is represented by at least
    # one plugin key. Guards against accidental deletions.
    required = {
        # system hive triage
        "compname",
        "winver",
        "timezone",
        # persistence
        "run",
        "runonce",
        "services",
        # user activity
        "userassist",
        "muicache",
        "shellbags",
        # execution evidence
        "appcompatcache",
        "shimcache",
        "amcache",
        # removable media
        "usb",
        "mountpoints2",
        # logging policy
        "auditpol",
    }
    assert required.issubset(REGRIPPER_PLUGINS.keys())
    # Every reason is a non-empty string.
    for name, reason in REGRIPPER_PLUGINS.items():
        assert isinstance(reason, str) and reason.strip(), name


def test_profiles_allow_list_has_classic_five() -> None:
    assert set(REGRIPPER_PROFILES) == {
        "software",
        "system",
        "ntuser",
        "sam",
        "security",
    }
    for name, reason in REGRIPPER_PROFILES.items():
        assert isinstance(reason, str) and reason.strip(), name


# ---------------------------------------------------------------------------
# plugin -- argv shape + acceptance
# ---------------------------------------------------------------------------


def test_plugin_argv_shape_run_against_system_hive(tmp_path: Path) -> None:
    hive = _hive(tmp_path, "SYSTEM")
    fake_bin = _fake_binary(tmp_path)

    with patch(
        "core.sift.runner.subprocess.run", return_value=_fake_proc()
    ) as mock_run:
        result = run_regripper_plugin(
            hive=hive,
            plugin="run",
            regripper_binary=fake_bin,
        )
    assert result.ok is True
    argv = mock_run.call_args.args[0]
    assert argv[0] == str(fake_bin)
    # Order matters: `-r <hive>` must come before `-p <plugin>`.
    assert argv[1] == "-r"
    assert argv[2] == str(hive)
    assert argv[3] == "-p"
    assert argv[4] == "run"
    # No profile flag should appear in a plugin invocation.
    assert "-f" not in argv
    # No "list plugins" flag should ever be emitted from the wrapper.
    assert "-l" not in argv


def test_plugin_accepts_every_key_in_allow_list(tmp_path: Path) -> None:
    # Smoke test: every allow-listed plugin name is accepted and
    # forwarded verbatim. Guards against argv-builder bugs.
    hive = _hive(tmp_path, "NTUSER.DAT")
    fake_bin = _fake_binary(tmp_path)
    with patch("core.sift.runner.subprocess.run", return_value=_fake_proc()):
        for plugin in REGRIPPER_PLUGINS:
            result = run_regripper_plugin(
                hive=hive,
                plugin=plugin,
                regripper_binary=fake_bin,
            )
            assert result.ok is True


# ---------------------------------------------------------------------------
# plugin -- rejection paths
# ---------------------------------------------------------------------------


def test_plugin_rejects_unknown_plugin(tmp_path: Path) -> None:
    hive = _hive(tmp_path)
    with pytest.raises(RegRipperPluginError) as excinfo:
        run_regripper_plugin(
            hive=hive,
            plugin="definitely-not-a-real-plugin",
        )
    # Error message must mention the supported vocabulary so callers
    # can self-correct without reading the module source.
    assert "Tier 0 allow-list" in str(excinfo.value)


def test_plugin_rejects_missing_hive(tmp_path: Path) -> None:
    with pytest.raises(ToolRunError):
        run_regripper_plugin(
            hive=tmp_path / "does-not-exist",
            plugin="run",
        )


def test_plugin_rejects_directory_hive(tmp_path: Path) -> None:
    hive_dir = tmp_path / "SYSTEM.dir"
    hive_dir.mkdir()
    fake_bin = _fake_binary(tmp_path)
    with pytest.raises(ToolRunError) as excinfo:
        run_regripper_plugin(
            hive=hive_dir,
            plugin="run",
            regripper_binary=fake_bin,
        )
    assert "not a regular file" in str(excinfo.value)


# ---------------------------------------------------------------------------
# profile -- argv shape + acceptance
# ---------------------------------------------------------------------------


def test_profile_argv_shape_run_against_software_hive(tmp_path: Path) -> None:
    hive = _hive(tmp_path, "SOFTWARE")
    fake_bin = _fake_binary(tmp_path)

    with patch(
        "core.sift.runner.subprocess.run", return_value=_fake_proc()
    ) as mock_run:
        result = run_regripper_profile(
            hive=hive,
            profile="software",
            regripper_binary=fake_bin,
        )
    assert result.ok is True
    argv = mock_run.call_args.args[0]
    assert argv[0] == str(fake_bin)
    assert argv[1] == "-r"
    assert argv[2] == str(hive)
    assert argv[3] == "-f"
    assert argv[4] == "software"
    # A profile invocation must not emit a plugin flag.
    assert "-p" not in argv


def test_profile_accepts_every_key_in_allow_list(tmp_path: Path) -> None:
    hive = _hive(tmp_path)
    fake_bin = _fake_binary(tmp_path)
    with patch("core.sift.runner.subprocess.run", return_value=_fake_proc()):
        for profile in REGRIPPER_PROFILES:
            result = run_regripper_profile(
                hive=hive,
                profile=profile,
                regripper_binary=fake_bin,
            )
            assert result.ok is True


# ---------------------------------------------------------------------------
# profile -- rejection paths
# ---------------------------------------------------------------------------


def test_profile_rejects_unknown_profile(tmp_path: Path) -> None:
    hive = _hive(tmp_path)
    with pytest.raises(RegRipperProfileError) as excinfo:
        run_regripper_profile(
            hive=hive,
            profile="brandnew",
        )
    assert "Tier 0 allow-list" in str(excinfo.value)


def test_profile_rejects_missing_hive(tmp_path: Path) -> None:
    with pytest.raises(ToolRunError):
        run_regripper_profile(
            hive=tmp_path / "absent",
            profile="system",
        )


def test_profile_rejects_directory_hive(tmp_path: Path) -> None:
    hive_dir = tmp_path / "SOFTWARE.dir"
    hive_dir.mkdir()
    fake_bin = _fake_binary(tmp_path)
    with pytest.raises(ToolRunError):
        run_regripper_profile(
            hive=hive_dir,
            profile="software",
            regripper_binary=fake_bin,
        )


# ---------------------------------------------------------------------------
# binary resolution fallback
# ---------------------------------------------------------------------------


def test_resolve_binary_prefers_rip_pl_over_rip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rip_pl = _fake_binary(tmp_path, "rip.pl")
    rip = _fake_binary(tmp_path, "rip")

    def fake_which(name: str) -> str | None:
        if name == "rip.pl":
            return str(rip_pl)
        if name == "rip":
            return str(rip)
        return None

    monkeypatch.setattr("core.sift.regripper.shutil.which", fake_which)
    resolved = _resolve_binary()
    assert resolved == rip_pl


def test_resolve_binary_falls_back_to_rip_when_rip_pl_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rip = _fake_binary(tmp_path, "rip")

    def fake_which(name: str) -> str | None:
        if name == "rip":
            return str(rip)
        return None

    monkeypatch.setattr("core.sift.regripper.shutil.which", fake_which)
    resolved = _resolve_binary()
    assert resolved == rip


def test_resolve_binary_raises_when_neither_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "core.sift.regripper.shutil.which", lambda _name: None
    )
    with pytest.raises(ToolRunError) as excinfo:
        _resolve_binary()
    # Error must surface both probed names so preflight / operator can
    # act on it without reading the source.
    assert "rip.pl" in str(excinfo.value)
    assert "rip" in str(excinfo.value)


# ---------------------------------------------------------------------------
# audit payload
# ---------------------------------------------------------------------------


def test_plugin_audit_payload_marks_evidence_readonly(
    tmp_path: Path,
    tmp_log_dir: Path,
) -> None:
    hive = _hive(tmp_path, "SYSTEM")
    fake_bin = _fake_binary(tmp_path)
    audit = AuditLogger(incident_id="incident-regripper", log_dir=tmp_log_dir)

    with patch("core.sift.runner.subprocess.run", return_value=_fake_proc()):
        run_regripper_plugin(
            hive=hive,
            plugin="services",
            audit=audit,
            regripper_binary=fake_bin,
        )
    start_events = [
        e for e in audit.find("tool_call") if e.payload.get("phase") == "start"
    ]
    assert len(start_events) == 1
    payload = start_events[0].payload
    assert payload["tool"] == "regripper"
    assert payload["mode"] == "plugin"
    assert payload["plugin"] == "services"
    assert payload["hive"] == str(hive)
    assert payload["evidence_readonly_assumed"] is True
    # The plugin reason should be surfaced for downstream review.
    assert payload["plugin_reason"] == REGRIPPER_PLUGINS["services"]


def test_profile_audit_payload_marks_evidence_readonly(
    tmp_path: Path,
    tmp_log_dir: Path,
) -> None:
    hive = _hive(tmp_path, "NTUSER.DAT")
    fake_bin = _fake_binary(tmp_path)
    audit = AuditLogger(
        incident_id="incident-regripper-profile", log_dir=tmp_log_dir
    )

    with patch("core.sift.runner.subprocess.run", return_value=_fake_proc()):
        run_regripper_profile(
            hive=hive,
            profile="ntuser",
            audit=audit,
            regripper_binary=fake_bin,
        )
    start_events = [
        e for e in audit.find("tool_call") if e.payload.get("phase") == "start"
    ]
    assert len(start_events) == 1
    payload = start_events[0].payload
    assert payload["tool"] == "regripper"
    assert payload["mode"] == "profile"
    assert payload["profile"] == "ntuser"
    assert payload["hive"] == str(hive)
    assert payload["evidence_readonly_assumed"] is True
    assert payload["profile_reason"] == REGRIPPER_PROFILES["ntuser"]


# ---------------------------------------------------------------------------
# timeout propagation
# ---------------------------------------------------------------------------


def test_plugin_timeout_propagates_to_subprocess(tmp_path: Path) -> None:
    hive = _hive(tmp_path)
    fake_bin = _fake_binary(tmp_path)
    with patch(
        "core.sift.runner.subprocess.run", return_value=_fake_proc()
    ) as mock_run:
        run_regripper_plugin(
            hive=hive,
            plugin="run",
            timeout=42.0,
            regripper_binary=fake_bin,
        )
    assert mock_run.call_args.kwargs["timeout"] == 42.0


def test_profile_timeout_propagates_to_subprocess(tmp_path: Path) -> None:
    hive = _hive(tmp_path)
    fake_bin = _fake_binary(tmp_path)
    with patch(
        "core.sift.runner.subprocess.run", return_value=_fake_proc()
    ) as mock_run:
        run_regripper_profile(
            hive=hive,
            profile="software",
            timeout=123.5,
            regripper_binary=fake_bin,
        )
    assert mock_run.call_args.kwargs["timeout"] == 123.5
