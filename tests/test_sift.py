"""
Tests for core.sift — Tier 0 SIFT tool wrappers.

Mocks subprocess.run and shutil.which so the suite runs on any host,
not just a SIFT VM with real vol3 installed.
"""

from __future__ import annotations

from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired
from unittest.mock import patch

import pytest

from core.audit import AuditLogger
from core.sift.runner import ToolRunError, run_tool
from core.sift.volatility import (
    VOLATILITY_PLUGINS,
    VolatilityPluginError,
    run_volatility,
)

# ---------------------------------------------------------------------------
# runner
# ---------------------------------------------------------------------------


def test_run_tool_rejects_empty_argv() -> None:
    with pytest.raises(ToolRunError):
        run_tool([], tool_name="whatever")


def test_run_tool_rejects_unresolved_binary() -> None:
    with pytest.raises(ToolRunError):
        run_tool(["vol.py", "-f", "mem.vmem"], tool_name="volatility3")


def test_run_tool_captures_stdout_and_returncode(tmp_path: Path) -> None:
    # Use a real binary that exists on every POSIX: /bin/echo
    binary = Path("/bin/echo")
    if not binary.exists():
        pytest.skip("/bin/echo not available on this host")
    result = run_tool([str(binary), "hello"], tool_name="echo-test", timeout=5.0)
    assert result.ok is True
    assert result.returncode == 0
    assert "hello" in result.stdout
    assert result.duration_seconds >= 0.0
    assert result.correlation_id


def test_run_tool_writes_audit_start_and_end_events(tmp_log_dir: Path) -> None:
    binary = Path("/bin/echo")
    if not binary.exists():
        pytest.skip("/bin/echo not available on this host")
    audit = AuditLogger(incident_id="incident-sift-test", log_dir=tmp_log_dir)
    result = run_tool(
        [str(binary), "auditable"],
        tool_name="echo-test",
        audit=audit,
        timeout=5.0,
    )
    events = audit.find("tool_call")
    # One start + one end event, same correlation_id, different phases.
    assert len(events) == 2
    assert {e.payload["phase"] for e in events} == {"start", "end"}
    assert all(e.correlation_id == result.correlation_id for e in events)


def test_run_tool_timeout_reported(tmp_path: Path) -> None:
    fake_binary = tmp_path / "fake-vol"
    fake_binary.write_text("#!/bin/sh\nexit 0\n")
    fake_binary.chmod(0o755)

    def _raise_timeout(*a: object, **kw: object) -> CompletedProcess[str]:
        raise TimeoutExpired(cmd=kw.get("args") or a[0], timeout=1.0)

    with patch("core.sift.runner.subprocess.run", side_effect=_raise_timeout):
        result = run_tool([str(fake_binary)], tool_name="slow", timeout=1.0)
    assert result.timed_out is True
    assert result.ok is False
    assert result.returncode == -1


# ---------------------------------------------------------------------------
# volatility wrapper
# ---------------------------------------------------------------------------


def test_volatility_allow_list_has_expected_plugins() -> None:
    # Guard against silent plugin removal.
    assert "windows.pslist.PsList" in VOLATILITY_PLUGINS
    assert "windows.malfind.Malfind" in VOLATILITY_PLUGINS
    for plugin in VOLATILITY_PLUGINS:
        assert "." in plugin, f"plugin {plugin!r} is not dotted-path form"


def test_run_volatility_rejects_unknown_plugin(tmp_path: Path) -> None:
    mem = tmp_path / "mem.vmem"
    mem.write_bytes(b"FAKEMEM")
    with pytest.raises(VolatilityPluginError):
        run_volatility(memory_image=mem, plugin="windows.not.real.Plugin")


def test_run_volatility_rejects_missing_image(tmp_path: Path) -> None:
    with pytest.raises(ToolRunError):
        run_volatility(memory_image=tmp_path / "does-not-exist.vmem", plugin="windows.pslist.PsList")


def test_run_volatility_builds_expected_argv(tmp_path: Path) -> None:
    mem = tmp_path / "mem.vmem"
    mem.write_bytes(b"FAKEMEM")
    fake_vol = tmp_path / "vol3"
    fake_vol.write_text("#!/bin/sh\nexit 0\n")
    fake_vol.chmod(0o755)

    fake_proc = CompletedProcess(
        args=["vol3"],
        returncode=0,
        stdout="PID\tPPID\tImageFileName\n4\t0\tSystem\n",
        stderr="",
    )
    with patch("core.sift.runner.subprocess.run", return_value=fake_proc) as mock_run:
        result = run_volatility(
            memory_image=mem,
            plugin="windows.pslist.PsList",
            vol_binary=fake_vol,
        )
    assert result.ok is True
    # First positional arg to subprocess.run is the argv.
    called_argv = mock_run.call_args.args[0]
    assert called_argv[0] == str(fake_vol)
    assert "-f" in called_argv
    assert str(mem) in called_argv
    assert "windows.pslist.PsList" in called_argv
    assert "-q" in called_argv


def test_run_volatility_audit_payload_includes_plugin_reason(
    tmp_path: Path,
    tmp_log_dir: Path,
) -> None:
    mem = tmp_path / "mem.vmem"
    mem.write_bytes(b"FAKEMEM")
    fake_vol = tmp_path / "vol3"
    fake_vol.write_text("#!/bin/sh\nexit 0\n")
    fake_vol.chmod(0o755)

    fake_proc = CompletedProcess(args=["vol3"], returncode=0, stdout="", stderr="")
    audit = AuditLogger(incident_id="incident-volatility-test", log_dir=tmp_log_dir)
    with patch("core.sift.runner.subprocess.run", return_value=fake_proc):
        run_volatility(
            memory_image=mem,
            plugin="windows.pslist.PsList",
            audit=audit,
            vol_binary=fake_vol,
        )
    start_events = [e for e in audit.find("tool_call") if e.payload.get("phase") == "start"]
    assert len(start_events) == 1
    payload = start_events[0].payload
    assert payload["plugin"] == "windows.pslist.PsList"
    assert "plugin_reason" in payload
    assert payload["memory_image"] == str(mem)
    assert payload["evidence_readonly_assumed"] is True
