"""
Tests for core.preflight.

We mock `shutil.which` and `subprocess.run` so these tests run identically
on a SIFT VM, macOS, or a bare CI runner — no real tool binaries required.
"""

from __future__ import annotations

from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from core.preflight import (
    _version_meets_minimum,
    build_evidence_manifest,
    hash_evidence_file,
    preflight,
    probe_tool,
)


def test_version_meets_minimum_basic() -> None:
    assert _version_meets_minimum("2.4.0", "2.4") is True
    assert _version_meets_minimum("2.3", "2.4") is False
    assert _version_meets_minimum("20240601", "20240504") is True
    assert _version_meets_minimum(None, "2.4") is True  # unparsed -> pass through


def test_probe_tool_returns_none_when_absent() -> None:
    with patch("core.preflight.shutil.which", return_value=None):
        assert probe_tool("nonexistent-tool") is None


def test_probe_tool_extracts_version() -> None:
    fake_proc = CompletedProcess(args=["volatility3", "--version"], returncode=0, stdout="Volatility 3 Framework 2.5.0\n", stderr="")
    with (
        patch("core.preflight.shutil.which", return_value="/opt/sift/bin/volatility3"),
        patch("core.preflight.subprocess.run", return_value=fake_proc),
    ):
        tv = probe_tool("volatility3")
    assert tv is not None
    assert tv.name == "volatility3"
    assert tv.version == "3"  # first numeric group in the default extractor
    # Note: minimum is "2.4"; "3" parses to [3] which >= [2,4]=[2,4]? pad: [3,0] >= [2,4] -> True
    assert tv.meets_minimum is True


def test_preflight_missing_required_marks_not_ok() -> None:
    with patch("core.preflight.probe_tool", return_value=None):
        report = preflight("windows-host-triage")
    assert report.ok is False
    assert "volatility3" in report.missing_required


def test_preflight_all_present_marks_ok() -> None:
    from core.types import ToolVersion

    def fake_probe(name: str) -> ToolVersion:
        return ToolVersion(name=name, version="99.0", path=f"/fake/{name}", meets_minimum=True)

    with patch("core.preflight.probe_tool", side_effect=fake_probe):
        report = preflight("memory-only")
    assert report.ok is True
    assert report.missing_required == []


def test_hash_and_manifest_roundtrip(tmp_path: Path) -> None:
    f = tmp_path / "evidence.pcap"
    f.write_bytes(b"PCAPDATA")
    digest = hash_evidence_file(f)
    assert len(digest) == 64  # SHA-256 hex

    manifest = build_evidence_manifest([f])
    assert len(manifest) == 1
    assert manifest[0].sha256 == digest
    assert manifest[0].kind == "pcap"
    assert manifest[0].size_bytes == len(b"PCAPDATA")
