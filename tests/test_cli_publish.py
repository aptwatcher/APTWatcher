"""
Tests for `aptwatcher publish` -- bundle publication adapters.

No real network I/O. All adapter classes are patched with MagicMock
stand-ins so we can observe what the command instantiates + calls.
"""

from __future__ import annotations

import argparse
import json
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

from agent_extension.cli import app
from agent_extension.publish import ALLOWED_ADAPTERS, _load_bundle, cmd_publish

# ---------------------------------------------------------------------------
# Fake core.publish so the cmd_publish import machinery always resolves
# ---------------------------------------------------------------------------


class _FakePublicationError(Exception):
    """Stand-in for core.publish.PublicationError in tests."""


@pytest.fixture
def fake_publish_pkg(monkeypatch):
    """Inject a minimal `core.publish` + submodule shape into sys.modules.

    This lets `cmd_publish` successfully import the adapter classes; the
    individual tests then replace the classes with MagicMock-based fakes.
    """
    pkg = types.ModuleType("core.publish")
    pkg.PublicationError = _FakePublicationError
    monkeypatch.setitem(sys.modules, "core.publish", pkg)

    for submod_name, class_name in [
        ("netcraft", "NetcraftAdapter"),
        ("misp", "MispAdapter"),
        ("glpi_attachment", "GLPIAttachmentAdapter"),
        ("stub", "StubPublicationAdapter"),
    ]:
        mod = types.ModuleType(f"core.publish.{submod_name}")
        setattr(mod, class_name, MagicMock(name=class_name))
        monkeypatch.setitem(sys.modules, f"core.publish.{submod_name}", mod)

    return pkg


# ---------------------------------------------------------------------------
# Bundle helpers
# ---------------------------------------------------------------------------


def _minimal_finding() -> dict:
    return {
        "finding_id": "f-001",
        "summary": "Outbound beacon",
        "mitre": ["T1071.001"],
        "confidence": 0.9,
        "evidence": [
            {"source": "Security.evtx", "locator": "e=4624", "tool_call_id": "c-1"},
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


def _write_bundle_dir(tmp_path: Path) -> Path:
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    (bundle_dir / "findings.json").write_text(
        json.dumps([_minimal_finding()]),
        encoding="utf-8",
    )
    (bundle_dir / "iocs.json").write_text(
        json.dumps([_minimal_ioc()]),
        encoding="utf-8",
    )
    (bundle_dir / "manifest.json").write_text(
        json.dumps({"incident_id": "INC-XYZ", "campaign_tag": "TEST"}),
        encoding="utf-8",
    )
    return bundle_dir


def _base_args(bundle_dir: Path, **overrides) -> argparse.Namespace:
    defaults = {
        "bundle_dir": bundle_dir,
        "adapters": ["stub"],
        "dry_run": True,
        "netcraft_api_key_env": "APTW_NETCRAFT_API_KEY",
        "misp_api_key_env": "APTW_MISP_API_KEY",
        "misp_url": None,
        "glpi_ticket_id": None,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


# ---------------------------------------------------------------------------
# CLI registration
# ---------------------------------------------------------------------------


def test_publish_subcommand_is_registered_in_cli() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    combined = result.stdout + (result.stderr or "")
    assert "publish" in combined


def test_publish_requires_bundle_dir(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["publish", "--adapter", "stub"])
    assert result.exit_code != 0
    combined = result.stdout + (result.stderr or "")
    assert "--bundle-dir" in combined or "Missing option" in combined or "required" in combined.lower()


def test_publish_rejects_unknown_adapter(tmp_path: Path) -> None:
    runner = CliRunner()
    bundle_dir = _write_bundle_dir(tmp_path)
    result = runner.invoke(
        app,
        [
            "publish",
            "--bundle-dir", str(bundle_dir),
            "--adapter", "nonsense",
        ],
    )
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Default dry-run
# ---------------------------------------------------------------------------


def test_publish_dry_run_default_is_true(
    tmp_path: Path, capsys, fake_publish_pkg,
) -> None:
    bundle_dir = _write_bundle_dir(tmp_path)
    from core.publish.stub import StubPublicationAdapter  # type: ignore

    instance = MagicMock()
    instance.publish = MagicMock(return_value={"count": 1})
    StubPublicationAdapter.return_value = instance

    args = _base_args(bundle_dir=bundle_dir)  # dry_run default TRUE
    code = cmd_publish(args)
    assert code == 0
    # Adapter.publish should have been invoked with dry_run=True.
    instance.publish.assert_called_once()
    kw = instance.publish.call_args.kwargs
    assert kw["dry_run"] is True
    out = capsys.readouterr().out
    assert "dry-run" in out


def test_publish_no_dry_run_sets_flag_false(
    tmp_path: Path, fake_publish_pkg,
) -> None:
    bundle_dir = _write_bundle_dir(tmp_path)
    from core.publish.stub import StubPublicationAdapter  # type: ignore

    instance = MagicMock()
    instance.publish = MagicMock(return_value={"count": 1})
    StubPublicationAdapter.return_value = instance

    args = _base_args(bundle_dir=bundle_dir, dry_run=False)
    code = cmd_publish(args)
    assert code == 0
    kw = instance.publish.call_args.kwargs
    assert kw["dry_run"] is False


# ---------------------------------------------------------------------------
# Per-adapter wiring
# ---------------------------------------------------------------------------


def test_publish_stub_adapter_records_call(
    tmp_path: Path, fake_publish_pkg,
) -> None:
    bundle_dir = _write_bundle_dir(tmp_path)
    from core.publish.stub import StubPublicationAdapter  # type: ignore

    instance = MagicMock()
    instance.publish = MagicMock(return_value={"count": 1})
    StubPublicationAdapter.return_value = instance

    args = _base_args(bundle_dir=bundle_dir, adapters=["stub"])
    code = cmd_publish(args)
    assert code == 0
    StubPublicationAdapter.assert_called_once_with()
    instance.publish.assert_called_once()
    kw = instance.publish.call_args.kwargs
    assert kw["incident_id"] == "INC-XYZ"
    assert kw["campaign_tag"] == "TEST"
    assert len(kw["findings"]) == 1
    assert len(kw["iocs"]) == 1


def test_publish_netcraft_adapter_reads_env_var(
    tmp_path: Path, monkeypatch, fake_publish_pkg,
) -> None:
    bundle_dir = _write_bundle_dir(tmp_path)
    monkeypatch.setenv("APTW_NETCRAFT_TEST", "nc-secret-xyz")
    from core.publish.netcraft import NetcraftAdapter  # type: ignore

    instance = MagicMock()
    instance.publish = MagicMock(return_value={"count": 2})
    NetcraftAdapter.return_value = instance

    args = _base_args(
        bundle_dir=bundle_dir,
        adapters=["netcraft"],
        netcraft_api_key_env="APTW_NETCRAFT_TEST",
        dry_run=False,
    )
    code = cmd_publish(args)
    assert code == 0
    NetcraftAdapter.assert_called_once()
    ck = NetcraftAdapter.call_args.kwargs
    assert ck["api_key"] == "nc-secret-xyz"


def test_publish_misp_adapter_requires_url(
    tmp_path: Path, monkeypatch, capsys, fake_publish_pkg,
) -> None:
    bundle_dir = _write_bundle_dir(tmp_path)
    monkeypatch.setenv("APTW_MISP_TEST", "misp-secret")
    args = _base_args(
        bundle_dir=bundle_dir,
        adapters=["misp"],
        misp_api_key_env="APTW_MISP_TEST",
        misp_url=None,
    )
    code = cmd_publish(args)
    assert code == 1
    err = capsys.readouterr().err
    assert "misp-url" in err


def test_publish_misp_adapter_instantiates_with_url_and_key(
    tmp_path: Path, monkeypatch, fake_publish_pkg,
) -> None:
    bundle_dir = _write_bundle_dir(tmp_path)
    monkeypatch.setenv("APTW_MISP_TEST", "misp-secret")
    from core.publish.misp import MispAdapter  # type: ignore

    instance = MagicMock()
    instance.publish = MagicMock(return_value={"count": 3})
    MispAdapter.return_value = instance

    args = _base_args(
        bundle_dir=bundle_dir,
        adapters=["misp"],
        misp_api_key_env="APTW_MISP_TEST",
        misp_url="https://misp.example.com",
    )
    code = cmd_publish(args)
    assert code == 0
    MispAdapter.assert_called_once()
    ck = MispAdapter.call_args.kwargs
    assert ck["api_key"] == "misp-secret"
    assert ck["base_url"] == "https://misp.example.com"


def test_publish_glpi_adapter_requires_ticket_id(
    tmp_path: Path, capsys, fake_publish_pkg,
) -> None:
    bundle_dir = _write_bundle_dir(tmp_path)
    args = _base_args(
        bundle_dir=bundle_dir,
        adapters=["glpi"],
        glpi_ticket_id=None,
    )
    code = cmd_publish(args)
    assert code == 1
    err = capsys.readouterr().err
    assert "glpi-ticket-id" in err


def test_publish_glpi_adapter_passes_ticket_and_bundle_dir(
    tmp_path: Path, fake_publish_pkg,
) -> None:
    bundle_dir = _write_bundle_dir(tmp_path)
    from core.publish.glpi_attachment import GLPIAttachmentAdapter  # type: ignore

    instance = MagicMock()
    instance.publish = MagicMock(return_value={"count": 1})
    GLPIAttachmentAdapter.return_value = instance

    args = _base_args(
        bundle_dir=bundle_dir,
        adapters=["glpi"],
        glpi_ticket_id=12345,
    )
    code = cmd_publish(args)
    assert code == 0
    GLPIAttachmentAdapter.assert_called_once()
    ck = GLPIAttachmentAdapter.call_args.kwargs
    assert ck["ticket_id"] == 12345
    assert ck["bundle_dir"] == bundle_dir


# ---------------------------------------------------------------------------
# Error propagation
# ---------------------------------------------------------------------------


def test_publish_publication_error_exits_3(
    tmp_path: Path, capsys, fake_publish_pkg,
) -> None:
    bundle_dir = _write_bundle_dir(tmp_path)
    from core.publish.stub import StubPublicationAdapter  # type: ignore

    instance = MagicMock()
    instance.publish.side_effect = _FakePublicationError("upstream rejected batch")
    StubPublicationAdapter.return_value = instance

    args = _base_args(bundle_dir=bundle_dir, adapters=["stub"])
    code = cmd_publish(args)
    assert code == 3
    err = capsys.readouterr().err
    assert "PublicationError" in err or "upstream rejected" in err


def test_publish_missing_bundle_dir_returns_1(
    tmp_path: Path, capsys, fake_publish_pkg,
) -> None:
    args = _base_args(bundle_dir=tmp_path / "no-such-bundle")
    code = cmd_publish(args)
    assert code == 1
    err = capsys.readouterr().err
    assert "not found" in err.lower()


def test_publish_multiple_adapters_run_in_sequence(
    tmp_path: Path, fake_publish_pkg,
) -> None:
    bundle_dir = _write_bundle_dir(tmp_path)
    from core.publish.glpi_attachment import GLPIAttachmentAdapter  # type: ignore
    from core.publish.stub import StubPublicationAdapter  # type: ignore

    stub_inst = MagicMock()
    stub_inst.publish = MagicMock(return_value={"count": 1})
    StubPublicationAdapter.return_value = stub_inst

    glpi_inst = MagicMock()
    glpi_inst.publish = MagicMock(return_value={"count": 2})
    GLPIAttachmentAdapter.return_value = glpi_inst

    args = _base_args(
        bundle_dir=bundle_dir,
        adapters=["stub", "glpi"],
        glpi_ticket_id=42,
    )
    code = cmd_publish(args)
    assert code == 0
    stub_inst.publish.assert_called_once()
    glpi_inst.publish.assert_called_once()


# ---------------------------------------------------------------------------
# Bundle loading
# ---------------------------------------------------------------------------


def test_load_bundle_reads_findings_iocs_manifest(tmp_path: Path) -> None:
    bundle_dir = _write_bundle_dir(tmp_path)
    findings, iocs, manifest = _load_bundle(bundle_dir)
    assert len(findings) == 1
    assert len(iocs) == 1
    assert manifest["incident_id"] == "INC-XYZ"
    assert manifest["campaign_tag"] == "TEST"


def test_load_bundle_raises_when_directory_missing(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        _load_bundle(tmp_path / "no-bundle")


def test_allowed_adapters_covers_documented_set() -> None:
    assert set(ALLOWED_ADAPTERS) == {"netcraft", "misp", "glpi", "stub", "taxii"}
