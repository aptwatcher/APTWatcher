"""
Tests for core.sift.chainsaw -- Tier 0 EVTX Sigma-hunt + search wrapper.

Mocks subprocess.run so the suite runs on any host. Verifies:
- subcommand allow-list shape (CHAINSAW_SUBCOMMANDS)
- output-format allow-list shape (good + bad)
- argv shape for `hunt` with directory and single-file evtx sources
- argv shape for `search` with safe search terms
- precondition errors: missing evtx_source, missing sigma rules dir,
  missing mapping file, non-empty output path, missing output parent,
  unsupported output_format
- search-term safety: shell metacharacters rejected, empty rejected
- audit payload carries `evidence_readonly_assumed=True` plus the
  canonical metadata (subcommand, output_format, paths, term)
- timeout is propagated to subprocess.run
- binary resolution error when chainsaw is not on PATH
- module's `__all__` matches the documented public surface
"""

from __future__ import annotations

from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from core.audit import AuditLogger
from core.sift import chainsaw as chainsaw_mod
from core.sift.chainsaw import (
    CHAINSAW_OUTPUT_FORMATS,
    CHAINSAW_SUBCOMMANDS,
    ChainsawOutputFormatError,
    ChainsawSearchError,
    ChainsawSubcommandError,
    run_chainsaw_hunt,
    run_chainsaw_search,
)
from core.sift.runner import ToolRunError

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _fake_binary(tmp_path: Path, name: str = "chainsaw") -> Path:
    fake_bin = tmp_path / name
    fake_bin.write_text("#!/bin/sh\nexit 0\n")
    fake_bin.chmod(0o755)
    return fake_bin


def _fake_proc() -> CompletedProcess[str]:
    return CompletedProcess(args=["chainsaw"], returncode=0, stdout="", stderr="")


def _evtx_dir(tmp_path: Path) -> Path:
    evtx_dir = tmp_path / "evtx"
    evtx_dir.mkdir()
    (evtx_dir / "Security.evtx").write_bytes(b"ELFF")
    return evtx_dir


def _evtx_file(tmp_path: Path) -> Path:
    evtx = tmp_path / "Security.evtx"
    evtx.write_bytes(b"ELFF")
    return evtx


def _sigma_dir(tmp_path: Path) -> Path:
    d = tmp_path / "sigma"
    d.mkdir()
    (d / "rule.yml").write_text("title: example\n")
    return d


def _mapping_file(tmp_path: Path) -> Path:
    m = tmp_path / "mapping.yml"
    m.write_text("fields: {}\n")
    return m


# ---------------------------------------------------------------------------
# public surface & allow-list shapes
# ---------------------------------------------------------------------------


def test_module_exports_documented_public_surface() -> None:
    assert set(chainsaw_mod.__all__) == {
        "CHAINSAW_OUTPUT_FORMATS",
        "CHAINSAW_SUBCOMMANDS",
        "ChainsawOutputFormatError",
        "ChainsawSearchError",
        "ChainsawSubcommandError",
        "run_chainsaw_hunt",
        "run_chainsaw_search",
    }


def test_subcommand_allow_list_shape() -> None:
    # Only `hunt` and `search` are in the Tier 0 allow-list.
    assert set(CHAINSAW_SUBCOMMANDS) == {"hunt", "search"}
    for reason in CHAINSAW_SUBCOMMANDS.values():
        assert isinstance(reason, str) and reason.strip()


def test_output_format_allow_list_shape() -> None:
    assert set(CHAINSAW_OUTPUT_FORMATS) == {"json", "csv"}
    for reason in CHAINSAW_OUTPUT_FORMATS.values():
        assert isinstance(reason, str) and reason.strip()


def test_error_class_hierarchy() -> None:
    assert issubclass(ChainsawSubcommandError, ValueError)
    assert issubclass(ChainsawOutputFormatError, ValueError)
    assert issubclass(ChainsawSearchError, ValueError)


# ---------------------------------------------------------------------------
# hunt -- argv shape
# ---------------------------------------------------------------------------


def test_hunt_argv_with_directory_source_json(tmp_path: Path) -> None:
    src = _evtx_dir(tmp_path)
    sigma = _sigma_dir(tmp_path)
    mapping = _mapping_file(tmp_path)
    out = tmp_path / "hunt.json"
    fake_bin = _fake_binary(tmp_path)

    with patch(
        "core.sift.runner.subprocess.run", return_value=_fake_proc()
    ) as mock_run:
        result = run_chainsaw_hunt(
            evtx_source=src,
            sigma_rules_dir=sigma,
            mapping=mapping,
            output_path=out,
            output_format="json",
            chainsaw_binary=fake_bin,
        )
    assert result.ok is True
    argv = mock_run.call_args.args[0]
    assert argv[0] == str(fake_bin)
    assert argv[1] == "hunt"
    # evtx source is the first positional after the subcommand
    assert argv[2] == str(src)
    # -s <sigma_rules_dir>
    assert "-s" in argv
    s_idx = argv.index("-s")
    assert argv[s_idx + 1] == str(sigma)
    # --mapping <mapping>
    assert "--mapping" in argv
    m_idx = argv.index("--mapping")
    assert argv[m_idx + 1] == str(mapping)
    # -o <output_path>
    assert "-o" in argv
    o_idx = argv.index("-o")
    assert argv[o_idx + 1] == str(out)
    # output format flag (--json / --csv)
    assert "--json" in argv
    assert "--csv" not in argv


def test_hunt_argv_with_file_source_csv(tmp_path: Path) -> None:
    src = _evtx_file(tmp_path)
    sigma = _sigma_dir(tmp_path)
    mapping = _mapping_file(tmp_path)
    out = tmp_path / "hunt.csv"
    fake_bin = _fake_binary(tmp_path)

    with patch(
        "core.sift.runner.subprocess.run", return_value=_fake_proc()
    ) as mock_run:
        run_chainsaw_hunt(
            evtx_source=src,
            sigma_rules_dir=sigma,
            mapping=mapping,
            output_path=out,
            output_format="csv",
            chainsaw_binary=fake_bin,
        )
    argv = mock_run.call_args.args[0]
    assert argv[1] == "hunt"
    assert argv[2] == str(src)
    assert "--csv" in argv
    assert "--json" not in argv


# ---------------------------------------------------------------------------
# hunt -- rejection paths
# ---------------------------------------------------------------------------


def test_hunt_rejects_missing_evtx_source(tmp_path: Path) -> None:
    sigma = _sigma_dir(tmp_path)
    mapping = _mapping_file(tmp_path)
    out = tmp_path / "hunt.json"
    with pytest.raises(ToolRunError):
        run_chainsaw_hunt(
            evtx_source=tmp_path / "nope.evtx",
            sigma_rules_dir=sigma,
            mapping=mapping,
            output_path=out,
        )


def test_hunt_rejects_missing_sigma_rules_dir(tmp_path: Path) -> None:
    src = _evtx_dir(tmp_path)
    mapping = _mapping_file(tmp_path)
    out = tmp_path / "hunt.json"
    with pytest.raises(ToolRunError):
        run_chainsaw_hunt(
            evtx_source=src,
            sigma_rules_dir=tmp_path / "missing-sigma",
            mapping=mapping,
            output_path=out,
        )


def test_hunt_rejects_sigma_rules_dir_that_is_a_file(tmp_path: Path) -> None:
    src = _evtx_dir(tmp_path)
    fake_sigma = tmp_path / "not-a-dir"
    fake_sigma.write_text("oops")
    mapping = _mapping_file(tmp_path)
    out = tmp_path / "hunt.json"
    with pytest.raises(ToolRunError):
        run_chainsaw_hunt(
            evtx_source=src,
            sigma_rules_dir=fake_sigma,
            mapping=mapping,
            output_path=out,
        )


def test_hunt_rejects_missing_mapping(tmp_path: Path) -> None:
    src = _evtx_dir(tmp_path)
    sigma = _sigma_dir(tmp_path)
    out = tmp_path / "hunt.json"
    with pytest.raises(ToolRunError):
        run_chainsaw_hunt(
            evtx_source=src,
            sigma_rules_dir=sigma,
            mapping=tmp_path / "nope-mapping.yml",
            output_path=out,
        )


def test_hunt_rejects_unsupported_output_format(tmp_path: Path) -> None:
    src = _evtx_dir(tmp_path)
    sigma = _sigma_dir(tmp_path)
    mapping = _mapping_file(tmp_path)
    out = tmp_path / "hunt.xml"
    with pytest.raises(ChainsawOutputFormatError):
        run_chainsaw_hunt(
            evtx_source=src,
            sigma_rules_dir=sigma,
            mapping=mapping,
            output_path=out,
            output_format="xml",
        )


def test_hunt_refuses_to_overwrite_populated_output_file(tmp_path: Path) -> None:
    src = _evtx_dir(tmp_path)
    sigma = _sigma_dir(tmp_path)
    mapping = _mapping_file(tmp_path)
    out = tmp_path / "hunt.json"
    out.write_text("prior run content")
    fake_bin = _fake_binary(tmp_path)
    with pytest.raises(ToolRunError):
        run_chainsaw_hunt(
            evtx_source=src,
            sigma_rules_dir=sigma,
            mapping=mapping,
            output_path=out,
            chainsaw_binary=fake_bin,
        )


def test_hunt_refuses_to_overwrite_populated_output_directory(
    tmp_path: Path,
) -> None:
    src = _evtx_dir(tmp_path)
    sigma = _sigma_dir(tmp_path)
    mapping = _mapping_file(tmp_path)
    out_dir = tmp_path / "hunt_out"
    out_dir.mkdir()
    (out_dir / "old.json").write_text("prior")
    fake_bin = _fake_binary(tmp_path)
    with pytest.raises(ToolRunError):
        run_chainsaw_hunt(
            evtx_source=src,
            sigma_rules_dir=sigma,
            mapping=mapping,
            output_path=out_dir,
            chainsaw_binary=fake_bin,
        )


def test_hunt_allows_empty_output_directory(tmp_path: Path) -> None:
    src = _evtx_dir(tmp_path)
    sigma = _sigma_dir(tmp_path)
    mapping = _mapping_file(tmp_path)
    out_dir = tmp_path / "hunt_out"
    out_dir.mkdir()
    fake_bin = _fake_binary(tmp_path)

    with patch(
        "core.sift.runner.subprocess.run", return_value=_fake_proc()
    ) as mock_run:
        run_chainsaw_hunt(
            evtx_source=src,
            sigma_rules_dir=sigma,
            mapping=mapping,
            output_path=out_dir,
            chainsaw_binary=fake_bin,
        )
    argv = mock_run.call_args.args[0]
    assert str(out_dir) in argv


def test_hunt_rejects_missing_output_parent(tmp_path: Path) -> None:
    src = _evtx_dir(tmp_path)
    sigma = _sigma_dir(tmp_path)
    mapping = _mapping_file(tmp_path)
    out = tmp_path / "nowhere" / "hunt.json"
    fake_bin = _fake_binary(tmp_path)
    with pytest.raises(ToolRunError):
        run_chainsaw_hunt(
            evtx_source=src,
            sigma_rules_dir=sigma,
            mapping=mapping,
            output_path=out,
            chainsaw_binary=fake_bin,
        )


# ---------------------------------------------------------------------------
# search -- argv shape
# ---------------------------------------------------------------------------


def test_search_argv_with_directory_source_json(tmp_path: Path) -> None:
    src = _evtx_dir(tmp_path)
    out = tmp_path / "search.json"
    fake_bin = _fake_binary(tmp_path)

    with patch(
        "core.sift.runner.subprocess.run", return_value=_fake_proc()
    ) as mock_run:
        result = run_chainsaw_search(
            evtx_source=src,
            search_term="mimikatz",
            output_path=out,
            chainsaw_binary=fake_bin,
        )
    assert result.ok is True
    argv = mock_run.call_args.args[0]
    assert argv[0] == str(fake_bin)
    assert argv[1] == "search"
    assert argv[2] == str(src)
    assert "mimikatz" in argv
    # term comes right after the evtx source positional
    assert argv[3] == "mimikatz"
    assert "-o" in argv
    o_idx = argv.index("-o")
    assert argv[o_idx + 1] == str(out)
    assert "--json" in argv


def test_search_argv_csv_with_file_source(tmp_path: Path) -> None:
    src = _evtx_file(tmp_path)
    out = tmp_path / "search.csv"
    fake_bin = _fake_binary(tmp_path)

    with patch(
        "core.sift.runner.subprocess.run", return_value=_fake_proc()
    ) as mock_run:
        run_chainsaw_search(
            evtx_source=src,
            search_term="cmd.exe powershell",
            output_path=out,
            output_format="csv",
            chainsaw_binary=fake_bin,
        )
    argv = mock_run.call_args.args[0]
    assert argv[1] == "search"
    assert argv[2] == str(src)
    assert "cmd.exe powershell" in argv
    assert "--csv" in argv


# ---------------------------------------------------------------------------
# search -- rejection paths
# ---------------------------------------------------------------------------


def test_search_rejects_missing_evtx_source(tmp_path: Path) -> None:
    out = tmp_path / "search.json"
    with pytest.raises(ToolRunError):
        run_chainsaw_search(
            evtx_source=tmp_path / "nope.evtx",
            search_term="something",
            output_path=out,
        )


def test_search_rejects_empty_term(tmp_path: Path) -> None:
    src = _evtx_dir(tmp_path)
    out = tmp_path / "search.json"
    with pytest.raises(ChainsawSearchError):
        run_chainsaw_search(
            evtx_source=src,
            search_term="",
            output_path=out,
        )


def test_search_rejects_whitespace_only_term(tmp_path: Path) -> None:
    src = _evtx_dir(tmp_path)
    out = tmp_path / "search.json"
    with pytest.raises(ChainsawSearchError):
        run_chainsaw_search(
            evtx_source=src,
            search_term="   ",
            output_path=out,
        )


@pytest.mark.parametrize(
    "bad_term",
    [
        "foo; rm -rf /",
        "foo && bar",
        "foo | grep x",
        "foo`whoami`",
        "foo$(whoami)",
        'foo"bar"',
        "foo'bar'",
        "foo>out",
        "foo<in",
    ],
)
def test_search_rejects_shell_metacharacters(tmp_path: Path, bad_term: str) -> None:
    src = _evtx_dir(tmp_path)
    out = tmp_path / "search.json"
    with pytest.raises(ChainsawSearchError):
        run_chainsaw_search(
            evtx_source=src,
            search_term=bad_term,
            output_path=out,
        )


def test_search_rejects_unsupported_output_format(tmp_path: Path) -> None:
    src = _evtx_dir(tmp_path)
    out = tmp_path / "search.xml"
    with pytest.raises(ChainsawOutputFormatError):
        run_chainsaw_search(
            evtx_source=src,
            search_term="mimikatz",
            output_path=out,
            output_format="xml",
        )


def test_search_refuses_to_overwrite_populated_output(tmp_path: Path) -> None:
    src = _evtx_dir(tmp_path)
    out = tmp_path / "search.json"
    out.write_text("prior")
    fake_bin = _fake_binary(tmp_path)
    with pytest.raises(ToolRunError):
        run_chainsaw_search(
            evtx_source=src,
            search_term="mimikatz",
            output_path=out,
            chainsaw_binary=fake_bin,
        )


# ---------------------------------------------------------------------------
# audit payload
# ---------------------------------------------------------------------------


def test_hunt_audit_payload_marks_evidence_readonly(
    tmp_path: Path,
    tmp_log_dir: Path,
) -> None:
    src = _evtx_dir(tmp_path)
    sigma = _sigma_dir(tmp_path)
    mapping = _mapping_file(tmp_path)
    out = tmp_path / "hunt.json"
    fake_bin = _fake_binary(tmp_path)
    audit = AuditLogger(incident_id="incident-chainsaw-hunt", log_dir=tmp_log_dir)

    with patch("core.sift.runner.subprocess.run", return_value=_fake_proc()):
        run_chainsaw_hunt(
            evtx_source=src,
            sigma_rules_dir=sigma,
            mapping=mapping,
            output_path=out,
            output_format="json",
            audit=audit,
            chainsaw_binary=fake_bin,
        )
    start_events = [
        e for e in audit.find("tool_call") if e.payload.get("phase") == "start"
    ]
    assert len(start_events) == 1
    payload = start_events[0].payload
    assert payload["tool"] == "chainsaw"
    assert payload["subcommand"] == "hunt"
    assert payload["output_format"] == "json"
    assert payload["evtx_source"] == str(src)
    assert payload["evidence_readonly_assumed"] is True
    assert payload["output_path"] == str(out)
    assert payload["sigma_rules_dir"] == str(sigma)
    assert payload["mapping"] == str(mapping)


def test_search_audit_payload_marks_evidence_readonly(
    tmp_path: Path,
    tmp_log_dir: Path,
) -> None:
    src = _evtx_file(tmp_path)
    out = tmp_path / "search.json"
    fake_bin = _fake_binary(tmp_path)
    audit = AuditLogger(incident_id="incident-chainsaw-search", log_dir=tmp_log_dir)

    with patch("core.sift.runner.subprocess.run", return_value=_fake_proc()):
        run_chainsaw_search(
            evtx_source=src,
            search_term="beacon",
            output_path=out,
            audit=audit,
            chainsaw_binary=fake_bin,
        )
    start_events = [
        e for e in audit.find("tool_call") if e.payload.get("phase") == "start"
    ]
    assert len(start_events) == 1
    payload = start_events[0].payload
    assert payload["tool"] == "chainsaw"
    assert payload["subcommand"] == "search"
    assert payload["output_format"] == "json"
    assert payload["evtx_source"] == str(src)
    assert payload["evidence_readonly_assumed"] is True
    assert payload["output_path"] == str(out)
    assert payload["search_term"] == "beacon"


# ---------------------------------------------------------------------------
# runner propagation
# ---------------------------------------------------------------------------


def test_hunt_timeout_propagates_to_subprocess(tmp_path: Path) -> None:
    src = _evtx_dir(tmp_path)
    sigma = _sigma_dir(tmp_path)
    mapping = _mapping_file(tmp_path)
    out = tmp_path / "hunt.json"
    fake_bin = _fake_binary(tmp_path)

    with patch(
        "core.sift.runner.subprocess.run", return_value=_fake_proc()
    ) as mock_run:
        run_chainsaw_hunt(
            evtx_source=src,
            sigma_rules_dir=sigma,
            mapping=mapping,
            output_path=out,
            timeout=42.0,
            chainsaw_binary=fake_bin,
        )
    assert mock_run.call_args.kwargs["timeout"] == 42.0


def test_search_timeout_propagates_to_subprocess(tmp_path: Path) -> None:
    src = _evtx_dir(tmp_path)
    out = tmp_path / "search.json"
    fake_bin = _fake_binary(tmp_path)

    with patch(
        "core.sift.runner.subprocess.run", return_value=_fake_proc()
    ) as mock_run:
        run_chainsaw_search(
            evtx_source=src,
            search_term="mimikatz",
            output_path=out,
            timeout=17.5,
            chainsaw_binary=fake_bin,
        )
    assert mock_run.call_args.kwargs["timeout"] == 17.5


def test_binary_resolution_error_when_chainsaw_missing(tmp_path: Path) -> None:
    src = _evtx_dir(tmp_path)
    sigma = _sigma_dir(tmp_path)
    mapping = _mapping_file(tmp_path)
    out = tmp_path / "hunt.json"
    # Force shutil.which to return None to simulate a host without chainsaw.
    with patch("core.sift.chainsaw.shutil.which", return_value=None):
        with pytest.raises(ToolRunError):
            run_chainsaw_hunt(
                evtx_source=src,
                sigma_rules_dir=sigma,
                mapping=mapping,
                output_path=out,
            )
        with pytest.raises(ToolRunError):
            run_chainsaw_search(
                evtx_source=src,
                search_term="mimikatz",
                output_path=out,
            )
