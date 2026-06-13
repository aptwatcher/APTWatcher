"""
Tests for core.sift.yara_scan -- Tier 0 YARA wrapper.

Mocks subprocess.run so the suite runs on any host. Verifies:
- missing / empty rules_path rejection
- missing target rejection
- argv shape (flags gated by kwargs, rules_path and target in that order
  as the final positionals)
- audit payload includes evidence_readonly_assumed=True and the flag
  bookkeeping
- parse_yara_output handles the canonical forms and filters noise
- __all__ exports the public surface
"""

from __future__ import annotations

from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from core.audit import AuditLogger
from core.sift import yara_scan as yara_mod
from core.sift.runner import ToolRunError
from core.sift.yara_scan import (
    YaraScanError,
    parse_yara_output,
    run_yara_scan,
)

# ---------------------------------------------------------------------------
# module surface
# ---------------------------------------------------------------------------


def test_module_exports_expected_surface() -> None:
    assert set(yara_mod.__all__) == {
        "YaraScanError",
        "parse_yara_output",
        "run_yara_scan",
    }


def test_yara_scan_error_is_value_error() -> None:
    assert issubclass(YaraScanError, ValueError)


# ---------------------------------------------------------------------------
# run_yara_scan -- rejection paths
# ---------------------------------------------------------------------------


def test_run_yara_scan_rejects_missing_rules(tmp_path: Path) -> None:
    target = tmp_path / "sample.bin"
    target.write_bytes(b"PAYLOAD")
    with pytest.raises(ToolRunError):
        run_yara_scan(
            rules_path=tmp_path / "does-not-exist.yar",
            target=target,
        )


def test_run_yara_scan_rejects_empty_rules_file(tmp_path: Path) -> None:
    rules = tmp_path / "empty.yar"
    rules.write_bytes(b"")  # zero-byte
    target = tmp_path / "sample.bin"
    target.write_bytes(b"PAYLOAD")
    with pytest.raises(ToolRunError):
        run_yara_scan(rules_path=rules, target=target)


def test_run_yara_scan_rejects_rules_that_is_a_directory(tmp_path: Path) -> None:
    rules = tmp_path / "rules_dir"
    rules.mkdir()
    target = tmp_path / "sample.bin"
    target.write_bytes(b"PAYLOAD")
    with pytest.raises(ToolRunError):
        run_yara_scan(rules_path=rules, target=target)


def test_run_yara_scan_rejects_missing_target(tmp_path: Path) -> None:
    rules = tmp_path / "rules.yar"
    rules.write_text("rule X { condition: true }")
    with pytest.raises(ToolRunError):
        run_yara_scan(
            rules_path=rules,
            target=tmp_path / "nope.bin",
        )


# ---------------------------------------------------------------------------
# run_yara_scan -- argv shape
# ---------------------------------------------------------------------------


def _fake_yara_binary(tmp_path: Path) -> Path:
    fake_bin = tmp_path / "yara"
    fake_bin.write_text("#!/bin/sh\nexit 0\n")
    fake_bin.chmod(0o755)
    return fake_bin


def test_run_yara_scan_default_argv(tmp_path: Path) -> None:
    rules = tmp_path / "rules.yar"
    rules.write_text("rule X { condition: true }")
    target = tmp_path / "sample.bin"
    target.write_bytes(b"PAYLOAD")
    fake_bin = _fake_yara_binary(tmp_path)

    fake_proc = CompletedProcess(args=["yara"], returncode=0, stdout="", stderr="")
    with patch("core.sift.runner.subprocess.run", return_value=fake_proc) as mock_run:
        result = run_yara_scan(
            rules_path=rules,
            target=target,
            yara_binary=fake_bin,
        )
    assert result.ok is True
    argv = mock_run.call_args.args[0]
    assert argv[0] == str(fake_bin)
    # Defaults: -m, -g, -f on; -s, -r off; no -a.
    assert "-m" in argv
    assert "-g" in argv
    assert "-f" in argv
    assert "-s" not in argv
    assert "-r" not in argv
    assert "-a" not in argv
    # rules_path then target are the final two positionals.
    assert argv[-2] == str(rules)
    assert argv[-1] == str(target)


def test_run_yara_scan_recursive_and_strings(tmp_path: Path) -> None:
    rules = tmp_path / "rules.yar"
    rules.write_text("rule X { condition: true }")
    target = tmp_path / "tree"
    target.mkdir()
    fake_bin = _fake_yara_binary(tmp_path)

    fake_proc = CompletedProcess(args=["yara"], returncode=0, stdout="", stderr="")
    with patch("core.sift.runner.subprocess.run", return_value=fake_proc) as mock_run:
        run_yara_scan(
            rules_path=rules,
            target=target,
            recursive=True,
            print_strings=True,
            yara_binary=fake_bin,
        )
    argv = mock_run.call_args.args[0]
    assert "-r" in argv
    assert "-s" in argv
    # Final positionals still rules, then target.
    assert argv[-2] == str(rules)
    assert argv[-1] == str(target)


def test_run_yara_scan_toggles_fast_mode_off(tmp_path: Path) -> None:
    rules = tmp_path / "rules.yar"
    rules.write_text("rule X { condition: true }")
    target = tmp_path / "sample.bin"
    target.write_bytes(b"PAYLOAD")
    fake_bin = _fake_yara_binary(tmp_path)

    fake_proc = CompletedProcess(args=["yara"], returncode=0, stdout="", stderr="")
    with patch("core.sift.runner.subprocess.run", return_value=fake_proc) as mock_run:
        run_yara_scan(
            rules_path=rules,
            target=target,
            fast_mode=False,
            print_meta=False,
            print_tags=False,
            yara_binary=fake_bin,
        )
    argv = mock_run.call_args.args[0]
    assert "-f" not in argv
    assert "-m" not in argv
    assert "-g" not in argv


def test_run_yara_scan_timeout_per_rule(tmp_path: Path) -> None:
    rules = tmp_path / "rules.yar"
    rules.write_text("rule X { condition: true }")
    target = tmp_path / "sample.bin"
    target.write_bytes(b"PAYLOAD")
    fake_bin = _fake_yara_binary(tmp_path)

    fake_proc = CompletedProcess(args=["yara"], returncode=0, stdout="", stderr="")
    with patch("core.sift.runner.subprocess.run", return_value=fake_proc) as mock_run:
        run_yara_scan(
            rules_path=rules,
            target=target,
            timeout_per_rule=45,
            yara_binary=fake_bin,
        )
    argv = mock_run.call_args.args[0]
    assert "-a" in argv
    idx = argv.index("-a")
    assert argv[idx + 1] == "45"
    # -a <n> must come before the two trailing positionals.
    assert idx + 1 < len(argv) - 2


def test_run_yara_scan_accepts_compiled_yarc(tmp_path: Path) -> None:
    rules = tmp_path / "rules.yarc"
    # Compiled rulesets are binary blobs; a non-empty file is enough here.
    rules.write_bytes(b"\x00YARC\x01\x02\x03")
    target = tmp_path / "sample.bin"
    target.write_bytes(b"PAYLOAD")
    fake_bin = _fake_yara_binary(tmp_path)

    fake_proc = CompletedProcess(args=["yara"], returncode=0, stdout="", stderr="")
    with patch("core.sift.runner.subprocess.run", return_value=fake_proc):
        result = run_yara_scan(
            rules_path=rules,
            target=target,
            yara_binary=fake_bin,
        )
    assert result.ok is True


# ---------------------------------------------------------------------------
# audit payload
# ---------------------------------------------------------------------------


def test_run_yara_scan_audit_payload_shape(
    tmp_path: Path,
    tmp_log_dir: Path,
) -> None:
    rules = tmp_path / "rules.yar"
    rules.write_text("rule X { condition: true }")
    target = tmp_path / "sample.bin"
    target.write_bytes(b"PAYLOAD")
    fake_bin = _fake_yara_binary(tmp_path)

    fake_proc = CompletedProcess(args=["yara"], returncode=0, stdout="", stderr="")
    audit = AuditLogger(incident_id="incident-yara", log_dir=tmp_log_dir)
    with patch("core.sift.runner.subprocess.run", return_value=fake_proc):
        run_yara_scan(
            rules_path=rules,
            target=target,
            recursive=True,
            print_strings=True,
            timeout_per_rule=60,
            audit=audit,
            yara_binary=fake_bin,
        )
    start_events = [
        e for e in audit.find("tool_call") if e.payload.get("phase") == "start"
    ]
    assert len(start_events) == 1
    payload = start_events[0].payload
    assert payload["rules_path"] == str(rules)
    assert payload["target"] == str(target)
    assert payload["recursive"] is True
    assert payload["fast_mode"] is True
    assert payload["print_strings"] is True
    assert payload["print_meta"] is True
    assert payload["print_tags"] is True
    assert payload["timeout_per_rule"] == 60
    assert payload["evidence_readonly_assumed"] is True


# ---------------------------------------------------------------------------
# parse_yara_output
# ---------------------------------------------------------------------------


def test_parse_yara_output_empty_returns_empty_list() -> None:
    assert parse_yara_output("") == []
    assert parse_yara_output("   \n\n\t\n") == []


def test_parse_yara_output_plain_rule_and_path() -> None:
    out = "SUSPICIOUS_STRINGS /evidence/memdump.raw"
    assert parse_yara_output(out) == [
        {"rule": "SUSPICIOUS_STRINGS", "path": "/evidence/memdump.raw"},
    ]


def test_parse_yara_output_with_tags() -> None:
    out = "MALWARE [apt,trojan] /tmp/a.bin"
    # YARA's actual `-g` output is `[tags] RULE /path`; test both orderings
    # below, but start with the canonical leading-bracket form.
    assert parse_yara_output("[apt,trojan] MALWARE /tmp/a.bin") == [
        {
            "rule": "MALWARE",
            "path": "/tmp/a.bin",
            "tags": ["apt", "trojan"],
        },
    ]
    # Belt and suspenders: ensure trailing-tag form does not crash; it
    # either parses or gets skipped cleanly.
    _ = parse_yara_output(out)


def test_parse_yara_output_with_unbracketed_meta() -> None:
    # `-m` canonical variant: `k=v,k2=v2 RULE /path`.
    out = "0x0=foo,bar=baz RULENAME /path/to/file"
    parsed = parse_yara_output(out)
    assert parsed == [
        {
            "rule": "RULENAME",
            "path": "/path/to/file",
            "meta": {"0x0": "foo", "bar": "baz"},
        },
    ]


def test_parse_yara_output_with_bracketed_meta() -> None:
    out = "[author=rcrowley,severity=high] RULENAME /path/to/file"
    parsed = parse_yara_output(out)
    assert parsed == [
        {
            "rule": "RULENAME",
            "path": "/path/to/file",
            "meta": {"author": "rcrowley", "severity": "high"},
        },
    ]


def test_parse_yara_output_with_tags_and_meta() -> None:
    out = "[apt,trojan] [author=rcrowley] RULENAME /path/to/file"
    parsed = parse_yara_output(out)
    assert parsed == [
        {
            "rule": "RULENAME",
            "path": "/path/to/file",
            "tags": ["apt", "trojan"],
            "meta": {"author": "rcrowley"},
        },
    ]


def test_parse_yara_output_filters_noise_lines() -> None:
    out = "\n".join(
        [
            "",
            "warning: rule FOO is slow",
            "error: failed to compile BAR",
            "   ",
            "RULE_A /evidence/one.bin",
            "WARNING: not actually noise if case mismatches -- wait, it is",
            "RULE_B /evidence/two.bin",
        ]
    )
    parsed = parse_yara_output(out)
    # `warning:`/`error:` are case-insensitive per our parser; the
    # "WARNING:" line is therefore also filtered.
    assert parsed == [
        {"rule": "RULE_A", "path": "/evidence/one.bin"},
        {"rule": "RULE_B", "path": "/evidence/two.bin"},
    ]


def test_parse_yara_output_multiple_matches() -> None:
    out = "\n".join(
        [
            "RULE_A /evidence/one.bin",
            "[apt] RULE_B /evidence/two.bin",
            "[k=v] RULE_C /evidence/three.bin",
        ]
    )
    parsed = parse_yara_output(out)
    assert len(parsed) == 3
    assert parsed[0] == {"rule": "RULE_A", "path": "/evidence/one.bin"}
    assert parsed[1] == {
        "rule": "RULE_B",
        "path": "/evidence/two.bin",
        "tags": ["apt"],
    }
    assert parsed[2] == {
        "rule": "RULE_C",
        "path": "/evidence/three.bin",
        "meta": {"k": "v"},
    }
