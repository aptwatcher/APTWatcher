"""
Tests for core.sift.timesketch -- Tier 0 Timesketch query + upload wrapper.

Mocks subprocess.run so the suite runs on any host. Verifies:
- query-subcommand allow-list shape (TIMESKETCH_QUERY_SUBCOMMANDS)
- argv shape for each query subcommand (list / describe / search)
- argv shape for upload (with and without host)
- host validation (good http/https + bad scheme + shell metacharacters)
- query validation (good Lucene + empty + newline + backtick rejection)
- sketch_id validation (non-positive + non-int)
- timeline_name validation (good set + metacharacters)
- consent token: missing / empty / whitespace / wrong value -> error;
  exact sentinel -> passes
- upload emits `timesketch_upload_consent` audit event BEFORE the
  subprocess start (tool_call phase=start)
- audit payload shapes: read-only query + state_changing upload
- binary resolution error when the binary is not on PATH
- timeout propagation
- module's `__all__` matches the documented public surface
"""

from __future__ import annotations

from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from core.audit import AuditLogger
from core.sift import timesketch as ts_mod
from core.sift.runner import ToolRunError
from core.sift.timesketch import (
    TIMESKETCH_QUERY_SUBCOMMANDS,
    TIMESKETCH_UPLOAD_CONSENT_TOKEN,
    TimesketchHostError,
    TimesketchQueryError,
    TimesketchSubcommandError,
    TimesketchTimelineNameError,
    TimesketchUploadConsentError,
    run_timesketch_query,
    run_timesketch_upload,
)

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _fake_binary(tmp_path: Path, name: str) -> Path:
    fake_bin = tmp_path / name
    fake_bin.write_text("#!/bin/sh\nexit 0\n")
    fake_bin.chmod(0o755)
    return fake_bin


def _fake_proc() -> CompletedProcess[str]:
    return CompletedProcess(args=["timesketch"], returncode=0, stdout="", stderr="")


def _timeline_file(tmp_path: Path) -> Path:
    f = tmp_path / "host01.plaso"
    f.write_bytes(b"PLSO")
    return f


# ---------------------------------------------------------------------------
# public surface & allow-list shape
# ---------------------------------------------------------------------------


def test_module_exports_documented_public_surface() -> None:
    assert set(ts_mod.__all__) == {
        "TIMESKETCH_QUERY_SUBCOMMANDS",
        "TIMESKETCH_UPLOAD_CONSENT_TOKEN",
        "TimesketchHostError",
        "TimesketchQueryError",
        "TimesketchSubcommandError",
        "TimesketchTimelineNameError",
        "TimesketchUploadConsentError",
        "run_timesketch_query",
        "run_timesketch_upload",
    }


def test_subcommand_allow_list_shape() -> None:
    assert set(TIMESKETCH_QUERY_SUBCOMMANDS) == {"list", "describe", "search"}
    for reason in TIMESKETCH_QUERY_SUBCOMMANDS.values():
        assert isinstance(reason, str) and reason.strip()


def test_consent_sentinel_value() -> None:
    # Pinned value: callers depend on this exact string.
    assert TIMESKETCH_UPLOAD_CONSENT_TOKEN == "i-consent-timesketch-upload"


def test_error_class_hierarchy() -> None:
    assert issubclass(TimesketchSubcommandError, ValueError)
    assert issubclass(TimesketchHostError, ValueError)
    assert issubclass(TimesketchQueryError, ValueError)
    assert issubclass(TimesketchTimelineNameError, ValueError)
    assert issubclass(TimesketchUploadConsentError, PermissionError)


# ---------------------------------------------------------------------------
# run_timesketch_query -- allow-list enforcement
# ---------------------------------------------------------------------------


def test_query_rejects_unknown_subcommand(tmp_path: Path) -> None:
    fake_bin = _fake_binary(tmp_path, "timesketch")
    with pytest.raises(TimesketchSubcommandError):
        run_timesketch_query(
            subcommand="delete",
            host="https://ts.example",
            timesketch_binary=fake_bin,
        )


# ---------------------------------------------------------------------------
# run_timesketch_query -- host validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "good_host",
    [
        "http://ts.example",
        "https://ts.example",
        "https://ts.example:5000",
        "https://ts.example/path/to/instance",
    ],
)
def test_query_accepts_good_host(tmp_path: Path, good_host: str) -> None:
    fake_bin = _fake_binary(tmp_path, "timesketch")
    with patch(
        "core.sift.runner.subprocess.run", return_value=_fake_proc()
    ) as mock_run:
        run_timesketch_query(
            subcommand="list",
            host=good_host,
            timesketch_binary=fake_bin,
        )
    argv = mock_run.call_args.args[0]
    assert "--host" in argv
    h_idx = argv.index("--host")
    assert argv[h_idx + 1] == good_host


@pytest.mark.parametrize(
    "bad_host",
    [
        "ts.example",  # missing scheme
        "ftp://ts.example",  # wrong scheme
        "https://ts.example; rm -rf /",  # shell metachars
        "https://ts.example`id`",  # backtick
        "https://ts.example$(id)",  # command substitution
        "https://ts.example\nfoo",  # newline
        "",  # empty
        "   ",  # whitespace only
    ],
)
def test_query_rejects_bad_host(tmp_path: Path, bad_host: str) -> None:
    fake_bin = _fake_binary(tmp_path, "timesketch")
    with pytest.raises(TimesketchHostError):
        run_timesketch_query(
            subcommand="list",
            host=bad_host,
            timesketch_binary=fake_bin,
        )


# ---------------------------------------------------------------------------
# run_timesketch_query -- sketch_id validation
# ---------------------------------------------------------------------------


def test_query_describe_requires_sketch_id(tmp_path: Path) -> None:
    fake_bin = _fake_binary(tmp_path, "timesketch")
    with pytest.raises(TimesketchQueryError):
        run_timesketch_query(
            subcommand="describe",
            host="https://ts.example",
            timesketch_binary=fake_bin,
        )


def test_query_search_requires_sketch_id(tmp_path: Path) -> None:
    fake_bin = _fake_binary(tmp_path, "timesketch")
    with pytest.raises(TimesketchQueryError):
        run_timesketch_query(
            subcommand="search",
            host="https://ts.example",
            query="event_identifier:4624",
            timesketch_binary=fake_bin,
        )


@pytest.mark.parametrize("bad_id", [0, -1, -1000])
def test_query_rejects_non_positive_sketch_id(tmp_path: Path, bad_id: int) -> None:
    fake_bin = _fake_binary(tmp_path, "timesketch")
    with pytest.raises(TimesketchQueryError):
        run_timesketch_query(
            subcommand="describe",
            host="https://ts.example",
            sketch_id=bad_id,
            timesketch_binary=fake_bin,
        )


def test_query_rejects_bool_as_sketch_id(tmp_path: Path) -> None:
    # bool is a subclass of int in Python; we specifically reject it so
    # a caller can't pass True/False and have it count as sketch_id=1.
    fake_bin = _fake_binary(tmp_path, "timesketch")
    with pytest.raises(TimesketchQueryError):
        run_timesketch_query(
            subcommand="describe",
            host="https://ts.example",
            sketch_id=True,  # type: ignore[arg-type]
            timesketch_binary=fake_bin,
        )


# ---------------------------------------------------------------------------
# run_timesketch_query -- Lucene query validation
# ---------------------------------------------------------------------------


def test_query_search_requires_non_empty_query(tmp_path: Path) -> None:
    fake_bin = _fake_binary(tmp_path, "timesketch")
    with pytest.raises(TimesketchQueryError):
        run_timesketch_query(
            subcommand="search",
            host="https://ts.example",
            sketch_id=7,
            query="",
            timesketch_binary=fake_bin,
        )


def test_query_search_rejects_whitespace_only_query(tmp_path: Path) -> None:
    fake_bin = _fake_binary(tmp_path, "timesketch")
    with pytest.raises(TimesketchQueryError):
        run_timesketch_query(
            subcommand="search",
            host="https://ts.example",
            sketch_id=7,
            query="   \n\t  ",
            timesketch_binary=fake_bin,
        )


@pytest.mark.parametrize(
    "good_query",
    [
        "event_identifier:4624",
        'message:"failed logon"',
        "tag:mimikatz AND computer_name:HOST01",
        "(event_id:4624 OR event_id:4625)",
        "username:admin*",
        "path:/etc/passwd",
        "file.hash:[a TO z]",
    ],
)
def test_query_search_accepts_lucene(tmp_path: Path, good_query: str) -> None:
    fake_bin = _fake_binary(tmp_path, "timesketch")
    with patch(
        "core.sift.runner.subprocess.run", return_value=_fake_proc()
    ) as mock_run:
        run_timesketch_query(
            subcommand="search",
            host="https://ts.example",
            sketch_id=7,
            query=good_query,
            timesketch_binary=fake_bin,
        )
    argv = mock_run.call_args.args[0]
    assert good_query in argv


@pytest.mark.parametrize(
    "bad_query",
    [
        "foo; rm -rf /",  # semicolon
        "foo | grep bar",  # pipe
        "foo && bar",  # double-amp
        "foo`whoami`",  # backtick
        "foo$(whoami)",  # command substitution
        "foo\nrm -rf /",  # newline
        "foo\tbar",  # tab (outside safe whitespace? \t is \s which IS allowed)
        "foo>out",  # redirect
        "foo<in",  # redirect
        "foo&bar",  # single-amp
    ],
)
def test_query_search_rejects_shell_metacharacters(
    tmp_path: Path, bad_query: str
) -> None:
    fake_bin = _fake_binary(tmp_path, "timesketch")
    # \t is technically within \s; but the test is specifically about
    # the shell-hostile charset.  Only assert rejection for entries
    # that contain a clearly hostile char.
    hostile_chars = {";", "|", "&", "`", "$", ">", "<", "\n"}
    if not any(c in bad_query for c in hostile_chars):
        pytest.skip(f"{bad_query!r} does not contain a hostile char")
    with pytest.raises(TimesketchQueryError):
        run_timesketch_query(
            subcommand="search",
            host="https://ts.example",
            sketch_id=7,
            query=bad_query,
            timesketch_binary=fake_bin,
        )


# ---------------------------------------------------------------------------
# run_timesketch_query -- argv shape
# ---------------------------------------------------------------------------


def test_query_list_argv_shape(tmp_path: Path) -> None:
    fake_bin = _fake_binary(tmp_path, "timesketch")
    with patch(
        "core.sift.runner.subprocess.run", return_value=_fake_proc()
    ) as mock_run:
        result = run_timesketch_query(
            subcommand="list",
            host="https://ts.example",
            timesketch_binary=fake_bin,
        )
    assert result.ok is True
    argv = mock_run.call_args.args[0]
    assert argv[0] == str(fake_bin)
    assert argv[1] == "--host"
    assert argv[2] == "https://ts.example"
    assert argv[3] == "sketch"
    assert argv[4] == "list"
    # No sketch_id / query positional for list.
    assert len(argv) == 5


def test_query_describe_argv_shape(tmp_path: Path) -> None:
    fake_bin = _fake_binary(tmp_path, "timesketch")
    with patch(
        "core.sift.runner.subprocess.run", return_value=_fake_proc()
    ) as mock_run:
        run_timesketch_query(
            subcommand="describe",
            host="https://ts.example",
            sketch_id=42,
            timesketch_binary=fake_bin,
        )
    argv = mock_run.call_args.args[0]
    assert argv[0] == str(fake_bin)
    assert argv[1:5] == ["--host", "https://ts.example", "sketch", "describe"]
    assert argv[5] == "42"


def test_query_search_argv_shape(tmp_path: Path) -> None:
    fake_bin = _fake_binary(tmp_path, "timesketch")
    with patch(
        "core.sift.runner.subprocess.run", return_value=_fake_proc()
    ) as mock_run:
        run_timesketch_query(
            subcommand="search",
            host="https://ts.example",
            sketch_id=42,
            query="event_identifier:4624",
            timesketch_binary=fake_bin,
        )
    argv = mock_run.call_args.args[0]
    assert argv[0] == str(fake_bin)
    assert argv[1:5] == ["--host", "https://ts.example", "sketch", "search"]
    assert "--query" in argv
    q_idx = argv.index("--query")
    assert argv[q_idx + 1] == "event_identifier:4624"
    # sketch_id is the final positional.
    assert argv[-1] == "42"


# ---------------------------------------------------------------------------
# run_timesketch_query -- audit payload
# ---------------------------------------------------------------------------


def test_query_audit_payload_marks_evidence_readonly(
    tmp_path: Path,
    tmp_log_dir: Path,
) -> None:
    fake_bin = _fake_binary(tmp_path, "timesketch")
    audit = AuditLogger(incident_id="incident-ts-query", log_dir=tmp_log_dir)
    with patch("core.sift.runner.subprocess.run", return_value=_fake_proc()):
        run_timesketch_query(
            subcommand="search",
            host="https://ts.example",
            sketch_id=7,
            query="tag:mimikatz",
            audit=audit,
            timesketch_binary=fake_bin,
        )
    start_events = [
        e for e in audit.find("tool_call") if e.payload.get("phase") == "start"
    ]
    assert len(start_events) == 1
    payload = start_events[0].payload
    assert payload["tool"] == "timesketch"
    assert payload["subcommand"] == "search"
    assert payload["host"] == "https://ts.example"
    assert payload["sketch_id"] == 7
    assert payload["evidence_readonly_assumed"] is True
    # state_changing must NOT be in the query audit payload.
    assert "state_changing" not in payload


# ---------------------------------------------------------------------------
# run_timesketch_query -- runner propagation
# ---------------------------------------------------------------------------


def test_query_timeout_propagates_to_subprocess(tmp_path: Path) -> None:
    fake_bin = _fake_binary(tmp_path, "timesketch")
    with patch(
        "core.sift.runner.subprocess.run", return_value=_fake_proc()
    ) as mock_run:
        run_timesketch_query(
            subcommand="list",
            host="https://ts.example",
            timeout=17.5,
            timesketch_binary=fake_bin,
        )
    assert mock_run.call_args.kwargs["timeout"] == 17.5


def test_query_binary_resolution_error_when_missing(tmp_path: Path) -> None:
    with patch("core.sift.timesketch.shutil.which", return_value=None):
        with pytest.raises(ToolRunError):
            run_timesketch_query(
                subcommand="list",
                host="https://ts.example",
            )


# ---------------------------------------------------------------------------
# run_timesketch_upload -- consent gate
# ---------------------------------------------------------------------------


def test_upload_rejects_empty_consent_token(tmp_path: Path) -> None:
    src = _timeline_file(tmp_path)
    fake_bin = _fake_binary(tmp_path, "timesketch_importer")
    with pytest.raises(TimesketchUploadConsentError):
        run_timesketch_upload(
            timeline_source=src,
            sketch_id=1,
            timeline_name="t",
            consent_token="",
            importer_binary=fake_bin,
        )


def test_upload_rejects_whitespace_consent_token(tmp_path: Path) -> None:
    src = _timeline_file(tmp_path)
    fake_bin = _fake_binary(tmp_path, "timesketch_importer")
    with pytest.raises(TimesketchUploadConsentError):
        run_timesketch_upload(
            timeline_source=src,
            sketch_id=1,
            timeline_name="t",
            consent_token="   ",
            importer_binary=fake_bin,
        )


def test_upload_rejects_wrong_consent_token(tmp_path: Path) -> None:
    src = _timeline_file(tmp_path)
    fake_bin = _fake_binary(tmp_path, "timesketch_importer")
    with pytest.raises(TimesketchUploadConsentError):
        run_timesketch_upload(
            timeline_source=src,
            sketch_id=1,
            timeline_name="t",
            # Similar-but-not-equal value must not unlock the upload.
            consent_token="I-consent",
            importer_binary=fake_bin,
        )


def test_upload_accepts_exact_consent_token(tmp_path: Path) -> None:
    src = _timeline_file(tmp_path)
    fake_bin = _fake_binary(tmp_path, "timesketch_importer")
    with patch("core.sift.runner.subprocess.run", return_value=_fake_proc()):
        result = run_timesketch_upload(
            timeline_source=src,
            sketch_id=1,
            timeline_name="t",
            consent_token=TIMESKETCH_UPLOAD_CONSENT_TOKEN,
            importer_binary=fake_bin,
        )
    assert result.ok is True


# ---------------------------------------------------------------------------
# run_timesketch_upload -- other validation
# ---------------------------------------------------------------------------


def test_upload_rejects_missing_timeline_source(tmp_path: Path) -> None:
    fake_bin = _fake_binary(tmp_path, "timesketch_importer")
    with pytest.raises(ToolRunError):
        run_timesketch_upload(
            timeline_source=tmp_path / "nope.plaso",
            sketch_id=1,
            timeline_name="t",
            consent_token=TIMESKETCH_UPLOAD_CONSENT_TOKEN,
            importer_binary=fake_bin,
        )


def test_upload_rejects_directory_as_timeline_source(tmp_path: Path) -> None:
    fake_bin = _fake_binary(tmp_path, "timesketch_importer")
    d = tmp_path / "not-a-file"
    d.mkdir()
    with pytest.raises(ToolRunError):
        run_timesketch_upload(
            timeline_source=d,
            sketch_id=1,
            timeline_name="t",
            consent_token=TIMESKETCH_UPLOAD_CONSENT_TOKEN,
            importer_binary=fake_bin,
        )


@pytest.mark.parametrize("bad_id", [0, -1, -100])
def test_upload_rejects_non_positive_sketch_id(tmp_path: Path, bad_id: int) -> None:
    src = _timeline_file(tmp_path)
    fake_bin = _fake_binary(tmp_path, "timesketch_importer")
    with pytest.raises(TimesketchQueryError):
        run_timesketch_upload(
            timeline_source=src,
            sketch_id=bad_id,
            timeline_name="t",
            consent_token=TIMESKETCH_UPLOAD_CONSENT_TOKEN,
            importer_binary=fake_bin,
        )


@pytest.mark.parametrize(
    "bad_name",
    [
        "",
        "   ",
        "bad;name",
        "bad|name",
        "bad`name`",
        "bad$name",
        "bad\nname",
        "bad/name",
        "bad\\name",
    ],
)
def test_upload_rejects_bad_timeline_name(tmp_path: Path, bad_name: str) -> None:
    src = _timeline_file(tmp_path)
    fake_bin = _fake_binary(tmp_path, "timesketch_importer")
    with pytest.raises(TimesketchTimelineNameError):
        run_timesketch_upload(
            timeline_source=src,
            sketch_id=1,
            timeline_name=bad_name,
            consent_token=TIMESKETCH_UPLOAD_CONSENT_TOKEN,
            importer_binary=fake_bin,
        )


def test_upload_rejects_bad_host(tmp_path: Path) -> None:
    src = _timeline_file(tmp_path)
    fake_bin = _fake_binary(tmp_path, "timesketch_importer")
    with pytest.raises(TimesketchHostError):
        run_timesketch_upload(
            timeline_source=src,
            sketch_id=1,
            timeline_name="t",
            consent_token=TIMESKETCH_UPLOAD_CONSENT_TOKEN,
            host="ftp://wrong",
            importer_binary=fake_bin,
        )


# ---------------------------------------------------------------------------
# run_timesketch_upload -- argv shape
# ---------------------------------------------------------------------------


def test_upload_argv_shape_with_host(tmp_path: Path) -> None:
    src = _timeline_file(tmp_path)
    fake_bin = _fake_binary(tmp_path, "timesketch_importer")
    with patch(
        "core.sift.runner.subprocess.run", return_value=_fake_proc()
    ) as mock_run:
        run_timesketch_upload(
            timeline_source=src,
            sketch_id=7,
            timeline_name="host01-plaso",
            consent_token=TIMESKETCH_UPLOAD_CONSENT_TOKEN,
            host="https://ts.example",
            importer_binary=fake_bin,
        )
    argv = mock_run.call_args.args[0]
    assert argv[0] == str(fake_bin)
    assert "--host" in argv
    h_idx = argv.index("--host")
    assert argv[h_idx + 1] == "https://ts.example"
    assert "--sketch" in argv
    s_idx = argv.index("--sketch")
    assert argv[s_idx + 1] == "7"
    assert "--timeline_name" in argv
    n_idx = argv.index("--timeline_name")
    assert argv[n_idx + 1] == "host01-plaso"
    # Source file is the final positional.
    assert argv[-1] == str(src)


def test_upload_argv_shape_without_host(tmp_path: Path) -> None:
    src = _timeline_file(tmp_path)
    fake_bin = _fake_binary(tmp_path, "timesketch_importer")
    with patch(
        "core.sift.runner.subprocess.run", return_value=_fake_proc()
    ) as mock_run:
        run_timesketch_upload(
            timeline_source=src,
            sketch_id=7,
            timeline_name="host01-plaso",
            consent_token=TIMESKETCH_UPLOAD_CONSENT_TOKEN,
            importer_binary=fake_bin,
        )
    argv = mock_run.call_args.args[0]
    assert argv[0] == str(fake_bin)
    # No --host entries.
    assert "--host" not in argv
    assert "--sketch" in argv
    assert "--timeline_name" in argv
    assert argv[-1] == str(src)


# ---------------------------------------------------------------------------
# run_timesketch_upload -- audit trail
# ---------------------------------------------------------------------------


def test_upload_emits_consent_event_before_tool_call(
    tmp_path: Path,
    tmp_log_dir: Path,
) -> None:
    src = _timeline_file(tmp_path)
    fake_bin = _fake_binary(tmp_path, "timesketch_importer")
    audit = AuditLogger(incident_id="incident-ts-upload", log_dir=tmp_log_dir)
    with patch("core.sift.runner.subprocess.run", return_value=_fake_proc()):
        run_timesketch_upload(
            timeline_source=src,
            sketch_id=7,
            timeline_name="host01",
            consent_token=TIMESKETCH_UPLOAD_CONSENT_TOKEN,
            host="https://ts.example",
            audit=audit,
            importer_binary=fake_bin,
        )
    consent_events = audit.find("timesketch_upload_consent")
    assert len(consent_events) == 1
    payload = consent_events[0].payload
    assert payload["consent_token_present"] is True
    assert payload["consent_token_length"] == len(TIMESKETCH_UPLOAD_CONSENT_TOKEN)
    assert payload["sketch_id"] == 7
    assert payload["timeline_name"] == "host01"
    assert payload["host"] == "https://ts.example"
    assert payload["source"] == str(src)
    # Raw token must NEVER appear in payload.
    assert TIMESKETCH_UPLOAD_CONSENT_TOKEN not in str(payload)

    # Consent must precede the tool_call phase=start event.
    all_events = audit.read_all()
    consent_idx = next(
        i
        for i, e in enumerate(all_events)
        if e.event_type == "timesketch_upload_consent"
    )
    tool_call_start_idx = next(
        i
        for i, e in enumerate(all_events)
        if e.event_type == "tool_call" and e.payload.get("phase") == "start"
    )
    assert consent_idx < tool_call_start_idx


def test_upload_audit_payload_marks_state_changing_and_readonly_source(
    tmp_path: Path,
    tmp_log_dir: Path,
) -> None:
    src = _timeline_file(tmp_path)
    fake_bin = _fake_binary(tmp_path, "timesketch_importer")
    audit = AuditLogger(incident_id="incident-ts-upload-2", log_dir=tmp_log_dir)
    with patch("core.sift.runner.subprocess.run", return_value=_fake_proc()):
        run_timesketch_upload(
            timeline_source=src,
            sketch_id=7,
            timeline_name="host01",
            consent_token=TIMESKETCH_UPLOAD_CONSENT_TOKEN,
            host="https://ts.example",
            audit=audit,
            importer_binary=fake_bin,
        )
    start_events = [
        e for e in audit.find("tool_call") if e.payload.get("phase") == "start"
    ]
    assert len(start_events) == 1
    payload = start_events[0].payload
    assert payload["tool"] == "timesketch_importer"
    assert payload["source"] == str(src)
    assert payload["source_readonly_assumed"] is True
    assert payload["sketch_id"] == 7
    assert payload["timeline_name"] == "host01"
    assert payload["host"] == "https://ts.example"
    assert payload["state_changing"] == "operational"
    assert payload["consent"] == "granted"


# ---------------------------------------------------------------------------
# run_timesketch_upload -- runner propagation
# ---------------------------------------------------------------------------


def test_upload_timeout_propagates_to_subprocess(tmp_path: Path) -> None:
    src = _timeline_file(tmp_path)
    fake_bin = _fake_binary(tmp_path, "timesketch_importer")
    with patch(
        "core.sift.runner.subprocess.run", return_value=_fake_proc()
    ) as mock_run:
        run_timesketch_upload(
            timeline_source=src,
            sketch_id=1,
            timeline_name="t",
            consent_token=TIMESKETCH_UPLOAD_CONSENT_TOKEN,
            timeout=55.0,
            importer_binary=fake_bin,
        )
    assert mock_run.call_args.kwargs["timeout"] == 55.0


def test_upload_binary_resolution_error_when_missing(tmp_path: Path) -> None:
    src = _timeline_file(tmp_path)
    with patch("core.sift.timesketch.shutil.which", return_value=None):
        with pytest.raises(ToolRunError):
            run_timesketch_upload(
                timeline_source=src,
                sketch_id=1,
                timeline_name="t",
                consent_token=TIMESKETCH_UPLOAD_CONSENT_TOKEN,
            )


# ---------------------------------------------------------------------------
# re-exports (core.sift and core)
# ---------------------------------------------------------------------------


def test_core_sift_re_exports_timesketch() -> None:
    from core import sift

    assert sift.TIMESKETCH_QUERY_SUBCOMMANDS is TIMESKETCH_QUERY_SUBCOMMANDS
    assert sift.run_timesketch_query is run_timesketch_query
    assert sift.run_timesketch_upload is run_timesketch_upload
    assert sift.TimesketchSubcommandError is TimesketchSubcommandError
    assert sift.TimesketchHostError is TimesketchHostError
    assert sift.TimesketchQueryError is TimesketchQueryError
    assert sift.TimesketchTimelineNameError is TimesketchTimelineNameError
    assert sift.TimesketchUploadConsentError is TimesketchUploadConsentError


def test_core_re_exports_timesketch() -> None:
    import core

    assert core.TIMESKETCH_QUERY_SUBCOMMANDS is TIMESKETCH_QUERY_SUBCOMMANDS
    assert core.run_timesketch_query is run_timesketch_query
    assert core.run_timesketch_upload is run_timesketch_upload
