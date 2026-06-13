"""
Tests for core.sift.sleuthkit -- Tier 0 filesystem-forensics wrappers.

Stubs `run_tool` and `_resolve_binary` so the suite runs on any host
(no TSK install required). Verifies:
- argv shape for mmls / fsstat / fls / icat, with and without offset
- precondition errors: missing image, icat output already exists,
  negative offset
- audit payload always includes `evidence_readonly_assumed=True`
- `__all__` exports the four public functions plus ToolRunError
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from core.audit import AuditLogger
from core.sift import sleuthkit
from core.sift.runner import ToolRunError, ToolRunResult

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _fake_result(
    *,
    tool: str,
    argv: list[str],
    stdout: str = "",
) -> ToolRunResult:
    """Build a canned ToolRunResult so wrappers don't exec a real process."""
    return ToolRunResult(
        tool=tool,
        argv=argv,
        correlation_id="deadbeef",
        returncode=0,
        stdout=stdout,
        stderr="",
        duration_seconds=0.0,
        timed_out=False,
        started_at="2026-01-01T00:00:00+00:00",
        ended_at="2026-01-01T00:00:00+00:00",
    )


def _fake_bin(tmp_path: Path, name: str) -> Path:
    """Lay down a placeholder binary so `_resolve_binary` doesn't need it."""
    p = tmp_path / name
    p.write_text("#!/bin/sh\nexit 0\n")
    p.chmod(0o755)
    return p


# ---------------------------------------------------------------------------
# __all__ export check
# ---------------------------------------------------------------------------


def test_module_all_exports_public_surface() -> None:
    assert set(sleuthkit.__all__) == {
        "ToolRunError",
        "run_fls",
        "run_fsstat",
        "run_icat",
        "run_mmls",
    }


# ---------------------------------------------------------------------------
# run_mmls
# ---------------------------------------------------------------------------


def test_run_mmls_builds_expected_argv(tmp_path: Path) -> None:
    image = tmp_path / "disk.dd"
    image.write_bytes(b"FAKEIMG")
    fake_bin = _fake_bin(tmp_path, "mmls")

    captured: dict[str, object] = {}

    def _stub(argv: list[str], **kwargs: object) -> ToolRunResult:
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return _fake_result(tool="mmls", argv=argv)

    with patch("core.sift.sleuthkit.run_tool", side_effect=_stub):
        result = sleuthkit.run_mmls(image=image, mmls_binary=fake_bin)

    assert result.ok is True
    argv = captured["argv"]
    assert argv == [str(fake_bin), "-B", str(image)]
    payload = captured["kwargs"]["extra_audit_payload"]
    assert payload["image"] == str(image)
    assert payload["evidence_readonly_assumed"] is True


def test_run_mmls_rejects_missing_image(tmp_path: Path) -> None:
    fake_bin = _fake_bin(tmp_path, "mmls")
    with pytest.raises(ToolRunError):
        sleuthkit.run_mmls(
            image=tmp_path / "does-not-exist.dd",
            mmls_binary=fake_bin,
        )


# ---------------------------------------------------------------------------
# run_fsstat
# ---------------------------------------------------------------------------


def test_run_fsstat_without_offset_omits_dash_o(tmp_path: Path) -> None:
    image = tmp_path / "disk.dd"
    image.write_bytes(b"FAKEIMG")
    fake_bin = _fake_bin(tmp_path, "fsstat")

    captured: dict[str, object] = {}

    def _stub(argv: list[str], **kwargs: object) -> ToolRunResult:
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return _fake_result(tool="fsstat", argv=argv)

    with patch("core.sift.sleuthkit.run_tool", side_effect=_stub):
        sleuthkit.run_fsstat(image=image, fsstat_binary=fake_bin)

    argv = captured["argv"]
    assert argv == [str(fake_bin), str(image)]
    assert "-o" not in argv
    payload = captured["kwargs"]["extra_audit_payload"]
    assert payload["offset"] is None
    assert payload["evidence_readonly_assumed"] is True


def test_run_fsstat_with_offset_includes_dash_o(tmp_path: Path) -> None:
    image = tmp_path / "disk.dd"
    image.write_bytes(b"FAKEIMG")
    fake_bin = _fake_bin(tmp_path, "fsstat")

    captured: dict[str, object] = {}

    def _stub(argv: list[str], **kwargs: object) -> ToolRunResult:
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return _fake_result(tool="fsstat", argv=argv)

    with patch("core.sift.sleuthkit.run_tool", side_effect=_stub):
        sleuthkit.run_fsstat(image=image, offset=2048, fsstat_binary=fake_bin)

    argv = captured["argv"]
    assert argv == [str(fake_bin), "-o", "2048", str(image)]
    payload = captured["kwargs"]["extra_audit_payload"]
    assert payload["offset"] == 2048


def test_run_fsstat_rejects_negative_offset(tmp_path: Path) -> None:
    image = tmp_path / "disk.dd"
    image.write_bytes(b"FAKEIMG")
    fake_bin = _fake_bin(tmp_path, "fsstat")
    with pytest.raises(ToolRunError):
        sleuthkit.run_fsstat(image=image, offset=-1, fsstat_binary=fake_bin)


def test_run_fsstat_rejects_missing_image(tmp_path: Path) -> None:
    fake_bin = _fake_bin(tmp_path, "fsstat")
    with pytest.raises(ToolRunError):
        sleuthkit.run_fsstat(
            image=tmp_path / "nope.dd",
            fsstat_binary=fake_bin,
        )


# ---------------------------------------------------------------------------
# run_fls
# ---------------------------------------------------------------------------


def test_run_fls_minimal_argv(tmp_path: Path) -> None:
    image = tmp_path / "disk.dd"
    image.write_bytes(b"FAKEIMG")
    fake_bin = _fake_bin(tmp_path, "fls")

    captured: dict[str, object] = {}

    def _stub(argv: list[str], **kwargs: object) -> ToolRunResult:
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return _fake_result(tool="fls", argv=argv)

    with patch("core.sift.sleuthkit.run_tool", side_effect=_stub):
        sleuthkit.run_fls(image=image, fls_binary=fake_bin)

    argv = captured["argv"]
    assert argv == [str(fake_bin), str(image)]
    # No -o, no -r, no trailing inode.
    assert "-o" not in argv
    assert "-r" not in argv
    payload = captured["kwargs"]["extra_audit_payload"]
    assert payload["offset"] is None
    assert payload["inode"] is None
    assert payload["recursive"] is False
    assert payload["evidence_readonly_assumed"] is True


def test_run_fls_full_argv_with_offset_recursive_inode(tmp_path: Path) -> None:
    image = tmp_path / "disk.dd"
    image.write_bytes(b"FAKEIMG")
    fake_bin = _fake_bin(tmp_path, "fls")

    captured: dict[str, object] = {}

    def _stub(argv: list[str], **kwargs: object) -> ToolRunResult:
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return _fake_result(tool="fls", argv=argv)

    with patch("core.sift.sleuthkit.run_tool", side_effect=_stub):
        sleuthkit.run_fls(
            image=image,
            offset=2048,
            inode="5",
            recursive=True,
            fls_binary=fake_bin,
        )

    argv = captured["argv"]
    assert argv == [str(fake_bin), "-o", "2048", "-r", str(image), "5"]
    payload = captured["kwargs"]["extra_audit_payload"]
    assert payload["offset"] == 2048
    assert payload["inode"] == "5"
    assert payload["recursive"] is True


def test_run_fls_rejects_missing_image(tmp_path: Path) -> None:
    fake_bin = _fake_bin(tmp_path, "fls")
    with pytest.raises(ToolRunError):
        sleuthkit.run_fls(image=tmp_path / "nope.dd", fls_binary=fake_bin)


def test_run_fls_rejects_negative_offset(tmp_path: Path) -> None:
    image = tmp_path / "disk.dd"
    image.write_bytes(b"FAKEIMG")
    fake_bin = _fake_bin(tmp_path, "fls")
    with pytest.raises(ToolRunError):
        sleuthkit.run_fls(image=image, offset=-42, fls_binary=fake_bin)


# ---------------------------------------------------------------------------
# run_icat
# ---------------------------------------------------------------------------


def test_run_icat_builds_expected_argv_and_writes_stdout(tmp_path: Path) -> None:
    image = tmp_path / "disk.dd"
    image.write_bytes(b"FAKEIMG")
    fake_bin = _fake_bin(tmp_path, "icat")
    out = tmp_path / "carved" / "extracted.bin"
    out.parent.mkdir()

    captured: dict[str, object] = {}

    def _stub(argv: list[str], **kwargs: object) -> ToolRunResult:
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return _fake_result(tool="icat", argv=argv, stdout="hello-file-contents")

    with patch("core.sift.sleuthkit.run_tool", side_effect=_stub):
        result = sleuthkit.run_icat(
            image=image,
            inode="128-144-1",
            output_path=out,
            offset=2048,
            icat_binary=fake_bin,
        )

    assert result.ok is True
    argv = captured["argv"]
    assert argv == [str(fake_bin), "-o", "2048", str(image), "128-144-1"]
    payload = captured["kwargs"]["extra_audit_payload"]
    assert payload["image"] == str(image)
    assert payload["offset"] == 2048
    assert payload["inode"] == "128-144-1"
    assert payload["output_path"] == str(out)
    assert payload["evidence_readonly_assumed"] is True
    # Wrapper must actually persist captured stdout to disk.
    assert out.exists()
    assert out.read_bytes() == b"hello-file-contents"


def test_run_icat_without_offset_omits_dash_o(tmp_path: Path) -> None:
    image = tmp_path / "disk.dd"
    image.write_bytes(b"FAKEIMG")
    fake_bin = _fake_bin(tmp_path, "icat")
    out = tmp_path / "out.bin"

    captured: dict[str, object] = {}

    def _stub(argv: list[str], **kwargs: object) -> ToolRunResult:
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return _fake_result(tool="icat", argv=argv, stdout="")

    with patch("core.sift.sleuthkit.run_tool", side_effect=_stub):
        sleuthkit.run_icat(
            image=image,
            inode="5",
            output_path=out,
            icat_binary=fake_bin,
        )

    argv = captured["argv"]
    assert argv == [str(fake_bin), str(image), "5"]
    assert "-o" not in argv


def test_run_icat_rejects_missing_image(tmp_path: Path) -> None:
    fake_bin = _fake_bin(tmp_path, "icat")
    out = tmp_path / "out.bin"
    with pytest.raises(ToolRunError):
        sleuthkit.run_icat(
            image=tmp_path / "nope.dd",
            inode="5",
            output_path=out,
            icat_binary=fake_bin,
        )


def test_run_icat_refuses_to_overwrite_existing_output(tmp_path: Path) -> None:
    image = tmp_path / "disk.dd"
    image.write_bytes(b"FAKEIMG")
    fake_bin = _fake_bin(tmp_path, "icat")
    out = tmp_path / "already-there.bin"
    out.write_bytes(b"prior-extraction")
    with pytest.raises(ToolRunError):
        sleuthkit.run_icat(
            image=image,
            inode="5",
            output_path=out,
            icat_binary=fake_bin,
        )


def test_run_icat_rejects_missing_parent_dir(tmp_path: Path) -> None:
    image = tmp_path / "disk.dd"
    image.write_bytes(b"FAKEIMG")
    fake_bin = _fake_bin(tmp_path, "icat")
    out = tmp_path / "no-such-dir" / "out.bin"
    with pytest.raises(ToolRunError):
        sleuthkit.run_icat(
            image=image,
            inode="5",
            output_path=out,
            icat_binary=fake_bin,
        )


def test_run_icat_rejects_negative_offset(tmp_path: Path) -> None:
    image = tmp_path / "disk.dd"
    image.write_bytes(b"FAKEIMG")
    fake_bin = _fake_bin(tmp_path, "icat")
    out = tmp_path / "out.bin"
    with pytest.raises(ToolRunError):
        sleuthkit.run_icat(
            image=image,
            inode="5",
            output_path=out,
            offset=-1,
            icat_binary=fake_bin,
        )


# ---------------------------------------------------------------------------
# _resolve_binary fallback path (no explicit *_binary kwarg)
# ---------------------------------------------------------------------------


def test_resolve_binary_raises_when_missing() -> None:
    with patch("core.sift.sleuthkit.shutil.which", return_value=None):
        with pytest.raises(ToolRunError):
            sleuthkit._resolve_binary("mmls")


def test_run_mmls_uses_resolve_binary_when_not_supplied(tmp_path: Path) -> None:
    image = tmp_path / "disk.dd"
    image.write_bytes(b"FAKEIMG")
    fake_bin = _fake_bin(tmp_path, "mmls")

    captured: dict[str, object] = {}

    def _stub(argv: list[str], **kwargs: object) -> ToolRunResult:
        captured["argv"] = argv
        return _fake_result(tool="mmls", argv=argv)

    with (
        patch(
            "core.sift.sleuthkit._resolve_binary",
            return_value=fake_bin,
        ) as mock_resolve,
        patch("core.sift.sleuthkit.run_tool", side_effect=_stub),
    ):
        sleuthkit.run_mmls(image=image)

    mock_resolve.assert_called_once_with("mmls")
    assert captured["argv"][0] == str(fake_bin)


# ---------------------------------------------------------------------------
# audit payload sanity (evidence_readonly_assumed flag everywhere)
# ---------------------------------------------------------------------------


def test_every_wrapper_sets_evidence_readonly_assumed(
    tmp_path: Path,
    tmp_log_dir: Path,
) -> None:
    image = tmp_path / "disk.dd"
    image.write_bytes(b"FAKEIMG")
    out = tmp_path / "carved.bin"

    audit = AuditLogger(incident_id="incident-sleuthkit", log_dir=tmp_log_dir)

    # Each wrapper runs against the same stubbed runner. We check the
    # extra_audit_payload that the wrapper *passes* to run_tool -- this
    # is what downstream audit consumers see in the 'start' event.
    seen_payloads: list[dict[str, object]] = []

    def _stub(argv: list[str], **kwargs: object) -> ToolRunResult:
        seen_payloads.append(dict(kwargs["extra_audit_payload"]))
        return _fake_result(tool=kwargs["tool_name"], argv=argv, stdout="")

    with patch("core.sift.sleuthkit.run_tool", side_effect=_stub):
        sleuthkit.run_mmls(
            image=image,
            audit=audit,
            mmls_binary=_fake_bin(tmp_path, "mmls"),
        )
        sleuthkit.run_fsstat(
            image=image,
            offset=2048,
            audit=audit,
            fsstat_binary=_fake_bin(tmp_path, "fsstat"),
        )
        sleuthkit.run_fls(
            image=image,
            audit=audit,
            fls_binary=_fake_bin(tmp_path, "fls"),
        )
        sleuthkit.run_icat(
            image=image,
            inode="5",
            output_path=out,
            audit=audit,
            icat_binary=_fake_bin(tmp_path, "icat"),
        )

    assert len(seen_payloads) == 4
    for payload in seen_payloads:
        assert payload["evidence_readonly_assumed"] is True
        assert payload["image"] == str(image)
