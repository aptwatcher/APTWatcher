"""
Tests for the per-type plain-text IOC exporter.

Coverage:
- One file per IOC type present in the input.
- Values are sorted alphabetically and deduplicated.
- Domain / email / sha256 are lowercased.
- URL values are preserved verbatim (case-sensitive paths).
- Refuses to overwrite existing ``<type>.txt`` files.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.analysis.export_iocs_txt import export_per_type_txt
from core.analysis.export_stix import IOCExportError
from core.types import IOCVerdict


def _ioc(value: str, ioc_type: str) -> IOCVerdict:
    return IOCVerdict(
        value=value,
        ioc_type=ioc_type,  # type: ignore[arg-type]
        verdict="malicious",
    )


def test_one_file_per_type(tmp_path: Path) -> None:
    iocs = [
        _ioc("1.1.1.1", "ipv4"),
        _ioc("evil.example", "domain"),
        _ioc("a" * 64, "sha256"),
        _ioc("https://bad.example/p", "url"),
    ]
    result = export_per_type_txt(iocs=iocs, output_dir=tmp_path)
    assert set(result) == {"ipv4", "domain", "sha256", "url"}
    for ioc_type, path in result.items():
        assert path == tmp_path / f"{ioc_type}.txt"
        assert path.exists()


def test_values_sorted_and_deduplicated(tmp_path: Path) -> None:
    iocs = [
        _ioc("9.9.9.9", "ipv4"),
        _ioc("1.1.1.1", "ipv4"),
        _ioc("5.5.5.5", "ipv4"),
        _ioc("1.1.1.1", "ipv4"),  # duplicate
    ]
    result = export_per_type_txt(iocs=iocs, output_dir=tmp_path)
    body = result["ipv4"].read_text(encoding="utf-8")
    lines = [ln for ln in body.splitlines() if ln]
    assert lines == ["1.1.1.1", "5.5.5.5", "9.9.9.9"]


def test_domains_and_emails_lowercased(tmp_path: Path) -> None:
    iocs = [
        _ioc("Evil.Example", "domain"),
        _ioc("ANOTHER.example", "domain"),
        _ioc("Attacker@Bad.Example", "email"),
    ]
    result = export_per_type_txt(iocs=iocs, output_dir=tmp_path)
    domain_lines = result["domain"].read_text(encoding="utf-8").splitlines()
    email_lines = result["email"].read_text(encoding="utf-8").splitlines()
    assert "evil.example" in domain_lines
    assert "another.example" in domain_lines
    assert "Evil.Example" not in domain_lines  # original case dropped
    assert "attacker@bad.example" in email_lines


def test_sha256_lowercased_and_deduplicated(tmp_path: Path) -> None:
    upper = "A" * 64
    lower = "a" * 64
    mixed = "aA" * 32
    iocs = [_ioc(upper, "sha256"), _ioc(lower, "sha256"), _ioc(mixed, "sha256")]
    result = export_per_type_txt(iocs=iocs, output_dir=tmp_path)
    lines = [
        ln for ln in result["sha256"].read_text(encoding="utf-8").splitlines() if ln
    ]
    # upper and lower normalize to the same value, so dedup -> 2 entries.
    assert lines == sorted({lower, mixed.lower()})


def test_url_case_preserved(tmp_path: Path) -> None:
    iocs = [
        _ioc("https://Bad.example/Path?Query=1", "url"),
        _ioc("https://Bad.example/path?Query=1", "url"),  # different by case
    ]
    result = export_per_type_txt(iocs=iocs, output_dir=tmp_path)
    lines = [
        ln for ln in result["url"].read_text(encoding="utf-8").splitlines() if ln
    ]
    # Both entries kept; URL paths are case-sensitive.
    assert len(lines) == 2
    assert "https://Bad.example/Path?Query=1" in lines
    assert "https://Bad.example/path?Query=1" in lines


def test_refuses_to_overwrite_existing_file(tmp_path: Path) -> None:
    (tmp_path / "ipv4.txt").write_text("preexisting\n", encoding="utf-8")
    with pytest.raises(IOCExportError):
        export_per_type_txt(
            iocs=[_ioc("1.1.1.1", "ipv4")],
            output_dir=tmp_path,
        )
    # File must remain untouched.
    assert (tmp_path / "ipv4.txt").read_text(encoding="utf-8") == "preexisting\n"


def test_empty_input_raises(tmp_path: Path) -> None:
    with pytest.raises(IOCExportError):
        export_per_type_txt(iocs=[], output_dir=tmp_path)


def test_empty_value_raises(tmp_path: Path) -> None:
    with pytest.raises(IOCExportError):
        export_per_type_txt(
            iocs=[_ioc("   ", "ipv4")],
            output_dir=tmp_path,
        )


def test_output_dir_created_if_missing(tmp_path: Path) -> None:
    nested = tmp_path / "nested" / "iocs"
    assert not nested.exists()
    result = export_per_type_txt(
        iocs=[_ioc("1.1.1.1", "ipv4")],
        output_dir=nested,
    )
    assert nested.is_dir()
    assert result["ipv4"].exists()
