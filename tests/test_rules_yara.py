"""
Tests for the YARA rule synthesizer.

Focus areas:
- Rule name sanitization (uppercase, non-alphanumeric stripped,
  campaign prefix, YARA identifier shape).
- Hash-only rule emission from explicit `hashes` argument.
- Hash-only rule emission from `sha256` IOCs.
- Filename rule emission when a name repeats across >= 3 findings.
- Meta block required keys (author, campaign, created, source_findings).
- Empty input returns `[]`.
- Invalid hash input raises `RuleGenerationError`.
"""

from __future__ import annotations

import re

import pytest

from core.analysis import (
    RuleGenerationError,
    YaraRule,
    generate_yara_rules,
)
from core.types import Finding, FindingCitation, IOCVerdict

_SHA256_A = "a" * 64
_SHA256_B = "b" * 64
_SHA256_C = "c" * 64


def _finding(fid: str, sources: list[str]) -> Finding:
    return Finding(
        finding_id=fid,
        summary=f"synthetic finding {fid}",
        confidence=0.8,
        evidence=[FindingCitation(source=s) for s in sources],
    )


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------


def test_empty_input_returns_empty_list() -> None:
    assert generate_yara_rules(findings=[], iocs=[]) == []


# ---------------------------------------------------------------------------
# Hash-based rules
# ---------------------------------------------------------------------------


def test_hash_only_rule_emitted_from_explicit_hashes() -> None:
    rules = generate_yara_rules(
        findings=[], iocs=[], hashes=[_SHA256_A]
    )
    assert len(rules) == 1
    rule = rules[0]
    assert isinstance(rule, YaraRule)
    assert _SHA256_A in rule.text
    assert rule.source_iocs == [_SHA256_A]
    # Condition uses hash.sha256 form.
    assert "hash.sha256(0, filesize)" in rule.text


def test_hash_rule_emitted_from_sha256_ioc() -> None:
    ioc = IOCVerdict(value=_SHA256_B, ioc_type="sha256", verdict="malicious")
    rules = generate_yara_rules(findings=[], iocs=[ioc])
    assert len(rules) == 1
    assert _SHA256_B in rules[0].text


def test_duplicate_hash_across_explicit_and_ioc_is_deduped() -> None:
    ioc = IOCVerdict(value=_SHA256_A, ioc_type="sha256", verdict="malicious")
    rules = generate_yara_rules(
        findings=[], iocs=[ioc], hashes=[_SHA256_A]
    )
    assert len(rules) == 1


def test_invalid_hash_raises() -> None:
    with pytest.raises(RuleGenerationError):
        generate_yara_rules(findings=[], iocs=[], hashes=["not-a-hex"])


def test_invalid_sha256_ioc_raises() -> None:
    ioc = IOCVerdict(value="ZZZ", ioc_type="sha256", verdict="malicious")
    with pytest.raises(RuleGenerationError):
        generate_yara_rules(findings=[], iocs=[ioc])


# ---------------------------------------------------------------------------
# Filename (string) rules
# ---------------------------------------------------------------------------


def test_filename_repeated_three_times_emits_string_rule() -> None:
    findings = [
        _finding("f1", ["badapp.exe"]),
        _finding("f2", ["badapp.exe"]),
        _finding("f3", ["badapp.exe"]),
    ]
    rules = generate_yara_rules(findings=findings, iocs=[])
    assert len(rules) == 1
    rule = rules[0]
    assert '$s1 = "badapp.exe" ascii wide' in rule.text
    assert "any of them" in rule.text
    assert rule.source_iocs == ["badapp.exe"]


def test_filename_with_two_occurrences_is_not_promoted() -> None:
    findings = [
        _finding("f1", ["rarely.dll"]),
        _finding("f2", ["rarely.dll"]),
    ]
    rules = generate_yara_rules(findings=findings, iocs=[])
    assert rules == []


# ---------------------------------------------------------------------------
# Naming + meta
# ---------------------------------------------------------------------------


_YARA_IDENT = re.compile(r"^[A-Z][A-Z0-9_]*$")


def test_rule_name_is_valid_yara_identifier() -> None:
    rules = generate_yara_rules(
        findings=[], iocs=[], hashes=[_SHA256_A],
        campaign_tag="Op Crimson Tide!",
    )
    assert _YARA_IDENT.match(rules[0].name)
    # Campaign tag sanitization preserves case as uppercase.
    assert rules[0].name.startswith("OP_CRIMSON_TIDE")


def test_rule_name_accepts_campaign_with_leading_digit() -> None:
    rules = generate_yara_rules(
        findings=[], iocs=[], hashes=[_SHA256_A], campaign_tag="2026q1"
    )
    # Must start with a letter.
    assert _YARA_IDENT.match(rules[0].name)
    assert rules[0].name[0].isalpha()


def test_meta_block_contains_required_keys() -> None:
    findings = [
        _finding("f1", [f"{_SHA256_C}"]),
        _finding("f2", [f"{_SHA256_C}"]),
    ]
    rules = generate_yara_rules(
        findings=findings, iocs=[], hashes=[_SHA256_C],
        campaign_tag="TESTCAMPAIGN",
    )
    meta = rules[0].meta
    assert meta["author"] == "APTWatcher"
    assert meta["campaign"] == "TESTCAMPAIGN"
    # Created is a UTC date.
    assert re.match(r"^\d{4}-\d{2}-\d{2}$", meta["created"])
    # source_findings key present and lists the citing finding ids.
    assert "f1" in meta["source_findings"]
    assert "f2" in meta["source_findings"]
    # Same data surfaces in the rendered rule text.
    text = rules[0].text
    assert 'author = "APTWatcher"' in text
    assert 'campaign = "TESTCAMPAIGN"' in text


def test_empty_campaign_tag_rejected() -> None:
    with pytest.raises(RuleGenerationError):
        generate_yara_rules(
            findings=[], iocs=[], hashes=[_SHA256_A], campaign_tag="   "
        )


def test_hash_and_filename_rules_both_emitted() -> None:
    findings = [
        _finding("f1", ["loader.exe"]),
        _finding("f2", ["loader.exe"]),
        _finding("f3", ["loader.exe"]),
    ]
    rules = generate_yara_rules(
        findings=findings, iocs=[], hashes=[_SHA256_A]
    )
    assert len(rules) == 2
    sources = [r.source_iocs[0] for r in rules]
    assert _SHA256_A in sources
    assert "loader.exe" in sources
