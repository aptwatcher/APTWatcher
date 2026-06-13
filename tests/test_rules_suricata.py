"""
Tests for the Suricata rule synthesizer.

Focus areas:
- Contiguous SID assignment from `sid_start`.
- One rule per supported IOC type (domain, url, ipv4, ipv6).
- Unsupported IOC types are skipped.
- Values with unsafe characters are rejected.
- Rule `msg` field embeds the campaign_tag.
- Empty input returns `[]`.
"""

from __future__ import annotations

import pytest

from core.analysis import (
    RuleGenerationError,
    SuricataRule,
    generate_suricata_rules,
)
from core.types import Finding, FindingCitation, IOCVerdict


def _ioc(value: str, ioc_type: str, verdict: str = "malicious") -> IOCVerdict:
    return IOCVerdict(value=value, ioc_type=ioc_type, verdict=verdict)  # type: ignore[arg-type]


def _finding(fid: str, summary: str = "placeholder") -> Finding:
    return Finding(
        finding_id=fid,
        summary=summary,
        confidence=0.8,
        evidence=[FindingCitation(source="synthetic")],
    )


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------


def test_empty_input_returns_empty_list() -> None:
    assert generate_suricata_rules(findings=[], iocs=[]) == []


# ---------------------------------------------------------------------------
# SID allocation
# ---------------------------------------------------------------------------


def test_sids_contiguous_from_sid_start() -> None:
    iocs = [
        _ioc("evil1.example", "domain"),
        _ioc("evil2.example", "domain"),
        _ioc("203.0.113.10", "ipv4"),
    ]
    rules = generate_suricata_rules(
        findings=[], iocs=iocs, sid_start=3_000_100
    )
    assert [r.sid for r in rules] == [3_000_100, 3_000_101, 3_000_102]


def test_sid_start_default_is_in_private_range() -> None:
    iocs = [_ioc("evil.example", "domain")]
    rules = generate_suricata_rules(findings=[], iocs=iocs)
    # Default declared in the design doc as 3_000_000.
    assert rules[0].sid == 3_000_000


def test_negative_sid_start_rejected() -> None:
    with pytest.raises(RuleGenerationError):
        generate_suricata_rules(findings=[], iocs=[], sid_start=-1)


# ---------------------------------------------------------------------------
# Per-type rule shape
# ---------------------------------------------------------------------------


def test_domain_rule_uses_dns_query_directive() -> None:
    rules = generate_suricata_rules(
        findings=[], iocs=[_ioc("evil.example", "domain")]
    )
    assert len(rules) == 1
    rule = rules[0]
    assert isinstance(rule, SuricataRule)
    assert rule.text.startswith("alert dns ")
    assert "dns.query" in rule.text
    assert 'content:"evil.example"' in rule.text
    assert "sid:3000000" in rule.text
    assert "rev:1" in rule.text


def test_url_rule_uses_http_uri_directive() -> None:
    rules = generate_suricata_rules(
        findings=[],
        iocs=[_ioc("http://evil.example/payload.bin?x=1", "url")],
    )
    assert len(rules) == 1
    rule = rules[0]
    assert rule.text.startswith("alert http ")
    assert "http.uri" in rule.text
    assert "payload.bin" in rule.text


def test_ipv4_rule_has_ip_destination() -> None:
    rules = generate_suricata_rules(
        findings=[], iocs=[_ioc("203.0.113.10", "ipv4")]
    )
    assert len(rules) == 1
    assert rules[0].text.startswith("alert ip any any -> 203.0.113.10 any ")


def test_ipv6_rule_has_ip_destination() -> None:
    rules = generate_suricata_rules(
        findings=[], iocs=[_ioc("2001:db8::1", "ipv6")]
    )
    assert len(rules) == 1
    assert "2001:db8::1" in rules[0].text
    assert rules[0].text.startswith("alert ip any any -> 2001:db8::1 any ")


def test_unsupported_ioc_types_are_skipped() -> None:
    iocs = [
        _ioc("a" * 64, "sha256"),
        _ioc("user@example.com", "email"),
        _ioc("evil.example", "domain"),
    ]
    rules = generate_suricata_rules(findings=[], iocs=iocs)
    assert len(rules) == 1
    assert "evil.example" in rules[0].text


# ---------------------------------------------------------------------------
# Safety guard
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_value",
    [
        'evil.example";drop-me',
        "evil.example;sid:1",
        'evil.example\nline2',
        'evil.example"quoted"',
        "evil.example\\escaped",
    ],
)
def test_unsafe_content_characters_rejected(bad_value: str) -> None:
    with pytest.raises(RuleGenerationError):
        generate_suricata_rules(
            findings=[], iocs=[_ioc(bad_value, "domain")]
        )


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


def test_msg_contains_campaign_tag() -> None:
    rules = generate_suricata_rules(
        findings=[],
        iocs=[_ioc("203.0.113.10", "ipv4")],
        campaign_tag="OPCRIMSON",
    )
    assert 'msg:"OPCRIMSON - outbound to 203.0.113.10"' in rules[0].text
    assert rules[0].meta["campaign"] == "OPCRIMSON"


def test_empty_campaign_tag_rejected() -> None:
    with pytest.raises(RuleGenerationError):
        generate_suricata_rules(
            findings=[], iocs=[_ioc("203.0.113.10", "ipv4")],
            campaign_tag="",
        )


def test_finding_ids_surface_in_meta_when_value_cited() -> None:
    findings = [
        Finding(
            finding_id="f-42",
            summary="beacon to 203.0.113.10 seen in proxy log",
            confidence=0.9,
            evidence=[FindingCitation(source="proxy.log")],
        ),
    ]
    rules = generate_suricata_rules(
        findings=findings, iocs=[_ioc("203.0.113.10", "ipv4")]
    )
    assert rules[0].meta["source_findings"] == "f-42"


def test_source_iocs_lists_the_original_value() -> None:
    rules = generate_suricata_rules(
        findings=[], iocs=[_ioc("evil.example", "domain")]
    )
    assert rules[0].source_iocs == ["evil.example"]
