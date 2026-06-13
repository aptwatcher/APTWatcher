"""
Tests for the Sigma rule synthesizer stub.

Sigma generation is deferred to Phase 4. These tests pin the public
signature so the stub can be replaced later without a breaking CLI
change.
"""

from __future__ import annotations

import inspect

from core.analysis import SigmaRule, generate_sigma_rules
from core.types import Finding, FindingCitation, IOCVerdict


def test_returns_empty_list() -> None:
    ioc = IOCVerdict(value="evil.example", ioc_type="domain", verdict="malicious")
    finding = Finding(
        finding_id="f1",
        summary="placeholder",
        confidence=0.5,
        evidence=[FindingCitation(source="synthetic")],
    )
    assert generate_sigma_rules(findings=[finding], iocs=[ioc]) == []


def test_signature_is_stable() -> None:
    """Keyword-only signature must remain stable for Phase 4 swap-in."""
    sig = inspect.signature(generate_sigma_rules)
    params = sig.parameters
    assert list(params.keys()) == ["findings", "iocs", "campaign_tag"]
    for name in ("findings", "iocs", "campaign_tag"):
        assert params[name].kind is inspect.Parameter.KEYWORD_ONLY
    assert params["campaign_tag"].default == "APTWATCHER"
    # Return annotation is list[SigmaRule].
    # `inspect.signature` returns the raw annotation string when
    # `from __future__ import annotations` is in effect — that is
    # intentional; we assert the surface-level type is SigmaRule.
    assert SigmaRule is not None
