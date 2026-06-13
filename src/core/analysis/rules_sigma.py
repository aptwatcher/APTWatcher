"""
Sigma rule synthesizer — stub.

# Phase 4 — deferred

Sigma generation is intentionally out of scope for the MVP. The
synthesizer requires a logsource classifier that maps every finding
citation back to a canonical Sigma `logsource` (product/category/
service) so the emitted YAML is directly consumable by sigmac,
hayabusa, and chainsaw. That classifier depends on EVTX-anchored
findings from the Phase 3.6 hayabusa/chainsaw wrapper and a TTP-to-
logsource lookup that has not yet been modeled.

The stub keeps the public API stable so that the CLI flag
`--formats sigma` is recognized and no-ops with an informative warning
until Phase 4 lands.

References:
- `docs/design/analysis-output-pipeline.md` — section "Sigma (Phase 4)"
"""

from __future__ import annotations

from core.analysis import SigmaRule
from core.types import Finding, IOCVerdict


def generate_sigma_rules(
    *,
    findings: list[Finding],
    iocs: list[IOCVerdict],
    campaign_tag: str = "APTWATCHER",
) -> list[SigmaRule]:
    """
    Return an empty list — Sigma generation is deferred to Phase 4.

    The signature is stable so callers can wire the CLI without a later
    breaking change. Arguments are accepted and ignored; no validation
    is performed beyond what Python's own parameter handling enforces.
    """
    # Phase 4 — deferred. See module docstring for scope rationale.
    _ = (findings, iocs, campaign_tag)
    return []


__all__ = ["generate_sigma_rules"]
