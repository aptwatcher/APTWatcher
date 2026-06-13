"""
Accuracy-harness scoring primitives.

Exact-match v1 scoring. Each function returns a small tuple/dataclass
so callers can assemble a `ScoreCard` without re-implementing the
counting logic. No dependencies outside the standard library so the
math is trivially unit-testable.

The harness design doc
(`docs/design/accuracy-harness.md`) is the source of truth for match
semantics. This module implements exactly what that doc specifies
and nothing more; fuzzy matching, MITRE-adjacency credit, and
embedding similarity are all future work.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------


# Collapse runs of whitespace to a single space.
_WS_RE = re.compile(r"\s+")

# Strip one trailing punctuation mark (., !, ?, ;, :) after whitespace trim
# so "Suspicious macro execution." matches "Suspicious macro execution".
_TRAILING_PUNCT_RE = re.compile(r"[.!?;:]+$")


def normalize_title(title: str) -> str:
    """Lowercase, collapse whitespace, strip trailing punctuation."""
    if title is None:
        return ""
    s = _WS_RE.sub(" ", title).strip().lower()
    return _TRAILING_PUNCT_RE.sub("", s).strip()


def normalize_mitre(mitre: Iterable[str]) -> frozenset[str]:
    """Frozenset of upper-cased MITRE IDs with surrounding whitespace trimmed."""
    return frozenset((m or "").strip().upper() for m in (mitre or []) if (m or "").strip())


def confidence_to_tier(confidence: float | None) -> str:
    """Derive a coarse tier band from a 0.0-1.0 confidence score.

    See the design doc's "Tier" discussion; `Finding` has no tier
    field today so this band mapping is the compatibility shim.
    """
    if confidence is None:
        return "low"
    if confidence >= 0.75:
        return "high"
    if confidence >= 0.50:
        return "medium"
    return "low"


def normalize_ioc_value(value: str, ioc_type: str) -> str:
    """Apply per-type normalization so comparison is canonical."""
    if value is None:
        return ""
    v = value.strip()
    t = (ioc_type or "").strip().lower()
    if t in {"domain", "email", "url", "sha256", "sha1", "md5"}:
        v = v.lower()
    if t == "url":
        v = v.rstrip("/")
    return v


# ---------------------------------------------------------------------------
# Finding-shaped record for scoring
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScoredFinding:
    """Minimal shape the scorer compares on.

    Produced from either a live `core.types.Finding` (via
    `from_finding`) or a golden JSON dict (via `from_golden_dict`).
    Keeping this tiny record separate from the production `Finding`
    model means scoring has no pydantic import and runs on plain
    dataclasses.
    """

    tier: str
    title: str
    mitre: frozenset[str]


def from_finding(finding: Any) -> ScoredFinding:
    """Pull (tier, title, mitre) out of a live Finding-like object."""
    title = normalize_title(getattr(finding, "summary", "") or "")
    mitre = normalize_mitre(getattr(finding, "mitre", []) or [])
    tier = confidence_to_tier(getattr(finding, "confidence", None))
    return ScoredFinding(tier=tier, title=title, mitre=mitre)


def from_golden_dict(d: dict[str, Any]) -> ScoredFinding:
    """Lift a golden-finding JSON dict into the scored shape."""
    title = normalize_title(d.get("title") or "")
    mitre = normalize_mitre(d.get("mitre") or [])
    tier = (d.get("tier") or "low").strip().lower()
    if tier not in {"high", "medium", "low"}:
        tier = "low"
    return ScoredFinding(tier=tier, title=title, mitre=mitre)


# ---------------------------------------------------------------------------
# IOC-shaped record for scoring
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScoredIOC:
    ioc_type: str
    value: str


def ioc_from_dict(d: dict[str, Any]) -> ScoredIOC:
    """Lift a golden or actual IOC dict into the scored shape.

    Accepts either `type` (the golden JSON convention) or
    `ioc_type` (the `core.types.IOCVerdict` attribute name).
    """
    t = (d.get("type") or d.get("ioc_type") or "").strip().lower()
    v = normalize_ioc_value(d.get("value") or "", t)
    return ScoredIOC(ioc_type=t, value=v)


# ---------------------------------------------------------------------------
# Scoring primitives
# ---------------------------------------------------------------------------


def score_findings(
    actual: list[ScoredFinding],
    expected: list[ScoredFinding],
) -> tuple[int, int, int]:
    """Return (tp, fp, fn) from a one-to-one greedy match on findings.

    Match rule: ALL of tier, normalized title, and frozenset(mitre)
    must be equal. Each actual finding consumes at most one expected
    match, and vice versa.
    """
    unmatched_expected = list(expected)  # mutable copy; pop when matched
    tp = 0
    fp = 0
    for a in actual:
        hit_index: int | None = None
        for i, e in enumerate(unmatched_expected):
            if a.tier == e.tier and a.title == e.title and a.mitre == e.mitre:
                hit_index = i
                break
        if hit_index is not None:
            tp += 1
            unmatched_expected.pop(hit_index)
        else:
            fp += 1
    fn = len(unmatched_expected)
    return tp, fp, fn


def score_iocs(
    actual: list[ScoredIOC],
    expected: list[ScoredIOC],
) -> tuple[int, int, int]:
    """Return (tp, fp, fn) from a one-to-one match on IOCs.

    Match rule: (type, normalized value) equality. Normalization is
    applied by `ioc_from_dict`; callers who build `ScoredIOC` by
    hand must normalize first.
    """
    unmatched_expected = list(expected)
    tp = 0
    fp = 0
    for a in actual:
        hit_index: int | None = None
        for i, e in enumerate(unmatched_expected):
            if a.ioc_type == e.ioc_type and a.value == e.value:
                hit_index = i
                break
        if hit_index is not None:
            tp += 1
            unmatched_expected.pop(hit_index)
        else:
            fp += 1
    fn = len(unmatched_expected)
    return tp, fp, fn


def precision_recall_f1(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    """Return (precision, recall, F1) with the design-doc zero handling.

    Convention: when tp == fp == fn == 0 (nothing expected, nothing
    produced), all three values are 1.0. Other divide-by-zero cases
    return 0.0. See `docs/design/accuracy-harness.md`.
    """
    if tp == 0 and fp == 0 and fn == 0:
        return 1.0, 1.0, 1.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )
    return precision, recall, f1


__all__ = [
    "ScoredFinding",
    "ScoredIOC",
    "confidence_to_tier",
    "from_finding",
    "from_golden_dict",
    "ioc_from_dict",
    "normalize_ioc_value",
    "normalize_mitre",
    "normalize_title",
    "precision_recall_f1",
    "score_findings",
    "score_iocs",
]
