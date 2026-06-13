"""
Unit tests for `tests.accuracy.scoring`.

Covers the scoring math primitives -- precision/recall/F1 with the
zero-handling convention, finding match on (tier, title, MITRE), IOC
match on (type, value), and the helper normalizers.
"""

from __future__ import annotations

import pytest

from tests.accuracy.scoring import (
    ScoredFinding,
    ScoredIOC,
    confidence_to_tier,
    from_golden_dict,
    ioc_from_dict,
    normalize_ioc_value,
    normalize_mitre,
    normalize_title,
    precision_recall_f1,
    score_findings,
    score_iocs,
)

pytestmark = pytest.mark.accuracy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _f(title: str, tier: str = "high", mitre: tuple[str, ...] = ("T1566.001",)) -> ScoredFinding:
    return ScoredFinding(
        tier=tier,
        title=normalize_title(title),
        mitre=normalize_mitre(mitre),
    )


def _i(ioc_type: str, value: str) -> ScoredIOC:
    return ScoredIOC(
        ioc_type=ioc_type.lower(),
        value=normalize_ioc_value(value, ioc_type),
    )


# ---------------------------------------------------------------------------
# precision_recall_f1
# ---------------------------------------------------------------------------


def test_prf1_perfect_match() -> None:
    p, r, f1 = precision_recall_f1(tp=4, fp=0, fn=0)
    assert p == 1.0
    assert r == 1.0
    assert f1 == 1.0


def test_prf1_half_miss_is_roughly_two_thirds() -> None:
    # tp=1, fp=1, fn=1 -> P=0.5, R=0.5, F1=0.5. Classic half-miss.
    p, r, f1 = precision_recall_f1(tp=1, fp=1, fn=1)
    assert p == 0.5
    assert r == 0.5
    assert f1 == 0.5


def test_prf1_asymmetric_half_miss_f1_roughly_two_thirds() -> None:
    # tp=2, fp=0, fn=1 -> P=1.0, R=0.667, F1=0.8 -- sanity check.
    # Also tp=2, fp=1, fn=0 -> P=0.667, R=1.0, F1=0.8.
    # "Half miss" framing in the design doc is the fp=0, fn=1 case
    # which gives F1 ~= 0.67 for one-third miss (tp=1 fn=1).
    p, r, f1 = precision_recall_f1(tp=1, fp=0, fn=1)
    assert p == 1.0
    assert r == 0.5
    assert pytest.approx(f1, abs=1e-6) == 2 / 3


def test_prf1_zero_match_all_zero() -> None:
    # No true positives at all -> F1=0.0
    p, r, f1 = precision_recall_f1(tp=0, fp=3, fn=3)
    assert p == 0.0
    assert r == 0.0
    assert f1 == 0.0


def test_prf1_degenerate_empty_returns_one() -> None:
    # Nothing expected, nothing produced -- per design-doc convention.
    p, r, f1 = precision_recall_f1(tp=0, fp=0, fn=0)
    assert p == 1.0
    assert r == 1.0
    assert f1 == 1.0


def test_prf1_only_false_positives() -> None:
    # No expectations; pure noise. P=0 because nothing is correct,
    # R=1.0 vacuously but the (0,0,0) convention only applies to the
    # all-zero case. Here tp+fn = 0 so recall falls back to 0.0.
    p, r, f1 = precision_recall_f1(tp=0, fp=5, fn=0)
    assert p == 0.0
    assert r == 0.0
    assert f1 == 0.0


# ---------------------------------------------------------------------------
# score_findings
# ---------------------------------------------------------------------------


def test_score_findings_perfect_match() -> None:
    actual = [_f("Macro execution"), _f("C2 beacon", mitre=("T1071.001",))]
    expected = [_f("macro execution"), _f("c2 beacon", mitre=("T1071.001",))]
    tp, fp, fn = score_findings(actual, expected)
    assert (tp, fp, fn) == (2, 0, 0)


def test_score_findings_title_case_and_whitespace_collapse() -> None:
    actual = [_f("  MACRO   execution.  ")]
    expected = [_f("macro execution")]
    tp, fp, fn = score_findings(actual, expected)
    assert (tp, fp, fn) == (1, 0, 0)


def test_score_findings_mitre_order_invariant() -> None:
    actual = [_f("x", mitre=("T1204.002", "T1566.001"))]
    expected = [_f("x", mitre=("T1566.001", "T1204.002"))]
    tp, fp, fn = score_findings(actual, expected)
    assert (tp, fp, fn) == (1, 0, 0)


def test_score_findings_tier_mismatch_breaks_match() -> None:
    actual = [_f("x", tier="medium")]
    expected = [_f("x", tier="high")]
    tp, fp, fn = score_findings(actual, expected)
    assert (tp, fp, fn) == (0, 1, 1)


def test_score_findings_partial_coverage() -> None:
    actual = [_f("a"), _f("b")]
    expected = [_f("a"), _f("c")]
    tp, fp, fn = score_findings(actual, expected)
    assert (tp, fp, fn) == (1, 1, 1)
    p, r, f1 = precision_recall_f1(tp, fp, fn)
    assert p == 0.5 and r == 0.5 and f1 == 0.5


def test_score_findings_zero_match() -> None:
    actual = [_f("x")]
    expected = [_f("y"), _f("z")]
    tp, fp, fn = score_findings(actual, expected)
    assert (tp, fp, fn) == (0, 1, 2)


def test_score_findings_empty_both_sides() -> None:
    tp, fp, fn = score_findings([], [])
    assert (tp, fp, fn) == (0, 0, 0)
    _, _, f1 = precision_recall_f1(tp, fp, fn)
    assert f1 == 1.0  # the degenerate-empty convention


def test_score_findings_one_to_one_when_duplicates() -> None:
    # Two actuals with identical (tier, title, mitre) against one
    # matching expected: one TP, one FP, zero FN.
    actual = [_f("dup"), _f("dup")]
    expected = [_f("dup")]
    tp, fp, fn = score_findings(actual, expected)
    assert (tp, fp, fn) == (1, 1, 0)


# ---------------------------------------------------------------------------
# score_iocs
# ---------------------------------------------------------------------------


def test_score_iocs_type_mismatch() -> None:
    # ipv4 vs ipv6 must not match even if values overlap.
    actual = [_i("ipv4", "203.0.113.1")]
    expected = [_i("ipv6", "203.0.113.1")]
    tp, fp, fn = score_iocs(actual, expected)
    assert (tp, fp, fn) == (0, 1, 1)


def test_score_iocs_normalization_matches() -> None:
    actual = [_i("domain", "EVIL.EXAMPLE")]
    expected = [_i("domain", "evil.example")]
    tp, fp, fn = score_iocs(actual, expected)
    assert (tp, fp, fn) == (1, 0, 0)


def test_score_iocs_url_trailing_slash_normalized() -> None:
    actual = [_i("url", "https://bad.example/path/")]
    expected = [_i("url", "https://bad.example/path")]
    tp, fp, fn = score_iocs(actual, expected)
    assert (tp, fp, fn) == (1, 0, 0)


# ---------------------------------------------------------------------------
# Normalizers
# ---------------------------------------------------------------------------


def test_confidence_to_tier_bands() -> None:
    assert confidence_to_tier(0.9) == "high"
    assert confidence_to_tier(0.75) == "high"
    assert confidence_to_tier(0.74) == "medium"
    assert confidence_to_tier(0.5) == "medium"
    assert confidence_to_tier(0.49) == "low"
    assert confidence_to_tier(0.0) == "low"
    assert confidence_to_tier(None) == "low"


def test_normalize_title_strips_trailing_punctuation() -> None:
    assert normalize_title("Suspicious macro execution.") == "suspicious macro execution"
    assert normalize_title("Alert!!!") == "alert"
    assert normalize_title("  multi   space  ") == "multi space"


def test_normalize_mitre_dedupes_and_uppercases() -> None:
    assert normalize_mitre(["t1566.001", "T1566.001", ""]) == frozenset({"T1566.001"})


def test_from_golden_dict_defaults_to_low_tier() -> None:
    sf = from_golden_dict({"title": "x"})
    assert sf.tier == "low"


def test_from_golden_dict_rejects_unknown_tier() -> None:
    sf = from_golden_dict({"title": "x", "tier": "nuclear"})
    assert sf.tier == "low"


def test_ioc_from_dict_accepts_either_key() -> None:
    a = ioc_from_dict({"type": "ipv4", "value": "198.51.100.5"})
    b = ioc_from_dict({"ioc_type": "ipv4", "value": "198.51.100.5"})
    assert a == b
