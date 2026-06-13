"""
Tests for core.profiles.

The profile registry is the source of truth for preflight and tool
advertisement. These tests lock in the invariants we rely on elsewhere.
"""

from __future__ import annotations

import pytest

from core.profiles import ALL_PROFILES, get_profile
from core.types import ProfileDefinition


def test_seven_profiles_registered() -> None:
    expected = {
        "windows-host-triage",
        "linux-host-triage",
        "memory-only",
        "timeline-only",
        "network-artifact",
        "osx-host-triage",
        "mobile-host-triage",
    }
    assert set(ALL_PROFILES) == expected


def test_get_profile_returns_matching_definition() -> None:
    prof = get_profile("windows-host-triage")
    assert isinstance(prof, ProfileDefinition)
    assert prof.name == "windows-host-triage"
    assert "volatility3" in prof.required_tools


def test_get_profile_unknown_raises_with_hint() -> None:
    with pytest.raises(KeyError, match="Known profiles"):
        get_profile("not-a-real-profile")


def test_every_profile_declares_required_tools_and_artifacts() -> None:
    for name, prof in ALL_PROFILES.items():
        assert prof.required_tools, f"{name} has no required tools"
        assert prof.required_artifact_categories, f"{name} has no required artifact categories"


def test_profile_tier_prereqs_use_known_values() -> None:
    allowed = {"optional", "required", "gated_by_flag", "not_applicable"}
    for prof in ALL_PROFILES.values():
        for tier, marker in prof.tier_prerequisites.items():
            assert marker in allowed, f"{prof.name}/{tier}: {marker!r} not in {allowed}"
