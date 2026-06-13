"""
Tests for core.config.

Checks: defaults are Tier 0 only, YAML round-trip via load_config, unknown
top-level sections are allowed (extra="allow" for forward compatibility).
"""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest

from core.config import APTWatcherConfig, default_config, load_config


def test_default_config_is_tier_zero_only() -> None:
    cfg = default_config()
    assert cfg.tiers.tier_0 is True
    assert cfg.tiers.tier_1 is False
    assert cfg.tiers.tier_2 is False
    assert cfg.tiers.tier_3 is False
    assert cfg.tiers.tier_4 is False
    assert cfg.profile == "windows-host-triage"


def test_load_config_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(
        dedent(
            """
            profile: memory-only
            tiers:
              tier_0: true
              tier_1: true
            intel:
              apt_watch:
                enabled: true
                base_url: https://apt-watch.internal/api
                api_key_env: APT_WATCH_API_KEY
            workflow:
              glpi:
                enabled: false
            """,
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    cfg = load_config(path)
    assert isinstance(cfg, APTWatcherConfig)
    assert cfg.profile == "memory-only"
    assert cfg.tiers.tier_1 is True
    assert cfg.intel.apt_watch.enabled is True
    assert cfg.intel.apt_watch.api_key_env == "APT_WATCH_API_KEY"


def test_load_config_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "no-such-file.yaml")


def test_unknown_top_level_section_allowed(tmp_path: Path) -> None:
    """Config sections allow extra keys so forward-compatible YAML parses."""
    path = tmp_path / "config.yaml"
    path.write_text(
        "profile: windows-host-triage\nfuture_section:\n  key: val\n",
        encoding="utf-8",
    )
    cfg = load_config(path)
    assert cfg.profile == "windows-host-triage"
