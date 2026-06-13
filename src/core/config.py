"""
Configuration loader.

Reads `config.yaml` and overlays environment variables. Credentials never
live in the YAML — they come from env vars referenced by `*_env` keys. The
loader does not *read* those env vars itself (the adapters do, at
connect time); it only records their names.

References:
- docs/getting-started/installation.md (config shape)
- docs/integrations/apt-watch.md (Tier 1 config)
- docs/integrations/ms-threat-analytics.md (Tier 1 config)
- docs/integrations/glpi.md (Tier 2 config)
- docs/integrations/cnc-disruptor.md (Tier 3/4 config)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field


class _Section(BaseModel):
    model_config = ConfigDict(extra="allow")


class TierConfig(_Section):
    tier_0: bool = True
    tier_1: bool = False
    tier_2: bool = False
    tier_3: bool = False
    tier_4: bool = False


class AuditConfig(_Section):
    log_dir: str = "logs"


class IntelProviderConfig(_Section):
    enabled: bool = False
    base_url: str | None = None
    mcp_endpoint: str | None = None
    api_key_env: str | None = None
    auth_mode: str | None = None
    tenant_id_env: str | None = None
    client_id_env: str | None = None
    client_secret_env: str | None = None
    rate_limit: dict[str, int] = Field(default_factory=dict)
    timeout_seconds: int = 10
    cache_ttl_seconds: int = 900


class IntelConfig(_Section):
    # Curated + MS (existing)
    apt_watch: IntelProviderConfig = Field(default_factory=IntelProviderConfig)
    ms_threat_analytics: IntelProviderConfig = Field(default_factory=IntelProviderConfig)
    # Keyless OSINT providers
    dshield: IntelProviderConfig = Field(default_factory=IntelProviderConfig)
    shodan_internetdb: IntelProviderConfig = Field(default_factory=IntelProviderConfig)
    firehol: IntelProviderConfig = Field(default_factory=IntelProviderConfig)
    stevenblack: IntelProviderConfig = Field(default_factory=IntelProviderConfig)
    ipsum: IntelProviderConfig = Field(default_factory=IntelProviderConfig)
    threatfox: IntelProviderConfig = Field(default_factory=IntelProviderConfig)
    tweetfeed: IntelProviderConfig = Field(default_factory=IntelProviderConfig)
    # Keyed OSINT providers (api_key_env names the env var, never the key)
    virustotal: IntelProviderConfig = Field(default_factory=IntelProviderConfig)
    abuseipdb: IntelProviderConfig = Field(default_factory=IntelProviderConfig)
    otx: IntelProviderConfig = Field(default_factory=IntelProviderConfig)
    censys: IntelProviderConfig = Field(default_factory=IntelProviderConfig)


class GLPIConfig(_Section):
    enabled: bool = False
    mcp_endpoint: str | None = None
    config_file: str | None = None
    default_entity_id: int = 0
    default_itil_category: str = "Security / Incident Response"
    default_urgency: int = 4
    default_impact: int = 4
    default_priority: int = 4
    ticket_title_template: str = "[APTWatcher] {scenario_id} — {host} — {summary}"
    idempotency: dict[str, Any] = Field(default_factory=dict)


class WorkflowConfig(_Section):
    glpi: GLPIConfig = Field(default_factory=GLPIConfig)


class ContainmentConfig(_Section):
    enabled: bool = False
    path: str | None = None
    powershell_bin: str | None = None
    python_bin: str | None = None
    require_per_action_confirm: bool = True
    audit_preflight: bool = True


class OffensiveConfig(_Section):
    enabled: bool = False
    require_legal_ack: bool = True
    legal_ack_phrase: str = "I accept responsibility for this action"


class ContainmentSection(_Section):
    cnc_disruptor: ContainmentConfig = Field(default_factory=ContainmentConfig)


class APTWatcherConfig(_Section):
    profile: str = "windows-host-triage"
    tiers: TierConfig = Field(default_factory=TierConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    intel: IntelConfig = Field(default_factory=IntelConfig)
    workflow: WorkflowConfig = Field(default_factory=WorkflowConfig)
    containment: ContainmentSection = Field(default_factory=ContainmentSection)
    offensive: OffensiveConfig = Field(default_factory=OffensiveConfig)

    # --- Phase 3.8 — optional analysis pipeline fan-out --------------
    # When `emit_analysis_pipeline` is True the AgentLoop's finalize()
    # step fans verified findings + IOCs into the shared-brain analysis
    # pipeline (rule generators, IOC exporters, report renderers). The
    # fan-out is strictly additive — a failure anywhere inside it must
    # not abort the verdict. See docs/design/analysis-output-pipeline.md.
    emit_analysis_pipeline: bool = False
    analysis_output_dir: Path | None = None
    analysis_campaign_tag: str | None = None
    # If set AND emit_analysis_pipeline is True, an IncidentBundle is
    # exported with this Ed25519 private key (raw hex, 32 bytes = 64
    # hex chars). Leave unset to skip the bundle step.
    analysis_sign_key_hex: str | None = None
    # Languages for the .docx report renderer. Markdown outputs stay EN.
    analysis_languages: list[str] = Field(default_factory=lambda: ["en"])


def load_config(path: Path | str) -> APTWatcherConfig:
    """Load a YAML config into a typed `APTWatcherConfig`."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config not found at {p}")
    with p.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Config root must be a mapping; got {type(data).__name__}")
    return APTWatcherConfig.model_validate(data)


def default_config() -> APTWatcherConfig:
    """Tier 0-only default. Runs on any SIFT VM with no credentials."""
    return APTWatcherConfig()


__all__ = [
    "APTWatcherConfig",
    "AuditConfig",
    "ContainmentConfig",
    "ContainmentSection",
    "GLPIConfig",
    "IntelConfig",
    "IntelProviderConfig",
    "OffensiveConfig",
    "TierConfig",
    "WorkflowConfig",
    "default_config",
    "load_config",
]
