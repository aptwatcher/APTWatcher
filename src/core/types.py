"""
Core data types for APTWatcher.

Every deployment mode (A/B/C) imports these. They are the contract between
the shared brain and the surfaces that expose it. Keep them boring,
immutable where possible, and always explicitly typed.

References:
- docs/architecture/shared-brain.md
- docs/architecture/audit-logging.md
- docs/architecture/evidence-integrity.md
- docs/design/tier1-intel-lookup-pattern.md
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Identity / provenance
# ---------------------------------------------------------------------------


IOCType = Literal[
    "ipv4",
    "ipv6",
    "domain",
    "url",
    "sha256",
    "sha1",
    "md5",
    "email",
]

Verdict = Literal["malicious", "suspicious", "benign", "unknown"]

SpoliationRisk = Literal[
    "read_only",
    "state_changing_operational",
    "state_changing_external",
]


class Tier(int, Enum):
    """Capability tier. See docs/architecture/tier-model.md."""

    CORE_TRIAGE = 0
    EXTERNAL_INTEL = 1
    IR_WORKFLOW = 2
    DEFENSIVE_CONTAINMENT = 3
    OFFENSIVE_CONTAINMENT = 4


# ---------------------------------------------------------------------------
# Base model config
# ---------------------------------------------------------------------------


class _Model(BaseModel):
    """Base model with frozen semantics for value-like records."""

    model_config = ConfigDict(
        frozen=False,  # audit records get rebuilt; keep them mutable-by-default
        extra="forbid",
        populate_by_name=True,
    )


def utcnow() -> datetime:
    """Single source of truth for 'now'. All timestamps are UTC."""
    return datetime.now(tz=UTC)


# ---------------------------------------------------------------------------
# Threat-intel verdicts (Tier 1)
# ---------------------------------------------------------------------------


class IOCProviderResult(_Model):
    """One provider's answer for one IOC. Adapter-internal shape."""

    name: str
    verdict: Verdict
    score: float | None = Field(default=None, ge=0.0, le=1.0)
    raw: dict[str, Any] = Field(default_factory=dict)


class IOCAttribution(_Model):
    actor: str | None = None
    campaign: str | None = None
    family: str | None = None


class IOCVerdict(_Model):
    """
    Normalized answer returned by `check_ioc()`. Aggregates across providers.

    Sources are preserved so the agent can reason about disagreement.
    `verdict: unknown` is a legitimate terminal state, never an error.
    """

    value: str
    ioc_type: IOCType
    verdict: Verdict
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    sources: list[IOCProviderResult] = Field(default_factory=list)
    attributions: list[IOCAttribution] = Field(default_factory=list)
    notes: str | None = None


# ---------------------------------------------------------------------------
# Evidence + findings (Tier 0)
# ---------------------------------------------------------------------------


class EvidenceFile(_Model):
    """One file on the evidence mount. Recorded at preflight."""

    path: str
    sha256: str
    size_bytes: int
    kind: Literal["disk_image", "memory_image", "triage_bundle", "pcap", "log_bundle", "other"]


class HostEvidence(_Model):
    """Everything the agent knows about one host's evidence."""

    host: str
    platform: Literal["windows", "linux", "macos", "unknown"] = "unknown"
    evidence_files: list[EvidenceFile] = Field(default_factory=list)
    artifact_categories_present: list[str] = Field(default_factory=list)
    artifact_categories_missing: list[str] = Field(default_factory=list)


class FindingCitation(_Model):
    """Link a finding to the tool call and raw source that supports it."""

    source: str  # e.g., "Security.evtx", "registry:HKLM\\...", "volatility:malfind"
    locator: str | None = None  # e.g., "event_id=4624 record=9421"
    tool_call_id: str | None = None  # correlation_id in the audit log


class Finding(_Model):
    """
    A single scored observation the agent intends to include in the report.

    Every finding MUST have at least one citation. The self-correction pass
    rejects findings with `evidence: []`.
    """

    finding_id: str
    summary: str
    mitre: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[FindingCitation] = Field(default_factory=list)
    reasoning: str | None = None
    spoliation_risk: SpoliationRisk | None = None
    created_at: datetime = Field(default_factory=utcnow)


# ---------------------------------------------------------------------------
# Preflight (Tier 0 bootstrap)
# ---------------------------------------------------------------------------


class ToolVersion(_Model):
    """Detected version of a SIFT tool."""

    name: str
    version: str | None  # None = tool present but version parse failed
    path: str
    meets_minimum: bool


class PreflightReport(_Model):
    """Return shape of `preflight()`. Persisted to the audit log verbatim."""

    profile: str
    tool_inventory: list[ToolVersion]
    missing_required: list[str] = Field(default_factory=list)
    missing_optional: list[str] = Field(default_factory=list)
    evidence_manifest: list[EvidenceFile] = Field(default_factory=list)
    tier_config: dict[str, bool] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    ok: bool  # True iff run may proceed
    generated_at: datetime = Field(default_factory=utcnow)


# ---------------------------------------------------------------------------
# Profile registry (Tier 0)
# ---------------------------------------------------------------------------


class ProfileDefinition(_Model):
    """One use-case profile. See docs/use-cases/README.md."""

    name: str
    description: str
    required_tools: list[str]
    optional_tools: list[str] = Field(default_factory=list)
    required_artifact_categories: list[str] = Field(default_factory=list)
    optional_artifact_categories: list[str] = Field(default_factory=list)
    tier_prerequisites: dict[str, Literal["optional", "required", "gated_by_flag", "not_applicable"]] = Field(
        default_factory=dict,
    )


# ---------------------------------------------------------------------------
# Audit log (see docs/architecture/audit-logging.md)
# ---------------------------------------------------------------------------


AuditEventType = Literal[
    "preflight",
    "tool_call",
    "finding",
    "self_correction",
    "claim_verification",
    "report_emit",
    "run_start",
    "run_end",
    "sift_update_consent",
    "timesketch_upload_consent",
    "llm_call",
    "analysis_emit",
    "analysis_error",
]


class AuditEvent(_Model):
    """
    One line in the JSONL audit log. Subclasses are never created; all
    variation is captured in `payload` so the log remains uniformly
    queryable with `jq '.event_type == "..."'`.
    """

    event_type: AuditEventType
    incident_id: str
    correlation_id: str | None = None
    timestamp: datetime = Field(default_factory=utcnow)
    payload: dict[str, Any] = Field(default_factory=dict)
    # Emitted at the logger boundary (see core.audit.AUDIT_SCHEMA_VERSION).
    # Optional so in-memory construction stays cheap; populated on replay.
    schema_version: str | None = None
    # Token-usage + latency telemetry for LLM-flavored events (llm_call,
    # analysis_emit, self_correction, claim_verification). Left None for
    # non-LLM events so existing `extra="forbid"` round-trips remain valid.
    token_input: int | None = None
    token_output: int | None = None
    latency_ms: int | None = None


# ---------------------------------------------------------------------------
# Containment (Tier 3/4)
# ---------------------------------------------------------------------------


class OperatorConfirmation(_Model):
    prompted_at: datetime
    confirmed_at: datetime
    confirmation_text: str


class ContainmentResult(_Model):
    tool: str
    parameters: dict[str, Any]
    pre_state_hash: str
    post_state_hash: str
    operator_confirmation: OperatorConfirmation
    result: Literal["success", "partial", "failed"]
    notes: str | None = None


# ---------------------------------------------------------------------------
# Tier 2 — ticketing
# ---------------------------------------------------------------------------


class TicketRef(_Model):
    provider: Literal["glpi"]
    ticket_id: int
    url: str | None = None


class IncidentRef(_Model):
    """Cross-system incident reference, e.g., a Defender incident ID."""

    provider: Literal["ms_defender"]
    incident_id: str
    host: str | None = None
    status: str | None = None


# ---------------------------------------------------------------------------
# Knowledge base
# ---------------------------------------------------------------------------


SourceType = Literal[
    "author-original",
    "llm-synthesis",
    "mitre-attack",
    "nist",
    "public-blog-summary",
    "dfir-report-cc",
]


class KBEntry(_Model):
    """A single file in `knowledge/`. See knowledge/README.md."""

    id: str
    title: str
    source_type: SourceType
    attribution: str
    mitre_techniques: list[str] = Field(default_factory=list)
    artifact_types: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    last_updated: str  # YYYY-MM-DD
    body: str
    path: str  # repo-relative, for citation



__all__ = [
    "AuditEvent",
    "AuditEventType",
    "ContainmentResult",
    "EvidenceFile",
    "Finding",
    "FindingCitation",
    "HostEvidence",
    "IOCAttribution",
    "IOCProviderResult",
    "IOCType",
    "IOCVerdict",
    "IncidentRef",
    "KBEntry",
    "OperatorConfirmation",
    "PreflightReport",
    "ProfileDefinition",
    "SourceType",
    "SpoliationRisk",
    "TicketRef",
    "Tier",
    "ToolVersion",
    "Verdict",
    "utcnow",
]
