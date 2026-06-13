# Shared brain — `src/core/`

> The core library that all three deployment modes import from.
> No mode owns business logic.

## Contents

```
src/core/
├── types.py           Data classes: IOCVerdict, HostEvidence, Finding, …
├── preflight.py       SIFT tool inventory + use-case profile validation
├── knowledge.py       Indexed search over knowledge/
├── ioc_extract.py     Defang + regex extractors (ipv4, ipv6, domain, url, hash, email, CVE)
├── correlation.py     Host-evidence vs intel cross-reference
├── audit.py           Structured audit logger with correlation IDs
└── intel/             Provider adapters, all returning IOCVerdict
    ├── base.py        Adapter interface
    ├── aptwatch.py    APT Watch API adapter
    ├── ms_ta.py       MS Threat Analytics adapter
    └── registry.py    Loads configured adapters at startup
```

## Key abstractions

### `IOCVerdict`

The normalized output shape every intel provider returns. Keeps the agent
from needing per-provider parsing.

```python
@dataclass
class IOCVerdict:
    value: str
    ioc_type: IOCType
    verdict: Literal["malicious", "suspicious", "benign", "unknown"]
    confidence: float          # 0.0 – 1.0
    attribution: list[str]     # ["APT28", "FancyBear"]
    first_seen: datetime | None
    last_seen: datetime | None
    sources: list[SourceHit]   # per-provider breakdown
    providers_queried: list[str]
    providers_skipped: list[str]
    cache_hit: bool
```

See [Tier 1 intel design](../design/tier1-intel-lookup-pattern.md).

### `HostEvidence`

The bundle of observables extracted from a host during triage — outbound
IPs, resolved domains, file hashes, process command lines, registry keys,
etc. Fed into `correlation.correlate_host_against_intel(evidence)` to
produce a `CorrelationReport`.

### `Finding`

Every finding the agent reports carries:

- `id` — correlation ID linking to the audit log
- `mitre_techniques` — list of ATT&CK IDs
- `confidence` — the agent's self-assessed confidence
- `evidence` — list of audit-log event IDs that support the finding
- `narrative` — the analyst-facing prose
- `next_steps` — what to investigate next (not what to do — that's for the
  human IR lead)

Findings without at least one `evidence` reference are rejected by the
audit system. Structurally, **no evidence → no finding**.

### Audit logger

JSON-lines, append-only, per-session file. Each event:

```json
{
  "session_id": "apts-2026-04-19-abc123",
  "correlation_id": "vol-001",
  "timestamp": "2026-04-19T14:22:01.412Z",
  "event": "tool_call",
  "tool": "volatility_run",
  "input": { "plugin": "windows.pslist", "image": "…" },
  "output_summary": "47 processes; 3 unsigned",
  "duration_ms": 2412,
  "spoliation_risk": "read_only"
}
```

Findings carry `evidence: ["vol-001", "vol-004"]` — every claim traces to
one or more logged tool calls. See [Audit logging](audit-logging.md).

## Why the shared-brain model matters

Without it, the three modes would diverge fast. Bug fixes would happen in
one surface but not the others. Prompt updates would drift. Intel adapter
changes would have to be ported manually.

With it, a change to `src/core/intel/aptwatch.py` immediately benefits all
three modes. Tests live at the core level. Modes are thin.

This is also the reason APTWatcher can be honest about "three modes sharing
one brain" — it's not marketing, it's repo structure.
