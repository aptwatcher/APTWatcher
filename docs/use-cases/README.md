# Use cases

> A use case is the **profile** the agent runs under. It declares which SIFT
> tools are required, which optional tiers are in play, and which artifact
> categories matter. `preflight()` reads the profile; if required tools are
> missing, the run refuses to start.

Use cases exist to keep the agent honest. Without them, an analyst handing
APTWatcher a memory-only bundle would get a quietly degraded run — no
timeline, no registry hives — with no mention that the analysis is
incomplete. With them, the agent either confirms it can do the job or
refuses with a clear message.

## The five profiles

| Profile                                             | Scope                          | Common trigger                   |
|-----------------------------------------------------|--------------------------------|----------------------------------|
| [Windows host triage](windows-host-triage.md)       | Full E01 + memory + triage     | Single-host suspected compromise |
| [Linux host triage](linux-host-triage.md)           | Full disk + memory + triage    | Suspected Linux server compromise|
| [Memory only](memory-only.md)                       | Memory image, no disk          | Live-response, early triage      |
| [Timeline only](timeline-only.md)                   | Logs, prefetch, evtx, no image | Multi-host correlation           |
| [Network artifact](network-artifact.md)             | PCAP + flow data               | Egress-alert-driven investigation|

The three [scenarios](../scenarios/README.md) each map to a profile:

- S01 → `windows-host-triage`
- S02 → `timeline-only` for cross-host, `windows-host-triage` per host
- S03 → `memory-only` (primary) with partial `windows-host-triage`

## What a profile declares

Each profile is a YAML-like record read by `preflight()`. The declarative
form is:

```yaml
profile: windows-host-triage
required_tools:
  - volatility3 >= 2.4
  - log2timeline.py
  - bulk_extractor
  - RegRipper
  - yara
optional_tools:
  - evtx_dump
artifact_categories:
  - memory
  - registry
  - event_logs
  - prefetch
  - scheduled_tasks
  - browser_history
tier_prerequisites:
  tier_1: optional
  tier_2: optional
  tier_3: not_applicable
```

`preflight()` probes each required tool, records versions to the audit log,
and aborts the run if any is missing. Optional tools are noted but not
required. See [Tier 0 — SIFT lifecycle](../design/tier0-sift-lifecycle.md)
for the probe mechanism.

## Why this is architectural, not prompt-based

A profile is a **structured config** the agent cannot override. If the user
starts a run under `memory-only`, the agent literally does not have the
timeline tools in its tool list until preflight is re-run under a different
profile. This is the [tier model](../architecture/tier-model.md) pattern
applied one level deeper: the profile acts as a sub-gate inside Tier 0.

The alternative — letting the agent decide which tools to use based on
prose instructions — produces more eloquent failures (the agent confidently
hallucinates a timeline from nothing) but fewer admissible reports.

## Graceful degradation

A profile can be partially satisfied. If an optional artifact category is
missing (e.g., no browser history in the triage bundle), the agent notes
the gap in the report but does not refuse to run. If a **required** tool or
artifact category is missing, the run refuses.

Refusal is a feature. An agent that silently works around missing evidence
is a hallucination engine. The refusal message is always actionable — it
names the missing tool and the next step.

## Choosing a profile

The choice is driven by what evidence you have, not what you wish you had:

- **Full live acquisition?** Triage profile for the OS.
- **Memory snapshot only** (e.g., vSphere pause)? Memory-only.
- **Log bundle from WEF/Graylog** with no image? Timeline-only.
- **Firewall or PCAP alert** with no host evidence yet? Network-artifact.

When in doubt, start with the narrowest profile that fits. Escalating to a
broader profile re-runs preflight cleanly. The reverse requires rolling
back findings that depended on now-unavailable tools.

## Related

- [Tier model](../architecture/tier-model.md) — where profiles sit in the
  tier architecture
- [Tier 0 — SIFT lifecycle](../design/tier0-sift-lifecycle.md) — how
  `preflight()` is implemented
- [Reference — SIFT tools](../reference/sift-tools.md) — tool version
  expectations across profiles
