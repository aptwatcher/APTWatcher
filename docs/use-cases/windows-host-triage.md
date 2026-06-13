# Use case: Windows host triage

> The default profile for single-host Windows work. Full disk image, memory
> capture, and a triage bundle. If you have all three, this is where you
> start.

## When to use

- A single Windows workstation or server is suspected of compromise.
- You have either a full E01 / AFF4 disk image **or** a KAPE-style triage
  bundle plus a memory capture.
- The host is no longer live (or has been paused) — evidence integrity is
  established before the profile runs.

If the host is still live and the encryption routine is running, use
[Memory only](memory-only.md) until the capture is clean.

## Profile declaration

```yaml
profile: windows-host-triage
required_tools:
  - volatility3 >= 2.4
  - log2timeline.py >= 20240504
  - bulk_extractor
  - RegRipper
  - yara
optional_tools:
  - evtx_dump
  - prefetch-parser
  - shellbag_parser
artifact_categories:
  required:
    - memory OR disk_image
    - event_logs
    - registry
    - scheduled_tasks
  optional:
    - prefetch
    - browser_history
    - shellbags
    - srum
tier_prerequisites:
  tier_1: optional
  tier_2: optional
  tier_3: gated_by_flag
```

`memory OR disk_image` means at least one must be present. Both is preferred.

## What the agent does under this profile

1. **Preflight** records tool versions and evidence inventory to the audit log.
2. **Timeline before artifact inspection.** Plaso runs first; the super-timeline
   becomes the cross-reference spine for every later finding.
3. **Registry sweep** via RegRipper: autoruns, scheduled tasks, USB history,
   user accounts, installed services.
4. **Event log review** scoped to the timeline window of interest.
5. **Prefetch + SRUM** for execution evidence, scoped similarly.
6. **Memory triage** (if present) via Volatility: `pslist`, `pstree`,
   `netscan`, `malfind`, `handles`, `cmdline`.
7. **Yara scan** of the memory image and any suspicious files surfaced.
8. **Report** with MITRE mapping, phrased as "consistent with..." not
   "caused by...".

See [shared brain](../architecture/shared-brain.md) for the `HostEvidence`
structure that carries this across modes.

## What it cannot do

- **Cloud audit logs.** M365 / Azure AD log analysis is out of scope for
  this profile. Treat those as a separate artifact source.
- **Network-level answers.** If the question is "what left the network",
  this profile shows staging (files on disk) but not egress (PCAP, netflow).
  Pair with [Network artifact](network-artifact.md).
- **Active containment.** Tier 3 is gated by flag; this profile does not
  enable it automatically.

## Failure modes

- **Missing Volatility**: aborts with a pointer to the SIFT update command.
  The agent will not proceed memory-blind if memory was part of the bundle.
- **Missing memory capture but disk present**: proceeds; logs a warning that
  volatile-state artifacts (injected processes, unlinked handles) cannot be
  surfaced.
- **Triage bundle with no registry hives**: aborts. Registry evidence is
  core to Windows triage; without it, the report risks being fiction.

## Scenario mapping

- [S01 — Single Windows host compromise](../scenarios/S01-single-windows-compromise.md)
  runs under this profile end-to-end.
- [S02](../scenarios/S02-multi-host-lateral-movement.md) runs this profile
  per host, then pivots to [Timeline only](timeline-only.md) for cross-host
  correlation.

## Related

- [Reference — SIFT tools](../reference/sift-tools.md)
- [Reference — MCP tools](../reference/mcp-tools.md)
- [Tier 0 — SIFT lifecycle](../design/tier0-sift-lifecycle.md)
