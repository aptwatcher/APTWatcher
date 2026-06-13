# Use case: Timeline only

> Event logs, prefetch, evtx bundles, syslog exports. No image. The agent
> runs super-timeline work across one or many hosts, correlates by actor and
> time, and produces a narrative — without claiming to have seen anything
> the evidence does not contain.

## When to use

- Multi-host correlation where acquiring full images is impractical.
- Log bundles delivered by the SOC after an EDR or SIEM alert.
- Retrospective investigation of an incident already closed on the ops
  side, where image evidence was not preserved.
- S02-style lateral-movement analysis after per-host triage.

## Profile declaration

```yaml
profile: timeline-only
required_tools:
  - log2timeline.py >= 20240504
  - psort.py
  - evtx_dump
  - jq  # for JSONL manipulation
optional_tools:
  - chainsaw         # Sigma-rule-based evtx triage
  - hayabusa         # evtx threat hunting
  - plaso-extras
artifact_categories:
  required:
    - at_least_one:
        - event_logs (evtx)
        - syslog OR journalctl_export
        - prefetch
        - scheduled_tasks_export
        - edr_bundle
  optional:
    - firewall_logs
    - proxy_logs
    - dns_logs
    - auth_server_logs  # AD, LDAP, RADIUS
tier_prerequisites:
  tier_1: optional
  tier_2: optional
  tier_3: not_applicable
```

`at_least_one` is literal: the agent requires at least one authoritative
time-source log category. Without one, there is no timeline to build.

## What the agent does under this profile

1. **Preflight** + manifest. Every input artifact is hashed, its source
   host recorded, and its time range extracted. This becomes the evidence
   manifest in the audit log.
2. **Super-timeline build.** `log2timeline.py` against all inputs,
   normalized to UTC with host and source tags. Output is a `.plaso`
   database plus a JSONL export for the agent to read.
3. **Actor extraction.** For each event, extract the principal (user,
   service account, computer account) and the host. Build an `actor ×
   host × time` matrix.
4. **Correlation passes.** Three fixed passes:
   - **Authentication anomalies**: logons outside normal hours; new
     host-principal pairs; logon type 3 from unusual sources.
   - **Execution chains**: parent→child process events that span known
     LOLBin patterns.
   - **Credential-use sequences**: Kerberos TGT/TGS patterns that match
     Kerberoasting, AS-REP roasting, or DCSync fingerprints.
5. **Narrative assembly.** The agent builds a time-ordered narrative that
   names every event with its source. Claims without an event citation are
   a hallucination and fail self-correction.
6. **Tier 1 overlay** if enabled. IPs, hashes, and domains extracted from
   the timeline run through `check_ioc()`. Results attach to their
   originating events.
7. **Report.** Narrative first, evidence manifest second, rubric appendix
   third.

## The citation discipline

Every claim in a timeline-only report carries a citation of the form:

```
[host=ENG-WS-027, source=Security.evtx, event_id=4624, ts=2026-04-08T13:12:04Z]
```

The agent is configured to refuse to finalize a report that contains
uncited claims. This is how [self-correction](../architecture/self-correction.md)
operates under this profile specifically — because with no image, citation
is the only thing separating analysis from storytelling.

## What it cannot do

- **Artifact recovery.** Deleted files, carved registry hives, unlinked
  processes — any of these require image-based work. The agent declines
  to speculate about their existence.
- **Memory claims.** No injection calls, no LSASS scraping. If memory
  questions are essential, add [memory-only](memory-only.md).
- **Filesystem forensics.** MFT analysis, USN journal reconstruction, and
  file-slack inspection are out of scope.

## Failure modes

- **No authoritative time source**: aborts. Timeline-only without time is a
  contradiction.
- **Time skew detected** across hosts >5 min: the agent builds the timeline
  anyway but flags every cross-host correlation as low-confidence. The
  operator is explicitly told to verify NTP synchronization before treating
  cross-host claims as reliable.
- **evtx corruption** on a subset of files: the agent processes what it
  can and lists the skipped files by hash in the manifest.

## Scenario mapping

- [S02 — Multi-host lateral movement](../scenarios/S02-multi-host-lateral-movement.md)
  uses this profile for cross-host correlation after per-host triage under
  [Windows host triage](windows-host-triage.md).

## Related

- [Windows host triage](windows-host-triage.md)
- [Architecture — self-correction](../architecture/self-correction.md)
- [Reference — MITRE coverage](../reference/mitre-coverage.md)
