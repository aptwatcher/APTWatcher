---
id: kb-win-impact-vss-001
title: "Shadow copy deletion — ransomware pre-detonation signal"
source_type: author-original
attribution: "APTWatcher team (clean-room)"
mitre_techniques:
  - T1490
artifact_types:
  - event_logs
  - registry
  - prefetch
tools:
  - RegRipper
  - evtx_dump
  - prefetch-parser
last_updated: "2026-04-19"
---

## Why this matters

The single most reliable pre-detonation signal for commodity ransomware
is the deletion of Volume Shadow Copies. Ransomware crews remove VSS
snapshots so victims cannot roll back after encryption. An observation
of this activity in the last hour before an incident call is strong
evidence that detonation has happened or is imminent; catching it
pre-encryption is one of the clearest "act now" triggers.

APTWatcher treats VSS deletion as a **high-priority, early-interrupt
finding** in the timeline pass, not a routine observation buried in
the report body.

## What to look for

Common commands issued by ransomware operators:

| Command                                    | Notes                                |
|--------------------------------------------|--------------------------------------|
| `vssadmin.exe delete shadows /all /quiet`  | Classic signature                    |
| `wmic.exe shadowcopy delete`               | WMI variant                          |
| `bcdedit.exe /set {default} recoveryenabled No` | Boot recovery disable          |
| `wbadmin.exe delete catalog -quiet`        | Windows Server Backup catalog delete |
| `powershell ... Get-WmiObject Win32_Shadowcopy | ... | Remove-WmiObject` | PowerShell variant |

Any of these, run by a process that is not a scheduled Windows Backup
task, in a window adjacent to other compromise indicators, is high
confidence.

## Where the evidence lives

- **Event logs**
  - Security 4688 (process creation) with `vssadmin.exe`, `bcdedit.exe`,
    `wbadmin.exe`, or `wmic.exe` as the new process name. If command-line
    auditing is enabled, the full argv is in the event.
  - System 7036 / 7040 around the VSS service state changes.
- **Prefetch** — `VSSADMIN.EXE-<hash>.pf` and `BCDEDIT.EXE-<hash>.pf` if
  created or updated recently. Prefetch alone tells you *when* the
  binary ran and how many times, not *how*.
- **Registry** — `HKLM\SYSTEM\CurrentControlSet\Services\VSS\Diag` may
  hold recent shadow operation traces depending on the Windows build.

## What APTWatcher records

A VSS-deletion finding cites:

1. The 4688 event (source=`Security.evtx`, locator=`event_id=4688
   record=<n>`) with the exact command line.
2. The Prefetch entry for `vssadmin.exe` or the alternative LOLBin,
   with `run_count` and `last_run_times` (source=`prefetch:
   VSSADMIN.EXE-<hash>.pf`).
3. The parent process (source=4688 `Creator Process`). A legitimate
   backup solution, a scheduled task, or a human admin session narrows
   the false-positive rate substantially.
4. Proximity to file-modification anomalies in the same window —
   relevant if encryption has started, still worth noting if not.

## Confidence calibration

- Command observed, no other indicators: `confidence <= 0.6` — could be
  legitimate maintenance.
- Command + unusual parent (Office child, PowerShell reflective loader,
  `rundll32.exe` from user profile): `confidence <= 0.85`.
- Command + unusual parent + concurrent mass-file-modification
  signature: high confidence ransomware pre-detonation or detonation.

## Pairing with other findings

VSS deletion rarely stands alone in a real incident. Pair this finding
with:

- Scheduled task persistence (T1053.005) — the launcher.
- Defender tamper / event-log clear (T1070.001) — the cover-up.
- Service installation for beacon persistence (T1543.003) — the
  foothold.

A report that lists VSS deletion without these adjacent findings is
likely incomplete; APTWatcher flags it for reviewer attention rather
than shipping silently.
