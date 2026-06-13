---
id: kb-win-evasion-masq-001
title: "Masquerading — file and process names"
source_type: author-original
attribution: "APTWatcher team (clean-room)"
mitre_techniques:
  - T1036.005
artifact_types:
  - prefetch
  - event_logs
  - registry
  - scheduled_tasks
tools:
  - prefetch-parser
  - evtx_dump
  - RegRipper
last_updated: "2026-04-19"
---

## The pattern

Attackers disguise their payloads by using file names, paths, and
parent-child process relationships that mimic legitimate Windows or
common application components. The goal is to blend into process
listings, scheduled tasks, and service registries so that a casual
sweep does not catch them. APTWatcher should always cross-check a
suspicious artifact's name against where that name is *supposed* to
live on disk and what is *supposed* to launch it.

## Categories and detection heuristics

### Wrong path for a known name

Canonical Microsoft binaries have canonical paths. A binary called
`svchost.exe` running from anywhere other than `C:\Windows\System32\`
or `C:\Windows\SysWOW64\` is immediately suspicious.

| Name            | Legitimate path(s)                                  |
|-----------------|-----------------------------------------------------|
| `svchost.exe`   | `C:\Windows\System32\`, `C:\Windows\SysWOW64\`      |
| `lsass.exe`     | `C:\Windows\System32\`                              |
| `explorer.exe`  | `C:\Windows\`                                       |
| `wininit.exe`   | `C:\Windows\System32\`                              |
| `services.exe`  | `C:\Windows\System32\`                              |
| `spoolsv.exe`   | `C:\Windows\System32\`                              |

### Look-alike names

Visual substitution: `scvhost.exe`, `svch0st.exe`, `lsasss.exe`, a
Cyrillic `а` in `chrome.exe`. Font rendering may hide single-character
swaps; normalize and compare byte-by-byte against the expected name.

### Right name, wrong parent

`cmd.exe` is legitimate; `cmd.exe` spawned by `WINWORD.EXE` in an
evidentiary triage window is consistent with a macro-dropper. Useful
parent→child flags:

- Office (`WINWORD.EXE`, `EXCEL.EXE`, `POWERPNT.EXE`) → shell (`cmd.exe`,
  `powershell.exe`, `wscript.exe`, `mshta.exe`).
- Services (`services.exe`) → shell — rare and high value.
- Browser (`chrome.exe`, `msedge.exe`) → shell — rare outside
  developer workflows.

### Scheduled-task name imitation

Tasks named `MicrosoftUpdater`, `WindowsDefenderFastScan`,
`OneDriveTelemetry` on a host that does not have the corresponding
product installed are suspicious. Cross-check against installed
products (ARP / Uninstall registry keys).

## Where to look

- `Security.evtx` 4688 — new process events with the full path; compare
  `NewProcessName` against the expected path for that basename.
- Prefetch (`C:\Windows\Prefetch\*.pf`) — each `.pf` records the
  executable's full path; compare and flag mismatches.
- `SAM` / service registry (`HKLM\SYSTEM\CurrentControlSet\Services\`)
  — service binary path is a common masquerade vector (T1543.003).
- Scheduled tasks — `C:\Windows\System32\Tasks\*` task XML has an
  `Actions\Exec\Command` field with the full path.

## What APTWatcher records

A masquerading finding cites:

1. The artifact (event, prefetch, service key) that recorded the
   unexpected path or parent.
2. The *expected* path or parent for that name — even if it's implicit
   knowledge, the finding should state what normal looks like so the
   reader can reason about it.
3. The MITRE mapping: T1036.005 for rename/path masquerading;
   T1036.004 for match-legitimate-name-and-location; T1036.003 for
   rename-system-utilities.

## Confidence calibration

- Wrong-path-for-a-known-name, no other indicators: `confidence <= 0.6`.
  Installer stubs and some AV products also place binaries in unusual
  locations.
- Wrong-path + unusual parent + evidentiary window correlation:
  `confidence <= 0.85`.
- Wrong-path + unusual parent + subsequent network/credential/disk
  activity attributable to the process: high confidence.

## Why the "expected path" citation matters

A naive masquerading finding that just says *"svchost.exe in the wrong
place"* fails the self-correction Rule 1 check: *in the wrong place
relative to what?*. State the expected location in the finding so the
reasoning survives review.
