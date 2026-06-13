---
id: kb-win-persist-schtasks-001
title: "Windows Scheduled Tasks — persistence and masquerading"
source_type: author-original
attribution: "APTWatcher team (clean-room)"
mitre_techniques:
  - T1053.005
  - T1036.005
artifact_types:
  - scheduled_tasks
  - event_logs
  - registry
tools:
  - RegRipper
  - evtx_dump
  - schtasks.exe
last_updated: "2026-04-19"
---

## When to look here

A scheduled task is one of the most durable persistence primitives on
Windows. A triage run should always sweep tasks because:

- They survive reboots and user logoff.
- They can run as `SYSTEM` even if the creating process ran as a user.
- They are trivial to disguise as Microsoft components.

APTWatcher checks tasks on every Tier 0 Windows triage regardless of
what else the evidence suggests — absence of a suspicious task is itself
a useful negative finding.

## Where the evidence lives

On a live or disk-image system:

- Task definitions — `C:\Windows\System32\Tasks\` (XML, one file per task).
- Task registrations — registry keys under
  `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks`
  and `...\Tree`.
- Execution history — `Microsoft-Windows-TaskScheduler/Operational.evtx`.

Key Security/TaskScheduler event IDs:

| Event ID | Log                                 | Meaning                                             |
|----------|-------------------------------------|-----------------------------------------------------|
| 4698     | Security.evtx                       | Scheduled task created                              |
| 4699     | Security.evtx                       | Scheduled task deleted                              |
| 4700     | Security.evtx                       | Scheduled task enabled                              |
| 4702     | Security.evtx                       | Scheduled task updated                              |
| 106      | TaskScheduler/Operational.evtx      | Task registered by a user                           |
| 140      | TaskScheduler/Operational.evtx      | Task updated                                        |
| 200      | TaskScheduler/Operational.evtx      | Action started (includes the command line)          |

## Indicators worth flagging

- Task action is a LOLBin (`powershell.exe`, `wscript.exe`, `mshta.exe`,
  `regsvr32.exe`, `rundll32.exe`) with encoded or obfuscated arguments.
- Task action path contains `%APPDATA%`, `%TEMP%`, `C:\Users\Public\`, or
  any writable location unusual for a system task.
- Task name imitates a Microsoft component (`MicrosoftUpdater`,
  `OneDriveSync`, `GoogleUpdateTaskMachineCore` *on a non-Google host*).
- Registering author is a local admin account rather than `SYSTEM` or a
  known service principal.
- Task created within the suspected intrusion window but with a
  pre-dated modification time — timestomping is worth a closer look.

## What APTWatcher records

A finding on a suspicious scheduled task cites:

1. The `Tasks` XML path or the TaskCache registry locator.
2. The task's command line (source=`Tasks\<name>.xml`, locator=XPath).
3. The creation event (Event ID 4698, Security.evtx, `record=<n>`).
4. If execution occurred: Event ID 200 from the Operational log.

One citation is circumstantial ("consistent with T1053.005"). All four
together are confirmed execution.

## Common pitfalls

- **Legitimate tasks masquerade too**. Chrome, OneDrive, and AV vendors
  install scheduled tasks with non-obvious names. Cross-check against a
  clean baseline of the same Windows version before calling a name
  suspicious.
- **Task XML alone does not prove execution**. The agent needs the
  Operational log entry to cite execution, not just registration.
- **Deleted tasks disappear from the filesystem but leave 4699 events**.
  An attacker who cleaned up leaves a trail in Security.evtx unless
  they also cleared the log (T1070.001, itself a flag).
