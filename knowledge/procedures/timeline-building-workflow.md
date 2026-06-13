---
id: kb-proc-timeline-building-001
title: "Timeline building workflow — from raw artifacts to narrative"
source_type: author-original
attribution: "APTWatcher team (clean-room)"
mitre_techniques:
  - T1070
  - T1070.006
  - T1078
  - T1059
  - T1569
artifact_types:
  - filesystem
  - evtx
  - registry
  - timeline
  - plaso_storage
tools:
  - plaso
  - psort
  - log2timeline
  - hayabusa
  - volatility3
last_updated: "2026-04-19"
---

## What a timeline is, and what it is not

A forensic timeline is an ordered list of events, each with at minimum
a UTC timestamp, a source artifact, and enough provenance to re-derive
the event from the original evidence. Every row answers three
questions: when did this happen, where on the host did we read it
from, and how certain are we the timestamp is trustworthy.

A timeline is not a verdict. It does not say "the attacker logged in
at 03:14." It says "Security event 4624, logon type 10, target user
`svc_backup`, source IP 10.4.2.19, at 2026-04-17T03:14:02Z, from
`C:\Windows\System32\winevt\Logs\Security.evtx` record 81293." The
interpretation — that this row is lateral movement — is the
narrative built on top, not part of the row. Mixing interpretation
into event rows is the fastest way to cement a bad theory.

Treat the timeline as the audit trail for the narrative. Every
sentence in the report should reach a row; every row should reach
an artifact on disk.

## Source inventory

The value of a timeline is proportional to the breadth of sources fed
into it. Before the first `log2timeline.py` run, enumerate what is
available from the evidence.

### Filesystem — NTFS

- `$MFT` — one record per file with `$STANDARD_INFORMATION` (SI) and
  `$FILE_NAME` (FN) MACB quartets. SI/FN divergence is the core
  timestomping signal for T1070.006. SI is writable from user mode;
  FN only updates on namespace operations. Plaso emits up to eight
  events per record.
- `$UsnJrnl:$J` — the NTFS change journal. Dense per-file create,
  rename, close, data-extend, and delete events. Retention is short
  on busy volumes (hours to a few days), so acquire early.
- `$LogFile` — NTFS transaction log, lower-level metadata changes.
- `$Volume` — volume creation date, used to sanity-check SI times
  that predate the filesystem itself.

### Windows registry

- `SYSTEM` — services, drivers, mounted devices, timezone, last-
  shutdown time, `ComputerName`.
- `SOFTWARE` — installed applications, Run keys, scheduled task
  roots, `NetworkList` with first/last connect times.
- `SAM` — local accounts, logon counts, last-logon times.
- `SECURITY` — LSA secrets, cached domain-logon counts.
- `NTUSER.DAT` per user — `UserAssist`, `RecentDocs`, `TypedPaths`,
  `RunMRU`, `ComDlg32\OpenSavePidlMRU`, shell bags.
- `UsrClass.dat` per user — additional shell bags, class
  registrations.

### Windows event logs (EVTX)

- `Security.evtx` — authentication and object-access events. Key
  IDs: 4624, 4625, 4634, 4647, 4648, 4672, 4688, 4697, 4698, 4720,
  4728, 4732, 4768, 4769, 4776.
- `System.evtx` — service control (7036, 7040, 7045), driver loads,
  boot and shutdown.
- `Application.evtx` — application errors, installer events.
- `Microsoft-Windows-PowerShell/Operational.evtx` — 4103 pipeline,
  4104 scriptblock (retains full script text when the policy is on).
- `Microsoft-Windows-WinRM/Operational.evtx` — remote PowerShell and
  WSMan session starts.
- `Microsoft-Windows-Sysmon/Operational.evtx` — richest per-process
  source when installed: event 1 (process create with hashes and
  command line), 3 (network), 7 (image load), 10 (process access),
  11 (file create), 13 (registry set), 22 (DNS), 23 (file delete),
  25 (process tampering).
- `Microsoft-Windows-TerminalServices-*` channels — RDP session
  lifecycle.
- `Microsoft-Windows-TaskScheduler/Operational.evtx` — task
  registration and execution.

### Execution and shell-activity artifacts

- Prefetch (`C:\Windows\Prefetch\*.pf`) — first and last eight
  execution times, run count, accessed files.
- Amcache (`C:\Windows\appcompat\Programs\Amcache.hve`) —
  `InventoryApplicationFile` entries with first-seen time and
  SHA-1. Stronger provenance than ShimCache on modern Windows.
- ShimCache / AppCompatCache (in `SYSTEM`) — last-modified time at
  shim insertion. Not a first-execution timestamp; easily misread.
- UserAssist — GUI-launched program history, ROT-13 encoded, with
  launch counts and last-run times.
- MUICache — executable paths keyed by localized display name.
- JumpLists under `AppData\Roaming\Microsoft\Windows\Recent` —
  application-specific MRU data.
- LNK files — target path, volume serial, target MAC times at link
  creation.
- Recycle bin (`$Recycle.Bin\<SID>\$I*`, `$R*`) — deletion time,
  original path, original size.
- Browser history — Chrome/Edge `History`, Firefox `places.sqlite`.

### Linux and macOS

- Linux: `/var/log/audit/audit.log` (auditd), `/var/log/journal/`
  (journald binary journals), `/var/log/auth.log` or
  `/var/log/secure`, `~/.bash_history` / `~/.zsh_history` (written
  at session exit only), `/var/log/wtmp`/`btmp`/`lastlog`,
  `/etc/cron*` and `/var/spool/cron/`.
- macOS: unified log (`log collect` or `.logarchive`), `KnowledgeC.db`
  under `~/Library/Application Support/Knowledge/`, FSEvents at each
  volume root, Spotlight metadata store.

## Plaso workflow

Plaso is the baseline timeline engine. The two commands that matter
for most cases are `log2timeline.py` (ingest) and `psort.py` (filter
and render).

### Capture narrative

Record the exact `log2timeline.py` invocation in the case notes
before running it. The invocation is part of the provenance chain —
changing parsers later produces different events from the same
evidence.

```bash
log2timeline.py \
  --storage-file case.plaso \
  --parsers "win7,!filestat" \
  --hashers "sha256" \
  /evidence/host01/
```

### Parser presets

Presets trade breadth for runtime. Common choices:

- `win7` — Windows 7-and-later preset, covers EVTX, registry,
  Prefetch, LNK, recycle bin, browser history, and filesystem.
- `win_gen` — the pre-7 preset, still useful for legacy hosts.
- `linux` — syslog family, auditd, utmp/wtmp, bash history.
- `macos` — plist family, KnowledgeC, FSEvents, unified log
  fragments.
- `webhist` — browser history only, fast triage pass.

Disable `filestat` on large disk images unless you need every
filesystem MAC change — it produces enormous event volume and
drowns higher-signal sources. The `$MFT` parser gives you SI/FN
events at the record level, which is usually what you want.

### Filter and render

```bash
# CSV in l2tcsv format, incident window only
psort.py -o l2tcsv -w timeline.csv case.plaso \
  "date > '2026-04-17 00:00:00' AND date < '2026-04-19 23:59:59'"

# JSONL for programmatic consumption by APTWatcher
psort.py -o json_line -w timeline.jsonl case.plaso

# XLSX for analyst review
psort.py -o xlsx -w timeline.xlsx case.plaso
```

Tagging rules let you annotate events as they flow out of the
`.plaso` store. A minimal tagging file flags persistence-adjacent
registry writes, fresh scheduled tasks, and the canonical
lateral-movement logon types.

```bash
psort.py --tagging-file tags.yaml -o json_line -w tagged.jsonl case.plaso
```

Time-window slicing is the single most useful filter. Most incidents
have a two-to-seventy-two-hour suspect window, and rendering only
that slice cuts a 500K-line master into something a human can read.

## Super-timeline assembly across hosts

Multi-host cases require a super-timeline: the union of per-host
timelines, sorted by UTC, with each row carrying its host of origin.
Per-host `.plaso` stores merge through psort's multi-file mode:

```bash
psort.py -o json_line -w super_timeline.jsonl \
  host01.plaso host02.plaso host03.plaso
```

Two rules keep the merged artifact honest:

1. Every event must carry a `source_host` field. APTWatcher's
   pipeline injects this during ingest because plaso itself does
   not record the originating host beyond what is in the artifact
   path. Without it, a merged timeline is ambiguous the moment two
   hosts produce events at the same second.
2. All timestamps convert to UTC before merge. Hosts in different
   time zones produce rows that sort incorrectly if any stage of
   the pipeline leaks local time.

## Hayabusa layering

Hayabusa is an EVTX-specific Sigma rule engine. Its rule-tagged
event stream overlays on the plaso master: plaso provides breadth,
Hayabusa provides rule-driven pivots.

```bash
hayabusa csv-timeline -d /evidence/host01/evtx -o hayabusa.csv
hayabusa json-timeline -d /evidence/host01/evtx -o hayabusa.jsonl
```

Merge by matching Hayabusa events into the plaso timeline on
`(channel, event_record_id, event_id)`. The rule hits become a
`tags` field on the corresponding timeline row. Pivot on tags like
`defense_evasion`, `lateral_movement`, `credential_access` to jump
from a 500K-line master to the few hundred rule-tagged rows.

Hayabusa rule hits are leads, not verdicts. A `suspicious_cmdline`
tag on a Sysmon event 1 row is a pointer to review that row, not a
declaration that the command was hostile.

## Volatility-derived events

The memory image is a timeline source too. Plugins that produce
timestamps fold back into the master.

```bash
vol.py -f memory.raw windows.pslist.PsList > pslist.txt
vol.py -f memory.raw windows.pstree.PsTree > pstree.txt
vol.py -f memory.raw windows.cmdline.CmdLine > cmdline.txt
vol.py -f memory.raw windows.netscan.NetScan > netscan.txt
```

`pslist` gives a `CreateTime` in UTC per running process, and an
`ExitTime` for terminated-but-still-present processes. Each becomes
a timeline row: source `memory_image`, provenance
`plugin=windows.pslist.PsList`, plus PID, PPID, image path, and the
command line from `cmdline`. `netscan` contributes connection rows
keyed to their creation time where the kernel structure exposes it.

Memory-derived rows survive anti-forensic actions that target on-
disk artifacts. A process deleted from `Amcache` and `Prefetch`
often still appears in `pslist` if capture preceded reboot.

## From super-timeline to narrative

A 500K-line super-timeline is a reference, not a story. The
narrative is a pruned sequence — typically twenty to forty events —
that tells the incident from initial access to impact. The transition
from one to the other follows three passes.

**Pivot pass.** Start from a known anchor — a ransom note, a
suspicious 4624, a Sysmon event 1 with a known-bad hash, a Hayabusa
rule hit. Expand ±5 minutes around each anchor and read every row.
New anchors in that window become the next pivot. Repeat until the
anchor set stops growing.

**Prune pass.** Drop everything not causally connected: kernel
driver loads, routine service restarts, scheduled maintenance. Test
for keeping a row — could this appear in a narrative sentence, or
is it background?

**Witness rule.** Every claim is witnessed by two independent
artifact sources, or annotated as single-source. "The attacker ran
`powershell.exe` with encoded command X" is strong when Sysmon event
1, Security 4688, and Prefetch all corroborate; weak when only
Prefetch has it. This maps to T1059 — command-line evidence is
strongest when EVTX, Prefetch, and amcache agree.

Recurring MITRE tags in the margin help readers: T1070 (Indicator
Removal) and T1070.006 (Timestomp) flag anti-forensic activity;
T1078 (Valid Accounts) marks the transition from compromised machine
to compromised identity; T1059 tags each interactive shell; T1569
(System Services) tags execution via the Service Control Manager
(psexec-style, `sc create` with immediate start).

## Anti-pattern: timezone sloppiness

The single most common way a multi-host timeline goes wrong is
inconsistent timezones. Windows stores EVTX event times in UTC but
displays them in local time in Event Viewer; plaso stores UTC; many
third-party parsers silently apply the collection host's local zone.
Three rules:

1. Every event in the master timeline is UTC. Convert at ingest, not
   at render. If the source artifact uses local time (bash history
   with `HISTTIMEFORMAT` set to local, say), record both the local
   timestamp and the host's `/etc/timezone` or `tzutil /g` output,
   and perform the conversion in the pipeline.
2. The render layer converts back to a single reporting zone
   (usually UTC, sometimes the victim organization's HQ zone for
   executive audiences). Conversion happens once, at the
   presentation boundary, and is labelled.
3. Record host clock drift at collection time. A single
   `w32tm /stripchart` or `chronyc tracking` snapshot documents how
   far the host clock differed from a trusted NTP source. Every
   timeline row from that host inherits that offset as uncertainty.

## Handoff to the analysis pipeline

The JSON Lines timeline feeds APTWatcher's `TriageResult.timeline`
field directly, one event per line, each carrying `timestamp_utc`,
`source_host`, `source_artifact`, `event_type`, `parser`, and a
free-form `details` dictionary with the parser-specific payload.

Downstream consumers: the narrative generator produces
`ANALYSIS-<case>.md` (one paragraph per kill-chain phase with
citations back to timeline row IDs); the report generator renders
the same narrative into the `.docx` executive report with the
twenty-to-forty-event timeline as an embedded table; the IOC
extractor pulls hashes, IPs, domains, and filenames from flagged
rows into a STIX bundle.

Integrity check at the pipeline boundary: every claim in
`ANALYSIS-<case>.md` cites at least one row in
`TriageResult.timeline`, and every row is reachable to a file in
the evidence directory by its `source_artifact` path and, where
applicable, a record number.

## References

- Plaso documentation — https://plaso.readthedocs.io/
- log2timeline and psort command reference —
  https://plaso.readthedocs.io/en/latest/sources/user/Using-log2timeline.html
- Hayabusa — https://github.com/Yamato-Security/hayabusa
- Volatility 3 — https://volatility3.readthedocs.io/
- MITRE ATT&CK technique pages for T1070, T1070.006, T1078, T1059,
  and T1569
