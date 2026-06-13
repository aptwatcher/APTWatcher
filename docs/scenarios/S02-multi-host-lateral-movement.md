# S02 — Multi-host lateral movement

> Three hosts, one adversary, a long weekend of Kerberos abuse. S02 forces the
> agent to correlate across evidence sources instead of treating each image as
> its own universe. This is where Tier 1 intel pays for itself and Tier 2
> ticketing stops being decorative.

## Story

A regional engineering firm runs a flat AD forest with a single domain,
`eng.local`, ~800 users. Their VPN gateway has been showing anomalous
outbound TLS from what looks like an engineering workstation. The SOC pulls
the workstation (`ENG-WS-027`), a file-share server (`ENG-FS-01`), and a
domain controller (`ENG-DC-01`) and hands all three triage bundles to the
analyst.

The adversary has been inside for nine days. Initial foothold was a
Kerberoasting attack following the compromise of a service account password
leaked in a GitHub commit three months earlier. The attacker stayed low,
moved twice, and touched the DC once.

APTWatcher's job: stitch three independent evidence sources into one
timeline, identify the pivot points, and produce a coherent narrative with
MITRE mapping that holds up across hosts.

## Environment

- **Hosts**:
  - `ENG-WS-027` — Windows 11, engineer's daily driver
  - `ENG-FS-01` — Windows Server 2022, SMB share `\\ENG-FS-01\Projects`
  - `ENG-DC-01` — Windows Server 2022, PDC emulator
- **Domain**: `eng.local`, forest functional level 2016
- **Auth**: Kerberos default; NTLM fallback still enabled
- **Logging**: Windows Event Forwarding to a Graylog collector — collected
  bundle covers the last 14 days
- **EDR**: Defender for Endpoint present on `ENG-WS-027` only

Evidence bundles delivered:

- `/mnt/evidence/ENG-WS-027/` — full E01 + memory + WEF logs
- `/mnt/evidence/ENG-FS-01/` — triage bundle only (host still in production)
- `/mnt/evidence/ENG-DC-01/` — triage bundle + Security.evtx + ntds.dit
  extract

## Attacker timeline (ground truth)

Nine days compressed. Only the inflection points shown.

| Day       | When         | Host                  | Action                                                                 |
|-----------|--------------|-----------------------|------------------------------------------------------------------------|
| D-9 Wed   | 11:30        | external              | TGS-REQ for `svc_backup`, offline cracked                              |
| D-9 Wed   | 13:12        | ENG-WS-027            | SMB logon as `svc_backup`; Impacket `wmiexec` lands `a.exe`            |
| D-9 Wed   | 13:14        | ENG-WS-027            | `schtasks` creates `OneDriveUpdater` task (hourly)                     |
| D-8 Thu   | 09:45        | ENG-WS-027            | LSASS access via `rundll32 comsvcs.dll, MiniDump`                      |
| D-7 Fri   | 22:08        | ENG-WS-027 → ENG-FS-01| Kerberos TGS for `cifs/ENG-FS-01`; SMB read of `Projects\Engineering`  |
| D-7 Fri   | 22:14        | ENG-FS-01             | Staging dir `C:\PerfLogs\Admin\` created; 2.3 GB copied                |
| D-4 Mon   | 18:22        | ENG-WS-027 → ENG-DC-01| DCSync (GetNCChanges) as `svc_backup` with delegated rights            |
| D-2 Wed   | 03:11        | ENG-FS-01             | 2.3 GB TLS egress to `104.xx.xx.xx` — flagged by VPN gateway           |
| D-0 Fri   | 10:00        | all                   | Incident declared; triage bundles collected                            |

The narrative spine is: leaked creds → Kerberoasting → foothold → credential
dumping → SMB lateral movement → DCSync → staged exfil. The agent must find
all four phases and tie the DCSync to the TGS-REQ pattern that preceded it.

## Artifacts to find (the rubric)

Grouped by host, with cross-host correlations flagged.

### On ENG-WS-027

- Inbound NTLM/SMB session from a host with no reverse DNS. *T1078.002*
- `a.exe` in `%WINDIR%\Temp\`, unsigned, written by `WmiPrvSE.exe`. *T1047*
- Scheduled task `OneDriveUpdater` with a binary path under `%ProgramData%`.
  *T1053.005*
- LSASS memory dump via `comsvcs.dll` — classic LOLBin pattern. *T1003.001*
- Prefetch entry for `a.exe` confirming execution. *T1204.002*

### On ENG-FS-01

- Kerberos logon ticket from `svc_backup` for `cifs/ENG-FS-01`. *T1558*
- Staging directory `C:\PerfLogs\Admin\` with ~2.3 GB of engineering files.
  *T1074.001*
- SMB access pattern consistent with bulk recursive read. *T1039*

### On ENG-DC-01

- Security event 4662 with property mask `1131f6aa-...` (replication get
  changes) by `svc_backup`. *T1003.006* (DCSync)
- Security event 4624 logon type 3 correlated to the DCSync, with source IP
  matching `ENG-WS-027`.

### Cross-host correlations (the hard part)

- Time-ordered chain: scheduled task creation on WS-027 → LSASS dump → TGS
  for FS-01 → DCSync on DC-01. All within a 5-day window, all attributable
  to `svc_backup`.
- The staged 2.3 GB on FS-01 matches the volume of the later egress flagged
  by the VPN gateway. APTWatcher must not *conclude* exfiltration, but must
  surface the volumetric consistency as supporting evidence.

## Expected agent approach

1. **Preflight** against `windows-host-triage` for each host, plus a
   multi-host variant profile that also enables `kerberos-log-parser` and
   `evtx-tools`.
2. **Unified super-timeline.** Plaso on each host, merged into a single
   timeline sorted by UTC. This is the canonical artifact of S02 — every
   subsequent finding cites timeline entries by `(host, timestamp, source)`.
3. **Anchor on the VPN gateway alert.** Work backwards from Wed 03:11 on
   FS-01. Find the write operations that produced the staged data.
4. **Pivot via Kerberos.** The TGS-REQ for `cifs/ENG-FS-01` names the
   principal (`svc_backup`) and the source host. That is the pivot to
   WS-027.
5. **On WS-027, find the foothold.** Scheduled task, unsigned binary,
   WmiPrvSE parent process. The LSASS dump sits nearby in time.
6. **On DC-01, confirm DCSync.** Event 4662 with the replication GUID is
   the signature. Correlate source IP.
7. **Tier 1.** `check_ioc()` on the egress IP and the `a.exe` hash. If
   APT Watch or MS Threat Analytics returns anything, fold it in as
   corroboration. If not, note the gap.
8. **Tier 2 (optional).** File a GLPI ticket with the three-host narrative.
   HTML content, one section per host, cross-host correlations last. See
   [GLPI integration](../integrations/glpi.md).
9. **Self-correction.** Before finalizing, the agent re-examines whether the
   egress volume can be explained by a legitimate backup job. If the backup
   window aligns, that needs to be called out as an alternative explanation
   the evidence does not rule out.

## Success rubric

| Score band | Meaning                                                                                      |
|------------|----------------------------------------------------------------------------------------------|
| **Pass**   | All per-host items + both cross-host correlations; MITRE mapping correct; DCSync identified |
| **Partial**| Per-host items found but cross-host correlation missing or weak                              |
| **Fail**   | DCSync missed **or** any cross-host claim unsupported by the unified timeline                |

The cross-host correlation is the hard test. An agent that produces three
independent per-host reports without stitching them together fails the
scenario regardless of individual-host quality.

## Dataset strategy

S02 uses a **hybrid** dataset:

- **Synthetic base** (`datasets/s02/`): author-crafted evtx, prefetch,
  scheduled tasks, and memory snippets, giving deterministic ground truth
  for the rubric.
- **Public overlay** where compatible: SMB/Kerberos traffic patterns drawn
  from licensed DFIR Report cases that describe analogous chains. Any
  material so sourced is declared in the dataset manifest with its CC
  attribution.

See [Datasets — synthetic](../datasets/synthetic.md) and
[Datasets — public sources](../datasets/public-sources.md).

## MITRE coverage

| Tactic              | Technique                                          | Sub-technique |
|---------------------|----------------------------------------------------|---------------|
| Initial Access      | Valid Accounts: Domain Accounts                    | T1078.002     |
| Execution           | Windows Management Instrumentation                 | T1047         |
| Execution           | User Execution: Malicious File                     | T1204.002     |
| Persistence         | Scheduled Task/Job: Scheduled Task                 | T1053.005     |
| Credential Access   | Steal or Forge Kerberos Tickets: Kerberoasting     | T1558.003     |
| Credential Access   | OS Credential Dumping: LSASS Memory                | T1003.001     |
| Credential Access   | OS Credential Dumping: DCSync                      | T1003.006     |
| Lateral Movement    | Remote Services: SMB/Windows Admin Shares          | T1021.002     |
| Collection          | Data from Network Shared Drive                     | T1039         |
| Collection          | Data Staged: Local Data Staging                    | T1074.001     |

Full matrix at [Reference — MITRE coverage](../reference/mitre-coverage.md).

## Tiers exercised

- **Tier 0** — required. Multi-host timeline fusion runs on core tools only.
- **Tier 1** — materially improves the report. Without it, the egress IP and
  binary hash are ungrounded.
- **Tier 2** — the three-host narrative as a GLPI ticket is the demo's
  "IR workflow integration" proof point. Content is HTML-formatted per the
  GLPI content-field rule.
- **Tier 3/4** — not exercised. The compromise is old; live containment is
  out of scope here. (S03 is where containment earns its keep.)

## Related

- [S01 — Single Windows host compromise](S01-single-windows-compromise.md)
- [S03 — Ransomware pre-detonation](S03-ransomware-pre-detonation.md)
- [Use case: Timeline only](../use-cases/timeline-only.md)
- [Integration: GLPI](../integrations/glpi.md)
- [Integration: APT Watch](../integrations/apt-watch.md)
