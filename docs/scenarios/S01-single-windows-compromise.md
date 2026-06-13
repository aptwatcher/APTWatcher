# S01 — Single Windows host compromise

> A mid-size manufacturer's finance workstation. Phishing → credential theft →
> persistence. Single host, single analyst, 48 hours later. This is the demo
> floor: if APTWatcher can't do this cleanly, nothing else matters.

## Story

Friday 17:42 local. A finance clerk at a mid-size manufacturer opens what
looks like a DocuSign attachment forwarded by a known supplier. The file is a
signed PDF that links out to a lookalike Microsoft 365 login page. The clerk
enters the Windows domain password. Nothing visible happens, so the clerk
closes the tab and goes home.

Over the weekend, the adversary authenticates as the clerk, drops a persistence
payload on the workstation via a scheduled RDP session from a residential VPN
exit, stages a credential harvester in `%PROGRAMDATA%`, and exits.

Monday 08:11, the user reports "Outlook was weird this morning" to IT. The
help desk escalates. By 09:30 the workstation is imaged and handed to the
analyst running APTWatcher on a SIFT VM.

## Environment

- **Host**: `FIN-WS-014` — Windows 11 23H2, domain-joined
- **User**: `contoso\a.dupuis`, local admin by legacy policy
- **EDR**: none (small IT shop; endpoint protection is Defender baseline)
- **Image**: full disk E01 + memory capture (DumpIt) + running-process CSV
- **Network**: flat /24 behind a single firewall; no egress logging retained
  past 7 days

What SIFT sees: the E01 mounted read-only at `/mnt/evidence/FIN-WS-014`, the
memory image at `/mnt/evidence/FIN-WS-014/mem.raw`, and a triage bundle
(KAPE-style) at `/mnt/evidence/FIN-WS-014/triage/`.

## Attacker timeline (ground truth)

| When (local)         | Action                                                                 |
|----------------------|------------------------------------------------------------------------|
| Fri 17:42            | Phishing click; credentials posted to attacker-controlled form         |
| Sat 02:14            | First successful RDP from `185.220.xx.xx` (residential VPN exit)       |
| Sat 02:17            | `C:\ProgramData\Contoso\svchost.exe` written (lookalike name)          |
| Sat 02:18            | Scheduled task `MicrosoftEdgeUpdateTaskMachineUA` created (typosquat)  |
| Sat 02:22            | Mimikatz-style LSASS access via signed tool `procdump64.exe`           |
| Sat 02:24            | Credential dump written to `C:\ProgramData\Contoso\ntds.zip`           |
| Sat 02:31            | RDP logoff; no further activity until user returns Monday              |
| Mon 08:11            | User reports anomaly; host imaged at 09:15                             |

Two details matter: the persistence task disguises itself as an Edge update,
and the credential dump is zipped but never exfiltrated. The attacker
intended to return. They did not. The adversary is **still outside** the
environment when imaging happens.

## Artifacts to find (the rubric)

APTWatcher is scored on whether it surfaces, with correct MITRE mapping:

- **Initial access signals**: browser history entries pointing to a lookalike
  M365 login domain; MSHTA/PowerShell not involved (drop was a plain
  download). *T1566.002*
- **Authentication anomaly**: RDP logon outside business hours from a non-RFC1918
  address, user's first-ever RDP session on this host. *T1021.001*
- **Persistence**: scheduled task with a lookalike name and binary path under
  `C:\ProgramData\`. *T1053.005*
- **Dropped binary**: `svchost.exe` in a non-standard location; signature
  invalid or missing. *T1036.005*
- **Credential access**: procdump64.exe execution against LSASS; zipped output
  in same directory as the dropped binary. *T1003.001*
- **Evidence of staging, not exfiltration**: the ZIP exists on disk but there
  is no egress traffic large enough to have carried it out. *T1074.001*

The rubric rejects findings that are **plausible but unsupported by
evidence** — e.g., claiming exfiltration without a matching netflow or
firewall log.

## Expected agent approach

A well-grounded APTWatcher run looks like this:

1. **Preflight** against the `windows-host-triage` profile. Confirm
   `volatility3`, `log2timeline`, `bulk_extractor`, `yara`, and `RegRipper`
   are present. Abort if not.
2. **Timeline first.** Run `plaso_timeline()` on the triage bundle. Do not
   inspect artifacts individually until the super-timeline exists. This is a
   deliberate anti-pattern avoidance: jumping to per-artifact views encourages
   confirmation bias and narrative-shaped reasoning.
3. **Anchor on the user complaint.** Narrow the timeline to Mon 06:00–09:30,
   then expand backwards looking for the last abnormal state transition.
4. **Scheduled tasks** via RegRipper `schedtasks.pl`. The lookalike task
   surfaces cleanly.
5. **Correlate** the task's trigger time with the authentication log. This
   is the pivot: the scheduled task was created while `a.dupuis` was logged
   in via RDP from an external IP.
6. **Examine the dropped binary.** Hash it, pass the hash to
   `check_ioc()` if Tier 1 is enabled. Yara-scan with the stock SIFT ruleset.
7. **Memory.** Volatility `pslist`, `pstree`, `handles`, `malfind` against
   the memory image, focused on the time window.
8. **Self-correction gate.** Before writing the report, the agent asks
   itself: *"What evidence would overturn this narrative?"* — then looks for
   it. This is the mechanic the demo video highlights.
9. **Report** a triage finding, not a conclusion. Phrase as
   *"consistent with..."* never *"caused by..."*.

## Success rubric

| Score band | Meaning                                                                     |
|------------|-----------------------------------------------------------------------------|
| **Pass**   | All 6 rubric items surfaced; MITRE mapping correct; ≤1 speculative claim    |
| **Partial**| 4–5 items surfaced; correct mapping on surfaced items                       |
| **Fail**   | ≤3 items, **or** any hallucinated artifact (claim not in the evidence)      |

The hallucination check is hard-fail. An agent that invents an exfiltration
event to round out the story fails S01 regardless of how many other items it
gets right. See [self-correction](../architecture/self-correction.md) for the
gating mechanic.

## Dataset strategy

S01 uses a **synthetic** dataset (`datasets/s01/`). See
[Datasets — synthetic](../datasets/synthetic.md) for generation scripts and
versioning.

Why synthetic for S01:

- Full ground truth is required for the rubric. Public cases rarely disclose
  every artifact cleanly.
- The scenario is designed to be reproducible by any judge in under 15
  minutes with no external dependencies.
- Synthetic generation lets us pin the exact log entries the agent must find,
  which makes hallucination detection deterministic.

A parallel **public** variant is maintained against DFIR Report Case 2023-x
(see [public sources](../datasets/public-sources.md)) for live-fire validation.

## MITRE coverage

| Tactic              | Technique                                           | Sub-technique |
|---------------------|-----------------------------------------------------|---------------|
| Initial Access      | Phishing: Spearphishing Link                        | T1566.002     |
| Credential Access   | OS Credential Dumping: LSASS Memory                 | T1003.001     |
| Lateral Movement    | Remote Services: Remote Desktop Protocol            | T1021.001     |
| Persistence         | Scheduled Task/Job: Scheduled Task                  | T1053.005     |
| Defense Evasion     | Masquerading: Match Legitimate Name or Location     | T1036.005     |
| Collection          | Data Staged: Local Data Staging                     | T1074.001     |

Full matrix at [Reference — MITRE coverage](../reference/mitre-coverage.md).

## Tiers exercised

- **Tier 0** — everything above. A Tier 0-only install completes S01.
- **Tier 1 (optional)** — `check_ioc()` against the external IP and the
  dropped binary hash adds confidence to the report. If all providers are
  absent, the agent notes the gap and proceeds.
- **Tier 2/3/4** — not exercised by S01. (S02 adds Tier 2; S03 adds Tier 3.)

## Related

- [S02 — Multi-host lateral movement](S02-multi-host-lateral-movement.md)
- [Use case: Windows host triage](../use-cases/windows-host-triage.md)
- [Architecture — self-correction](../architecture/self-correction.md)
- [Datasets — synthetic](../datasets/synthetic.md)
