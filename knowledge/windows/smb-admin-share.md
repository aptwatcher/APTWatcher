---
id: kb-win-lat-smb-admin-share-001
title: "SMB admin share abuse — lateral movement via ADMIN$, C$, IPC$"
source_type: author-original
attribution: "APTWatcher team (clean-room)"
mitre_techniques:
  - T1021.002
  - T1570
  - T1569.002
artifact_types:
  - event_logs
  - network_traffic
tools:
  - evtx_dump
  - chainsaw
  - zeek
last_updated: "2026-04-19"
---

## What SMB admin share abuse is

Every Windows host exposes a set of hidden administrative shares over
SMB: `C$` (and a letter share for each extra volume), `ADMIN$` (mapped
to `%SystemRoot%`), and `IPC$` (the named-pipe endpoint). These shares
are not advertised in share enumeration but are reachable by any
principal whose token lands in the local Administrators group on the
remote machine. That single fact is the engine behind most "classic"
Windows lateral movement.

With valid admin credentials on the target, an attacker chains three
primitives over the same authenticated SMB session:

1. **Stage a payload.** The attacker writes a binary or script to the
   target's disk through `\\target\ADMIN$\` or `\\target\C$\`, typically
   under `Windows\Temp`, `Windows\`, or another writable directory the
   operator expects to find. This is the Lateral Tool Transfer step
   (T1570).
2. **Execute it remotely.** The most common vector is to bind to the
   Service Control Manager RPC interface (`SVCCTL`) over `IPC$`, create
   a new service whose `ImagePath` points at the staged payload, and
   start it — the Service Execution pattern (T1569.002). Equivalent
   paths use WMI (`IWbemServices::ExecMethod` over DCOM), DCOM
   activation of `MMC20.Application` / `ShellWindows`, or task
   scheduling through `ATSVC` / modern `ITaskSchedulerService`.
3. **Clean up.** The service is stopped and deleted; sometimes the
   staged binary is removed, often it is not.

Tooling around this primitive is mature: Sysinternals `PsExec`,
Impacket's `psexec.py` / `smbexec.py` / `wmiexec.py` / `atexec.py`,
`CrackMapExec` / `NetExec`, and Cobalt Strike's `jump psexec`,
`jump psexec64`, and `jump psexec_psh`. They differ in how they
handle output (named pipe vs. file) and in how random the service name
looks, but the underlying SMB + SVCCTL pattern is shared.

## How to detect it

Host side, target machine Security and System logs:

| Signal                                                         | Log / tool                | Field                                           |
|----------------------------------------------------------------|---------------------------|-------------------------------------------------|
| Network logon from an unusual peer                             | Security 4624 Type 3      | `IpAddress`, `WorkstationName`, `TargetUserName`|
| Share object accessed                                          | Security 5140             | `ShareName` (= `\\*\ADMIN$` or `\\*\C$`)        |
| Detailed file access on the share                              | Security 5145             | `ShareName`, `RelativeTargetName`, `AccessMask` |
| Service installed                                              | System 7045               | `ServiceName`, `ImagePath`, `AccountName`       |
| Service state churn (start/stop in seconds)                    | System 7036               | `ServiceName`, `ServiceState`                   |
| Process creation under `services.exe`                          | Security 4688 / Sysmon 1  | `ParentImage`, `NewProcessName`, `CommandLine`  |
| Named pipe creation (`\PSEXESVC`, `\paexec`, random names)     | Sysmon 17 / 18            | `PipeName`, `Image`                             |

Network side, Zeek output:

- `smb_mapping.log` with `share` equal to `ADMIN$`, `C$`, or `IPC$`
  from a non-administrative peer.
- `smb_files.log` showing `SMB::FILE_WRITE` of an `.exe`, `.dll`, or
  `.bat` into `ADMIN$` or `C$`.
- `dce_rpc.log` binding to `SVCCTL`
  (`367abb81-9844-35f1-ad32-98f038001003`), `TSCH` / `ATSVC`, or
  `IWbemServices` on the same `uid` as the preceding SMB session.

The strongest cluster is: `4624 Type 3` → `5145` write under `ADMIN$`
→ `7045` naming a binary in that same path → `4688` spawned by
`services.exe` — all within a few seconds, from one source address.

## What APTWatcher records

An SMB admin share lateral movement finding cites:

1. The `4624` Type 3 event on the target
   (source=`Security.evtx`, locator=`event_id=4624 record=<n>`), with
   `LogonType`, `IpAddress`, `WorkstationName`, and
   `TargetUserName` captured verbatim.
2. One or more `5140` / `5145` events naming `ADMIN$` or `C$`, with
   the `RelativeTargetName` of the written file and the accessing
   `SubjectUserName` (source=`Security.evtx`,
   locator=`event_id=5145 record=<n>`).
3. The `7045` Service Installed event with `ServiceName`, `ImagePath`,
   `ServiceType`, and `AccountName`
   (source=`System.evtx`, locator=`event_id=7045 record=<n>`).
4. A `4688` / Sysmon 1 event whose parent is `services.exe` and whose
   `Image` matches the `ImagePath` from step 3.
5. If network evidence is present, the Zeek `uid` that ties the SMB
   session to the `SVCCTL` (or `TSCH` / `IWbemServices`) bind on the
   same five-tuple (source=`zeek:smb_mapping.log`,
   `zeek:smb_files.log`, `zeek:dce_rpc.log`).
6. Where available, the SHA-256 of the staged binary recovered from
   `C$\Windows\Temp\` or the equivalent path.

## Confidence calibration and pitfalls

SMB admin shares are also the substrate of legitimate operations:
SCCM / MECM client push, Intune / MDM agent deployment, vendor remote
management suites (Kaseya, ConnectWise, N-able), backup agents, and
human admins running `PsExec` on purpose. Each produces the same
4624 / 5145 / 7045 / 4688 chain.

Discriminators that matter:

- **Service name entropy.** Legitimate tooling uses stable service
  names (`CcmExec`, `ccmsetup`, `Sense`, vendor-branded strings).
  PsExec by default names the service `PSEXESVC`, but operators
  commonly override it; randomised 8-character service names are a
  strong tell.
- **Source host plausibility.** A push from a known management server
  to a managed endpoint is routine; a push from a user workstation or
  from a server that has no business role is not.
- **Account tier.** A Tier-0 principal (Domain Admin, Enterprise
  Admin, `krbtgt`, or a DC machine account) authenticating Type 3 to
  a workstation is almost never legitimate and should raise the
  finding's confidence substantially.
- **Dwell time.** A service that appears, starts, stops, and
  disappears within a few seconds is the PsExec execution model;
  legitimate agents run continuously.

APTWatcher caps a standalone `7045` at roughly `confidence=0.5`.
Pairing it with a `5145` write into `ADMIN$` from an unusual source
host lifts the finding to about `0.8`. Adding a Tier-0 principal or a
`4688` with a randomised `ImagePath` under `Windows\Temp\` pushes it
toward `0.95`. A single `4624 Type 3` alone is not actionable without
one of the later steps in the chain.
