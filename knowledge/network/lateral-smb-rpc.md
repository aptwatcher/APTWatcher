---
id: kb-net-smb-rpc-lateral-001
title: "SMB and RPC lateral movement"
source_type: author-original
attribution: "APTWatcher team (clean-room)"
mitre_techniques:
  - T1021.002
  - T1569.002
  - T1053.002
  - T1053.005
  - T1003.006
  - T1047
artifact_types:
  - pcap
  - zeek_logs
tools:
  - zeek
  - tshark
  - suricata
last_updated: "2026-04-19"
---

# SMB and RPC lateral movement

## Why SMB/RPC is the primary lateral-movement fabric on Windows

On a Windows estate, SMB (TCP/445) and the DCE/RPC services layered on top of
it form the default machine-to-machine control plane. File transfer, service
control, scheduled-task creation, registry edits, account enumeration and
domain replication all ride over the same sockets that carry legitimate
administration. An operator with valid credentials (local admin, domain admin,
or even a low-privileged account with delegated rights) can therefore pivot
without deploying any new listener on the target: they piggy-back on protocols
the host already speaks.

This document focuses on the **network-side** signals. Windows event-log
correlation (4624 type 3, 7045, 5140, 5145, task-scheduler operational log)
lives in the `windows/` branch of the knowledge base. Here we work from
packet captures, Zeek `smb_files.log`, `smb_mapping.log`, `dce_rpc.log`, and
Suricata alerts.

The network advantage is breadth: even when an endpoint agent is absent,
muted, or the adversary has cleared logs, the wire shows the pivot. The
network disadvantage is noise: RSAT consoles, GPO refresh, SCCM client
actions, WSUS deployments and Windows Update orchestration all traverse the
same pipes. Detection depends on **provenance** — which source host is
making the call — at least as much as on the call itself.

## SMB share patterns

Three administrative shares are the classical targets of a lateral pivot:

| Share    | Purpose on target                              | Lateral-movement indication when accessed from non-admin host |
|----------|------------------------------------------------|---------------------------------------------------------------|
| `ADMIN$` | Maps to `%SystemRoot%` (usually `C:\Windows`)  | File drop preceding service creation; psexec-family tooling   |
| `C$`     | Full C: volume                                 | Arbitrary file placement, tool staging, exfil copy            |
| `IPC$`   | Inter-process comms; carries named pipes       | Required for any RPC-over-SMB; first hop of the pivot         |

A normal workstation almost never mounts `ADMIN$` or `C$` on another
workstation. Workstation-to-workstation administrative-share traffic is the
single strongest low-volume indicator. Server-to-workstation traffic is also
suspicious unless the server is a known management host (SCCM primary site
server, MDT, Intune connector, patch relay).

Named pipes carried inside `IPC$` reveal the RPC intent:

| Named pipe              | Interface served                       | Typical abuse                                  |
|-------------------------|----------------------------------------|------------------------------------------------|
| `\pipe\svcctl`          | Service Control Manager                | Remote service create/start (psexec, smbexec)  |
| `\pipe\atsvc`           | Legacy `at` scheduler                  | Remote scheduled task (`at.exe` style)         |
| `\pipe\epmapper`        | RPC endpoint mapper                    | Discovery of dynamic RPC endpoints             |
| `\pipe\winreg`          | Remote registry                        | Hive read/write, autorun persistence           |
| `\pipe\samr`            | SAM account manager                    | User/group enumeration                         |
| `\pipe\lsarpc`          | Local Security Authority               | SID lookup, trust enumeration                  |
| `\pipe\netlogon`        | Secure channel / Netlogon              | Zerologon, coerced auth                        |
| `\pipe\spoolss`         | Print Spooler                          | PrinterBug, coerced NTLM relay                 |
| `\pipe\browser`         | Computer browser (legacy)              | Often seen in old toolchains                   |
| `\pipe\wkssvc`          | Workstation service                    | Session enumeration                            |
| `\pipe\srvsvc`          | Server service                         | Share enumeration, session enumeration         |

A pivot chain commonly shows this ordering within a few seconds on a single
SMB session:

1. Tree connect to `IPC$`.
2. Tree connect to `ADMIN$`.
3. SMB2 Create + Write of an executable under `ADMIN$\` (root) or
   `ADMIN$\Temp\`.
4. Tree connect back to `IPC$`.
5. Bind to `\pipe\svcctl`.
6. `CreateServiceW` then `StartServiceW` referencing the dropped binary.

That sequence — write-to-ADMIN$ followed inside the same session by an
svcctl create/start — is the canonical psexec fingerprint and should be a
high-priority alert when the source host is not an approved admin jump box.

## DCE/RPC interfaces of interest

Zeek resolves RPC interface UUIDs to human-readable names in `dce_rpc.log`
(`endpoint` field). The operations worth flagging:

| Endpoint   | Operation                               | Technique                       | Notes                                                |
|------------|-----------------------------------------|---------------------------------|------------------------------------------------------|
| `svcctl`   | `CreateServiceW`, `CreateServiceA`      | T1569.002                       | Remote service creation — psexec/smbexec core        |
| `svcctl`   | `StartServiceW`, `ChangeServiceConfigW` | T1569.002                       | Service activation or hijack                         |
| `atsvc`    | `JobAdd`                                | T1053.002                       | Legacy `at` scheduler                                |
| `taskschd` | `SchRpcRegisterTask`, `SchRpcRun`       | T1053.005                       | Modern scheduled task via Task Scheduler 2.0         |
| `winreg`   | `OpenKey` on `HKLM\SYSTEM\CCS\Services` | T1112, T1543.003                | Remote registry, service-key tampering               |
| `winreg`   | `SetValue` on `Run` / `RunOnce`         | T1547.001                       | Remote autorun persistence                           |
| `samr`     | `EnumDomainUsers`, `QueryUserInfo`      | T1087.002                       | Domain account enumeration                           |
| `lsarpc`   | `LsarLookupNames`, `LsarLookupSids`     | T1087.002, T1482                | SID translation, trust walking                       |
| `drsuapi`  | `DRSGetNCChanges`                       | T1003.006                       | DCSync — replication from a non-DC source is critical|
| `eventlog` | `ElfrClearELFW`                         | T1070.001                       | Remote event-log clearing                            |
| `IOXIDResolver` + dynamic port | `ActivationContextInfo`, DCOM object | T1047, T1021.003 | WMI / DCOM remote execution                    |

`drsuapi` deserves special treatment. Replication calls between domain
controllers are normal and constant. Replication calls from **any host that
is not a DC** are almost always DCSync. A single `DRSGetNCChanges` from a
workstation or member server to a DC is a priority-one event.

For WMI (T1047) the pattern is a connection to TCP/135, an
`IOXIDResolver`-style bind that returns a dynamic high port, then a
follow-up TCP session on that ephemeral port carrying the actual IWbem
traffic. Flagging the pair (135 RPC bind followed by a new session to the
same destination on a port > 49152 within a few seconds, from a host that
does not usually do WMI) is more reliable than trying to decode the DCOM
stream.

## Zeek field-level hunts

The Zeek logs most useful here are `smb_mapping.log`, `smb_files.log`,
`dce_rpc.log`, and `conn.log` for flow context. Example hunts, expressed as
`zeek-cut` one-liners; adapt to your SIEM query language.

**Administrative-share mounts not originating from an approved jump box:**

```bash
zeek-cut -d ts id.orig_h id.resp_h path share_type < smb_mapping.log \
  | awk '$4 ~ /ADMIN\$|C\$/ {print}' \
  | grep -v -F -f approved_admin_sources.txt
```

**File writes to `ADMIN$` with executable-looking names:**

```bash
zeek-cut -d ts id.orig_h id.resp_h action path name size < smb_files.log \
  | awk '$4 == "SMB::FILE_WRITE" && $6 ~ /\.(exe|dll|bat|ps1|scr)$/ {print}'
```

**svcctl CreateService or StartService calls:**

```bash
zeek-cut -d ts id.orig_h id.resp_h endpoint operation named_pipe < dce_rpc.log \
  | awk '$4 == "svcctl" && $5 ~ /CreateService|StartService/ {print}'
```

**Remote scheduled task registration:**

```bash
zeek-cut -d ts id.orig_h id.resp_h endpoint operation < dce_rpc.log \
  | awk '($4 == "atsvc" && $5 == "JobAdd") || ($4 == "ITaskSchedulerService" && $5 ~ /SchRpcRegisterTask|SchRpcRun/) {print}'
```

**DCSync candidate (drsuapi from non-DC):**

```bash
zeek-cut -d ts id.orig_h id.resp_h endpoint operation < dce_rpc.log \
  | awk '$4 == "drsuapi" && $5 == "DRSGetNCChanges" {print}' \
  | grep -v -F -f known_dc_hosts.txt
```

**Correlate the psexec sequence within one SMB session:**

Join `smb_files.log` writes to `ADMIN$` with `dce_rpc.log` svcctl
operations on the same `uid` (Zeek connection UID) or the same
`id.orig_h` / `id.resp_h` pair within a 60-second window. A true psexec
will present both events on the same `uid` because the named pipe rides
the same TCP session.

## Workflow

Starting from a single suspicion — "host A may have moved laterally to
host B" — expand as follows:

1. **Confirm the pivot.** In `smb_mapping.log`, show all shares A mounted
   on B. Any of `ADMIN$`, `C$`, or access to `IPC$` followed by RPC
   operations is confirmation.
2. **Identify the technique.** In `dce_rpc.log`, list operations on that
   Zeek `uid`. Map to the technique table above (svcctl = service,
   atsvc/taskschd = scheduled task, winreg = registry, wmi = DCOM).
3. **Recover the payload.** In `smb_files.log`, list `FILE_WRITE` events
   on that session. If Zeek file extraction is enabled, pull the object
   from the `extract_files/` directory; otherwise carve from pcap with
   `tshark -r capture.pcap -Y "smb2.filename" --export-objects smb,out/`.
4. **Pivot outward from A.** Query `smb_mapping.log` for every destination
   A touched on 445 in the past N days. Each new destination is a
   candidate compromise.
5. **Pivot outward from B.** Query for every source that mounted
   administrative shares on B; those are possible upstream compromises.
6. **Check DC exposure.** Search `dce_rpc.log` for `drsuapi`,
   `DRSGetNCChanges`, `samr` enumeration, or `lsarpc LookupSids` originating
   from A or B toward any DC. A successful DCSync re-scopes the incident to
   domain-wide credential compromise.
7. **Correlate with endpoint telemetry.** On B, match against Windows
   events 4624 (type 3), 5140/5145 (share access), 7045 (service
   installed), 4697 (service installed, security log), 4698/4702
   (scheduled task), and the Task Scheduler operational log. The
   `windows/` KB branch covers that side.

## Indicator table

| Indicator                                                        | Source log        | Severity |
|------------------------------------------------------------------|-------------------|----------|
| ADMIN$ or C$ mount from workstation subnet                       | `smb_mapping.log` | High     |
| Executable write to `ADMIN$` followed by svcctl in same session  | `smb_files.log` + `dce_rpc.log` | Critical |
| `svcctl::CreateServiceW` from non-admin host                     | `dce_rpc.log`     | High     |
| `atsvc::JobAdd` (legacy scheduler)                               | `dce_rpc.log`     | High     |
| `ITaskSchedulerService::SchRpcRegisterTask` from non-admin host  | `dce_rpc.log`     | High     |
| `winreg` bind followed by write under `CurrentControlSet\Services` | `dce_rpc.log`   | High     |
| `drsuapi::DRSGetNCChanges` from host not in DC list              | `dce_rpc.log`     | Critical |
| `samr::EnumDomainUsers` from workstation                         | `dce_rpc.log`     | Medium   |
| `lsarpc::LsarLookupSids` burst toward DC from member host        | `dce_rpc.log`     | Medium   |
| 135/TCP RPC bind then new session to ephemeral port > 49152      | `conn.log` + `dce_rpc.log` | Medium-High (WMI) |
| `spoolss` or `netlogon` bind from unexpected source              | `dce_rpc.log`     | Medium (coercion) |
| `eventlog::ElfrClearELFW` over the wire                          | `dce_rpc.log`     | Critical |
| Named pipe `\pipe\svcctl` from host that never before used it    | `smb_files.log`   | High     |

## Confidence and pitfalls

Each of the signals above exists in legitimate traffic. Tuning is not
optional.

**RSAT consoles.** Administrators running `services.msc`, `regedit`
(Connect Network Registry), `compmgmt.msc`, or `taskschd.msc` against
another host produce svcctl, winreg, and taskschd RPC from their
workstation. Mitigation: maintain an allow-list of admin source hosts
(the PAW / jump-box subnet) and suppress there, alert everywhere else.

**Group Policy refresh.** `gpupdate` pulls from `SYSVOL`, a standard SMB
share on DCs. It does **not** touch `ADMIN$` or `C$`, so a correctly
scoped hunt excludes it. If you see `SYSVOL` flagged, your filter is too
broad.

**SCCM / MECM and other management platforms.** Primary and secondary
site servers push content to clients over SMB, create services
(`ccmexec`, client installs), and remotely kick policy evaluation. The
site servers and distribution points are **known-good svcctl and
ADMIN$-writing hosts**. Treat them as an allow-listed control plane and
baseline them. Unknown hosts performing SCCM-like actions are not
SCCM — they are adversaries mimicking it.

**WSUS and Windows Update.** WSUS uses HTTP(S) on 8530/8531 by default,
not SMB, so confusion with lateral movement is rare. However, third-party
patch tools (PDQ Deploy, Action1, ManageEngine, Tanium) frequently write
to `ADMIN$` and create services. Inventory them and allow-list the
source hosts.

**Domain controller replication.** DC-to-DC `drsuapi DRSGetNCChanges`
calls are **constant** and expected. The rule must be "`drsuapi` from
any host not on the DC list" — never a blanket `drsuapi` alert.

**Backup and EDR agents.** Some backup products (for VSS snapshot
coordination) and EDR platforms open `IPC$` and bind RPC pipes. These
produce false positives on samr / lsarpc / srvsvc enumeration rules.
Baseline their source hosts.

**Encryption hides content but not metadata.** SMB3 encryption
(`SMB2_GLOBAL_CAP_ENCRYPTION`) will blind file-name and RPC-operation
visibility in Zeek, leaving only `smb_mapping.log` and `conn.log`. When
SMB encryption is enforced, detection shifts to "which host mounted
`ADMIN$` on which target, and when" — source-provenance hunts retain
value even without payload visibility.

**Provenance is the discriminator.** The same svcctl `CreateServiceW`
call is benign from the SCCM primary site server and critical from a
finance-department workstation. Build and maintain a small set of host
classes — DCs, admin jump boxes, management platforms, servers,
workstations — and evaluate every RPC-based alert against the source
class. Without that, alert volume will bury the real pivots.
