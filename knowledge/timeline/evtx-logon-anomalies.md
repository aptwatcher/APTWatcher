---
id: kb-tl-evtx-logon-001
title: "Windows EVTX logon anomalies — 4624/4625/4672 correlation for lateral movement"
source_type: author-original
attribution: "APTWatcher team (clean-room)"
mitre_techniques:
  - T1078
  - T1021
  - T1110
  - T1558
artifact_types:
  - evtx
  - security_log
  - authentication_events
tools:
  - chainsaw
  - hayabusa
  - evtx_dump
  - plaso
last_updated: "2026-04-19"
---

## What EVTX logon events record

The `Security.evtx` channel is the authoritative source for logon
activity on a workstation, member server, or domain controller.
A handful of event IDs carry most of the signal:

- **4624 — successful logon.** Payload includes `TargetUserName`,
  `TargetDomainName`, `TargetLogonId`, `LogonType`,
  `AuthenticationPackageName` (Kerberos, NTLM, Negotiate),
  `WorkstationName`, `IpAddress`, `IpPort`, and `ImpersonationLevel`.
  Triage-relevant `LogonType` values: 2 interactive at console, 3
  network (SMB, WMI, RPC), 4 batch (scheduled tasks), 5 service
  (SCM-started), 7 workstation unlock, 8 network cleartext (basic
  auth against IIS), 9 new credentials (`runas /netonly`), 10 remote
  interactive (RDP, fast-user-switch), 11 cached interactive (domain
  cache used while DC unreachable).
- **4625 — failed logon.** Carries `Status` and `SubStatus` NTSTATUS
  codes: `0xC000006A` bad password, `0xC0000064` unknown user,
  `0xC0000234` account locked, `0xC0000072` account disabled,
  `0xC000006F` outside working hours, `0xC0000071` password expired.
- **4672 — special privileges assigned.** Fires when the new session
  holds sensitive privileges (SeDebug, SeTcb, SeBackup, etc.). Pairs
  with a preceding 4624 for privileged logons.
- **4768 — Kerberos TGT requested.** Emitted on the DC for AS-REQ
  with `TicketEncryptionType`, `PreAuthType`, client IP, account.
- **4769 — Kerberos service ticket requested.** Emitted on the DC
  for TGS-REQ; `ServiceName` identifies the SPN; encryption type
  `0x17` is RC4-HMAC, `0x12` is AES256-CTS-HMAC-SHA1-96.
- **4776 — DC NTLM credential validation.** Fires for NTLM traffic;
  references `PackageName` = `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`.

## How to detect anomalies

Triage keys on pattern stacking across these IDs rather than any
single event in isolation.

- **Password spray.** A burst of 4625 with `SubStatus=0xC000006A`
  against many distinct `TargetUserName` values from a single
  `IpAddress` or `WorkstationName` in a short window. Sprays keep
  per-account attempts low to dodge lockout; global counts spike
  while per-user counts stay flat.
- **Lateral movement.** 4624 `LogonType=3` with non-empty `IpAddress`
  against multiple destination hosts from the same source, often
  reusing one `TargetUserName`. A `runas /netonly` pivot shows a
  preceding 4624 `LogonType=9` on the source host.
- **Token manipulation.** 4672 without a corresponding 4624 on the
  same `TargetLogonId` suggests a forged or injected token;
  legitimate privileged logons always emit the 4624 first.
- **Kerberoasting.** 4769 against a user account (not a machine
  account) carrying an SPN, with `TicketEncryptionType=0x17` (RC4)
  in an otherwise AES-capable domain. A single host requesting
  tickets for many service accounts in rapid succession is canonical.
- **Golden Ticket.** 4624 with `AuthenticationPackageName=Kerberos`
  on a member host with no preceding 4768 on any DC for that
  `TargetUserName` in the relevant window — the TGT was minted
  offline.
- **Anonymous logon.** 4624 where `TargetUserSid=S-1-5-7` or
  `TargetUserName=ANONYMOUS LOGON`, especially `LogonType=3` to
  non-IPC shares.
- **RDP from unusual source.** 4624 `LogonType=10` where `IpAddress`
  is outside the expected admin network or unexpected geography.
- **Service account interactive logon.** 4624 `LogonType=2` or `10`
  for a principal marked by naming convention (`svc_*`, `$`-suffixed,
  gMSA). Service accounts should use types 3, 4, or 5 only.

## What APTWatcher records

A logon-anomaly finding cites, for each event referenced:

1. The EVTX file path inside the image and the SHA-256 of that file
   (`source=<path>`, `sha256=<hex>`).
2. The event record range (`record=<first>..<last>`) and the
   `EventRecordID` of the pivotal event.
3. The event ID (4624 / 4625 / 4672 / 4768 / 4769 / 4776) and its
   `TimeCreated` in UTC with millisecond precision.
4. `TargetUserName`, `TargetDomainName`, `TargetUserSid`, and
   `TargetLogonId` verbatim from the XML payload.
5. `IpAddress` and `IpPort` when present; `WorkstationName` when the
   event is a 4776 or a pre-logon 4625.
6. `LogonType`, `AuthenticationPackageName`, `LmPackageName`, and
   `ImpersonationLevel` for 4624.
7. `Status` and `SubStatus` hex codes for 4625, with the
   human-readable meaning beside them.
8. `TicketEncryptionType`, `ServiceName`, `ServiceSid`, and
   `PreAuthType` for 4768/4769.
9. `ProcessName` and `ProcessId` when the event carries them (4624
   does on modern Windows).

Parser of record is `evtx_dump` for verbatim XML extraction;
`chainsaw` and `hayabusa` provide rule-based pre-triage, and their
hits are recorded as corroboration rather than as the primary
citation. `plaso` is used when the logon events need to be fused
into a super-timeline alongside MFT, registry, and Prefetch.

## Confidence calibration and pitfalls

Most anomaly patterns have legitimate analogues. Service accounts
routinely produce 4624 `LogonType=5`; the Task Scheduler produces
`LogonType=4` for every batch task; `runas /netonly` from a helpdesk
operator produces `LogonType=9` that is event-level indistinguishable
from an adversary's credential pivot. MDM agents (Intune, SCCM), WSUS
sync, and Exchange ActiveSync connectors emit 4625 bursts as health
probes retry against rotated service credentials. Laptop sleep/resume
cycles add 4634 and 4647 noise that inflates session counts. Clock
skew up to the Kerberos tolerance of five minutes desynchronises
4768/4769 pairs from their corresponding 4624s.

APTWatcher therefore caps a single-signature finding at
`confidence=0.5`. Tiering up to high confidence requires at least two
independent anomaly signatures stacking on the same principal or the
same source host — for example a 4625 spray followed within minutes
by a successful 4624 from impossible-travel geography, or a
`LogonType=9` new-credential event followed by 4769 SPN requests with
RC4 encryption against accounts the source host has no operational
reason to contact. Corroboration from non-EVTX artifacts (Sysmon 1
process-create, Defender/EDR telemetry, NetFlow) raises confidence
further and should be cited alongside the EVTX record references.
