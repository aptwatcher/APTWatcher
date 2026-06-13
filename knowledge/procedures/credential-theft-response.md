---
id: kb-proc-credential-theft-001
title: "Credential theft incident — detection, scoping, response"
source_type: author-original
attribution: "APTWatcher team (clean-room)"
mitre_techniques:
  - T1003
  - T1003.001
  - T1003.006
  - T1552
  - T1558
  - T1078
artifact_types:
  - live_host
  - memory_image
  - filesystem
  - evtx
  - ad_logs
tools:
  - volatility3
  - yara
  - plaso
  - hayabusa
last_updated: "2026-04-19"
---

## Purpose

This playbook covers incident response for suspected credential theft,
where an adversary has obtained usable authentication material
(passwords, hashes, Kerberos tickets, OAuth tokens, cloud API keys, or
browser-stored secrets). Credential theft is a pivot primitive: it
usually precedes lateral movement, privilege escalation, or persistence
with valid accounts (T1078), so response time compounds.

The procedure assumes APTWatcher is triaging a hybrid environment:
on-premises Active Directory, Microsoft 365, and one or more SaaS or
cloud consoles.

## Detection triggers

Treat any of the following as a credible trigger to open this
playbook. None are sufficient alone; two unrelated triggers on the
same principal within a short window is a high-confidence signal.

- **Impossible-travel sign-in.** Two interactive logons for the same
  user from geographically incompatible source IPs inside a window
  shorter than plausible travel time. Cloud identity providers emit
  this directly; on-prem, reconstruct from 4624 logon events plus
  VPN source IP.
- **Kerberoasting signature.** A flurry of TGS-REQs (event 4769) for
  service accounts with SPNs set, requested by a single user
  principal, with `TicketEncryptionType` of `0x17` (RC4-HMAC) on a
  domain that otherwise issues AES. Short inter-request intervals
  and many distinct target SPNs increase confidence.
- **LSASS access from unexpected callers.** Sysmon event 10
  (`ProcessAccess`) targeting `lsass.exe` with `GrantedAccess`
  values such as `0x1010`, `0x1410`, or `0x1438` from a process
  that is not a known security product.
- **Suspicious DPAPI decryption.** Microsoft-Windows-Crypto-DPAPI
  operational events showing master-key unwrap activity on behalf
  of an account that does not typically access that user's
  credential store, or decryption activity correlated with a
  prior remote logon.
- **OAuth token abuse.** A refresh token being exchanged from an IP
  that never authenticated interactively, or a non-interactive
  sign-in emitting `riskLevelAggregated=high` in Entra ID sign-in
  logs. Look for sudden consent grants to unknown applications.

## Scoping

The scoping goal is to answer four questions, in order: which accounts
are compromised, when compromise occurred, which services the stolen
material unlocks, and what the adversary did with it.

Start with the principal that tripped the trigger. Pull every logon
in the trailing 30 days: interactive (type 2), remote interactive
(type 10), network (type 3), and cached (type 11). For service
accounts add batch (type 4) and service (type 5). Correlate against
known source hosts for that principal.

Enumerate service reach:

- **AD/Windows domain.** Groups the principal is in, resources the
  principal has recently touched (file shares via 5140/5145,
  Kerberos service tickets via 4769).
- **Microsoft 365.** Unified audit log for mailbox access, SharePoint
  file access, Teams messaging, and admin operations under that UPN.
- **Other SaaS.** IdP (Entra, Okta, Ping) sign-in logs pivoted on
  the user's object ID, not just the UPN — adversaries sometimes
  rename accounts.
- **Cloud consoles.** CloudTrail / Azure Activity / GCP Cloud Audit
  for any API calls authenticated as that principal or with keys
  attributed to it.

If the principal has privileges on a domain controller, or if the
trigger is DCSync-shaped (4662 with a specific combination of
extended-rights GUIDs for `DS-Replication-Get-Changes` and
`DS-Replication-Get-Changes-All` from a non-DC principal), assume
all domain credentials are exposed and escalate scope to the full
directory.

## Memory-side IOCs

On hosts where LSASS dumping is suspected, acquire memory before
rebooting. Then run volatility3 against the image.

Relevant plugins:

```bash
vol -f host.raw windows.pslist.PsList
vol -f host.raw windows.pstree.PsTree
vol -f host.raw windows.handles.Handles --pid <PID_of_lsass>
vol -f host.raw windows.malfind.Malfind
vol -f host.raw windows.dlllist.DllList --pid <PID_of_lsass>
vol -f host.raw windows.cmdline.CmdLine
vol -f host.raw windows.filescan.FileScan
```

What to look for:

- A non-SYSTEM, non-security-product process holding an open handle
  to `lsass.exe` with `PROCESS_VM_READ` (`0x0010`) and typically
  `PROCESS_QUERY_INFORMATION` (`0x0400`) rights.
- A `lsass.exe` minidump file on disk (often named like
  `lsass.dmp`, `out.dmp`, `debug.bin`, or with a random prefix) in
  `C:\Windows\Temp`, `C:\ProgramData`, `C:\Users\Public`, or a user
  `AppData\Local\Temp` directory.
- Private, executable memory regions in an otherwise-signed process
  containing strings such as `SamLogon`, `KerbRetrieve`,
  `NtlmShared`, or `CredentialDelegation`. The credential-dumping
  tool families (Mimikatz family, Rubeus, Kekeo, SafetyKatz,
  LSASSy, Pypykatz, Dumpert) leave recognizable string and code
  patterns that YARA rules match at the family level.
- Unusual drivers loaded for direct LSASS access. A recently-
  installed kernel driver on a workstation, especially one signed
  with an unfamiliar certificate or loaded via a `SeLoadDriver`
  right assignment, can indicate BYOVD-assisted credential access.

Hand the dumped region or full image to YARA:

```bash
yara -r -s /opt/rules/credential-access/ host.raw
```

Family-level rules are preferred over single-version-specific ones
so that recompiled or mildly modified variants still match.

## Disk and log-side IOCs

EVTX is the backbone of scoping. Prioritize:

- **4624 / 4625** — successful and failed logons. Pivot on
  `LogonType`, `AuthenticationPackageName`, `WorkstationName`, and
  `IpAddress`. Pass-the-hash usually surfaces as a 4624 type 3 with
  `AuthenticationPackageName=NTLM` to a host that normally uses
  Kerberos.
- **4648** — "A logon was attempted using explicit credentials".
  This is the canonical pivot event. Look at `SubjectUserName`
  (who ran the tool) vs `TargetUserName` (whose credentials were
  used) and `TargetServerName`.
- **4769** — Kerberos service ticket requested. Kerberoasting
  shows as many 4769s from one user to many SPNs with RC4
  encryption. Golden/silver ticket use often has anomalous
  `TicketEncryptionType` or missing pre-auth data.
- **4776** — NTLM credential validation. Spikes in failed 4776s on
  a domain controller indicate password spray or NTLM relay.
- **4672** — special privileges assigned at logon. Watch for
  unexpected principals receiving SeDebug or SeTcb.
- **4662** — directory object access. Combinations of extended-
  rights GUIDs `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` and
  `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` from a non-DC principal
  are the DCSync signature (T1003.006).

Registry and filesystem:

- Access to `HKLM\SAM` and `HKLM\SECURITY` hives, or their copies
  saved via `reg save`, `esentutl /y`, or VSS shadow copies.
- `NTDS.dit` reads or copies off a domain controller filesystem.
- Browser credential stores: `Login Data` SQLite in Chromium
  profiles, `logins.json` / `key4.db` in Firefox profiles,
  `Vault` folders under `AppData\Local\Microsoft\Vault`.
- Password manager artifacts: KeePass `.kdbx` files opened by
  unexpected processes, `.1pif` exports, `.csv` exports from
  browsers.

Feed full EVTX sets to hayabusa for rule-based triage; Hayabusa's
sigma-backed ruleset will flag most of the above with reasonable
noise characteristics.

## Containment decision tree

Order matters. Rotating a secret without first killing active
sessions leaves the adversary authenticated on existing tokens
until they expire naturally.

1. **Identify the blast radius.** Is this a single user account, a
   service account, a tier-0 admin, or a domain controller
   compromise?
2. **Kill live sessions first.**
   - Windows: `klist purge` on affected hosts; at the DC, use
     AD PowerShell `Revoke-ADAccessToken` flow or mark the account
     as logon-denied.
     Entra ID: `Revoke-AzureADUserAllRefreshToken` / modern
     `Revoke-MgUserSignInSession`.
   - SaaS/IdP: invalidate refresh tokens through the provider's
     admin console.
3. **Rotate the stolen material.**
   - User password + MFA factor reset.
   - Service account password; rekey any secret stored in a
     CI/CD vault or configuration file that referenced it.
   - OAuth client secrets if the stolen material was an app
     credential; revoke and reissue.
   - Cloud API keys; rotate and redeploy any workload that
     consumed them.
4. **If a domain controller was compromised or DCSync occurred,
   re-key krbtgt.** Reset the krbtgt account password **twice**,
   with a delay between the two resets that exceeds the maximum
   Kerberos ticket lifetime (typically 10 hours plus a safety
   margin — wait at least 24 hours between the two resets in
   practice). A single reset still lets forged tickets issued
   before the reset validate.
5. **Quarantine the access path.** Block the source IP at the
   perimeter, disable the involved endpoint's network access,
   or isolate the VM in the cloud platform.
6. **Preserve evidence before reimaging.** Memory image, triage
   collection (registry hives, EVTX, Prefetch, Amcache, browser
   history), and a forensic disk image if scope warrants.

## Recovery sequencing

The failure mode to avoid is partial rotation. Sequence:

1. Session kill on identity provider.
2. Session kill on target services (M365, SaaS, cloud).
3. Secret rotation (user, service, OAuth, API).
4. For DC compromise: krbtgt double-reset with the mandatory
   interval.
5. Force reauthentication for all users who share trust paths
   with the compromised principal (shared tenant, shared SSO
   app, shared key vault).
6. Rebuild or reimage the host that was used to harvest
   credentials. Do not trust agent-based cleanup on a host that
   ran an LSASS-access tool with admin rights.
7. Re-enroll MFA factors for the affected user. A stolen
   TOTP seed or authenticator backup survives password reset.
8. Review conditional access and sign-in risk policies; lower
   the risk threshold temporarily for the affected principals.

## MITRE mapping

- **T1003 — OS Credential Dumping.** Parent technique.
- **T1003.001 — LSASS Memory.** In-memory credential extraction
  from the LSASS process.
- **T1003.006 — DCSync.** Directory replication abuse from a
  non-DC principal to extract domain secrets.
- **T1552 — Unsecured Credentials.** Credentials in files, in
  registry, in process memory, in Group Policy Preferences, or
  in cloud metadata services.
- **T1558 — Steal or Forge Kerberos Tickets.** Kerberoasting,
  AS-REP roasting, golden ticket, silver ticket, diamond and
  sapphire ticket variants.
- **T1078 — Valid Accounts.** The post-theft use that closes the
  loop: the adversary authenticates with the stolen material.

## Common operator mistakes

- **krbtgt reset once only.** A single reset leaves pre-reset
  forged tickets valid until they expire. Two resets with a
  sufficient interval are required.
- **Missing service accounts in scope.** A human-user
  compromise often implies any service account whose secret
  the user could read — GMSAs, scheduled-task accounts, SQL
  service accounts. Enumerate them explicitly.
- **Forgetting SaaS refresh tokens.** Rotating the password on
  the IdP does not always invalidate tokens already issued to
  SaaS apps. Each SaaS needs its own revocation step.
- **Rotating before revoking.** Attackers keep working on
  existing sessions while you reset the password. Kill sessions
  first.
- **Treating MFA bypass as a password problem.** If the
  adversary used a session-hijacking or token-theft pattern
  (e.g., AiTM phishing), password rotation alone does not
  remediate. Factor re-enrollment and device compliance review
  are required.
- **Not preserving memory.** Rebooting a host to "clean it"
  before imaging LSASS destroys the best available evidence of
  which tool was used and what material it touched.
- **Ignoring cached credentials.** Domain-cached credentials
  on disconnected endpoints survive password resets until the
  endpoint reauthenticates against a domain controller with
  the new secret.

## What to hand to the downstream tools

- **volatility3.** The raw memory image plus a target PID list
  (LSASS PID, any process flagged by the detection trigger, and
  any parent that spawned a suspicious child). Collect
  `pslist`, `pstree`, `handles --pid lsass`, `malfind`,
  `dlllist --pid lsass`, `cmdline`, `filescan`, and
  `svcscan` outputs.
- **plaso (log2timeline).** The full triage collection so a
  super-timeline spans EVTX, registry, Prefetch, Amcache,
  browser history, and filesystem timestamps. Filter the
  timeline to the incident window plus a 72-hour pre-window
  to catch staging activity.
- **hayabusa.** The EVTX archive from the affected host(s) and
  the domain controller(s). Run the full sigma ruleset; post-
  process to pull only credential-access, lateral-movement,
  and defense-evasion hits first.
- **yara.** Memory image, dumped regions from malfind, any
  suspicious `.dmp` file found on disk, and browser profile
  folders. Use credential-access rule family collections, not
  single-sample rules.

## References

- NIST SP 800-61r2 — Computer Security Incident Handling Guide.
- NIST SP 800-63B — Digital Identity Guidelines, Authentication.
- MITRE ATT&CK techniques T1003, T1552, T1558, T1078
  (https://attack.mitre.org/).
- Microsoft documentation on krbtgt account maintenance and the
  double-reset procedure.
