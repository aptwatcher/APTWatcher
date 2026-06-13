---
id: kb-proc-lateral-movement-001
title: "Lateral movement — detection, scoping, rapid containment"
source_type: author-original
attribution: "APTWatcher team (clean-room)"
mitre_techniques:
  - T1021
  - T1021.001
  - T1021.002
  - T1021.006
  - T1570
  - T1563
  - T1047
artifact_types:
  - live_host
  - memory_image
  - evtx
  - network_capture
tools:
  - volatility3
  - plaso
  - hayabusa
  - bulk_extractor
last_updated: "2026-04-19"
---

## Patient zero plus N hops

Lateral movement is what turns a single-host incident into an enterprise event. Once an operator uses stolen credentials or a forged ticket to reach a second host, every subsequent artifact — process trees, prefetch, scheduled tasks, RDP bitmap cache, memory — now needs to be collected on a growing set of systems. Each new hop roughly doubles collection cost, evidence volume, and the probability that one host gets missed.

The responder's first job is therefore not to remediate, but to bound the blast radius. Until the set of compromised principals (user accounts, service accounts, machine accounts, certificates) and the set of reached hosts are known, any containment action is guesswork and risks tipping the operator without cutting them out.

APTWatcher treats lateral movement as a graph problem. Nodes are hosts and identities. Edges are authenticated sessions with timestamps and a protocol label. The containment plan is derived from the graph, not from individual alerts.

## Detection signals by technique

### T1021.001 — Remote Desktop Protocol

Authentication lands as EVTX `Security` event `4624` with `LogonType=10` (RemoteInteractive) on the destination, correlated with `4648` (explicit credential use) on the source. NTLM fallbacks produce `4776` on the authenticator. The destination `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` log records session connect/disconnect as events `21`, `22`, `24`, `25`. `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational` event `1149` captures the source IP and username at connection time.

```
wevtutil qe Security /q:"*[System[(EventID=4624)]] and *[EventData[Data[@Name='LogonType']='10']]" /f:text /c:50
```

Host-side residue: RDP bitmap cache at `%LOCALAPPDATA%\Microsoft\Terminal Server Client\Cache\`, `Default.rdp` in the user profile, and `mstsc.exe` prefetch on the source.

### T1021.002 — SMB and admin shares

Network logons to `C$`, `ADMIN$`, `IPC$` produce EVTX `4624` with `LogonType=3` on the destination, plus `5140` (share accessed) and `5145` (detailed file-share access check) when object-access auditing is on. `5145` is the single richest event for lateral movement: it captures source address, user, share name, relative target, and access mask.

Lateral tool drop signatures: write to `ADMIN$\system32\` or to a user `C$\Users\<u>\AppData\Local\Temp\` from a non-local SID, followed seconds later by service creation (`7045` in `System`) or scheduled task registration (`4698` in `Security`).

### T1021.006 — WinRM and PowerShell Remoting

Destination logs: EVTX `Microsoft-Windows-WinRM/Operational` event `91` (session created), `Microsoft-Windows-PowerShell/Operational` events `4103` (pipeline execution) and `4104` (script block logging). `Windows PowerShell` classic log event `400` with `HostName=ServerRemoteHost` is a strong tell. A `wsmprovhost.exe` process whose parent is `svchost.exe -k DcomLaunch` is the standard PSRemoting server-side footprint.

WSMan traffic is HTTP on TCP/5985 or HTTPS on TCP/5986. Expect `Microsoft WinRM Client` in the User-Agent.

### T1570 — Lateral Tool Transfer

When pcap or disk-resident packet capture is available, `bulk_extractor` will carve SMB sessions and reconstruct transferred files:

```
bulk_extractor -o be_out -E smb -E net capture.pcap
```

Resulting carved objects live under `be_out/smb_carved/` and `be_out/packets.txt`. On the destination host, recently created executables under `C:\Windows\`, `C:\ProgramData\`, or user `AppData` with a creation time that matches an inbound `5145` record are the canonical drop pattern. Prefetch entries with `RUN COUNT = 1` created within seconds of a remote logon close the loop.

### T1563 — Remote Service Session Hijacking

RDP hijack via `tscon.exe` leaves a distinctive trail: `services.exe` spawning `cmd.exe` or `tscon`, followed by a `TerminalServices-LocalSessionManager` event `25` (reconnect) for a session that was never disconnected by the legitimate user. SSH session hijack on Windows (OpenSSH) is rarer but shows as a second authorized process attached to an existing `sshd.exe` child.

### T1047 — Windows Management Instrumentation

WMI-based execution surfaces in `Microsoft-Windows-WMI-Activity/Operational` events `5857`, `5858`, `5860`, `5861` on the destination. Event `5861` records permanent event subscriptions — a persistence cousin of lateral execution. `wmiprvse.exe` spawning `cmd.exe`, `powershell.exe`, or an attacker binary is the near-real-time signal. On the wire, DCOM over TCP/135 followed by a dynamically negotiated high port identifies the channel.

## Scoping — build the session graph

Before containing anything, assemble a session graph. Each edge is a tuple:

```
(source_host, source_ip, dest_host, dest_ip, account, protocol, t_start, t_end, evidence_refs)
```

Populate edges from:

- EVTX `4624`/`4625`/`4648`/`4672` across the Domain Controllers and all suspect endpoints.
- `4769` (Kerberos service ticket requested) on DCs — pivot on `ServiceName` to find which hosts a compromised account reached.
- `5140`/`5145` on file servers and workstations with auditing enabled.
- Hayabusa timeline for cross-host correlation.

```
hayabusa csv-timeline -d ./evtx_collection -o timeline.csv --profile lateral-movement
```

- Plaso super-timeline to unify EVTX, prefetch, registry, and filesystem mtime into one feed:

```
log2timeline.py --parsers "winevtx,prefetch,mft,usnjrnl,registry" case.plaso ./triage_image
psort.py -o l2tcsv -w super_timeline.csv case.plaso
```

Each new edge expands the scope set. Stop expanding only when a pass adds no new host or identity.

## Containment ordered by evidence impact

Containment actions destroy or preserve evidence differently. Pick the lowest-impact action that achieves the objective.

### Network layer — lowest evidence impact

- Per-host firewall rule blocking outbound to the operator's known C2 IPs and inbound on SMB/RDP/WinRM from non-admin subnets. Preserves memory, preserves logs, breaks the edge.
- VLAN quarantine: move the host to an isolated VLAN with only the collection server reachable. Host remains live for memory capture and live response.
- Switch port shutdown or 802.1X quarantine: harder — severs any in-flight command and may cause in-memory loaders to fail noisily. Still preserves disk.

### Identity layer — medium evidence impact

- Disable the compromised account (`Disable-ADAccount`) and force all session TGTs to be re-requested. Existing TGTs remain valid until their 10-hour lifetime expires.
- Revoke current TGTs by resetting the account password twice in quick succession.
- Revoke issued certificates if the operator used AD CS abuse.
- `krbtgt` double-reset is the domain-wide sledgehammer for suspected Golden Ticket. It invalidates every TGT and every service ticket in the forest. Plan it — do not improvise it — and coordinate with identity owners. Preserves host-side evidence fully.

### Host layer — highest evidence impact

- Force logoff of a specific session (`logoff <id> /server:<host>`) terminates interactive attacker shells and loses any in-memory unsaved state. Take a memory image first.
- Kill specific processes (`Stop-Process`) — same caveat, take memory first.
- Block admin shares (`Set-SmbServerConfiguration -EnableAdminShares $false`) prevents further lateral drops but will break legitimate admin tooling and alert the operator.
- Shut down the host. Do this only if you are prepared to lose volatile evidence and if isolation at the network layer is not feasible.

## The observation versus hard-stop dilemma

Cutting the operator before the graph is complete is the single most common scoping failure. Arguments in each direction:

Silent observation — pros: more edges collected, identities surfaced, C2 infrastructure mapped, chance to see staging and data-collection TTPs. Cons: every minute is potential new damage, data exfiltration continues, ransomware pre-encryption staging may complete.

Immediate hard containment — pros: bounds damage, removes ongoing exfil, lets remediation begin. Cons: truncates the graph, operator rotates infrastructure, sleeper persistence on un-enumerated hosts survives and re-awakens weeks later.

APTWatcher's default stance: network-layer quarantine of known-compromised hosts as soon as they are confirmed, combined with continued passive observation at the DC and egress points. Identity revocations are staged so account disables fire only after the graph expansion pass produces zero new edges for a configured dwell window (default two cycles, roughly 30 minutes). `krbtgt` reset is never automatic — it requires operator approval.

## Memory and timeline pivots — what to run next

Once a host is network-quarantined but still live:

```
# Memory capture first, before any session kill
winpmem -o mem.raw

# Volatility3 network pivot
vol -f mem.raw windows.netscan.NetScan
vol -f mem.raw windows.netstat.NetStat
vol -f mem.raw windows.sessions.Sessions
vol -f mem.raw windows.pslist.PsList
vol -f mem.raw windows.pstree.PsTree
```

`netscan` output filtered to `ESTABLISHED` connections to non-RFC1918 addresses or to other internal hosts on TCP/445, 3389, 5985, 5986, 135 gives the current outbound edge set from this host. Cross-reference with the session graph.

Hayabusa hunt focused on lateral movement rules:

```
hayabusa csv-timeline -d ./evtx -o lateral.csv --include-tag lateral_movement
```

Plaso pivot — once super-timeline exists, slice around each `4624 LogonType=3/10` event to see what executed in the minutes after:

```
psort.py -o l2tcsv case.plaso "date > '2026-04-19 14:00:00' AND date < '2026-04-19 14:30:00'" > slice.csv
```

## MITRE mapping

| Technique   | Name                                      |
|-------------|-------------------------------------------|
| T1021       | Remote Services                           |
| T1021.001   | Remote Desktop Protocol                   |
| T1021.002   | SMB / Windows Admin Shares                |
| T1021.006   | Windows Remote Management                 |
| T1570       | Lateral Tool Transfer                     |
| T1563       | Remote Service Session Hijacking          |
| T1047       | Windows Management Instrumentation        |

## Common mistakes

- Containing only patient zero. By the time lateral movement is visible, patient zero is usually the least important host — the operator has already moved. Quarantine the current foothold, not the historical one.
- Missing domain-trust paths. Cross-domain and cross-forest trusts extend the graph beyond the primary domain. Include trusted-domain DCs in EVTX collection, especially `4769` service ticket logs.
- Killing the decoy. Operators routinely run a noisy tool on one host to draw attention while their real C2 sits on a quieter host. Do not close the ticket on the first confirmed beacon; continue expanding the graph.
- Forgetting service and machine accounts. Human-user hunts miss `NT AUTHORITY\SYSTEM` lateral movement via machine accounts (`HOST/<fqdn>`), service accounts with SPNs, and managed service accounts. Include these in credential scoping.
- Disabling an account while TGTs are still valid. A disabled account with a live TGT continues to work for up to ten hours. Reset the password twice to invalidate tickets.
- Skipping memory capture before session kill. A forced logoff drops every injected loader and any in-memory-only credentials. Image first, kill second.

## Prerequisites for the agent

Before APTWatcher can run this procedure end-to-end, the following inputs must be reachable:

- Read access to Domain Controller Security EVTX (live or archived) for the full incident window plus 24 hours of pre-incident baseline.
- A credential with rights to query `4624`/`4648`/`4769` events on member servers and workstations.
- A deployed collection agent or WMI/WinRM foothold able to pull EVTX, prefetch, and memory from the expanding scope set.
- A configured timeline build host with Plaso, Hayabusa, Volatility3, and `bulk_extractor` on PATH.
- Write access to the evidence vault that will hold the IncidentBundle.
- An approval workflow wired in for the high-impact containment actions (krbtgt reset, mass account disable, switch port shutdown).

If any prerequisite is missing, the agent raises a blocker finding rather than running partial scoping.

## Procedure summary

1. Ingest the initial alert. Record the implicated host, account, and timestamp as the root node of the session graph.
2. Pull Security EVTX from the DCs. Extract every `4624`/`4648`/`4769` referencing the initial account or host within the window.
3. Pull EVTX, prefetch, and — when a live attacker process is suspected — memory, from each host reached by edges discovered in step 2.
4. Build the initial graph. Feed it to Hayabusa and Plaso for corroboration.
5. Loop: expand the scope set by one hop; re-run steps 2 and 3 for new nodes; stop when two consecutive passes add no new edges.
6. Quarantine confirmed-compromised hosts at the network layer.
7. Stage identity revocations. Execute after the expansion loop stabilises.
8. Emit the IncidentBundle and escalate to offline analysis.

## Handoff artifacts for offline analysis

Every lateral-movement finding produces an IncidentBundle record for the online-to-offline handoff. Required contents:

1. Session graph export as JSON: nodes (host, identity) and edges (protocol, timestamps, evidence refs).
2. EVTX collection per host in the scope set, hashed and signed.
3. Memory images of every host where a live attacker process was observed, with `winpmem` or equivalent capture metadata.
4. Hayabusa CSV timeline and the rule profile used.
5. Plaso storage file (`.plaso`) plus the filtered CSV slice around each lateral edge.
6. Bulk-extractor output directory when pcap was available, with the SMB-carved object manifest.
7. Volatility3 `netscan`, `netstat`, `pslist`, `pstree`, `sessions` output per imaged host, tagged with `correlation_id`.
8. Containment action log: timestamp, action, operator, target, reversibility flag. This becomes the audit trail for the identity and network teams.
9. List of accounts with confirmed or suspected compromise, flagged for password reset, TGT revocation, and — if applicable — `krbtgt` reset recommendation.

The offline analyst consumes the IncidentBundle without needing live access, re-runs the graph construction to verify, and either closes the incident or requests an additional online expansion cycle.

## References

- MITRE ATT&CK — Remote Services (T1021) and sub-techniques
- Microsoft documentation — Windows Security Auditing event IDs 4624, 4648, 4672, 4769, 4776, 5140, 5145
- Microsoft documentation — Terminal Services operational logs
- Volatility Foundation — volatility3 plugin reference
- Plaso project documentation — log2timeline and psort
- Hayabusa project documentation — Sigma-based EVTX timeline
- Bulk Extractor project documentation — SMB and network scanners
