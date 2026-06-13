---
id: kb-proc-ransomware-triage-001
title: "Ransomware incident — initial triage playbook (first 60 minutes)"
source_type: author-original
attribution: "APTWatcher team (clean-room)"
mitre_techniques:
  - T1486
  - T1489
  - T1490
  - T1491.001
artifact_types:
  - live_host
  - memory_image
  - filesystem
  - network_capture
tools:
  - volatility3
  - plaso
  - yara
  - bulk_extractor
last_updated: "2026-04-19"
---

## Scope of the first hour

The first sixty minutes of a ransomware incident set the ceiling on every artifact that will be available for the rest of the investigation. Decisions made under time pressure — whether to pull the power cable, whether to kill a process tree, whether to disconnect the switch port — directly determine what the memory image, pagefile, and volatile network state will still contain when the forensic examiner sits down. The priority order is: confirm the incident is real, bound the blast radius, preserve volatile evidence, then contain. Recovery planning waits until triage is complete.

A public baseline for these decisions is NIST SP 800-61r2, which separates detection and analysis from containment, eradication, and recovery for a reason: eradication without analysis destroys the data needed to prevent recurrence. NIST SP 800-86 covers the companion discipline of forensic data acquisition and is the public-domain reference for volatility ordering. The playbook below assumes that ordering.

Assume from the start that this incident will become legal evidence. Chain of custody begins the moment triage begins: every acquired artifact gets a filename, a SHA-256, a collection timestamp in UTC, the collector's name, and the source host. A simple per-case CSV that grows one row per artifact is sufficient for the first hour; formal evidence logs can be reconstructed from it later. Photograph the screen before touching the keyboard if the ransom note or encryption progress is visible — a timestamped photo is cheaper than trying to recover the same information from memory later.

## Decision tree — what state is the incident in

Three states drive very different responses. Classifying the incident correctly in the first ten minutes is the single highest-leverage decision.

**Pre-detonation.** The loader is present, a command-and-control channel may be established, staging has occurred (volume shadow copies deleted, backup agents disabled, credentials dumped), but bulk encryption has not started. User files are still readable. This is the state where isolation pays off most: the encryption phase can be prevented entirely. Indicators: suspicious process lineage from a recently executed document or signed LOLBin, fresh entries in scheduled tasks or run keys, `vssadmin delete shadows` or `wbadmin delete catalog` events, disabled recovery services, but no `.encrypted` files and no ransom note yet.

**Active detonation.** The encryptor is running right now. New files with anomalous extensions are appearing every second, CPU on one or more processes is pinned, and disk I/O is saturated. The ransom note may or may not have been dropped yet. This is the hardest state — every additional second of uptime destroys more user data, but pulling the plug also destroys the encryption key material currently resident in process memory. The correct move is usually network isolation plus an immediate memory capture on the encrypting host, in that order.

**Post-detonation.** Encryption has completed, the ransom note is present on the desktop and in every encrypted directory, and the operator has moved to the extortion phase. The encryptor process may have self-deleted. Preservation is the priority here because the evidence window is closing as scheduled tasks, timers, and orchestration scripts continue to clean up artifacts. Do not reboot.

## Immediate priorities

Within the first ten minutes, the incident handler needs three facts: which hosts are affected, which user accounts were used to execute payloads, and whether the attacker still has interactive access. Everything else is secondary. A quick scope pass checks EDR telemetry for processes writing at high rates to user directories, SIEM alerts for mass file rename or mass file modification events, and helpdesk ticket volume — users reporting inaccessible files from multiple departments inside a few minutes is itself a scoping signal.

Do not reboot or shut down any host that is believed to be compromised. A running host retains the decryption key in process memory, the attacker's injected modules in RAM, the current network connections in kernel structures, and the pagefile in a meaningful state. A cleanly shut-down host loses all of that. If power must be removed for safety reasons, pull the cable rather than issuing a shutdown — a hard power-off preserves more forensic state than a graceful shutdown that flushes handles and rotates logs.

Do not run antivirus cleanup, do not quarantine files, do not run "malware removal" utilities. Those tools will delete the exact binaries the examiner needs. If EDR offers a "contain host" option that blocks network traffic without terminating processes, that is preferable to a manual shutdown.

## Live-response collection order

Volatility decreases in a well-known order, and collection should mirror it. The guiding principle comes from RFC 3227: capture the most volatile data first. On a Windows host, the practical order is memory, then running process and network state, then scheduled tasks and persistence mechanisms, then selected filesystem artifacts, then logs.

Memory first. Take a full physical memory image before touching anything else. A 16 GB host produces a 16 GB image; allocate removable storage accordingly and write to external media, never to the C: volume. Tools like WinPmem, DumpIt, or FTK Imager Lite are the standard choice. Record the hash of the image file immediately after capture. The image is the primary input for later volatility3 work.

Volatile process and network state. Capture the output of `tasklist /v`, `wmic process get Name,ProcessId,ParentProcessId,CommandLine,ExecutablePath`, `netstat -anob`, `arp -a`, `ipconfig /displaydns`, `route print`, and `query user`. On modern systems, `Get-Process`, `Get-NetTCPConnection -IncludeAllCompartments`, and `Get-CimInstance Win32_Process` produce richer structured output. Each command runs once, output is redirected to files on the external media, and the collection time is logged.

Persistence enumeration. `schtasks /query /fo CSV /v`, `Get-ScheduledTask | Get-ScheduledTaskInfo`, `Get-Service | Where-Object {$_.StartType -eq "Automatic"}`, and a registry export of the standard run keys (`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, the `RunOnce` variants, the same paths under `HKCU`, and `Image File Execution Options`). WMI subscription persistence lives under `root\subscription` — `Get-CimInstance -Namespace root/subscription -ClassName __EventFilter` and the paired consumer and binding classes.

Targeted filesystem collection. Copy the Windows event logs from `C:\Windows\System32\winevt\Logs\`, the Prefetch directory from `C:\Windows\Prefetch\`, the registry hives from `C:\Windows\System32\config\` (requires a raw-disk tool like FTK or a VSS snapshot because the hives are locked), and the amcache hive from `C:\Windows\appcompat\Programs\Amcache.hve`. On the user side, collect `NTUSER.DAT` and `UsrClass.dat` for every affected account plus their Jump Lists under `AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`.

Network capture. If the host is still powered on and contained to a monitoring VLAN rather than fully isolated, a short `tcpdump` or `netsh trace` capture of ongoing connections documents active beacons and data exfiltration channels.

```powershell
# Example live-response sequence, output redirected to external media E:\ir\
Get-Process | Select Id,ParentProcessId,ProcessName,Path,StartTime | Export-Csv E:\ir\processes.csv
Get-NetTCPConnection -IncludeAllCompartments | Export-Csv E:\ir\tcp.csv
Get-ScheduledTask | ForEach-Object { $_ | Get-ScheduledTaskInfo } | Export-Csv E:\ir\tasks.csv
Get-CimInstance Win32_Service | Export-Csv E:\ir\services.csv
reg export HKLM\Software\Microsoft\Windows\CurrentVersion\Run E:\ir\run_hklm.reg
```

Hash the collection directory at the end with `Get-FileHash -Algorithm SHA256` and write the manifest to the same media. Once the external media is unmounted it becomes the authoritative evidence artifact.

## Indicator collection

Ransomware triage produces a small set of high-signal indicators that feed every downstream task.

The encrypted file extension. Every current ransomware family appends a suffix to encrypted files — sometimes a fixed string, sometimes a per-victim ID, sometimes a per-file pseudo-random value. Collect the suffix, hash one or two encrypted files, and note the file size delta between an encrypted file and a known pre-encryption backup if one exists. The extension alone is often enough to shortlist the family via public trackers like ID-Ransomware or the MalwareBazaar tag set.

The ransom note. Capture the filename, full contents, and SHA-256 of the note. Ransom notes are typically dropped as `README.txt`, `HOW_TO_DECRYPT.html`, `!RESTORE_FILES.txt`, or a family-specific name, and are written into every encrypted directory. Note content almost always includes a victim ID, a contact channel (Tor .onion address, email, qTox ID), and a payment deadline. Do not contact the threat actor from a production mailbox; do not click any URL inside the note from a production host.

Process tree at detonation. From memory or EDR history, reconstruct the parent-child chain that led to the encryptor. A classic chain is `winword.exe` or `outlook.exe` -> `powershell.exe` -> `rundll32.exe` -> `<encryptor>.exe`, or an RDP session from a non-standard source IP spawning `cmd.exe` -> `certutil.exe` -> `<encryptor>.exe`. Capture PID, PPID, image path, command line, and the SID under which each node ran.

Network beacons. Grep the netstat output for outbound connections to non-RFC1918 addresses, particularly on ports 443, 80, 8080, and high ephemeral ports. Cross-reference against EDR network history. Beacon cadence — a TCP connection to the same external IP every N seconds — is the cheapest indicator of live C2.

Shadow copy and backup state. `vssadmin list shadows`, `wbadmin get versions`, and a check of the Windows Server Backup or third-party agent status tell you whether rollback is possible. Most ransomware families run `vssadmin delete shadows /all /quiet` or `wmic shadowcopy delete` early in the chain — these map to T1490.

Account and credential footprint. Note every account that has logged on in the last 72 hours via Security log event 4624, paying attention to Type 10 (RemoteInteractive, i.e. RDP) and Type 3 (Network) logons from unexpected source IPs. Service account logons during off-hours and domain admin logons to non-admin workstations are both high-signal. Pair with event 4648 (explicit credential use) to see where stolen credentials were replayed.

## Containment — isolation versus shutdown

The containment choice is a direct trade-off between stopping further damage and preserving forensic state. Four options, ranked by evidence preservation.

Network isolation at the switch or EDR. The host stays powered, memory and processes remain intact, but all network traffic is blocked. This is the preferred option during active detonation because it stops lateral movement and data exfiltration while preserving the ability to capture a complete memory image. The downside is that local encryption continues on already-connected disks.

Host-based firewall block of all outbound traffic. Similar to switch isolation but controllable remotely through EDR. Preserves memory fully. Does not stop local encryption.

Graceful shutdown. Loses memory, loses volatile network state, flushes handles, rotates some logs. Stops local encryption. Use only after memory has been captured or when a memory capture is operationally impossible.

Hard power-off. Loses memory, loses volatile network state, but preserves pagefile and hiberfil contents more faithfully than a graceful shutdown because no flush path executes. Stops local encryption immediately. Appropriate only when active encryption is ongoing and memory capture is impossible.

The decision defaults to network isolation plus memory capture during active detonation, and to network isolation alone during pre-detonation or post-detonation.

## Handoff to deep forensic analysis

The live-response collection above feeds three downstream workflows.

The memory image goes to volatility3. Starting plugins are `windows.pslist.PsList`, `windows.pstree.PsTree`, `windows.cmdline.CmdLine`, `windows.netscan.NetScan`, `windows.malfind.Malfind`, `windows.filescan.FileScan`, and `windows.registry.hivescan.HiveScan`. Example invocation:

```bash
vol.py -f memory.raw windows.pstree.PsTree
vol.py -f memory.raw windows.malfind.Malfind --pid <suspect_pid> --dump
vol.py -f memory.raw windows.netscan.NetScan
```

Dumped regions from malfind are scanned with YARA against ransomware and loader rule sets:

```bash
yara -r ruleset/ransomware.yar ./malfind_dumps/
yara -r ruleset/ransomware.yar memory.raw
```

The collected filesystem artifacts feed plaso for a super-timeline. `log2timeline.py` ingests event logs, registry hives, Prefetch, amcache, MFT, and USN journal; `psort.py` filters and renders the timeline around the detonation window.

```bash
log2timeline.py --storage-file case.plaso evidence_directory/
psort.py -o l2tcsv -w case_timeline.csv case.plaso "date > '2026-04-19 00:00:00' AND date < '2026-04-19 23:59:59'"
```

Disk images or large file collections feed bulk_extractor for rapid IOC sweeps — email addresses, URLs, IP addresses, credit card numbers, and PGP keys fall out of a single pass.

```bash
bulk_extractor -o bulk_output/ disk_image.dd
```

## MITRE ATT&CK mapping

The ransomware kill chain in the final hour before detection typically touches four techniques worth tagging in the case notes.

**T1486 — Data Encrypted for Impact.** The primary action: bulk symmetric encryption of user and system files, usually AES-256 with the symmetric key wrapped by an attacker-held RSA or ECDH public key. Artifacts: mass file modification events, file extension changes, CPU and disk saturation on the encryptor process, encrypted-file magic bytes or header structure consistent across the file set.

**T1489 — Service Stop.** Operators stop database, backup, mail, and endpoint-protection services before encryption to unlock files and to disable defenders. Artifacts: Service Control Manager events 7036 and 7040 in the System log, `sc stop` or `net stop` command-line history, and `Set-Service -Status Stopped` PowerShell entries. Services frequently targeted include `MSSQLSERVER`, `Veeam` variants, `MSExchange*`, and third-party EDR agents.

**T1490 — Inhibit System Recovery.** Shadow copy deletion, backup catalog removal, and boot configuration tampering. Artifacts: `vssadmin delete shadows`, `wmic shadowcopy delete`, `wbadmin delete catalog`, `bcdedit /set {default} recoveryenabled No`, and `bcdedit /set {default} bootstatuspolicy ignoreallfailures` in command-line telemetry or Security log event 4688 records.

**T1491.001 — Internal Defacement.** Ransom note deployment to every encrypted directory, desktop wallpaper replacement, and in some families an HTA or HTML landing page that opens automatically at logon. Artifacts: identical note file appearing at every directory level, registry modifications under `HKCU\Control Panel\Desktop\Wallpaper`, and scheduled tasks that display the note on next logon.

## Common mistakes that destroy evidence

Rebooting the host to "see if it comes back clean." The memory image is lost, the pagefile is overwritten during shutdown, process tree evidence is gone, and any in-memory key material is gone with it. This is the single most expensive mistake.

Running an antivirus scan or an "unlocker" tool across the encrypted filesystem. The scan rewrites file timestamps wholesale, destroys the timeline, and quarantines the encryptor binary before it has been acquired.

Restoring from backup before triage is complete. Restoration overwrites forensic artifacts on the original volume and, if the backup itself was compromised, reintroduces the attacker. Take a full disk image first.

Logging in with a domain admin account to investigate. The credential is cached in LSASS on the victim host and becomes available to any attacker code still resident. Use a dedicated forensic account with minimal privilege, or investigate remotely through EDR.

Copying files off the victim host onto a shared network drive. The samples may re-encrypt or re-infect the destination. Always collect to isolated removable media.

Connecting the victim host to a sandbox or analysis VM on the same network. Ransomware regularly enumerates SMB shares and encrypts reachable network storage. Keep analysis infrastructure on a physically separate, non-routed segment.

Emailing the ransom note or samples as attachments through the production mail system. Mail filters may quarantine the evidence, and the note itself may contain tracking tokens that alert the operator that the victim has engaged responders.

Deleting suspicious files "to clean up." Every deletion is an artifact loss. The correct move during triage is always to copy and hash, never to delete. Cleanup belongs to the eradication phase, after analysis is complete.

Forgetting time synchronization. If the victim host has clock drift or a tampered time source, every event log timestamp shifts relative to the network, DNS server, and domain controller logs. Record the host clock delta against a trusted NTP source during collection — a single `w32tm /stripchart /computer:<trusted_ntp>` snapshot is enough to document the offset for the later timeline reconstruction.

## Triage completion and exit criteria

Triage is complete when four conditions are met. First, a full memory image exists for each affected host with a recorded hash. Second, volatile process, network, and session state has been captured to external media. Third, persistence enumeration output exists for each host. Fourth, the incident scope — affected hosts, affected accounts, affected shares — has been documented well enough that containment can proceed without further live access. At that point the affected hosts can be powered down or imaged at the block level for deep forensic work, and the investigation moves out of the sixty-minute window into full case analysis.

## References

- NIST SP 800-61 Rev. 2, Computer Security Incident Handling Guide
- NIST SP 800-86, Guide to Integrating Forensic Techniques into Incident Response
- RFC 3227, Guidelines for Evidence Collection and Archiving
- MITRE ATT&CK technique pages for T1486, T1489, T1490, and T1491.001
