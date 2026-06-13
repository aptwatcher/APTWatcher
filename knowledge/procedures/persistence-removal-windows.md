---
id: kb-proc-persistence-removal-win-001
title: "Windows persistence — full-surface audit and removal playbook"
source_type: author-original
attribution: "APTWatcher team (clean-room)"
mitre_techniques:
  - T1547
  - T1547.001
  - T1053
  - T1053.005
  - T1543
  - T1543.003
  - T1546
  - T1574
artifact_types:
  - live_host
  - registry
  - filesystem
  - evtx
  - memory_image
tools:
  - volatility3
  - plaso
  - yara
  - hayabusa
last_updated: "2026-04-19"
---

## Did we miss one?

The recurring failure mode of Windows persistence removal is straightforward to state and hard to fix: a competent operator plants `N` persistence mechanisms, the responder finds and removes one or two obvious ones, the case is declared closed, and the attacker walks back in the next day through a mechanism nobody looked at. The encryptor gets pulled off the Run key, nobody notices the WMI event subscription that re-downloads it. The scheduled task gets disabled, nobody notices the COM hijack under `HKCU\Software\Classes\CLSID`. The service gets deleted, nobody notices the image file execution options debugger pointing `sethc.exe` at a reverse shell.

Persistence removal is therefore an inventory problem before it is a deletion problem. The correct sequence is: enumerate the full persistence surface first, diff against a known good baseline, treat every anomaly as a candidate until proven benign, and only then start removing. A shortcut at the inventory stage is paid for by a reinfection later.

This playbook assumes the host is isolated from the network, a memory image and registry-hive copy have been taken, and credentials available on the host are already considered compromised. See `procedures/ransomware-initial-triage.md` for the preceding live-response collection.

## Persistence surface — public OS-level mechanisms

The surface is large because Windows is designed to let third-party code run at almost every transition point: boot, logon, user input, network event, application launch, scheduled time, and system event. Every one of those transition points is a persistence candidate.

### Registry Run / RunOnce family (T1547.001)

The most common and most often the only place a junior responder looks. Every location below can autoexecute at logon or boot and must be exported.

```cmd
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /s
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /s
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices" /s
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce" /s
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /s
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /s
reg query "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run" /s
```

Winlogon keys (`Userinit`, `Shell`, `Notify`, `Taskman`) under `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon` are higher-privilege cousins — tampering here runs code before the desktop is available and often survives user-profile cleanup.

Image File Execution Options is the classic "debugger" hijack (T1546.012). An attacker sets the `Debugger` value under `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target>.exe` to a second binary; launching `<target>.exe` launches the debugger with the target as an argument. Accessibility binaries (`sethc.exe`, `osk.exe`, `utilman.exe`, `magnify.exe`) are frequent targets because they are reachable from the logon screen.

### Scheduled Tasks (T1053.005)

Scheduled tasks live in two places: a registry tree under `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\` and XML definition files under `C:\Windows\System32\Tasks\`. Both must be collected because they can be out of sync — a task hidden from `schtasks /query` may still exist on disk or in the registry.

```cmd
schtasks /query /fo CSV /v > tasks.csv
```

```powershell
Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" } | Select-Object TaskPath,TaskName,Actions,Triggers,Principal | Export-Csv tasks_ps.csv
Get-ChildItem -Recurse C:\Windows\System32\Tasks | Select-Object FullName,LastWriteTimeUtc,Length
```

Hidden tasks are a specific trap: a task XML can carry `<Settings><Hidden>true</Hidden></Settings>`, and some older tooling (including the `schtasks` CLI under some conditions) will not list it. Enumerate by walking the filesystem and the `TaskCache\Tree` registry subkey directly. At-jobs (legacy `at.exe`) appear under `HKLM\System\CurrentControlSet\Services\Schedule\TaskCache\Tasks`.

### Services (T1543.003)

Services are a registry construct. Each service is a subkey under `HKLM\System\CurrentControlSet\Services\<ServiceName>`, with `ImagePath`, `ServiceDll` (for svchost-hosted services), `Start`, and `Type` values driving behaviour. Attackers plant services in three common shapes:

- New service with `ImagePath` pointing at attacker binary and `Start=2` (automatic).
- Existing service's `ImagePath` rewritten to attacker binary.
- Existing svchost service's `ServiceDll` rewritten — the service hosts the attacker DLL inside a legitimate `svchost.exe` process, which is why `tasklist` alone never catches it.

```cmd
reg export HKLM\System\CurrentControlSet\Services services.reg
sc queryex type= service state= all > services_live.txt
```

```powershell
Get-CimInstance Win32_Service | Select-Object Name,DisplayName,PathName,StartMode,State,StartName | Export-Csv services.csv
```

Unsigned binaries under `ImagePath`, `ImagePath` values pointing into `C:\Users\`, `C:\ProgramData\`, `C:\Windows\Temp\`, or any world-writable path are all immediate escalations.

### Startup folders

Per-user: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`.
All-users: `%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup`.

LNK shortcuts with unusual targets, small executables, and script files (`.vbs`, `.js`, `.bat`, `.ps1`, `.hta`) dropped here autoexecute at logon. The low-tech nature of this location is exactly why it keeps working.

### WMI event subscription (T1546.003)

The single most frequently missed mechanism. A `__EventFilter` defines an event to watch (often a polling `__IntervalTimerInstruction` or a `Win32_ProcessStartTrace`), a `__EventConsumer` defines code to run (usually `CommandLineEventConsumer` with a command line, or `ActiveScriptEventConsumer` with inline VBScript / JScript), and a `__FilterToConsumerBinding` links them. Persistence survives reboot because the subscription is stored in the WMI repository.

```powershell
Get-CimInstance -Namespace root/subscription -ClassName __EventFilter
Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer
Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding
```

The WMI repository itself lives at `C:\Windows\System32\wbem\Repository\` — collect the whole directory for offline analysis. Relying on live WMI queries alone is risky because a sufficiently privileged implant can hide its own instances.

### COM hijacking (T1546.015)

Windows resolves a CLSID by looking under `HKCU\Software\Classes\CLSID\<guid>` before `HKLM\Software\Classes\CLSID\<guid>`. An attacker who writes a matching CLSID under the user hive with a replacement `InprocServer32` or `LocalServer32` value intercepts every load of that COM object by that user — without needing admin rights. Frequently abused CLSIDs are those loaded by Explorer, task scheduler, and the default shell.

```cmd
reg query "HKCU\Software\Classes\CLSID" /s /f "InprocServer32"
```

Diff the user-hive CLSID tree against `HKLM\Software\Classes\CLSID` — any CLSID that exists under `HKCU` but also under `HKLM` is a hijack candidate. Pay special attention to `TreatAs` and `ProgID` indirections that chain to another hijacked key.

### AppInit_DLLs, LSA plugins, Netsh helpers, shim databases

- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` and `LoadAppInit_DLLs` — load listed DLLs into every user32-linked process. Disabled by default on modern Windows with Secure Boot but still enumerate it.
- `HKLM\System\CurrentControlSet\Control\Lsa\Security Packages`, `Authentication Packages`, `Notification Packages` — DLLs loaded into `lsass.exe` at boot (T1547.002, T1556.002).
- `HKLM\Software\Microsoft\Netsh` — helper DLLs loaded when `netsh.exe` runs (T1546.007).
- Application Compatibility shim databases (`.sdb` files) registered under `HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB` and `\Custom` — shims can inject DLLs or redirect execution (T1546.011).

### DLL search-order and side-loading (T1574.001, T1574.002)

Not a registry artifact — a filesystem one. A signed application searches for a DLL in a deterministic order (application directory first on most configurations), and an attacker who writes a malicious DLL alongside the signed binary wins the search. Common targets are applications that ship in writable user-profile directories. Enumeration means hashing every DLL sitting next to every signed executable and comparing to Microsoft catalog or known-good sources. This is where file-baselining tools and PE-Sieve-style scans pay off.

### Port monitors and print processors

- Print monitors: `HKLM\System\CurrentControlSet\Control\Print\Monitors\<name>\Driver` — loaded by the spooler (`spoolsv.exe`) as SYSTEM (T1547.010).
- Print processors: `HKLM\System\CurrentControlSet\Control\Print\Environments\<env>\Print Processors\<name>\Driver` — same idea, same process.

The spooler service's SYSTEM context makes both a high-value target; PrintNightmare aftermath showed how durable this surface is.

### BITS jobs

Background Intelligent Transfer Service jobs can be configured with `SetNotifyCmdLine` to run a command on transfer completion. A BITS job with a transfer that never completes — or completes on a timer — fires the command on every boot.

```cmd
bitsadmin /list /allusers /verbose
```

### Office add-ins and Outlook rules

- Office COM add-ins: `HKCU\Software\Microsoft\Office\<app>\Addins\<name>` and the equivalent under `HKLM`.
- Office VSTO add-ins in `%APPDATA%\Microsoft\AddIns`.
- Office template files (`Normal.dotm`, `PERSONAL.xlsb`) containing auto-execute macros.
- Outlook rules that run a script or start an application on message arrival (T1137.005). Rules are stored server-side in Exchange for most accounts — must be enumerated via MAPI or EWS, not purely from the client.

## Audit order

Collect wide before deleting narrow. The order below minimises the risk that a delete operation destroys evidence pointing at a second mechanism.

1. Full live Autoruns-style inventory (all locations above) exported to CSV on external media.
2. Offline copies of the relevant registry hives: `SYSTEM`, `SOFTWARE`, each user `NTUSER.DAT` and `UsrClass.dat`, plus the corresponding `.LOG1`/`.LOG2` transaction logs. VSS or raw-disk access required because live hives are locked.
3. Full copy of `C:\Windows\System32\Tasks\` (the XML files) and the WMI repository at `C:\Windows\System32\wbem\Repository\`.
4. `winevt\Logs\` — at minimum `Security.evtx`, `System.evtx`, `Microsoft-Windows-TaskScheduler%4Operational.evtx`, `Microsoft-Windows-WMI-Activity%4Operational.evtx`, `Microsoft-Windows-Sysmon%4Operational.evtx` if present.
5. Hash and log every artifact as it is collected.

## Removal sequencing

The correct order is disable, audit, delete, rotate — not the reverse.

**Disable first.** Set the suspect service to `Disabled`, flip the scheduled task to `Disabled`, delete the registry value (but keep the value's original contents recorded), unbind the WMI filter from its consumer without deleting either object. Disabling is reversible and preserves the artifact for analysis; deletion destroys evidence.

**Audit the running system.** After disabling, reboot into a known-good state (or re-image a throwaway copy of the disk) and enumerate persistence again. Anything still firing is a mechanism you missed.

**Delete only after a second inventory pass confirms the list is complete.** Delete the registry value, remove the service, remove the task XML, delete the WMI filter/consumer/binding objects, remove the dropped binary, quarantine a hashed copy for the case file.

**Rotate credentials last.** Any password, Kerberos ticket, service account credential, API token, SSH key, or certificate that was resident on a compromised host must be treated as known to the attacker. Rotation before removal is a mistake because the attacker may still have a live persistence mechanism that re-harvests the new credentials the moment they are set.

## Verification

Verification is a differential exercise. A single pass of "I ran autoruns-like enumeration, nothing looked bad" is not sufficient.

- Compare the post-cleanup inventory CSV against a pre-incident baseline from a clean peer host (same build, same GPOs, same line-of-business software). Anything in the post-cleanup inventory but not in the baseline is a survivor candidate.
- Take a second memory image after reboot and run `windows.pslist.PsList`, `windows.cmdline.CmdLine`, `windows.malfind.Malfind`, and `windows.svcscan.SvcScan` against it. Compare running processes and services to the clean baseline.
- Re-run the full live inventory a second time, 24 hours later, to catch mechanisms that trigger only on specific events (scheduled monthly, on network connect, on idle).
- Confirm that no outbound network connections go to known attacker infrastructure. Cross-reference firewall egress logs against the original IOC set.
- Watch the relevant event logs: TaskScheduler `106` (task registered), `140` (task updated), `141` (task deleted); Security `4697` (service installed), `4698`-`4702` (task created/updated/deleted); WMI-Activity `5860`-`5861` (permanent subscription created) during the observation window.

A host is only clean when two consecutive inventories separated by a reboot and at least one business-day cycle produce zero deltas.

## MITRE ATT&CK mapping

- **T1547 — Boot or Logon Autostart Execution** (parent). Covers the whole Run / RunOnce / Winlogon family.
- **T1547.001 — Registry Run Keys / Startup Folder.** The classic.
- **T1053 — Scheduled Task/Job** (parent).
- **T1053.005 — Scheduled Task.** Windows-specific, schtasks / Task Scheduler.
- **T1543 — Create or Modify System Process** (parent).
- **T1543.003 — Windows Service.** New or tampered services, `ServiceDll` hijacks.
- **T1546 — Event Triggered Execution** (parent). Covers WMI subscription (`.003`), shim databases (`.011`), IFEO debugger (`.012`), Netsh helper (`.007`), COM hijack (`.015`).
- **T1574 — Hijack Execution Flow** (parent). Covers DLL search-order hijack (`.001`) and DLL side-loading (`.002`).

Case notes should carry the specific subtechnique IDs, not just the parent, because eradication steps differ between sub-techniques.

## Common operator mistakes

Quarantining the encryptor `.exe` in antivirus without disabling the scheduled task that re-downloads it. The file comes back within the task's next fire window; the responder sees the antivirus alert again and concludes the "malware is persistent" without ever looking at the task definition.

Deleting a Run-key value without exporting it first. The contents of the value were the only pointer to the attacker's secondary staging URL, and it is now gone from the evidence record.

Missing WMI subscriptions because the response toolkit did not query the `root\subscription` namespace. The subscription survives every reboot, triggers on the next `Win32_ProcessStartTrace` matching a polling interval, and re-establishes C2 from a clean-looking host.

Cleaning the Run key but not the matching Image File Execution Options debugger. The attacker parked a second channel specifically so a one-place cleanup would fail.

Removing a scheduled task via `schtasks /delete` but leaving the cached XML file under `C:\Windows\System32\Tasks\<name>`, where some older Windows builds will re-register it on service restart.

Deleting the suspicious service key but leaving the `ServiceDll` file on disk — a later attacker run with a new service-install primitive points at the same DLL.

Deleting a shim database registration but not the `.sdb` file itself; re-registration is a one-line attack.

Forgetting that `HKCU` persistence runs only when that user logs in — the attacker plants in a rarely-used account (service account, local helpdesk account, disabled domain account that is still provisioned) knowing the responder only checked the interactive user's hive.

Removing persistence from the original patient-zero host but not from the other hosts the attacker pivoted to. Lateral persistence is the point of lateral movement.

## Handoff to offline analysis

### plaso / log2timeline

Relevant parsers to enable against the collected registry hives, event logs, and filesystem artifacts:

- `winreg/windows_run` — Run and RunOnce values.
- `winreg/windows_services` — service entries.
- `winreg/windows_task_cache` — Task Scheduler registry tree.
- `winreg/userassist` — recent user-launched programs (corroboration, not persistence itself).
- `winreg/windows_shell_items` and `bagmru` — user activity around dropped binaries.
- `winevtx` — all event log files in one pass.
- `chrome_history`, `firefox_history`, `msie_webcache` if the initial access vector was browser-based and feeds back into the persistence chain.

```bash
log2timeline.py --parsers "winreg,winevtx,filestat,prefetch,amcache" --storage-file case.plaso evidence/
psort.py -o l2tcsv -w persistence_timeline.csv case.plaso "date > '2026-04-01' AND date < '2026-04-19'"
```

### volatility3 plugins

Against the memory image, the persistence-relevant plugin set is:

- `windows.svcscan.SvcScan` — services from memory, including hidden or rootkit-filtered entries that `sc query` missed.
- `windows.registry.hivescan.HiveScan` and `windows.registry.printkey.PrintKey` — dump Run, RunOnce, Services, IFEO, Winlogon keys directly from in-memory hives.
- `windows.registry.userassist.UserAssist` — user program execution corroboration.
- `windows.callbacks.Callbacks` — kernel-level persistence via registered callbacks.
- `windows.driverscan.DriverScan` and `windows.modules.Modules` — kernel driver persistence.
- `windows.getsids.GetSIDs` — process SID context for the persistence payload at runtime.
- `windows.pstree.PsTree` — confirm the persistence mechanism actually produced the suspect process tree at the observed time.

### YARA against registry and WMI

YARA can be run directly against raw registry hive files and against the WMI repository files (`OBJECTS.DATA`). Useful rule patterns for a persistence sweep:

- Base64-encoded PowerShell (`-enc`, `-EncodedCommand`, `FromBase64String`) inside any value content.
- `System.Management.Automation` or `System.Reflection.Assembly.Load` inside WMI `CommandLineTemplate` or `ScriptText` fields.
- IP-address-shaped strings and Tor `.onion` strings inside registry binary values.
- Known-bad file hashes as reference points for `ImagePath` and `ServiceDll` values.

```bash
yara -r persistence_rules.yar ./hives/
yara -r persistence_rules.yar ./wbem_repository/OBJECTS.DATA
```

### hayabusa

For the event-log side, hayabusa applies a sigma-rule corpus across the collected `.evtx` files and produces a ranked timeline of persistence-relevant events (service installs, task registrations, WMI subscription creations, PowerShell script-block logging hits).

```bash
hayabusa csv-timeline -d evtx_directory/ -o persistence_events.csv
```

The output CSV is imported into the case timeline alongside the plaso super-timeline; correlation between a persistence event and the corresponding file-creation or process-start event is typically what pins the exact mechanism.

## References

- MITRE ATT&CK technique pages for T1547, T1547.001, T1053, T1053.005, T1543, T1543.003, T1546 (and sub-techniques), and T1574.
- NIST SP 800-61 Rev. 2, Computer Security Incident Handling Guide — eradication and recovery phases.
- NIST SP 800-83, Guide to Malware Incident Prevention and Handling for Desktops and Laptops.
