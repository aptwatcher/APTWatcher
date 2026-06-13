---
id: kb-proc-memory-triage-live-001
title: "Live-response memory triage — capture, validate, handoff"
source_type: author-original
attribution: "APTWatcher team (clean-room)"
mitre_techniques:
  - T1055
  - T1055.002
  - T1055.012
  - T1003.001
  - T1620
  - T1027
  - T1140
artifact_types:
  - live_host
  - memory_image
tools:
  - volatility3
  - yara
  - bulk_extractor
last_updated: "2026-04-19"
---

## Why memory first

Live-response collection is governed by the order-of-volatility principle codified in RFC 3227: the most volatile data must be captured first, because every subsequent action destroys some of it. Physical memory sits at the top of that order. A running system holds, in RAM, information that either does not exist on disk at all or exists only in a degraded form: decrypted executable pages for packed or obfuscated binaries, in-process injected modules that were never file-backed, unlinked kernel structures, network sockets in the `ESTABLISHED` state, the current thread list of every process, cached credentials inside `lsass.exe`, kernel handle tables, and the cleartext of any key material that the attacker needed the CPU to operate on.

Shutdown destroys almost all of it. A graceful shutdown flushes handles, rotates a subset of event logs, tears down network connections, and gives usermode malware the chance to run cleanup routines registered on `WM_ENDSESSION` or through `SetConsoleCtrlHandler`. A hard power-off preserves the pagefile and the hibernation file in a more faithful state but still erases RAM. Either way, the volatile evidence window closes the moment power is interrupted.

What disk preserves across reboot is comparatively static: registry hives, event logs, Prefetch, the MFT, amcache, SRUM, ShimCache snapshots at shutdown, the pagefile, and `hiberfil.sys`. Disk is the base layer of the timeline. RAM is the layer that disappears. Capture RAM first.

## Pre-capture decisions

Three decisions need to be made before the acquisition command runs.

**Acquisition tool family.** Pick a tool appropriate to the operating system and kernel version of the target. On Windows, the common families are kernel-driver-backed DMA-like acquisition tools (winpmem-family, DumpIt-family, Magnet RAM Capture-family, FTK Imager Lite). Each loads a signed kernel driver, walks the physical memory map exposed by the HAL, and streams pages to a file. On Linux, the LiME loadable kernel module is the historical standard and requires a module compiled against the exact running kernel; AVML is a precompiled alternative that avoids the per-kernel build step. On macOS, the options have narrowed substantially with SIP and the removal of third-party kexts; current practice is vendor tooling or virtualization-based capture for supported hypervisor environments. The family-level choice matters more than the brand: use whichever tool is supported, signed on the target platform, and familiar to the responder.

**Output format.** Three formats dominate. The raw physical memory dump (`.raw`, `.mem`, `.bin`) is a byte-for-byte linear map of physical RAM and is the most broadly supported input across analysis frameworks. The LiME format wraps raw pages in a small header-per-region scheme, preserves the physical memory map for sparse regions, and is the Linux default. Windows crash-dump format (`.dmp`, specifically full kernel memory dumps) is convertible and debuggable with WinDbg but is not always the best input for volatility3. Default to raw on Windows and LiME on Linux unless the analysis toolchain requires otherwise.

**Compression.** A 64 GB image compresses well, often to a third of its raw size, but compression changes the hash. The rule is: hash the raw image first, record the SHA-256, then compress. The archive also gets a hash, recorded separately. Never compress before hashing and never rely on the compressed-archive hash as the integrity anchor for the raw image.

## Chain of custody

Treat the acquisition as potential legal evidence from the first byte. Minimum fields recorded per image:

- Source host name, FQDN, and MAC address
- Collector identity and, where policy requires, a witness identity
- Acquisition tool name and version
- Start and end timestamps in UTC
- Target output path and container (external SSD, write-blocked USB, network share)
- SHA-256 of the raw image, computed immediately after the tool exits
- SHA-256 of any compressed archive, computed separately

```powershell
# Windows — hash immediately after capture, on the collection host
Get-FileHash -Algorithm SHA256 E:\ir\host01\memory.raw | Format-List
```

```bash
# Linux / macOS — same principle
sha256sum /mnt/ir/host01/memory.lime
```

The manifest entry for the image is appended to a per-case CSV or JSON file before the media is transferred. Transfer means physical hand-off, courier, or a signed upload to an evidence bucket — every transfer adds a row.

## Validation before analysis

Never start deep triage on an image that has not been validated. An image that failed mid-capture, was truncated by a full destination volume, or was corrupted in transfer will produce plausible-looking but wrong output.

The first volatility3 invocation confirms three things: the image is readable, the OS profile auto-detects, and the page tables parse.

```bash
# Confirm image integrity and profile detection
vol -f memory.raw windows.info
# Equivalent on Linux and macOS images
vol -f memory.lime linux.info
vol -f memory.mem mac.info
```

A clean `windows.info` output reports the kernel build, the DTB (Directory Table Base), the number of processors, and the system time at capture. If the DTB cannot be located, or if `vol` reports that the kernel symbol file does not match, the image is either corrupt or built on a kernel version that lacks a symbol pack. A corrupt image goes back to the collector for re-capture. A missing-symbols image gets the appropriate ISF / symbol pack generated or downloaded before proceeding.

Check that the system time reported by `windows.info` matches the expected collection window. A clock skew larger than a few seconds versus the incident timeline should be recorded — it will shift every subsequent event correlation.

## Rapid triage — ten minutes

The goal of the first ten minutes of analysis is to identify obvious evil without yet committing to deep carving. A small set of volatility3 plugins covers the highest-value checks.

**Process lists — three views.** Run `pslist`, `pstree`, and `psscan` and compare.

```bash
vol -f memory.raw windows.pslist.PsList > pslist.txt
vol -f memory.raw windows.pstree.PsTree > pstree.txt
vol -f memory.raw windows.psscan.PsScan > psscan.txt
```

`pslist` walks the active process links. `psscan` scans physical memory for `_EPROCESS` pool tags and finds processes even when they have been unlinked from the doubly-linked list (DKOM). A process that appears in `psscan` but not `pslist` is an unlinked-process hiding indicator and a very strong signal on its own. `pstree` gives the parent-child view that catches anomalous lineages (`winword.exe -> powershell.exe -> rundll32.exe`, `services.exe` with an unexpected child, a `lsass.exe` with a parent that is not `wininit.exe`).

**Injected code — malfind.** Scan the VAD tree for private, committed, executable regions.

```bash
vol -f memory.raw windows.malfind.Malfind > malfind.txt
vol -f memory.raw windows.malfind.Malfind --pid 4820 --dump
```

A hit whose first bytes are `4D 5A` (`MZ`) inside a private region indicates a PE that is not loader-registered. Hits in JIT-heavy processes (Chrome, Edge, Code.exe, java.exe, PowerShell with CLR) are frequently benign; hits inside `lsass.exe`, `services.exe`, `svchost.exe`, `spoolsv.exe`, or a signed third-party service process are almost never benign.

**Network state — netscan.**

```bash
vol -f memory.raw windows.netscan.NetScan > netscan.txt
```

Look for unexpected listeners on high ports, outbound connections to non-RFC1918 destinations on ports 443/80/8080/53, and any connection owned by a process that should not be talking to the network (for example `notepad.exe` or `calc.exe` with an `ESTABLISHED` socket).

**Command lines.**

```bash
vol -f memory.raw windows.cmdline.CmdLine > cmdline.txt
```

A hollowed process typically has an empty or mismatched `CommandLine` in the PEB. A legitimate signed binary with no arguments where arguments are expected is suspicious. Obfuscated PowerShell (`-enc`, `-nop -w hidden -c`, base64 payloads) is high-signal for T1027 / T1140.

**Loaded DLLs.**

```bash
vol -f memory.raw windows.dlllist.DllList --pid 4820 > dlllist_4820.txt
```

Flag modules loaded from `%TEMP%`, `%APPDATA%`, `C:\Users\Public\`, `C:\ProgramData\` (for non-installer processes), or from UNC paths. Unsigned modules inside signed system processes are a strong indicator.

**Services.**

```bash
vol -f memory.raw windows.svcscan.SvcScan > svcscan.txt
```

Look for services pointing at unsigned binaries, services with random-looking names, and services whose `ServiceDll` is a temp path.

**Handles — credential access.**

```bash
vol -f memory.raw windows.handles.Handles --pid <target> | Select-String "lsass"
```

A non-administrative process holding an open handle to `lsass.exe` with rights that include `PROCESS_VM_READ` is the canonical T1003.001 indicator. Also flag unexpected handles to `\Device\PhysicalMemory`, to security-product file paths, and to named pipes with attacker-toolkit patterns.

**YARA across the image.**

```bash
vol -f memory.raw yarascan.YaraScan --yara-rules /opt/rules/implants.yar > yara_hits.txt
```

A broad scan against a curated implant / loader / ransomware rule set is the highest-yield single operation in the ten-minute pass. Hits give both an offset and the containing process or kernel region.

## Deep triage — the next tier

Once rapid triage has identified candidates, deeper plugins carve the details.

- `windows.modscan.ModScan` and `windows.driverscan.DriverScan` enumerate kernel modules and driver objects via pool-tag scanning. A loaded driver that does not appear in the clean module list is a rootkit indicator (T1014).
- SSDT hook checks (`windows.ssdt.SSDT`) identify kernel call-table hooks — less common on modern Windows due to PatchGuard, but still seen on older builds and in targeted implants.
- `windows.ldrmodules.LdrModules` compares the three PEB loader lists (`InLoadOrder`, `InMemoryOrder`, `InInitializationOrder`). A module that is present in memory but missing from one or more of these lists is consistent with reflective DLL injection (T1055.001).
- `windows.memmap.MemMap` plus `windows.vadinfo.VadInfo` give page-level layout for targeted carving of specific VAD ranges when malfind reported a hit but did not auto-dump the full region.
- `windows.mftparser.MFTParser` extracts MFT entries that happened to be resident in memory at capture — useful when the disk is not available or when the live MFT on disk has since been modified.
- `windows.registry.hivelist.HiveList` and `windows.registry.printkey.PrintKey` read registry hives directly from memory, catching run keys, service definitions, and AppInit_DLLs as they appeared at capture.
- `windows.filescan.FileScan` pool-scans for `_FILE_OBJECT` structures, often surfacing files that have since been deleted.
- `windows.callbacks.Callbacks` enumerates kernel notification callbacks (process, thread, image-load). Anomalous callbacks registered by unsigned or orphan drivers are a persistence indicator and frequently accompany EDR tampering (T1562).
- `bulk_extractor` run directly against the raw memory image is a fast second pass that surfaces URLs, email addresses, credit-card regex hits, PGP blocks, and Base64-encoded blobs without needing to pre-carve per-process regions.

```bash
bulk_extractor -o mem_bulk/ memory.raw
```

Each plugin output is stored to its own file and referenced by filename and SHA-256 in the case manifest.

## Linux and macOS memory triage

The workflow carries over; only the plugin prefixes change.

On Linux, run `linux.pslist.PsList`, `linux.pstree.PsTree`, `linux.psaux.PsAux`, `linux.check_syscall.Check_syscall`, `linux.check_modules.Check_modules`, `linux.malfind.Malfind`, `linux.bash.Bash` (to recover bash history from memory), and `linux.sockstat.Sockstat`. Profile availability is the operational constraint: Linux memory analysis requires a symbol pack (ISF) built from the target kernel's `vmlinux` and `System.map`. When the victim kernel is custom or patched, the symbol pack must be generated from the exact running kernel before analysis is possible. Generate it from a matching debug image using `dwarf2json` or the vendored tooling in the volatility3 contrib tree.

On macOS, run `mac.pslist.PsList`, `mac.pstree.PsTree`, `mac.malfind.Malfind`, `mac.lsof.Lsof`, `mac.netstat.Netstat`, and `mac.check_syscall.Check_syscall`. macOS profile coverage lags behind Windows and Linux; always confirm profile availability for the exact kernel build before committing to a memory-first strategy. When no profile is available, fall back to live-response command output captured before the host is powered down.

## MITRE mapping

The plugin set above maps to a recurring cluster of techniques that the triage report should tag in its findings:

- T1055 (Process Injection) and its sub-techniques T1055.002 (Portable Executable Injection) and T1055.012 (Process Hollowing) — surfaced primarily by `malfind`, `ldrmodules`, and `vadinfo`.
- T1003.001 (LSASS Memory) — surfaced by `handles` hits against `lsass.exe` and by YARA rules matching common credential-dumper loaders.
- T1620 (Reflective Code Loading) — surfaced by `ldrmodules` loader-list disparities and by malfind hits with no corresponding on-disk image.
- T1027 (Obfuscated Files or Information) and T1140 (Deobfuscate/Decode Files or Information) — surfaced by `cmdline` hits on encoded PowerShell and by YARA rules that match common packer / encoder stubs inside RWX regions.

Tagging is recorded in the triage report JSON as an array of technique IDs attached to each finding, so downstream correlation can group findings across hosts and across time without re-running plugin heuristics.

## Handoff artifacts

The memory-triage output for a single host feeds the IncidentBundle evidence manifest as three coupled artifacts:

1. The raw memory image plus its SHA-256 and acquisition metadata (tool, version, timestamps, collector).
2. The triage report: a structured JSON document containing, per plugin, the invocation arguments, the output file path, the SHA-256 of the output file, and a summary block of any findings promoted by the analyst.
3. The provenance record: the chain-of-custody CSV/JSON rows for the image and every derivative artifact, including any dumped regions produced by `--dump` options.

These three together satisfy `IncidentBundle.evidence_manifest` and are what downstream timeline, YARA, and correlation jobs consume. Nothing in the memory workflow should write into the bundle without a SHA-256 and a provenance entry — the manifest is the integrity contract for everything the agent reports.

## Common operator mistakes

**Rebooting "to be safe."** A reboot erases RAM, flushes handles, rotates logs, and gives usermode malware a chance to run cleanup handlers. If the host has been compromised, reboot is the most expensive single action available. Network-isolate instead; capture memory; then decide whether to shut down.

**Capturing over the wire without integrity hashing.** Streaming a memory image over SMB or SCP to a collection server is acceptable when local storage is not available, but the raw image must be hashed on the destination before any further processing, and a second hash should be computed on the source side when feasible so that transfer corruption is detectable. Never treat "the file arrived" as equivalent to "the file is intact."

**Running AV or EDR scan on the live host before capture.** Scanners quarantine, rename, and sometimes delete suspicious files. They also allocate large working sets that can push evidence out of the pagefile. Acquire first, scan later.

**Writing the image to the system volume.** A 32 GB image written to `C:\` on a compromised host competes for I/O with any running encryption or wiper process, and risks triggering attacker logic that monitors disk free space. Always write to external or network-mounted media.

**Skipping validation.** Starting `malfind` on an image whose profile has not been confirmed produces outputs that look plausible but may be wrong. `windows.info` (or the Linux/macOS equivalent) is not optional.

**Acquiring without a witness or a manifest entry.** An image without a chain-of-custody row is not evidence, it is a file. The cost of recording one CSV row at capture time is negligible; the cost of reconstructing provenance later can be infinite.

**Mixing evidence and tooling on the same media.** Keep the acquisition toolkit on one volume (read-only where possible) and the collected evidence on a separate volume. Cross-contamination during incident response is a recurring source of bad chain-of-custody.

## References

- RFC 3227, Guidelines for Evidence Collection and Archiving
- NIST SP 800-86, Guide to Integrating Forensic Techniques into Incident Response
- Volatility 3 documentation, https://volatility3.readthedocs.io/
- MITRE ATT&CK technique pages for T1055, T1055.002, T1055.012, T1003.001, T1620, T1027, T1140
