---
id: kb-mem-inj-hollowing-001
title: "Process hollowing and injected code — memory-image indicators"
source_type: author-original
attribution: "APTWatcher team (clean-room)"
mitre_techniques:
  - T1055.012
  - T1055.002
  - T1055
artifact_types:
  - memory_image
tools:
  - volatility3
  - yara
last_updated: "2026-04-19"
---

## What process hollowing is

Process hollowing (T1055.012) is an injection pattern in which the
attacker spawns a trusted image — typically something like
`svchost.exe`, `explorer.exe`, or a signed third-party binary — with
`CREATE_SUSPENDED`, then calls `NtUnmapViewOfSection` against the
newly created process to remove the legitimate image mapping at the
original image base. The attacker writes a replacement PE at that
same base, fixes up the thread context so `RIP`/`EIP` points at the
new entrypoint, and calls `ResumeThread`. From the outside the
process name and PID look ordinary; the code executing inside is not
the on-disk binary.

Two close relatives surface similarly in a memory image:

- **PE injection (T1055.002)** — attacker writes a full PE into a
  remote process but at an allocated private region (not the original
  image base). The original image stays mapped; the injected PE runs
  alongside it.
- **Reflective DLL injection** — a loader shellcode inside the target
  process maps a DLL from a memory buffer without ever calling
  `LoadLibrary`, so the DLL never appears in the module list.

All three produce the same high-level artifact: executable bytes
inside a process that do not correspond to a file-backed, loader-
registered module.

## How to detect it

This is a volatility3-centric workflow. Start wide, narrow per
process.

- `windows.pslist.PsList` — enumerate processes; flag unexpected
  parent PIDs, multiple instances of singletons (`lsass.exe`,
  `services.exe`), processes started from non-standard paths.
- `windows.pstree.PsTree` — visualise parent-child chains. A
  `winword.exe -> powershell.exe -> svchost.exe` tree is almost
  always hostile.
- `windows.cmdline.CmdLine` — the in-memory command line is taken
  from PEB and can diverge from what an EDR captured at launch;
  empty or mismatched command lines for signed binaries are
  suspicious.
- `windows.dlllist.DllList` — for a target PID, list loaded modules.
  The main module's full path should match the on-disk image the
  attacker claimed to be running. A hollowed process often shows a
  main-module path that does not match the bytes actually at the
  image base.
- `windows.malfind.Malfind` — the primary scanner. It walks the VAD
  tree looking for private, committed regions marked
  `PAGE_EXECUTE_READWRITE` (or `PAGE_EXECUTE_WRITECOPY` with no file
  backing) and dumps the first bytes. A hit where the first two
  bytes are `MZ` (`4D 5A`) is an unmapped PE sitting in a private
  region — a strong hollowing/PE-injection indicator.

Indicator table:

| Indicator                                      | Plugin                         | What a hit looks like                                                                 |
|------------------------------------------------|--------------------------------|---------------------------------------------------------------------------------------|
| RWX private VAD with executable bytes          | `windows.malfind.Malfind`      | VAD range + `PAGE_EXECUTE_READWRITE` + hex dump starting with shellcode or `4D 5A`    |
| Main module path disagrees with image base     | `windows.dlllist.DllList`      | Entry at PEB `ImageBaseAddress` whose `FullDllName` is blank or points elsewhere      |
| Anomalous parent                               | `windows.pstree.PsTree`        | `svchost.exe` whose parent is not `services.exe`; Office app spawning a system binary |
| Missing / tampered command line                | `windows.cmdline.CmdLine`      | PEB `ProcessParameters.CommandLine` empty for a process that should have arguments    |
| Unloaded main image, only shellcode present    | `windows.malfind.Malfind`      | No MZ at the reported image base; executable private region elsewhere in the VAD     |

When a malfind hit extracts bytes, chain a YARA scan (`yara` run
against the dumped region or the full memory image) against the
rule set shipped with the profile to identify known loaders or
implants.

## What APTWatcher records

A hollowing/injection finding produces these numbered citations:

1. The volatility3 `correlation_id` for the analysis run plus the
   plugin that fired (for example
   `plugin=windows.malfind.Malfind`,
   `correlation_id=vol3-<uuid>`).
2. Process identity: `PID`, `ProcessName`, `PPID`, parent name,
   session ID, and the image path reported by dlllist.
3. Suspicious VAD range: start address, end address, protection
   flags (e.g. `PAGE_EXECUTE_READWRITE`), and whether the region is
   private or file-backed.
4. If malfind extracted PE magic bytes (`4D 5A`) from a private
   region, the record notes `pe_in_private_region=true` and the
   first 64 bytes as hex.
5. Any chained YARA hits: rule name, rule namespace, offset inside
   the dumped region, and the scan job ID.
6. Cross-references to `windows.pstree.PsTree` output if the parent-
   child relationship is itself anomalous.

## Confidence calibration and pitfalls

Malfind alone is noisy. The highest-volume false positives come
from legitimate just-in-time compilers:

- **.NET CLR** allocates RWX regions for NGEN-less jitted code in
  almost every managed process.
- **V8** (Chrome, Edge, Node, Electron apps) writes RWX pages for
  jitted JavaScript — a Chrome memory image can produce dozens of
  malfind hits with zero malice.
- **Java HotSpot** and other JVMs behave the same way for bytecode
  compilation.
- Some anti-cheat, DRM, and EDR products deliberately inject into
  user processes.

Policy in APTWatcher: a lone malfind hit is recorded as
`consistent with injection`, never `confirmed by`. Promotion to
higher confidence requires at least one corroborator:

- An anomalous parent-child relationship from `PsTree` (Office or
  browser spawning a system binary).
- A dlllist disagreement between the PEB image base and the main-
  module on-disk path.
- A YARA rule hit on attacker tooling inside the flagged region.
- PE magic bytes in a private, non-file-backed region of a process
  that should not be jitting code (e.g. `lsass.exe`, `services.exe`,
  `spoolsv.exe`).

A hit inside a JIT-heavy process (`chrome.exe`, `msedge.exe`,
`Code.exe`, `powershell.exe` with loaded CLR, `java.exe`) without
any of the corroborators above is downgraded and annotated
`likely_jit=true` so the triage operator sees why confidence was
capped.
