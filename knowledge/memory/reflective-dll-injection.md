---
id: kb-mem-reflective-dll-001
title: "Reflective DLL injection triage in process memory"
source_type: author-original
attribution: "APTWatcher team (clean-room)"
mitre_techniques:
  - T1055.001
artifact_types:
  - memory_image
tools:
  - volatility3
last_updated: "2026-04-20"
---

## What reflective DLL loading bypasses

A normal DLL load on Windows goes through `LoadLibrary`, which walks
through the loader lock, maps the image, runs `DllMain`, and — crucial
for triage — links the new module into three doubly-linked lists
anchored in the PEB's `PEB_LDR_DATA`: `InLoadOrderModuleList`,
`InMemoryOrderModuleList`, and `InInitializationOrderModuleList`. Any
tool that enumerates loaded modules (`dlllist`, Process Explorer, EDR
telemetry) reads those lists.

Reflective loading is a technique in which shellcode running inside
the target process maps a DLL from a memory buffer on its own. It
parses the PE headers, allocates memory with `VirtualAlloc`, copies
sections, resolves imports, applies relocations, and calls the
DLL's entrypoint — all without touching `LoadLibrary`. Because the
loader never sees the module, it is absent from all three PEB lists.
The DLL is running, but the process claims, truthfully from the
loader's perspective, that it is not loaded.

## Volatility3 workflow

The triage chain is `malfind` first, then `ldrmodules` to confirm the
list gap, then `vadinfo` plus `memdump` to extract bytes for deeper
analysis.

`windows.malfind.Malfind` walks the VAD tree and flags private,
committed regions that are either `PAGE_EXECUTE_READWRITE` or
`PAGE_EXECUTE_WRITECOPY` with no file backing. A reflectively loaded
DLL almost always lives in such a region, and the first bytes of the
region will be `4D 5A` (`MZ`) followed by a valid PE header at the
usual offset. Malfind prints a hex dump that makes this trivial to
spot.

`windows.ldrmodules.LdrModules` compares the three PEB module lists
against the VAD tree. For each VAD-mapped image it reports three
boolean columns — `InLoad`, `InInit`, `InMem` — indicating which
lists reference that image. A mapped region whose bytes look like a
PE but which reports `False, False, False` across the three columns is
the canonical reflective-load signature: the loader has never heard
of it.

`windows.vadinfo.VadInfo` on the suspect PID gives the full VAD tree
with protection flags, region sizes, and backing file information.
Pick the VAD entries that correspond to the malfind hits and confirm
they are private (`Private Memory`) rather than file-backed. Dump the
bytes with `windows.vaddump.VadDump --pid <pid> --base <vad_base>`
and hand the dump to YARA.

A focused YARA pass over the dump usually decides the question. Run
the agent's standard implant rule set against the dumped region; a
named hit promotes the finding from "consistent with reflective
loading" to "identified loader family."

## False positives

Not every RWX private region with MZ bytes is hostile. Managed code
runtimes allocate RWX regions for jitted output as a matter of course:
`.NET` CLR does this in almost every managed process, V8 does it in
every Chromium-based process and in Node and Electron applications,
and Java HotSpot does it for jitted bytecode. These regions are often
large, often contain plausible-looking instruction streams, and
occasionally begin with byte sequences that trigger naive scanners.

The distinguishing feature of a reflective DLL is that the private
region starts with a real PE header at offset zero — `MZ`,
`PE\0\0` at the `e_lfanew` offset, a sane `SizeOfImage`, import table
entries that point at real Windows DLLs. A JIT region has none of
that; it is raw machine code with no PE wrapping. When in doubt, run
the dump through a PE parser before escalating.
