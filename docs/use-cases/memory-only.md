# Use case: Memory only

> You have a memory image and nothing else. This profile exists so the agent
> can produce an honest, bounded report from exactly that. It refuses to
> invent disk evidence that does not exist.

## When to use

- A live-response capture (DumpIt, `winpmem`, `LiME`, `AVML`, vSphere
  `.vmem`) is the only artifact.
- A compromised host is still live and the analyst wants a triage read
  before taking disk action.
- S03-style pre-detonation analysis where pausing the VM preserved memory
  but disk evidence is incomplete.

## Profile declaration

```yaml
profile: memory-only
required_tools:
  - volatility3 >= 2.4
  - yara
optional_tools:
  - bulk_extractor      # for carving strings/IoCs from memory
  - volshell            # interactive triage (manual use only)
artifact_categories:
  required:
    - memory_image
  optional:
    - process_list_snapshot  # e.g., a ps CSV captured alongside memory
    - network_state_snapshot # e.g., netstat CSV
tier_prerequisites:
  tier_1: optional
  tier_2: optional
  tier_3: gated_by_flag
```

## What the agent does under this profile

1. **Preflight** — Volatility symbol table must match the memory image's OS
   build. A mismatch aborts the run cleanly with a pointer to the symbol
   profile selection step. This is a common silent-failure mode elsewhere;
   here it is an explicit gate.
2. **Process tree.** `pslist`, `pstree`. Anomalies: parent/child mismatches
   (e.g., `cmd.exe` spawned by an unusual parent), orphaned processes,
   unlinked processes visible via `psxview`.
3. **Injection detection.** `malfind` for RWX regions with no disk-backed
   mapping; `ldrmodules` for unlinked DLLs; `hollowfind` for process
   hollowing.
4. **Network state.** `netscan` surfaces sockets and connections held open
   at capture time — including ones a live `netstat` may have missed.
5. **Command-line reconstruction.** `cmdline`, `consoles` (Windows).
6. **Credential material** in volatile state. The agent is configured **not
   to emit** plaintext credentials or hashes to the report; it emits the
   presence and location only. This is a privacy and evidence-handling
   discipline, not a technical limitation.
7. **Strings / IoC extraction** via `bulk_extractor` over the image.
   Extracted IPs, URLs, and file paths flow into `extract_iocs()` and, if
   Tier 1 is enabled, `check_ioc()`.
8. **Report** with explicit scope statement: *memory-only, no disk
   corroboration*. Every finding carries a confidence level reflecting that
   bounded evidence base.

## The cross-check discipline

Memory-only work is high-velocity but easy to get wrong. The agent applies
two fixed cross-checks:

- **Volatility vs. live snapshot.** If a running-process CSV or netstat
  export was captured alongside memory, the agent diffs them against
  Volatility output. Processes visible in memory but not the live snapshot
  are a rootkit signal; processes visible in the live snapshot but not
  memory are a capture-ordering or freshness issue.
- **Injection cross-reference.** A single plugin (`malfind`) claiming
  injection is not enough. The agent corroborates with `ldrmodules`,
  `handles`, and `cmdline` before calling injection confirmed.

## What it cannot do

- **Persistence enumeration** beyond what lives in memory. Scheduled tasks
  and registry run keys are not available here. The agent states this in
  the report rather than speculating.
- **Timeline correlation with disk events.** Without plaso-capable
  artifacts, the agent cannot anchor its findings to wall-clock except via
  timestamps already baked into memory structures (e.g., process creation
  times).
- **Deep file analysis.** Mapped files visible in memory are listed; the
  agent does not claim to have analyzed them.

## Failure modes

- **Symbol table missing**: aborts. Offered next step: run the
  Volatility symbol helper and re-try.
- **Image truncated / invalid**: aborts after preflight with the
  Volatility error surfaced verbatim.
- **OS version unsupported by installed Volatility**: aborts with a
  pointer to the update path (consent-gated per the SIFT lifecycle design).

## Scenario mapping

- [S03 — Ransomware pre-detonation](../scenarios/S03-ransomware-pre-detonation.md)
  runs primarily under this profile. The S03 rubric requires the injection
  call to be corroborated — the cross-check discipline above is how.

## Related

- [Windows host triage](windows-host-triage.md)
- [Linux host triage](linux-host-triage.md)
- [Evidence integrity](../architecture/evidence-integrity.md)
