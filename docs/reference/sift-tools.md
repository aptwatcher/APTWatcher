# Reference: SIFT tools

> The SIFT Workstation tools APTWatcher wraps, the minimum versions
> expected, the profiles that require each, and the spoliation posture.

APTWatcher does not re-implement forensic primitives. It wraps SIFT's
existing tools behind typed MCP calls and adds discipline (profile
checks, audit records, output normalization). Everything below must be
present on the SIFT VM for the relevant profile to preflight clean.

## Expectations

- **SIFT Workstation** >= 2024.2. Earlier builds may work; they are not
  tested.
- **Freshness**: if the SIFT distribution is >90 days old, `preflight()`
  warns. If YARA rules are >30 days old, `preflight()` warns. Neither
  warning is fatal; staleness is a signal, not a block.
- **Updates are consent-gated.** APTWatcher never runs `sift update`
  mid-incident without operator approval. See
  [Tier 0 SIFT lifecycle](../design/tier0-sift-lifecycle.md).

## The tool inventory

| Tool                  | Min version      | Wrapped by                | Profiles                                        | Spoliation  |
|-----------------------|------------------|---------------------------|-------------------------------------------------|-------------|
| `volatility3`         | 2.4              | `volatility_run`          | windows-host-triage, linux-host-triage, memory-only | read_only |
| `log2timeline.py`     | 20240504         | `plaso_timeline`          | windows-host-triage, linux-host-triage, timeline-only | read_only |
| `psort.py`            | 20240504         | `plaso_timeline` (post-process) | timeline-only                             | read_only   |
| `bulk_extractor`      | 2.0              | `bulk_extractor_run`      | all host/memory/network profiles                | read_only   |
| `yara`                | 4.3              | `yara_scan`               | all profiles                                    | read_only   |
| `RegRipper`           | 4.0              | `registry_parse`          | windows-host-triage                             | read_only   |
| `evtx_dump`           | 0.8              | inline (timeline build)   | windows-host-triage, timeline-only              | read_only   |
| `chkrootkit`          | 0.58             | inline (persistence sweep) | linux-host-triage                              | read_only   |
| `chainsaw`            | 2.8              | `run_chainsaw_hunt`, `run_chainsaw_search` | timeline-only                  | read_only   |
| `hayabusa`            | 2.17             | `run_hayabusa_timeline`, `run_hayabusa_logon_summary` | timeline-only       | read_only   |
| `sleuthkit` (`mmls`, `fsstat`, `fls`, `icat`) | 4.12 | `run_mmls`, `run_fsstat`, `run_fls`, `run_icat` | windows-host-triage, linux-host-triage | read_only |
| `timesketch_importer` | 20240101         | `run_timesketch_query`, `run_timesketch_upload` | timeline-only                  | read_only on local source; server is state-changing |
| `zeek`                | 6.0              | `pcap_protocol_breakdown` | network-artifact                                | read_only   |
| `tshark`              | 4.0              | `pcap_protocol_breakdown` (fallback) | network-artifact                    | read_only   |
| `suricata`            | 7.0              | optional (alert replay)   | network-artifact                                | read_only   |
| `rita`                | 5.x              | optional (beaconing)      | network-artifact                                | read_only   |

Version numbers are **minimums**. `preflight()` accepts anything equal or
greater. A major upstream break resets the minimum and is recorded in the
project changelog.

## Implemented wrappers

The general conventions below describe the **target** shape; the commits
land one tool at a time. Status as of 2026-04-20:

| Wrapper             | Module                            | Status      |
|---------------------|-----------------------------------|-------------|
| `run_volatility`    | `core.sift.volatility`            | shipped     |
| `run_log2timeline` / `run_psort` | `core.sift.plaso`    | shipped     |
| `run_bulk_extractor`| `core.sift.bulk_extractor`        | shipped     |
| `run_yara_scan`     | `core.sift.yara_scan`             | shipped     |
| `run_regripper_plugin` / `run_regripper_profile` | `core.sift.regripper` | shipped |
| `run_chainsaw_hunt` / `run_chainsaw_search` | `core.sift.chainsaw` | shipped |
| `run_hayabusa_timeline` / `run_hayabusa_logon_summary` | `core.sift.hayabusa` | shipped |
| `run_mmls` / `run_fsstat` / `run_fls` / `run_icat` | `core.sift.sleuthkit` | shipped |
| `run_timesketch_query` / `run_timesketch_upload` | `core.sift.timesketch` | shipped (upload consent-gated) |
| `run_sift_update`   | `core.sift.update`                | shipped (consent-gated) |
| `pcap_protocol_breakdown` | `core.sift.zeek` (nyt)      | planned     |

### Volatility3 plugin allow-list

The vol3 wrapper runs only the plugins below. The list is conservative by
design — any plugin added must be reviewed for read-only semantics and
bounded output before the commit lands.

| Plugin                              | Purpose                                     |
|-------------------------------------|---------------------------------------------|
| `windows.pslist.PsList`             | Process list from `PsActiveProcessHead`     |
| `windows.pstree.PsTree`             | Parent/child process tree                   |
| `windows.cmdline.CmdLine`           | Per-process command-line recovery           |
| `windows.netscan.NetScan`           | TCP/UDP endpoint scan                       |
| `windows.dlllist.DllList`           | Loaded DLL enumeration                      |
| `windows.malfind.Malfind`           | Suspected injected-code regions             |
| `windows.svcscan.SvcScan`           | Service enumeration                         |
| `windows.registry.hivelist.HiveList`| Registry hive enumeration                   |
| `linux.pslist.PsList`               | Linux task list                             |
| `linux.bash.Bash`                   | Bash-history recovery from memory           |

The live source of truth is `VOLATILITY_PLUGINS` in
`src/core/sift/volatility.py`; this table must track it.

## Wrapper conventions

Each wrapper follows a common shape:

1. **Input validation** — arguments checked against the tool's own
   argument schema before the subprocess runs.
2. **Sandboxed invocation** — tool is invoked as a subprocess with a
   constrained cwd (typically the evidence mount) and explicit argv. No
   shell interpolation.
3. **Audit record** — `audit_append()` entry with:
   - Tool name + version
   - Arguments (full)
   - Target artifact hash (for evidence-integrity proofs)
   - Start / end timestamps
   - Exit code
   - Output hash
4. **Structured output** — stdout parsed into a schema the LLM can reason
   about. Raw stdout is preserved in the audit log.
5. **Error surfacing** — non-zero exit codes are surfaced verbatim to the
   LLM with a recommendation (retry, escalate, skip).

## Spoliation risk notes

Every wrapper inherits the spoliation risk of the underlying tool. All
the tools above are read-only when invoked with read-only mount options.
APTWatcher enforces read-only mounts in its wrappers:

- **Volatility**: reads the memory image; never writes.
- **log2timeline / psort**: outputs `.plaso` + JSONL to a designated
  *output* directory, never to the evidence directory. The evidence
  mount itself is not modified.
- **bulk_extractor**: outputs to a dedicated directory; input is opened
  read-only.
- **RegRipper**: reads hives; never modifies.
- **yara**: read-only.
- **zeek / tshark / suricata**: read PCAP input; outputs go to a separate
  working directory.

If any wrapper ever needs to operate on a writable mount (e.g., for
bulk_extractor output that must live on the evidence volume for space
reasons), that wrapper's spoliation risk escalates to
`state_changing_operational` and the preflight warns explicitly.

## Failure-mode catalog

| Condition                                       | Wrapper response                                  |
|-------------------------------------------------|---------------------------------------------------|
| Tool not found at preflight                     | Profile aborts with a clear message               |
| Tool present but version < minimum              | Warning at preflight; run proceeds; report notes  |
| Tool produces malformed output                  | Wrapper surfaces the stderr verbatim to the LLM   |
| Tool crashes mid-run                            | Exit code captured; the agent decides continuation|
| Wrapper times out (per-tool default: 30 min)    | Subprocess killed; audit entry marks truncation   |

Timeouts are deliberately generous. Killing a slow plaso run to save
wall-clock time corrupts the super-timeline and propagates errors
silently into every later finding.

## Related

- [MCP tools reference](mcp-tools.md) — the typed calls these wrappers
  implement
- [Use cases](../use-cases/README.md) — which profile requires which
  subset of this inventory
- [Tier 0 SIFT lifecycle](../design/tier0-sift-lifecycle.md) — update
  policy and freshness checks
