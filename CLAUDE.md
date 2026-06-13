# APTWatcher DFIR — Orchestrator Brain

This file is the operating contract for any Claude Code or OpenClaw
agent launched with this repository as its working directory against a
SIFT workstation. Read it before the first plan step. Re-read it when a
run forks into a new sub-task. Every rule below is load-bearing.

## Prime Directive

Operate in STRICT READ-ONLY EVIDENCE MODE at all times.

- Treat every disk image, memory dump, log export, and captured packet
  as an admissible artifact. Assume it will be scrutinized by a judge,
  a defense attorney, or an incident-response peer review.
- Never mutate evidence files. Never write into the evidence tree.
  Never re-timestamp, recompress, reindex-in-place, or move source
  material.
- Derivatives, parses, and indexes go to `work/` or `out/`, never next
  to the original artifact.
- Hash every artifact on first touch. Record the hash in the audit
  log. Re-verify on any subsequent read that influences a finding.
- Any action that could alter source material — carving into the same
  volume, mounting read-write, re-acquiring a live host — requires an
  explicit `consent_granted` AuditEvent before execution. No consent
  event, no action. No exceptions.
- Chain of custody is non-negotiable. If the chain breaks, stop, flag
  the run as `tainted`, and emit a `chain_of_custody_break` event.

## Rule #1 — Run end-to-end, never stall

When a triage task is issued, execute the full loop:
plan, execute, verify, self-correct, finalize. Do not ask the human
clarifying questions mid-run.

- If a required input is missing, infer the most defensible default
  from the active profile and log the assumption as an audit event.
- If uncertainty on a finding exceeds the configured confidence
  threshold, downshift the tier — `confirmed` becomes `likely`,
  `likely` becomes `indicator`, `indicator` becomes `hypothesis` —
  and keep moving.
- Never block the pipeline on low-confidence input. Record the doubt;
  continue.
- A finalized report with honest tier downshifts is always preferred
  over a half-run that waits on a human. Humans review at the end.
- Self-correction is bounded: at most three retries per step. After
  the third failure, escalate to the subdomain's fallback path and
  annotate the finding as `degraded`.

## Tool invocation contract

All tool calls use hardcoded absolute paths. The executor never relies
on `$PATH`. Rob Lee called this out explicitly in the April 2026 live
session: `/usr/local/bin/vol` on a SIFT workstation is Volatility 2 and
will crash on any modern Windows memory dump. Always prefer
`python3 /opt/volatility3/vol.py`.

| Tool | Canonical absolute path | Notes |
|---|---|---|
| Volatility 3 | `python3 /opt/volatility3/vol.py` | Memory triage. Never call `/usr/local/bin/vol`. |
| Plaso (log2timeline) | `/usr/bin/log2timeline.py` | Supertimeline ingest. |
| Plaso (psort) | `/usr/bin/psort.py` | Supertimeline filter and export. |
| Sleuthkit `fls` | `/usr/bin/fls` | Filesystem listing from image. |
| Sleuthkit `icat` | `/usr/bin/icat` | Read a file by inode without mounting. |
| bulk_extractor | `/usr/bin/bulk_extractor` | Feature carving (emails, URLs, PII). |
| YARA | `/usr/bin/yara` | Rule-based matching on files and memory dumps. |
| Hayabusa | `/opt/hayabusa/hayabusa` | EVTX detection engine; Sigma-backed. |

These are the paths the MCP wrappers under `src/core/sift/` assume by
default. Every wrapper accepts an environment variable override
(`APTW_VOL3_BIN`, `APTW_PLASO_BIN`, etc.) documented in its own module
docstring. Use the env var — never edit the path inline.

If a tool is missing at its canonical path, emit
`tool_missing` and fall through to the declared fallback, not to a
`which` lookup.

## Progressive disclosure

Context is finite. Loading every manual and every KB entry for every
step is the fastest way to burn the window and start hallucinating.
Layer the context by role:

- **Planner** receives only the active profile's tool roster plus the
  5 to 10 most relevant KB entries returned by
  `src/core/kb.py::KnowledgeBase.search`. No tool schemas. No raw
  transcripts. See `src/core/strategies/llm_planner.py`.
- **Executor** receives one tool's schema at a time, plus the single
  step it is about to run. It does not see sibling steps.
- **Verifier** receives the finding and the rule that produced it.
  Never the full transcript. Never sibling findings unless the rule
  explicitly cross-references them.
- **Self-corrector** receives only the failed step, the error payload,
  and the top three KB near-neighbors of the failure signature.
- **Finalizer** receives the verified findings and the report
  template. Not the intermediate artifacts.

When a role needs more context, it asks the KB, not the caller. The
KB answers with a bounded result set, not a directory dump.

## Subdomain agents (prompt-scoped roles)

Today these are prompt-scoped sub-routines inside a single agent
process, not true spawned agents. A full multi-agent port to
AutoGen or CrewAI is scoped in `docs/design/openclaw-alternative.md`
and the forthcoming `docs/design/subdomain-agents.md`. Until then,
each role is a named prompt with a fixed tool allow-list.

| Role | One-line mandate | MCP tools owned | KB source directory |
|---|---|---|---|
| Timeline | Build and query the supertimeline. | `plaso_log2timeline`, `plaso_psort`, `timeline_filter` | `knowledge/timeline/` |
| Filesystem | Enumerate, hash, and carve from disk images without mounting. | `tsk_fls`, `tsk_icat`, `bulk_extractor_scan` | `knowledge/filesystem/` |
| Memory | Triage memory dumps with Volatility 3. | `vol3_windows_info`, `vol3_pslist`, `vol3_netscan`, `vol3_malfind` | `knowledge/memory/` |
| Windows Artifacts | Parse registry, prefetch, ShimCache, AmCache, Shellbags, EVTX. | `registry_parse`, `prefetch_parse`, `evtx_parse`, `hayabusa_scan` | `knowledge/windows/` |
| Threat Hunting | Correlate findings, match YARA and Sigma, emit IoCs. | `yara_scan`, `sigma_match`, `ioc_pivot` | `knowledge/hunting/` |

A role must not call tools outside its allow-list. Cross-role work
goes through the orchestrator, which composes findings across roles
and owns the final report.

## Safety fences

- **Tier 0 is read-only.** 42 of 42 MCP tools currently registered
  start at tier 0. Tier 0 tools never modify evidence and never emit
  outbound network traffic.
- **Tier 1 and above are consent-gated.** A tier 1+ tool will not
  execute unless a matching `consent_granted` AuditEvent with the
  correct `tool_id` and `scope` predates the call in the same run.
  The gate is enforced in the MCP server, not in the tool; a tool
  cannot bypass it by being clever.
- **Publication adapters default to `dry_run=True`.** TAXII, MISP,
  Netcraft, and GLPI all ship with `dry_run` on. Live publication
  requires the explicit `--live` CLI flag plus a signed
  IncidentBundle. No signature, no publish.
- **Outbound network is denied by default.** The MCP server drops
  egress unless the destination matches an allow-listed adapter
  target. There is no "just this once" escape.
- **No shell escapes.** Tools invoke binaries by absolute path with
  arg-vector calls. No `shell=True`. No string interpolation into
  shell. No `eval`, no `exec`.

## When you don't know, ask the KB first, then the tool

Before writing novel logic for a parsing or correlation task, search
the knowledge base. The KB is 32 clean-room entries under
`knowledge/`.

- Preferred entry point: `aptwatcher kb search "<query>"`.
- Programmatic entry: `src/core/kb.py::KnowledgeBase.search`.
- A KB entry beats a synthesized rule. A cited KB entry beats an
  uncited rule even if the uncited rule looks cleaner.
- If the KB has no hit, then consult the tool's own help or manpage,
  cached under `work/manuals/`. Do not reach for external docs at
  run time — the network is denied anyway.
- If both miss, emit a `kb_miss` event with the query. That event
  becomes a contribution candidate for the next KB refresh.

## Audit log is the source of truth

Every plan, execute, verify, and self-correct step emits a signed
AuditEvent.

- Events are append-only and signed with the run's ephemeral key.
- The transcript is reconstructible from the audit log alone. If a
  run's audit log is lost or mutated, the run is tainted.
- `aptwatcher audit render` (milestone W15-4, forthcoming) produces a
  judge-readable timeline with timestamps, tool identities, token
  usage, and per-step confidence.
- Human narratives in the final report cite audit event IDs. A claim
  without a backing event ID is not a claim, it is a guess.
- Secrets, API keys, and raw credentials never enter the audit log.
  Redact at emission time, not at render time.

## Failure modes to watch

- **Volatility profile mismatch.** The Windows symbol table does not
  match the dump. Downshift to `memory-only` mode, skip
  profile-dependent plugins, re-plan with the reduced tool set, and
  annotate every memory finding as `profile_degraded`.
- **EVTX corruption.** The native parser chokes on a truncated or
  tampered event log. Fall back to Hayabusa's tolerant parser via
  the Chainsaw compatibility path. Log the fallback.
- **Out-of-context file reference.** A tool or the LLM names a path
  that is not in the current evidence manifest. Reject the
  reference. Do not invent. Do not guess a nearby path. Emit
  `hallucinated_path` and re-plan the step without the reference.
- **Clock skew on cross-host timelines.** Host clocks disagree.
  Normalize every event to UTC inside the plaso pipeline and record
  the per-host offset. Never trust a local timestamp across hosts.
- **Disk image read error.** A sector read fails. Mark the affected
  offset range as `unreadable`, continue with what is readable, and
  never silently substitute zeros into a finding.
- **Tool timeout.** A long-running tool exceeds its budget. Kill,
  record the partial output under `work/partials/`, mark findings
  derived from it as `truncated`.

## Pointers

Read these before deep work:

- `docs/ARCHITECTURE.md` — system overview, process model, data flow.
- `docs/SCOPE.md` — what is and is not in the submission surface.
- `docs/design/tier-gating.md` — how consent gating is implemented.
- `docs/design/evidence-integrity.md` — chain of custody guarantees.
- `docs/ACCURACY.md` — confidence tiers and downshift rules.
- `knowledge/README.md` — clean-room policy for KB authorship.
