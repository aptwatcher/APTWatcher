---
title: Subdomain expert agents — role decomposition
status: draft
---

# Subdomain expert agents — role decomposition

> How APTWatcher's single-loop planner maps onto the five subdomain
> expert roles described in Rob T. Lee's 2026-04-21 presentation on
> progressive disclosure multi-agent architectures, and the forward
> path to a true multi-agent port after the hackathon.

---

## Motivation

Forensic incident response touches too many subdomains to fit cleanly
into one prompt. A single orchestrator that must simultaneously reason
about memory plugins, plaso parsers, MFT carving, event-log hunt
rules, and IOC intel providers ends up *context-rotting*: older
evidence and earlier tool output drift out of the effective attention
window, and the planner repeats steps or contradicts its own prior
conclusions.

Progressive disclosure addresses this by fanning one orchestrator out
to several subdomain specialists, each with a narrow tool belt and a
narrow knowledge slice. Rob Lee's framing on 2026-04-21 proposed five
roles: Timeline, Filesystem, Memory, Windows Artifacts, and Threat
Hunting. Each specialist sees only the tools, knowledge, and evidence
it needs; the orchestrator sees only each specialist's summarized
findings, not their intermediate tool output.

APTWatcher is aligned with this framing in spirit but not yet in
implementation. This note documents (a) how existing strategies map
onto those five roles today, (b) why we deliberately stayed
prompt-scoped for the hackathon build, and (c) the concrete path to a
true multi-agent port later.

See also:

- `CLAUDE.md` at the repo root — orchestrator brain.
- [`self-correction-gates.md`](./self-correction-gates.md) — the gate
  every role must pass before its findings reach a report.

---

## Five roles

### Timeline

Role statement: own temporal reconstruction across all evidence
sources, producing one ordered narrative of what happened and when.

Owned MCP tools:

- `run_log2timeline`, `run_psort`, `list_plaso_parser_presets`
- `run_timesketch_query`, `run_timesketch_upload`,
  `list_timesketch_query_subcommands`

Knowledge directory: `knowledge/timeline/` — plaso parser recipes,
EVTX logon-anomaly patterns, MFT timestomping heuristics. Secondary
draws: `knowledge/procedures/timeline-building-workflow.md`.

Typical self-correction triggers:

- Empty or sparse plaso super-timeline after ingest — downshift to a
  narrower parser preset, or verify the target path actually contains
  the expected artifacts.
- Timesketch upload that never indexes — verify the sketch exists and
  fall back to local `psort` output for the analyst report.
- Clock skew between sources — insert a normalization step before
  Timeline claims a causal ordering.

### Filesystem

Role statement: own on-disk artifact recovery, partition and volume
analysis, and content carving from raw images.

Owned MCP tools:

- `run_mmls`, `run_fsstat`, `run_fls`, `run_icat`
- `run_bulk_extractor`, `list_bulk_extractor_scanners`

Knowledge directory: primary draws from `knowledge/linux/`
(inode, mount, and carving guidance) and `knowledge/artifacts/`.
Procedure cross-references in `knowledge/procedures/` when a carved
artifact feeds containment.

Typical self-correction triggers:

- `mmls` on a target that turns out to be a volume, not an image —
  drop the partition-offset step and re-plan against a
  single-filesystem target.
- `bulk_extractor` saturating on an irrelevant scanner — drop the
  noisy scanner and re-run scoped.
- Inode reference that no longer resolves after a fresh `fls` —
  re-run `fls -r` and re-verify before any finding cites that inode.

### Memory

Role statement: own volatile-memory analysis against a captured RAM
image, producing process, network, and injection findings.

Owned MCP tools:

- `run_volatility`, `list_volatility_plugins`

Knowledge directory: `knowledge/memory/` — reflective DLL injection
patterns, rootkit indicators, and the `injection/` and `rootkit/`
sub-directories.

Typical self-correction triggers:

- Profile mismatch: volatility3 cannot resolve symbols for the
  captured image. The role downshifts to a memory-only profile,
  limits itself to symbol-free plugins, and flags the limitation in
  the finding.
- `pslist` empty or implausibly short — cross-check against
  `pstree` / `psscan` before asserting a finding.
- Network artifacts in memory that contradict Timeline's network
  events — publish a conflict and let the self-correction gate
  arbitrate.

### Windows Artifacts

Role statement: own Windows-specific artifact analysis — registry,
event logs, prefetch, scheduled tasks — and hunt-rule execution
against those sources.

Owned MCP tools:

- `run_chainsaw_hunt`, `run_chainsaw_search`,
  `list_chainsaw_output_formats`
- `run_hayabusa_timeline`, `run_hayabusa_logon_summary`,
  `list_hayabusa_output_formats`
- `run_regripper_plugin`, `run_regripper_profile`,
  `list_regripper_plugins`, `list_regripper_profiles`

Knowledge directory: `knowledge/windows/` — persistence, lateral,
credaccess, evasion, and impact subdirectories, each with
technique-indexed notes.

Typical self-correction triggers:

- Chainsaw rule set missing for the detected log channels — the role
  must either widen rule selection or flag a coverage gap rather than
  silently returning zero hits.
- RegRipper plugin crashing on a hive variant — swap to a
  profile-level run and record which plugins were skipped.
- Hayabusa logon summary that contradicts plaso event ordering —
  route to Timeline for arbitration.

### Threat Hunting

Role statement: own IOC enrichment, hunt-rule generation, and
cross-artifact pattern matching for anomalies that are not pinned to
a single subdomain.

Owned MCP tools:

- `run_yara_scan`
- `generate_yara_rules`, `generate_suricata_rules`
- `export_stix_bundle`, `export_community_yaml`,
  `export_per_type_txt`
- The IOC intel aggregator (`core.intel.aggregator`) and its HTTP
  providers, exposed through the shared brain rather than a raw MCP
  tool.
- `knowledge_search`, `knowledge_get` (shared, but most heavily used
  here for technique matching).

Knowledge directory: `knowledge/procedures/` for incident-wide
playbooks (credential-theft response, lateral-movement containment,
ransomware-initial-triage, c2-beacon-identification) and
`knowledge/network/` for beaconing, DNS-tunneling, SMB/RPC lateral
signatures.

Typical self-correction triggers:

- YARA rule generation from too few samples — require a minimum
  sample count or flag the rule as low-confidence.
- Intel aggregator returning contradictory verdicts across providers
  — defer to the aggregator's precedence rules and record the
  conflict.
- IOC enrichment that would change a Timeline finding's severity —
  republish the enriched finding and let the self-correction gate
  re-verify.

---

## Current implementation — prompt-scoped, single-loop

APTWatcher today does **not** spawn five separate agents. There is one
agent loop (`src/core/agent_loop.py`) driven by one planner strategy
(`src/core/strategies/llm_planner.py`), one verifier
(`llm_verifier.py`), and one self-corrector (`llm_self_corrector.py`).
The loop walks the four-phase cycle `plan → execute → verify →
self_correct` against a single accumulating `AgentState`.

The five roles above exist today as **personas baked into the planner
prompt**, not as independent LLM contexts. Scoping is achieved by:

1. **Profile-driven tool gating.** The active profile (windows-host,
   linux-host, memory-only, timeline-only, network-artifact, and so
   on) restricts which MCP tools the server registers. A memory-only
   run never sees Chainsaw; a timeline-only run never sees volatility3.
   The planner is effectively scoped to one role per run.
2. **Knowledge-search narrowing.** `knowledge_search` hits the KB
   subtree relevant to the active profile, so the planner's context
   window is dominated by documents from one subdomain.
3. **Prompt-embedded role guidance.** `prompts/planner.md` and
   `prompts/system.md` describe how to *think* like each specialist
   without separating the LLM contexts.

The result is progressive-disclosure-*flavored* behavior inside a
single audit chain and a single model conversation.

---

## Why prompt-scoped for now

The single-loop choice is deliberate, not an oversight.

- **One signed audit chain instead of five.** Every AuditEvent hashes
  into a linear chain rooted at the run's bootstrap event. A
  single-loop architecture produces one chain per run. Five parallel
  agents would need either five independent chains (and a merge
  proof) or a distributed-log coordination layer.
- **Smaller accuracy-harness surface.** The harness replays eight
  fixture scenarios through one loop. Moving to five specialists
  multiplies the replay matrix by five and forces us to reason about
  per-agent regression before we even have a baseline.
- **Deterministic replay with `FakeModelClient`.** The fake client
  serves recorded completions in the exact order the single loop
  requests them. Five concurrent agents introduce nondeterministic
  request interleaving that breaks byte-identical replay.
- **Coordination bugs we cannot afford to debug pre-deadline.** True
  multi-agent introduces deadlock on shared evidence, duplicate tool
  invocations, and race conditions on the shared bundle. The
  gate-and-finalize discipline in
  [`self-correction-gates.md`](./self-correction-gates.md) is much
  easier to enforce with exactly one loop emitting findings.

The cost is real: the single-prompt planner's attention is finite, and
at some point adding more MCP tools degrades planner quality faster
than it adds capability. The threshold below flags when to pay that
cost.

---

## Forward path — true multi-agent

The target shape, for a post-hackathon milestone, is an adapter layer
that can host either the current single loop or a fan-out of
specialist agents behind a common interface.

### SubdomainAgent Protocol

Introduce a `SubdomainAgent` Protocol in `src/core/strategies/` with
four methods matching the existing loop phases:

```python
class SubdomainAgent(Protocol):
    role: str                         # "memory", "timeline", ...

    def plan(self, state: AgentState) -> list[PlanStep]: ...
    def execute(self, step: PlanStep) -> ExecutionRecord: ...
    def verify(self, state: AgentState) -> VerifyReport: ...
    def self_correct(self, state: AgentState) -> CorrectionOutcome: ...
```

The existing `LLMPlanner` / `LLMVerifier` / `LLMSelfCorrector` trio
wraps to satisfy this Protocol as a single "generalist" agent. No
existing behavior changes at that point.

### Dispatcher

A thin dispatcher picks which subset of agents to spawn for a given
run, based on evidence present plus the active profile:

- Memory image present → spawn Memory.
- EVTX / registry hives present → spawn Windows Artifacts.
- Disk image / volume present → spawn Filesystem.
- Any of the above → spawn Timeline (it aggregates).
- Always spawn Threat Hunting unless running fully air-gapped with no
  local YARA ruleset.

The dispatcher is a pure function of the preflight report plus the
profile; it emits an ordered list of `SubdomainAgent` instances.

### Inter-agent evidence sharing

Agents do not talk to each other directly. They share state through an
in-memory `IncidentBundle` instance (an extended form of
`core.bundle`). Each agent appends raw findings (with provenance),
IOCs (with verdicts), and tool invocation records (with hashes). Reads
are copy-on-write snapshots so a slow agent never blocks a fast one on
shared state.

### EventBus coordination primitive

A minimal `EventBus` emits typed events — `finding_published`,
`ioc_observed`, `verification_failed` — into topics other agents
subscribe to. Typical wiring:

- Threat Hunting subscribes to `finding_published` to trigger IOC
  enrichment.
- Timeline subscribes to `ioc_observed` to fold the IOC back into the
  super-timeline.
- The orchestrator subscribes to `verification_failed` to decide
  whether to spawn a corrective step or fail the run.

No agent loop is kicked off by the bus directly; the orchestrator
still owns step dispatch. The bus is a notification channel, not a
task queue.

### Framework options

- **AutoGen (Microsoft).** Python-first, minimal external
  dependencies, leaves the agent loop shape up to the integrator.
  Lowest friction to slot behind our Protocol.
- **CrewAI.** Role-based, more opinionated about inter-agent
  conversation. Simpler mental model if agents should "talk" to each
  other; heavier runtime.

[`openclaw-alternative.md`](./openclaw-alternative.md) is orthogonal
to this decision — it is a backend (model host) choice, not an
orchestration choice. A true multi-agent port can target either the
Anthropic client or OpenClaw; the Protocol is agnostic.

### Threshold for when to make the jump

Do not port on calendar pressure. Port when at least one of:

- The MCP tool inventory crosses roughly 20 tools, at which point
  single-prompt planner context becomes the dominant cost and the
  planner starts skipping tools it should use.
- The accuracy harness shows measurable gains from role-separated
  prompts on a controlled experiment (same fixture set, one-prompt vs
  five-prompt planners, compared per-fixture).

Until one of those holds, the single loop is the right engineering
choice.

---

## Migration plan (post-hackathon)

1. **Introduce `SubdomainAgent` Protocol.** Land the Protocol in
   `src/core/strategies/` and wrap the current trio so it satisfies
   the Protocol as the generalist agent. No behavior change.
2. **Port Memory role first.** Smallest blast radius: volatility3 is
   two tools, `knowledge/memory/` is small, and Memory findings rarely
   need cross-agent verification. A Memory specialist is the cleanest
   first vertical slice.
3. **Add EventBus plus in-memory `IncidentBundle` coordination.** Only
   after Memory is running end-to-end, introduce the bus and the
   shared bundle. Generalist and Memory then coexist and exchange
   findings.
4. **Port the remaining four roles in parallel.** Timeline,
   Filesystem, Windows Artifacts, Threat Hunting. Each gets its own
   pull request with its own accuracy-harness baseline.
5. **Update the accuracy harness.** Report per-role precision / recall
   in addition to the aggregate score, and report coordination
   overhead (wall-clock time in EventBus dispatch, bundle merge, and
   cross-agent verification) as a first-class metric.

---

## Status

Noted, not scheduled. Target: post-hackathon milestone M2.

---

## References

- `CLAUDE.md` at the repo root — orchestrator brain.
- [`../SCOPE.md`](../SCOPE.md) — hackathon scope.
- [`../ARCHITECTURE.md`](../ARCHITECTURE.md) — system architecture.
- [`./self-correction-gates.md`](./self-correction-gates.md) — gate
  invariants every role must satisfy.
- [`./tier-gating.md`](./tier-gating.md) — tier / profile tool gating
  currently used to scope roles.
- [`./openclaw-alternative.md`](./openclaw-alternative.md) —
  orthogonal backend choice.
- `src/core/agent_loop.py` — four-phase loop.
- `src/core/strategies/llm_planner.py` — current single-loop planner.
- `src/core/strategies/llm_verifier.py` — current verifier.
- `src/core/strategies/llm_self_corrector.py` — current
  self-corrector.
- `src/core/knowledge.py` — KB search entry point used by all roles.
