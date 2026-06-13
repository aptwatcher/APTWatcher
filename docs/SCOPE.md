# SCOPE

> One-page scope for APTWatcher's hackathon submission. What is in, what is
> out, how we know we are done, and how we measure whether we are any good.

## Threat model — machine-speed autonomous adversaries (GTG-1002 class)

In 2025, Anthropic's security team publicly disclosed the GTG-1002 campaign:
a state-sponsored espionage operation that weaponized the Model Context
Protocol and an agentic LLM to execute approximately 80–90% of the attack
chain without human operator keystrokes. Recon, initial access, lateral
movement, and data staging ran at machine speed. The traditional defender
loop — a ticket, a human analyst, a 96-hour triage window — cannot match
an adversary that completes its objective in minutes. The barrier to entry
for machine-speed attacks has collapsed.

APTWatcher is explicitly designed for this threat class. It is not a faster
human; it is an AI-augmented defender that runs the same primitives the
attacker does — agentic orchestration, an MCP-backed tool surface,
iterative plan-execute-verify loops — but constrained by the Prime
Directive (strict read-only evidence mode) and tier gating (consent-required
state changes). See the [tier gating model](ARCHITECTURE.md) and the
forthcoming Prime Directive at `CLAUDE.md`. The design goal is **parity of
speed, not parity of autonomy**: the defender retains authority over chain
of custody and publication. See [evidence-integrity](design/evidence-integrity.md).

Concrete implications for scope. APTWatcher assumes (a) the adversary
toolchain can saturate a network in under an hour, (b) queue-based triage
will miss the window, (c) the defender must produce a signed, auditable
finding in single-digit minutes to be tactically useful, and (d) output
must survive review by analysts and judges who did not witness the agent's
execution — see [ACCURACY.md](ACCURACY.md). Mission statement reformulated:
**produce a signed, court-admissible triage bundle from a cold E01 and
memory dump within a 14.5-minute wall-clock budget.**

## In scope (MVP)

**Three deployment modes, one brain.**
Mode A (Direct Agent Extension on Claude Code), Mode B (Custom MCP Server
callable from any MCP client), Mode C (Hybrid — recommended). All three
import from `src/core/`. See
[deployment modes](architecture/deployment-modes.md).

**Five-tier capability model.**
Tier 0 always-on (core forensic triage). Tiers 1–4 opt-in via config and,
for Tier 3/4, additional runtime flags and confirmations. See
[tier model](architecture/tier-model.md).

**Three scenarios, two dataset strategies.**
S01 (single Windows compromise), S02 (multi-host lateral movement),
S03 (ransomware pre-detonation). Synthetic datasets with deterministic
rubrics, plus public-dataset overlays where license allows. See
[scenarios](scenarios/README.md) and [datasets](datasets/README.md).

**Four integrations** as optional capabilities, none vendored:
[APT Watch](integrations/apt-watch.md) and
[MS Threat Analytics](integrations/ms-threat-analytics.md) for Tier 1
intel; [GLPI](integrations/glpi.md) for Tier 2 workflow;
[cnc_disruptor](integrations/cnc-disruptor.md) for Tier 3/4 containment.

**Tier 1 intel aggregator.** A clean-room provider layer fans IOC lookups
out across ten sources — APT Watch (curated attribution) plus nine OSINT
providers (DShield, Shodan InternetDB, FireHOL, IPsum, Steven Black,
VirusTotal, AbuseIPDB, AlienVault OTX, Censys) — and folds them into one
`IOCVerdict`. Keyless providers need no secret; keyed providers activate
only when their API-key env var is set. Surfaced as `intel_lookup`,
`enrich_*`, `feed_*`, and `admin_*` MCP tools. See the
[MCP tools reference](reference/mcp-tools.md).

**Five use-case profiles** reading the SIFT tool inventory:
Windows host triage, Linux host triage, memory-only, timeline-only,
network-artifact.

**Self-correction as an architectural gate.**
Report emission is blocked until a self-correction pass has executed
against the draft findings. See
[self-correction](architecture/self-correction.md).

**Evidence integrity as a first-class property.**
Every MCP tool declares its spoliation risk. Containment actions write
pre/post state hashes to the audit log. See
[evidence integrity](architecture/evidence-integrity.md).

**All 8 hackathon deliverables.**
Code repo (MIT), demo video ≤5 min, architecture diagram, Devpost
description, dataset documentation, accuracy report, try-it-out
instructions, agent execution logs.

## Out of scope (MVP)

- **`submit_ioc()` feedback loop** to APT Watch. Deferred to post-MVP
  backlog. The shape is designed; the implementation waits.
- **Tier 4 offensive containment** is documented and gated, but stays
  **off** for the demo. The capability proves the tier model's
  extensibility; it is not a recommended feature.
- **Cloud audit log analysis** (M365, Azure AD sign-in logs). A separate
  profile in a later release.
- **Full container forensics.** Surfaced but not layer-by-layer analyzed.
- **Kubernetes cluster-level evidence** (audit logs, etcd state).
- **eBPF rootkit detection.** Flagged when relevant; detection requires
  kernel tooling beyond what SIFT ships.
- **Training data / fine-tuning.** APTWatcher is prompts + tools + a
  base model. Datasets are evaluation surface, not training input.
- **Content from `~/Dev/docs`.** Hard OUT OF SCOPE per
  clean-room policy. See [`knowledge/README.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/README.md).

## Decisions locked

| Decision                                        | Choice                                                      |
|-------------------------------------------------|-------------------------------------------------------------|
| License                                         | MIT (hackathon requirement)                                 |
| Name                                            | APTWatcher                                                  |
| Primary Tier 1 provider in demo                 | **Both** APT Watch and MS Threat Analytics, configurable    |
| Credential management                           | Environment variables; secrets file not supported           |
| Runtime — Mode A                                | Claude Code (primary). OpenClaw compatibility is a bonus    |
| Runtime — Mode B                                | Any MCP-capable client. Python runner ships for smoke tests |
| Runtime — Mode C                                | Claude Code + MCP server, both speaking the same `src/core/`|
| Logging format                                  | JSONL, append-only, one file per incident                   |
| Self-correction gate                            | Architectural (report emitter refuses without the event)    |
| Synthetic shellcode policy (S03)                | Sentinel pattern `APTWATCHER_SYN_` prefix, YARA-matching    |
| Tier 4 for hackathon demo                       | Off                                                         |
| `submit_ioc()` MVP or backlog                   | Backlog                                                     |

## Decisions still open

- **Which public datasets** get adopted. Pending license verification on
  candidate public IR case archives and Magnet Weekly CTF images. Finalized
  in Phase 4.
- **GitHub repo creation timing.** Repo is reserved; creation happens when
  author is ready to push the first commit.

## Definition of "correct"

A successful triage run produces a report where:

1. Every finding cites at least one tool call in the audit log.
2. Every finding maps to a MITRE technique ID; mapping is correct per the
   scenario rubric.
3. Findings are phrased as *"consistent with..."* when the evidence is
   circumstantial and as *"confirmed by..."* only when the cited evidence
   directly supports the claim.
4. The self-correction event exists in the audit log for the current
   incident.
5. No claim is present that contradicts evidence visible in the cited
   tool outputs.
6. Where a required artifact class is missing, the report states the gap
   explicitly and caps any dependent finding's confidence accordingly.

A run that meets 1–6 passes even if it misses some rubric items. A run
that fails any of 1, 4, or 5 fails regardless of rubric coverage.

## Accuracy metrics

Reported in [`docs/ACCURACY.md`](ACCURACY.md) per scenario per dataset
version:

- **Rubric hit rate** — fraction of `required: true` findings surfaced
  with the correct MITRE mapping.
- **Rubric near-miss rate** — findings surfaced with wrong-subtechnique
  mapping (e.g., T1003 vs. T1003.001).
- **Hallucination count** — claims in the report that are not supported
  by cited tool output, or that hit a `hallucination_trap` declared in
  the rubric. Target: **zero** per run.
- **Self-correction effectiveness** — ratio of findings rewritten or
  dropped by the self-correction pass over total draft findings. A healthy
  band is 0.05–0.25; outside that, investigate.
- **Time to triage** — wall-clock from preflight start to report emit.
  Tracked for trends, not gated.
- **Tier-0-only parity** — hit rate delta between Tier 0 alone and Tier 0
  plus available tiers. Shows how much value the optional tiers add.

Synthetic and public datasets are scored separately; the numbers never
blend.

## Time budget

Phase 3 (implementation) through Phase 4 (accuracy testing) has roughly
6 weeks to the June 15 deadline. Hard gates:

- **End of May 2026**: all Phase 3 items complete; first accuracy run on
  synthetic datasets.
- **First week of June 2026**: Phase 4 complete; final docs pass; demo
  video recorded.
- **June 10 2026 latest**: Devpost draft submitted (allows buffer for
  Devpost-side issues).
- **June 15 2026**: submission deadline. No code changes after this date.

## Related

- [README](README.md) — entry point
- [CLAUDE.md](https://github.com/aptwatcher/APTWatcher/blob/main/CLAUDE.md) — orchestrator brain file (Prime Directive, tool paths, subdomain roles)
- [SUBMISSION-CHECKLIST](https://github.com/aptwatcher/APTWatcher/blob/main/SUBMISSION-CHECKLIST.md) — final pre-submit gate
