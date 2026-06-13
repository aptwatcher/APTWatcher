---
title: Accuracy harness (Phase 4)
status: draft
---

# Accuracy harness

> **Status**: draft, Phase 4 scaffold. Author: APTWatcher core.
> **Scope**: measure whether the agent actually finds evil. Deterministic,
> offline-only, runs against recorded `FakeModelClient` transcripts and
> static golden expected-output files.
> **Related**: [`./analysis-output-pipeline.md`](./analysis-output-pipeline.md),
> [`./offline-to-online-handoff.md`](./offline-to-online-handoff.md),
> [`./self-correction-gates.md`](./self-correction-gates.md),
> [`./audit-log-format.md`](./audit-log-format.md).

## Goal

Phase 4 shifts from "does the pipeline run end-to-end" to "does the
agent actually find evil on a known-bad input". The accuracy harness
is the rig that answers that question numerically. Given a scenario
manifest, a recorded LLM transcript, and a golden expected-findings
file, the harness:

1. Replays the transcript against `AgentLoop` with the real
   `Planner` / `Verifier` / `SelfCorrector` strategies wired up,
   driven by a `core.llm.FakeModelClient`.
2. Captures the loop's final `state.findings` and `state.iocs`.
3. Scores that output against the golden.
4. Emits a machine-readable `accuracy_report.json` and a human-readable
   `accuracy_report.md` so operators and CI can compare runs.

The harness is the mechanism by which "the agent got better" stops
being a vibe check and becomes a diff on precision / recall / F1.

## Non-goals

- **No live model calls.** The harness is deterministic and offline
  by construction. The only allowed `ModelClient` is `FakeModelClient`.
  Wiring a real adapter into the eval path is an explicit error.
- **No scoring-algorithm research.** v1 uses exact-match scoring on a
  small set of fields. Fuzzy scoring, LLM-as-judge, embedding
  similarity, and MITRE-adjacency credit all live under "future work"
  and are out of scope for the initial landing.
- **No CI wiring yet.** The CLI command and exit-code contract exist
  so CI can be added later; this scaffold does not ship a workflow.
- **No regression detection.** The harness reports numbers. Deciding
  what counts as a regression is the operator's call until Phase 5.
- **No corpus sharing.** Transcripts and goldens in this repo are
  synthetic stand-ins; real incident transcripts never ship here.

## Scope

### In scope (this scaffold)

- `tests/accuracy/runner.py` — pipeline glue: load manifest, build
  `FakeModelClient`, drive `AgentLoop`, score against golden, write
  report files.
- `tests/accuracy/scoring.py` — the small exact-match scoring
  primitives (`score_findings`, `score_iocs`, `precision_recall_f1`).
- `tests/accuracy/fixtures/` — two committed scenarios:
  `s_phishing_beacon/` and `s_credential_dump/`, each with a manifest,
  a golden, and a short transcript.
- CLI surface: `aptwatcher eval` (Typer subcommand) with a
  threshold-based exit code.
- Unit tests for the scoring math and one runner integration test.

### Out of scope

- Writing more than the two seed scenarios (follow-up work).
- Tuning thresholds, score weighting, or MITRE-adjacency logic.
- Publishing reports to dashboards or hosted comparison tooling.
- Integrating with `analyze` / `publish` pipelines; the harness runs
  the loop itself, not the post-loop renderers.

## Inputs

Each scenario is a directory with exactly three files:

```
tests/accuracy/fixtures/<scenario_id>/
├── manifest.yaml     # scenario metadata
├── golden.json       # expected findings + iocs
└── transcript.json   # canned FakeModelClient responses
```

A fourth optional file is recognised when present:

```
└── kb_subset/        # directory globbed into a constrained KB view
    ├── <n>.md
    └── ...
```

### Scenario manifest (`manifest.yaml`)

```yaml
id: s_phishing_beacon
description: >
  Phishing email lands on a Windows host, a macro stages a loader,
  the loader beacons out to a known-bad C2 IP. Ground truth has two
  findings (macro execution, beacon) and two IOCs (exe hash, C2 IP).
profile: windows-host-triage
kb_subset_globs:
  - "kb_subset/**/*.md"   # optional; empty list == no KB context
transcript_path: transcript.json
golden_path: golden.json
```

Fields:

| Field | Type | Required | Notes |
|---|---|---|---|
| `id` | `str` | yes | Stable identifier; also becomes `incident_id` prefix. |
| `description` | `str` | yes | Human-readable summary for the report. |
| `profile` | `str` | yes | Must match a registered `ProfileDefinition`. |
| `kb_subset_globs` | `list[str]` | no | Glob patterns relative to the scenario dir. |
| `transcript_path` | `str` | yes | Path relative to the scenario dir. |
| `golden_path` | `str` | yes | Path relative to the scenario dir. |
| `seed_findings_path` | `str` | no | Scaffold-only shim (see below). |

### Scaffold-only: seed findings

Phase 3 does not yet have an `Executor` that synthesizes `Finding`
records from LLM tool-call output -- the `LLMPlanner` produces plans,
the null executor runs them, and findings land on the loop only via
external calls to `AgentLoop.add_finding()`. That is a hole the
harness has to bridge so v1 scoring is non-trivial.

The shim: when a scenario manifest points at a `seed_findings_path`,
the runner loads that JSON list of finding dicts, lifts each into a
real `core.types.Finding`, and calls `loop.add_finding()` for each
before driving the loop. The loop still runs verify / self-correct,
so the architectural gate is exercised; findings that fail the
baseline evidence check still get dropped. This keeps the harness
honest while the Executor work is in flight.

When the Executor lands (tracked under "Future work"), scenarios are
expected to drop their `seed_findings_path` and rely on the
transcript + Executor to produce findings organically. The shim
stays in the runner until every checked-in fixture has migrated,
then it is removed.

### Golden (`golden.json`)

```json
{
  "findings": [
    {
      "title": "Suspicious macro execution from email attachment",
      "tier": "high",
      "mitre": ["T1566.001", "T1204.002"]
    },
    {
      "title": "Outbound beacon to known C2 infrastructure",
      "tier": "high",
      "mitre": ["T1071.001"]
    }
  ],
  "iocs": [
    {"value": "203.0.113.42", "type": "ipv4"},
    {"value": "deadbeef" + "00" * 28, "type": "sha256"}
  ]
}
```

Field semantics:

- `findings[].title` — scored case-insensitively; normalization
  collapses consecutive whitespace and strips trailing punctuation.
- `findings[].tier` — one of `"high"`, `"medium"`, `"low"`. The
  `Finding` model has no `tier` field, so the harness derives it from
  `Finding.confidence` via the band mapping:

      confidence >= 0.75  ->  "high"
      0.50 <= confidence < 0.75  ->  "medium"
      confidence < 0.50  ->  "low"

  This keeps the scoring knob visible in the golden without requiring
  a schema change to `Finding`. A future `Finding.tier` field is
  tracked under "future work"; once it lands, the band mapping becomes
  a compatibility shim.
- `findings[].mitre` — a set of ATT&CK IDs; scoring compares sets
  for equality (order does not matter, duplicates collapse).
- `iocs[].value` — normalized per `core.types.IOCType` conventions
  (lowercased domains, canonical hash casing, defanging restored).
- `iocs[].type` — one of the `IOCType` literals.

### Transcript (`transcript.json`)

A JSON list of canned `ModelResponse`s, one per `ModelClient.complete`
call the loop will make, in order. Exact shape (matches the
`FakeModelClient` constructor):

```json
[
  {
    "content": "{\"reasoning\": \"...\", \"finalize\": false, \"steps\": [...]}",
    "stop_reason": "fake",
    "model": "fake-model"
  },
  {
    "content": "{\"reasoning\": \"baseline\", \"issues\": []}",
    "stop_reason": "fake",
    "model": "fake-model"
  },
  ...
]
```

Each entry's `content` is the string the `LLMPlanner` /
`LLMVerifier` / `LLMSelfCorrector` will parse. The transcript author
is responsible for ordering: `LLMPlanner` is called first each
iteration, then `LLMVerifier`, then `LLMSelfCorrector`, then
`LLMPlanner` again next iteration. See `prompts/planner.md`,
`prompts/verifier.md`, and `prompts/self-correction-checklist.md`
for the JSON schemas each parser expects. Malformed content is NOT
fatal — the defensive parsers absorb it — but malformed transcripts
are unlikely to drive the loop to the golden outcome.

Transcripts are kept deliberately short (3-5 calls) so a new
scenario is quick to author and review.

### Optional KB subset

When a scenario ships a `kb_subset/` directory, the runner loads it
as the `KnowledgeBase` instead of the full repo-level `knowledge/`
tree. This lets a scenario test "the agent handled this specific KB
context" rather than "the agent handled an arbitrary KB". Globs are
resolved relative to the scenario directory.

## Pipeline

```
    manifest.yaml + golden.json + transcript.json
            │
            ▼
    ┌──────────────────────────────────────────────┐
    │              run_scenario()                  │
    │                                              │
    │  1. load_manifest, load_golden, load         │
    │     transcript (JSON -> [ModelResponse])     │
    │                                              │
    │  2. Build FakeModelClient(transcript)        │
    │                                              │
    │  3. Instantiate AuditLogger in a temp dir;   │
    │     LLMPlanner/Verifier/SelfCorrector all    │
    │     share the SAME FakeModelClient — the     │
    │     transcript orders responses by call      │
    │     order, not by strategy.                  │
    │                                              │
    │  4. AgentLoop(incident_id=manifest.id, ...)  │
    │     .run() -> list[Finding]                  │
    │                                              │
    │  5. Collect state.findings and               │
    │     state.iocs (when the loop exposes       │
    │     IOCs; Phase 3 iocs are recorded via     │
    │     audit events and re-hydrated here).     │
    │                                              │
    │  6. score_findings(actual, expected.findings)│
    │     score_iocs(actual, expected.iocs)        │
    │     precision_recall_f1(tp, fp, fn) x 2      │
    │                                              │
    │  7. Build ScoreCard and return it.           │
    │                                              │
    │  8. aggregate() across all scorecards -> dict│
    │                                              │
    │  9. write_report(scorecards, output_dir)     │
    └──────────────────────────────────────────────┘
            │
            ▼
    accuracy_report_<timestamp>.json
    accuracy_report_<timestamp>.md
```

Stage invariants:

- **Transcript exhaustion.** If the loop asks for more responses than
  the transcript supplies, `FakeModelClient` raises
  `FakeClientExhausted`; the runner catches it, records the scenario
  error in the `ScoreCard.errors` list, and continues to the next
  scenario. One bad transcript does not tank the whole batch.
- **Audit log is throwaway.** Each scenario gets a temp directory for
  its audit log; the log is NOT part of the scoring surface. Future
  work could score on the event sequence, but v1 only looks at
  findings and IOCs.
- **No network.** The harness never instantiates a real
  `ModelClient`. Any attempt to import `core.llm_anthropic` in the
  harness module itself is an error (`from core.llm import
  FakeModelClient` only).

## Scoring

v1 scoring is exact-match on a small, human-authored field set. The
goal is to land the pipeline; tuning is follow-up work.

### Finding match rule

A predicted finding matches a golden finding when ALL of:

- `tier` (derived from `confidence` band) is equal.
- `title.lower().strip()` is equal after whitespace collapse.
- `set(mitre)` is equal (order-insensitive, duplicates collapsed).

A predicted finding that does not match any golden finding counts as
a false positive. A golden finding unmatched by any predicted finding
counts as a false negative. Matches are one-to-one: each predicted
finding consumes at most one golden, and vice versa.

### IOC match rule

A predicted IOC matches a golden IOC when ALL of:

- `type` is equal (`ipv4` != `ipv6` even for numerically equivalent
  values — they are different `IOCType` literals).
- `value` is equal after normalization (lowercase for domains,
  lowercase-hex for hashes, strip trailing slash on URLs).

IOC matching is also one-to-one.

### Precision / recall / F1

Standard definitions with explicit divide-by-zero handling:

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = 2 * p * r / (p + r) if (p + r) > 0 else 0.0

Convention for the degenerate "nothing expected, nothing produced"
case (`tp = fp = fn = 0`): precision, recall, and F1 are all `1.0`.
The harness treats an empty expected + empty actual scenario as a
perfect match because it is the only reading that does not penalise
a correctly empty answer. Scenarios with an empty golden must still
be listed in the manifest so the operator is acknowledging the
expectation explicitly; silent empty goldens are not accepted.

### Per-tier breakdown

The aggregate report also breaks findings down by tier so "the agent
got better at high-confidence findings but worse at low" is a
visible signal rather than an averaged blur. Tier buckets are
reported as separate sub-scorecards in the aggregate.

### Known limitations (documented, not fixed)

- **Title wording.** Exact-match on title is brittle. Two semantically
  identical findings with different wording score as FP + FN. Fuzzy
  title matching (edit distance or embedding similarity) is future
  work.
- **MITRE adjacency.** A prediction that says `T1071` when the golden
  wants `T1071.001` scores as a mismatch. Sub-technique credit is
  future work.
- **Tier tie-breaking.** Two goldens that share title + MITRE but
  differ only in tier are legal; the scorer walks them in list order
  and does not try to optimise the assignment. Pathological fixtures
  with heavy title overlap across tiers should be avoided.

## Output

Two files per run, emitted into the `--output-dir` the operator
supplies:

### `accuracy_report.json`

```json
{
  "schema_version": "1.0",
  "generated_at": "2026-04-20T10:14:02Z",
  "scenarios": [
    {
      "scenario_id": "s_phishing_beacon",
      "findings_tp": 2,
      "findings_fp": 0,
      "findings_fn": 0,
      "precision": 1.0,
      "recall": 1.0,
      "f1": 1.0,
      "ioc_precision": 1.0,
      "ioc_recall": 1.0,
      "duration_seconds": 0.41,
      "errors": []
    },
    ...
  ],
  "aggregate": {
    "scenario_count": 2,
    "mean_precision": 0.92,
    "mean_recall": 0.88,
    "mean_f1": 0.90,
    "by_tier": {
      "high":   {"tp": 3, "fp": 0, "fn": 1, "f1": 0.86},
      "medium": {"tp": 1, "fp": 1, "fn": 0, "f1": 0.67},
      "low":    {"tp": 0, "fp": 0, "fn": 0, "f1": 1.00}
    }
  }
}
```

The filename carries a UTC timestamp suffix
(`accuracy_report_<YYYYMMDDTHHMMSSZ>.json`) so successive runs do
not overwrite each other. The runner also writes a stable
`accuracy_report.json` symlink / copy pointing at the most recent
run, for CI convenience.

### `accuracy_report.md`

A short human-readable render of the same data: one table of
per-scenario P/R/F1, one table of the tier breakdown, and a bullet
list of any errors. The rendering is intentionally minimalist so
operators can paste it into a pull-request comment.

## Integration

### CLI

`aptwatcher eval` (wired in `src/agent_extension/cli.py`):

```
aptwatcher eval \
    --fixtures-dir tests/accuracy/fixtures \
    --output-dir  ./accuracy-runs/$(date +%Y%m%d-%H%M%S) \
    [--threshold 0.6]
```

- **Discovery.** Every direct subdirectory of `--fixtures-dir` that
  contains a `manifest.yaml` is treated as one scenario. Scenarios
  are sorted by id so the report ordering is stable.
- **Exit codes.** `0` when the aggregate F1 is `>=` `--threshold`
  (default `0.6`); `2` when below. Any unhandled runner exception
  exits `3`. A zero-scenario run exits `2` with a warning.
- **Deferred imports.** The eval command imports
  `tests.accuracy.runner` at call time, mirroring the `analyze` /
  `publish` pattern in `cli.py`. This keeps `aptwatcher --help` fast
  and avoids pulling PyYAML loading at every invocation.

### CI (future — not wired now)

The design reserves two follow-up hooks:

- A GitHub Actions job that runs `aptwatcher eval` with the default
  threshold on every pull request.
- A nightly job that runs against a larger scenario set (once it
  exists) and posts the delta versus the previous nightly into a
  check run.

Neither is implemented in this scaffold; both are captured here so
the exit-code contract above is not re-invented when they land.

## Trust boundary

The accuracy harness must NEVER make a live LLM call. This is a
policy invariant, enforced in three layers:

1. **Imports.** `tests/accuracy/runner.py` imports
   `FakeModelClient` directly and constructs the strategies with
   that client. The real provider adapters
   (`core.llm_anthropic.AnthropicModelClient`) are not imported in
   the harness module tree.
2. **Runtime assert.** Before calling `AgentLoop.run`, the runner
   asserts `isinstance(client, FakeModelClient)`; a mismatch raises
   an exception that aborts the whole batch.
3. **Environment.** The harness ignores `ANTHROPIC_API_KEY` and
   equivalents — it neither reads nor passes them to any strategy.
   A key in the environment while eval runs is benign but ignored.

The goal is two-fold: eval must be free (zero spend) and eval must
be deterministic (the same transcript produces the same scorecard on
any machine). A live model violates both. If a contributor ever
genuinely wants "real-model eval", that is a separate pipeline with
its own budget controls; it does not live in this harness.

## Directory layout

```
tests/accuracy/
├── __init__.py
├── README.md           # points at this design doc
├── runner.py           # load / run / score / report
├── scoring.py          # the math primitives
└── fixtures/
    ├── s_phishing_beacon/
    │   ├── manifest.yaml
    │   ├── golden.json
    │   └── transcript.json
    └── s_credential_dump/
        ├── manifest.yaml
        ├── golden.json
        └── transcript.json
```

The `tests/accuracy/` tree is a standard pytest collection site so
`pytest tests/accuracy/` runs the integration test. The fixtures
directory is also the default `--fixtures-dir` for the CLI.

## Testing strategy

Two test files seed the harness:

- `tests/test_accuracy_scoring.py` — unit tests for the math.
  Covers: perfect match, half miss, zero match, degenerate empty
  case, order independence for MITRE sets, tier-band derivation.
- `tests/test_accuracy_runner.py` — integration test that loads the
  `s_phishing_beacon` fixture, runs the harness, and asserts the
  scorecard F1 exceeds a calibrated threshold. This test guards
  against regressions in the pipeline wiring.

Both are marked with the `accuracy` pytest marker (already declared
in `pyproject.toml`). CI can toggle them with `-m accuracy` or
`-m "not accuracy"`.

## Future work

- **More scenarios.** The initial two fixtures are seed material.
  The target for Phase 4 close is ten diverse scenarios covering
  memory-only triage, timeline-only runs, ransomware pre-detonation,
  lateral movement, persistence via scheduled task, credential
  dumping, suspicious DNS, etc.
- **Fuzzy title matching.** Replace `title.lower() == other.lower()`
  with a pluggable similarity function (edit distance, embeddings).
  Threshold for "same finding" becomes a scoring knob with its own
  unit tests.
- **MITRE-adjacency credit.** Give partial credit when the prediction
  names a parent technique (e.g., `T1071`) and the golden names a
  sub-technique (e.g., `T1071.001`). The ATT&CK hierarchy is already
  encoded in `core.mitre`; the scorer can walk it.
- **LLM-as-judge.** For long-form findings where exact-match is
  hopeless, route the comparison through a frozen judge model and
  log the judgment as extra provenance in the scorecard. Requires a
  separate (budgeted) pipeline from the default offline eval.
- **Regression gate.** Compare the current `accuracy_report.json` to
  the previous committed baseline and fail when any per-scenario F1
  drops by more than X. Needs a stable baseline format; deferred
  until the scenario set is larger.
- **Receipt feedback loop.** When the online side acknowledges a
  bundle with a `RemediationReceipt`
  (`docs/design/offline-to-online-handoff.md` § Future work), that
  receipt becomes ground truth: an offline finding that the online
  side confirms is a confirmed TP, and the harness can score against
  real-incident outcomes instead of hand-authored goldens.
- **Native `Finding.tier` field.** Move from the confidence-band
  derivation to a first-class enum on `Finding`. Coordinated change:
  `core.types`, the planner / verifier prompts, every rendered
  report format.
- **Native Executor-driven findings.** Replace the
  `seed_findings_path` scaffold shim with an `Executor` that
  synthesizes `Finding` records from `LLMPlanner` tool calls and
  their recorded responses. Scenarios then produce findings
  organically from the transcript; the shim is deleted.

## References

- [`./analysis-output-pipeline.md`](./analysis-output-pipeline.md) —
  the downstream stages that consume what the harness scores.
- [`./offline-to-online-handoff.md`](./offline-to-online-handoff.md)
  — the receipt feedback loop that will eventually feed this
  harness with real ground truth.
- [`./self-correction-gates.md`](./self-correction-gates.md) — the
  gate the harness implicitly exercises every time the loop runs
  to `finalize()`.
- [`./audit-log-format.md`](./audit-log-format.md) — shape of the
  throwaway audit logs the harness produces per scenario.
- `src/core/llm.py` — `FakeModelClient`, `ModelRequest`,
  `ModelResponse`, `ModelMessage`.
- `src/core/agent_loop.py` — the loop contract the harness drives.
