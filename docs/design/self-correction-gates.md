---
title: Self-correction gates
status: draft
---

# Self-correction gates

> How APTWatcher prevents the agent from emitting a report that its own
> evidence does not support. The architectural form of "don't hallucinate
> past the facts in front of you."

---

## Purpose

APTWatcher is an autonomous agent driving forensic tools and an LLM
against incident evidence. Two failure modes are lethal for a defensive
IR product:

1. **Hallucinated findings.** The model invents a detail that no tool
   call supports, or upgrades a weak signal to a confident verdict
   without the citations to back it.
2. **Premature conclusions.** The model decides it is finished while
   the plan still has unresolved steps, or while the verifier is still
   complaining about a blocking issue.

Self-correction gates are the *architectural* answer to both. They are
not prompt discipline. They are code paths that refuse to let the loop
advance past the `report_emit` step unless specific invariants hold on
the current finding set. A prompt that tries to talk the model around
the gate fails at the `AgentLoop.finalize()` call site.

This design note specifies:

- when the self-corrector runs in the loop,
- what it is allowed to decide,
- what `finalize()` checks before a report can be emitted,
- the prompt contract the self-corrector speaks,
- how repeated corrections terminate,
- what the audit log sees,
- how all of the above is tested.

The wire-level audit event is specified in `./audit-log-format.md`; the
higher-level rationale sits in `../architecture/self-correction.md`.

---

## Reflect phase in the loop

`AgentLoop.run()` (see `src/core/agent_loop.py:236`) walks four phases
per iteration:

```
plan -> execute -> verify -> self_correct
```

The **Reflect** phase collapses `verify` and `self_correct` into one
method, `AgentLoop._verify_and_correct` (`agent_loop.py:297`). Every
iteration calls it exactly once, in this order:

1. `Verifier.verify(findings)` returns a flat `list[VerificationIssue]`.
   Each issue carries a `severity` (`block`, `warn`, `info`), a `rule`
   identifier (e.g. `rule1_evidence_required`), an optional
   `finding_id`, and a human-readable `detail`.
2. `SelfCorrector.correct(findings, issues, iteration)` is invoked. The
   default strategy is `LLMSelfCorrector`; `_NullSelfCorrector` is the
   offline test double.
3. The returned `SelfCorrectionDecision` is applied: findings listed in
   `decision.dropped` are removed from `state.findings`; findings
   listed in `decision.resolved` survive unchanged (the self-corrector
   is expected to have edited them in place when the strategy allows).
4. A `self_correction` audit event is written with the issues list,
   the decisions, the `replan` flag, and `notes`.
5. `state.self_correction_done_for_current_findings` flips to `True`.

Any mutation of the finding set through `AgentLoop.add_finding()`
immediately flips that flag back to `False` (see `agent_loop.py:271`).
The gate is therefore bound to the *current* finding set, not to
"some prior finding set the agent happens to remember."

A zero-finding run still gets a Reflect pass. `run()` guarantees it by
calling `_verify_and_correct()` one last time if the planner finalized
before any iteration completed (`agent_loop.py:248`). Zero findings
through the gate is still a gated zero.

---

## Decision outputs

`SelfCorrectionDecision` (in `src/core/agent_loop.py:70`) carries three
mutually compatible action channels plus a replan flag. Every verify
pass must produce exactly one decision; the loop never treats absence
of a decision as implicit acceptance.

### resolve

Meaning: the listed finding IDs have had their verifier issue
addressed and may be kept in the final set. The self-corrector is
trusted to have fixed the underlying problem (added a citation,
corrected a summary, trimmed an unsupported claim).

Fires when:

- The issue is `warn` or `info` severity and the corrector judges the
  finding shippable after an edit.
- The issue is `block` severity AND the corrector has materially
  repaired the finding (e.g. added the missing citation). In practice
  `block` issues with no fix available become `dropped`.

Constraint: every ID in `resolved` MUST appear in the input finding
list. Invented IDs are silently dropped by `_validate_id_list`
(`llm_self_corrector.py:316`) — the loop will not crash on invention,
but it also will not act on it.

### drop

Meaning: the listed findings are removed from the finding set entirely.
They will not appear in the emitted report.

Fires when:

- A `block`-severity issue cannot be resolved (most commonly
  `rule1_evidence_required`: finding has zero citations).
- A finding duplicates another and only one should survive.
- A finding's claim cannot be supported after follow-up tool calls.

Constraint: identical ID-existence check as `resolve`. If the model
returns the same ID in both `resolved` and `dropped`, `dropped` wins
(`llm_self_corrector.py:277`) — dropping is the safer action.

### replan

Meaning: go back to `plan -> execute` because follow-up tool calls
would plausibly change the answer. Set on the decision as a boolean
(`decision.replan`), independent of the resolve/drop lists.

Fires when:

- An issue has severity `block` or `warn` AND the corrector believes
  the missing information is *recoverable* by running another tool.
- The planner's last batch ran tools that returned ambiguous output;
  a targeted second pass would disambiguate.

Does NOT fire when:

- Iteration count has reached the terminal window (see Escalation
  paths). The corrector is instructed to prefer `replan=false` after
  iteration 6 unless a block-severity issue is still unresolved.
- The safe-default fallback is in effect. Fallback never replans —
  that would loop forever on garbage model output
  (`llm_self_corrector.py:378`).

---

## Gate invariants on `finalize()`

`AgentLoop.finalize()` (see `agent_loop.py:252`) is the architectural
choke point. No code path in `src/core/` emits a `report_emit` event
except this method. The invariants checked here are the contract the
whole agent lives or dies by.

Active invariants (enforced in code today):

1. **Self-correction preceded finalize.**
   `state.self_correction_done_for_current_findings` must be `True`.
   Otherwise `finalize()` raises `ReportEmitError`. A single
   `add_finding()` call after the last correction invalidates the
   flag; the loop must do another Reflect pass.
2. **Idempotent report emission.** `state.report_emitted` is checked
   before the `report_emit` event is written. A double call returns
   the cached finding list without re-emitting. This keeps the audit
   log honest — one incident, one `report_emit` event.

Invariants the gate is designed to enforce (partially landed,
specified here for completeness):

3. **Every finding cites evidence.** `Finding.evidence` must be a
   non-empty list of `FindingCitation`. `_NullVerifier.verify`
   (`agent_loop.py:135`) emits a `rule1_evidence_required` block-issue
   for any empty list; the self-corrector's safe default drops such
   findings. The invariant is that any finding reaching `report_emit`
   has at least one `FindingCitation` whose `tool_call_id` correlates
   to a `tool_call` event in the audit log.
4. **Verdict precedence.** When multiple findings speak to the same
   host, IOC, or claim, the emitted report must surface the highest
   severity: `malicious > suspicious > benign > unknown`. This is
   enforced by the report generator (Phase 3.1 pipeline), not by
   `finalize()` itself. `finalize()` only guarantees the finding set
   is self-correction-gated; precedence is the next stage's job.
5. **No dangling plan steps.** Every `PlanStep.step_id` that reached
   the executor must have a corresponding `ExecutionRecord` in
   `state.execution_log`. A planner that asked for 3 steps and only
   observed 2 `ExecutionRecord`s indicates an aborted run; the gate
   must refuse. This check is scheduled for the first Phase 2
   hardening pass.
6. **Audit correlation IDs are paired.** For every `tool_call`
   `phase=start` event there must be a matching `phase=end` event
   with the same `correlation_id`. An unmatched start means a tool
   crashed between the two writes, and any finding that cites the
   unmatched `tool_call_id` must be treated as uncitable. This is a
   log-replay check, enumerated in `./audit-log-format.md` under
   "Code gaps" (#4).
7. **Self-correction event matches current finding set.** Today the
   gate trusts an in-memory flag. A stronger form replays
   `audit.find("self_correction")` and compares the implied set of
   `finding_id` values against the current state. Same gap noted in
   `./audit-log-format.md`.

Invariants 1 and 2 are live. Invariants 3-7 are specified here as the
contract the loop is moving toward; the testing strategy below
includes them so that, as code lands, the property tests catch
regressions.

---

## Prompt contract

`prompts/self_corrector.md` is loaded once at `LLMSelfCorrector`
construction (`llm_self_corrector.py:90`). It is the system prompt for
every correction call; the user message is rendered per call by
`_render_user_message` (`llm_self_corrector.py:196`).

### Input the model receives

System prompt (verbatim from `prompts/self_corrector.md`):

- Role statement ("you are the self-corrector sub-module").
- The three per-finding decisions it may make: `resolved`, `dropped`,
  `keep`.
- The `replan` semantics.
- Three hard rules (never emit a report with an unresolved block-issue,
  never invent finding IDs, terminate).
- The exact output JSON shape.

User message (rendered at call time):

```
iteration: <int>
finding_count: <int>
issue_count: <int>
findings:
  - id: <finding_id>  summary: <short>  confidence: <float>  evidence: <int>
  - ...
issues:
  - severity: <block|warn|info>  rule: <rule_name>  finding_id: <id|None>  detail: <text>
  - ...

Decide per the system prompt and return JSON.
```

Note: the raw `Finding.reasoning`, full citation texts, and MITRE
identifiers are NOT shipped to the corrector. Only a densified view
(summary + confidence + citation count) is. This keeps the context
cheap and prevents the corrector from re-litigating the planner's
work.

### Output the model must return

A single JSON object. No markdown fence, no prose.

```json
{
  "notes": "one or two sentences explaining the decision",
  "resolved": ["F-014"],
  "dropped": ["F-021"],
  "replan": false
}
```

Shape contract enforced by `_parse_response`
(`llm_self_corrector.py:224`):

- Top-level value is an object.
- `notes` is a string (absent or non-string coerces to `""`).
- `resolved` is a list of strings; entries must exist in the input
  finding-ID set. Invented IDs are silently dropped.
- `dropped` is a list of strings; same validation.
- `replan` is a strict boolean; anything else raises
  `SelfCorrectorResponseError`.
- Overlap between `resolved` and `dropped` resolves in favor of
  `dropped`.
- Markdown code fences are tolerated and stripped
  (`llm_self_corrector.py:233`), but the prompt instructs the model
  not to emit them.

### Safe-default fallback

If the model emits malformed output (non-JSON, wrong top-level type,
non-boolean `replan`), `LLMSelfCorrector.correct` catches the
`SelfCorrectorResponseError` and falls back to `_safe_default_decision`
(`llm_self_corrector.py:349`):

- `resolved = []`
- `dropped` = every finding with a `severity: block` issue against it
- `replan = False`
- `notes` = `"fallback: <parse_error>"`

This mirrors `_NullSelfCorrector` exactly — the null strategy *is* the
fallback made explicit.

---

## Escalation paths

The corrector can, in principle, keep asking for another round
(`replan=True`) forever. The loop defends against that in three places.

1. **Hard iteration ceiling.** `AgentLoop.MAX_ITERATIONS = 12` is the
   outermost safety net (`agent_loop.py:215`). Once
   `state.iterations` reaches 12, `run()` exits the plan-execute-verify
   cycle regardless of what the corrector asked for, performs a final
   Reflect pass, and hands control to `finalize()`.
2. **Prompt-level taper.** The self-corrector prompt instructs the
   model to prefer `replan=false` after iteration 6 unless a
   `block`-severity issue is still unresolved. This is a soft cap; it
   biases the model toward termination without removing its agency.
3. **Fallback never replans.** If parsing fails, the fallback
   decision sets `replan=False`. A pathological model that keeps
   returning garbage cannot use replan loops to exhaust the host.

When the hard ceiling is hit and block-severity issues still exist,
the next layer is human escalation. MVP behavior: the `report_emit`
step still fires (since `self_correction_done_for_current_findings`
is `True`), but the emitted finding set reflects the fallback
drops, and the audit log carries the full trail of
`used_fallback: true` events for a reviewer to triage. A
human-in-the-loop signal path (SIEM alert, ticket escalation, operator
prompt) is planned for Phase 3.3 alongside the containment consent
flow.

---

## Observability

Every Reflect pass writes exactly one `self_correction` event; every
LLM-backed correction additionally writes one `llm_call` event. The
wire shapes are specified in `./audit-log-format.md`; this section
names which events fire and when.

| Trigger | Event type | Emitter | Notes |
|---|---|---|---|
| Reflect pass completes | `self_correction` | `AgentLoop._verify_and_correct` (`agent_loop.py:308`) | Includes issues, resolved, dropped, replan, notes |
| LLM corrector invoked | `llm_call` | `LLMSelfCorrector._emit_audit` (`llm_self_corrector.py:283`) | Payload `tool: "llm_self_corrector"`, `iteration`, `resolved`, `dropped`, `replan`, `used_fallback`; `notes` capped at 2000 chars; `parse_error` present only on fallback |
| Planner returns empty, zero-finding final pass | `self_correction` | same as above | Issues list is empty; decision is a no-op |
| Finalize succeeds | `report_emit` | `AgentLoop.finalize` (`agent_loop.py:260`) | Carries `incident_id`, `finding_count`, `iterations` |
| Finalize refused | none (exception) | `ReportEmitError` raised | No audit line is written; the outer `run_end` event's `payload.error` captures the failure |

Consumer queries (operator review):

```
# How many correction passes in this incident, and did any replan?
jq 'select(.event_type=="self_correction") | {iter: .payload.iteration, replan: .payload.replan, dropped: (.payload.dropped | length)}'

# Did the corrector ever fall back to safe-default?
jq 'select(.event_type=="llm_call" and .payload.tool=="llm_self_corrector" and .payload.used_fallback==true)'

# Did the run actually emit a report?
jq 'select(.event_type=="report_emit")'
```

---

## Testing strategy

Three tiers of test coverage, mirroring `./tier-gating.md`'s testing
pattern.

### Unit tests

`tests/test_agent_loop.py` (existing) and
`tests/test_llm_self_corrector.py` (planned) cover:

- `AgentLoop.finalize()` raises `ReportEmitError` when
  `self_correction_done_for_current_findings` is `False`.
- `AgentLoop.finalize()` emits `report_emit` exactly once even under
  double-call.
- `AgentLoop.add_finding()` invalidates the gate.
- `_NullSelfCorrector` drops every `block`-issue finding and never
  replans.
- `LLMSelfCorrector.correct` with a `FakeModelClient` returning
  well-formed JSON parses every field correctly, including list
  deduplication, overlap resolution (`dropped` wins), and invented-ID
  silent drop.
- `LLMSelfCorrector.correct` with malformed JSON falls back to the
  safe default and emits `used_fallback: true` in the audit payload.
- `LLMSelfCorrector.correct` with `issues=[]` short-circuits and does
  NOT call the model client (cost discipline; see
  `llm_self_corrector.py:106`).

### Golden-path fixtures

`tests/golden/self_correction/` (planned) holds paired
input/expected-output JSON files for the corrector prompt:

- `01_all_warn_no_replan.json` — every issue is `warn`, corrector
  returns `resolved: [...]`, `replan: false`.
- `02_block_unfixable.json` — `rule1_evidence_required` on a finding,
  corrector drops it.
- `03_block_fixable_replan.json` — block issue the corrector believes
  a tool call could fix; returns `replan: true`.
- `04_invented_ids.json` — model references finding IDs not in input;
  loop drops them silently, final decision unaffected.
- `05_malformed_json.json` — model returns prose; loop falls back.

Fixtures are consumed by a single parameterized test that loads the
input, replays it through `LLMSelfCorrector` with a
`FakeModelClient`, and asserts the resulting `SelfCorrectionDecision`
and `llm_call` audit payload match the expected file.

### Property tests

Using Hypothesis (or equivalent), the following invariants are asserted
over randomly generated finding sets and issue lists:

- For any finding set `F` and issue list `I`, the decision's
  `resolved` and `dropped` lists contain only IDs from `F`.
- For any finding set `F`, the post-correction finding set is a subset
  of `F` (no corrector can invent findings through the decision
  channel).
- For any finding set `F` where every finding has `evidence=[]`, the
  safe-default decision drops all of them.
- For any finding set `F` and any number of repeated Reflect passes,
  `state.iterations` never exceeds `MAX_ITERATIONS` + 1 (the trailing
  zero-finding pass).
- `finalize()` never writes a `report_emit` event when
  `self_correction_done_for_current_findings` is `False`.

Property tests target invariants 1 and 2 directly. Invariants 3-7
(evidence, precedence, plan-step pairing, correlation-ID pairing,
audit-replay gate) graduate from spec to test as the code lands; the
fixture file names are reserved now so follow-up PRs can fill them in
place.

---

## References

- `../ARCHITECTURE.md` — system overview and the self-correction gate
  in context.
- `../architecture/self-correction.md` — higher-level rationale.
- `./audit-log-format.md` — wire-level spec for `self_correction`,
  `llm_call`, and `report_emit` events.
- `./tier-gating.md` — sibling gate (capability gating); same shape
  of "structural guardrail, not prompt discipline."
- `./evidence-integrity.md` — pre/post hash discipline for
  state-changing tools; the reason invariant 3 must eventually
  inspect `FindingCitation.tool_call_id`.
- Source: `src/core/agent_loop.py`,
  `src/core/strategies/llm_self_corrector.py`,
  `prompts/self_corrector.md`,
  `src/core/types.py`.

---

## Discrepancies flagged

Documented for follow-up; not resolved in this doc-only pass.

1. **`keep` decision has no code channel.** The prompt
   (`prompts/self_corrector.md` line 15) tells the model it may return
   `keep` per finding "for warn or info issues the report can ship
   with." But `SelfCorrectionDecision` has only `resolved` and
   `dropped` lists. In practice any finding not named in either list
   is kept by default — the prompt's `keep` is implicit. The prompt
   should either explicitly state "omit the ID from both lists to
   keep," or the decision model should add a `kept` list for
   symmetry.
2. **No `Claim` model.** This spec references "claim" invariants
   (every finding has >=1 supporting claim with evidence), but
   `src/core/types.py` has `Finding` and `FindingCitation` only. The
   `Claim` abstraction lives in prose today, collapsed into
   `Finding.summary` + `Finding.evidence`. A formal `Claim` model
   would make invariant 3 more precisely checkable.
3. **Verdict precedence is unenforced in `finalize()`.** Invariant 4
   above states `malicious > suspicious > benign > unknown`, but
   `AgentLoop.finalize()` does not inspect finding verdicts. The
   precedence rule lives in the yet-to-land report generator. Until
   then, the invariant is a style guide for finding authors, not a
   guard.
4. **Prompt iteration-taper is advisory, not enforced.** The prompt
   says "prefer `replan=false` after iteration 6," but nothing in
   `LLMSelfCorrector` or `AgentLoop` forces the flag to `False` at
   iteration 7+. A pathological model could still request replan on
   every iteration up to `MAX_ITERATIONS = 12`. A code-level taper
   (e.g. `if iteration >= 6 and not has_block_issues: replan = False`)
   would make the behavior observable in tests.
5. **In-memory gate vs. log-replay gate.** `finalize()` checks an
   in-memory boolean. A process that bypassed the loop and appended
   findings through a side channel could, in theory, emit a report
   without a correction event. Same gap noted in
   `./audit-log-format.md` (#4 in "Code gaps").
