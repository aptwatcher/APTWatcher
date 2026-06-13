# Self-correction

> The agent is required to question itself before finalizing a report.
> Not as a soft norm — as an architectural gate that runs on every run.
> This is the single mechanic most responsible for keeping APTWatcher's
> findings honest.

## The problem

LLMs generalize. That is their strength and also their failure mode.
Given four pieces of evidence pointing to a scenario, an LLM will happily
add a fifth that fits the pattern but is not actually present in the
evidence. The result *reads* coherent, *feels* correct, and is often
right — but the fraction that is wrong is exactly the fraction a
forensic report cannot afford.

Synthetic rubrics expose this directly. S01's rubric includes a fixed
list of `hallucination_traps` — claims the scenario does not support but
that plausibly fall out of its surface evidence. A naive agent hits
multiple traps on S01.

Self-correction is the pass that catches those before the report is
finalized.

## The mechanic

Between "draft the findings" and "emit the report", the agent runs a
structured re-read of its own reasoning chain. The pass is prompt-driven
but enforced architecturally: the report emitter **refuses to run**
until the self-correction pass has emitted a `self_correction` event for
the current incident.

The pass operates on three rules:

### Rule 1. Every claim must cite

For each finding in the draft report, the agent retrieves the
`finding` event from the audit log. If the finding's `evidence` array
is empty or references tool calls that do not exist, the finding is
rejected. No exceptions — a correctly-worded but uncited claim fails
the same as a false one.

This is a surface-level check; it catches the most common failure mode
(claims written from context rather than from evidence).

### Rule 2. The cited evidence must support the claim

For each citation, the agent re-opens the tool output and asks:

> Given *only* the bytes in this output, is the finding's claim
> supported? If yes, by what exact substring? If no, what claim *is*
> supported?

The agent's answer is written to a `claim_verification` event. If
the claim is not supported, the finding is either rewritten to match
the evidence or dropped. A finding rewritten during self-correction
is flagged in the final report — transparency about what the agent
changed is part of the discipline.

### Rule 3. What evidence would overturn this narrative?

The hardest rule to enforce and the most valuable. For each finding,
the agent asks:

> What evidence, if it existed and we missed it, would overturn this
> finding? Does that evidence exist in the artifacts we have?

If it does and the agent missed it, the finding is downgraded or
dropped. If the evidence would exist but we do not have the artifact
class to see it, the finding's confidence is capped at a level that
reflects the gap.

This rule is what turns a high-confidence report into a
low-confidence-but-honest one when the evidence genuinely cannot
support certainty. Judges reward honesty about uncertainty; they
punish false certainty sharply.

## What the pass produces

A `self_correction` event in the audit log:

```json
{
  "event_type": "self_correction",
  "incident_id": "s01-2026-04-19-1523",
  "findings_draft_count": 8,
  "findings_after_correction": 7,
  "actions": [
    {
      "finding_id": "F-005",
      "action": "rewritten",
      "original_summary": "Exfiltration of credential archive to external IP",
      "new_summary": "Credential archive staged on disk; no egress evidence in the capture window",
      "rule": "rule_2_evidence_does_not_support"
    },
    {
      "finding_id": "F-009",
      "action": "dropped",
      "original_summary": "Second user account compromised",
      "rule": "rule_3_overturning_evidence_exists"
    }
  ],
  "timestamp": "2026-04-19T15:54:02Z"
}
```

`findings_draft_count` vs `findings_after_correction` is the key metric.
A pass with no changes is suspicious — either the first draft was
unusually clean, or the self-correction pass was not actually looking.
A pass with a very high drop rate is suspicious in the other direction
— the first draft was sloppy. Over time, tracking these numbers across
runs is how we detect regressions in either the agent or the pass
itself.

## Why this is architectural, not prompt-based

The self-correction pass is prompt-driven (the three rules are written
into the system prompt). But the **enforcement** is architectural: the
report emitter tool in the MCP server inspects the audit log for a
`self_correction` event belonging to the current incident. If there
isn't one, the emitter refuses:

```
ReportEmitterError: self-correction not executed for this incident.
Run self_correct() before finalize_report().
```

There is no prompt the LLM can use to bypass this. The check is in the
Python that wraps the emitter, not in the instructions it receives.

This is the exact pattern the [tier model](tier-model.md) uses. The
stronger guardrail is not *"please do X"* in the prompt — it is *X is a
precondition for the tool that does Y*.

## When self-correction does not catch the problem

Self-correction is a strong filter, not a guarantee. It fails in these
cases:

- **The LLM's re-reading of evidence is as confident and wrong as the
  original pass.** Same model, same biases, same blind spots.
- **The evidence genuinely does support a claim that turns out to be
  wrong because of context outside the evidence window.** No introspective
  pass can catch that.
- **Rule 3 is under-answered.** If the agent does not think hard about
  overturning evidence, it finds none. This is the failure mode that
  shows up most in benchmarking.

Mitigations layered on top:

- The rubric's `hallucination_traps` catch the first class directly.
- Scenarios with public-dataset overlays catch the second (different
  environments stress the claim differently).
- Per-rule audit entries make the third visible after the fact: a
  `self_correction` event with zero Rule 3 actions across many
  high-confidence findings is a flag to reviewers.

## Cost

Self-correction adds wall-clock time and token cost to every run. The
MVP implementation re-uses the same model and the same tool interface,
so the pass is effectively a second inference round over the draft
findings. On S01's complexity, this is typically 30–90 seconds and a
few thousand extra tokens — cheap relative to the value of not filing
a wrong report.

A future optimization is a smaller, cheaper model for the pass. The
current decision is to keep the same model to ensure the self-correction
is actually capable of catching the original model's errors. A
strictly-weaker reviewer produces the worst of both worlds.

## What the demo video shows

The 5-minute demo video must show a self-correction step in action —
the agent catching a mistake it was about to make, rewriting the
finding, and emitting the correction event. This is the moment that
distinguishes APTWatcher from a tool that just dresses LLM output up in
forensic vocabulary.

## Related

- [Audit logging](audit-logging.md) — the log events the pass reads and
  writes
- [Evidence integrity](evidence-integrity.md) — the claim-to-bytes
  chain
- [Scenarios](../scenarios/README.md) — the rubrics that measure the
  pass's effectiveness
