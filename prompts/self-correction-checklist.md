# Self-correction checklist

Run this pass after drafting findings, before emitting the report. The
report emitter tool will reject finalization without a
`self_correction` event in the audit log for the current incident.

For each draft `Finding`, work through the three rules below. Record
actions in the `self_correction` audit event.

---

## Rule 1 — every claim must cite

For the current finding:

- [ ] `finding.evidence` is non-empty.
- [ ] Every `tool_call_id` referenced in `finding.evidence` exists in the
      audit log as a `tool_call` event with a matching `correlation_id`.
- [ ] Every citation's `source` is specific enough to locate (e.g.
      `Security.evtx` plus `event_id=4624 record=9421`, not just
      `event logs`).

**If any of the above fails**: the finding is either rewritten to cite
real evidence, or dropped. Record which.

---

## Rule 2 — the cited evidence must support the claim

Re-open each tool output referenced in `finding.evidence`. Given **only**
the bytes in that output:

- [ ] Is the claim in `finding.summary` supported? If yes, identify the
      exact substring or record pattern.
- [ ] Is the MITRE mapping correct for what the evidence actually shows?
      A wrong subtechnique mapping (e.g. T1003.001 vs T1003.006) is a
      Rule 2 failure.
- [ ] Is `finding.confidence` consistent with the strength of the
      citation? One circumstantial source → not > 0.70. Multiple
      independent corroborating sources → can go higher.

**If the evidence supports a different claim**: rewrite `summary` and
`reasoning` to match. The rewrite is logged in the `self_correction`
event with `action: rewritten`, the original summary, the new summary,
and `rule: rule_2_evidence_does_not_support`.

**If the evidence does not support the claim at all**: drop the
finding. Log `action: dropped` and the original summary.

---

## Rule 3 — what would overturn this?

For each finding, answer:

- [ ] What evidence, if it existed, would overturn this conclusion?
      (e.g. *a legitimate backup process that ran in the same window
      would explain the egress*).
- [ ] Does that overturning evidence exist in artifacts we have?
- [ ] Did we check? If not, check now.
- [ ] If we do not have the artifact class required to check, cap
      `finding.confidence` at a level that reflects the uncertainty.
      Typically:
      - Can't verify via available artifacts → `confidence <= 0.70`
      - Single weak indicator only → `confidence <= 0.50`

**If overturning evidence exists in a checked artifact and we had
missed it**: drop or downgrade the finding and record the reason.

---

## Before emitting the self-correction event

Confirm the summary counts:

- [ ] `findings_draft_count`
- [ ] `findings_after_correction`
- [ ] `actions` list (one entry per rewrite or drop, each with
      `finding_id`, `action`, `original_summary`, `new_summary` where
      applicable, and the triggering `rule`).

A pass with zero actions is suspicious — either the first draft was
unusually clean, or the pass was not looking. A pass with very high
drop rate is also suspicious — either the first draft was sloppy, or
the rules were applied too mechanically. Both extremes deserve a note
in the event payload so a human reviewer can examine what happened.

---

## Emit the audit event

Only after all of the above:

```python
audit.append(
    event_type="self_correction",
    payload={
        "findings_draft_count": N,
        "findings_after_correction": M,
        "actions": [...],
    },
)
```

The report emitter now sees the event and will accept
`finalize_report()`. Without it, the emitter refuses and you must run
the pass again.
