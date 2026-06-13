# Scenarios

> Three compromise scenarios anchor the demo, the Devpost submission, and the
> accuracy evaluation. Each one is self-contained — an analyst can run it from
> a cold VM.

Scenarios are the proving ground for APTWatcher. They exist for three reasons:

1. **Demo material.** The 5-minute video walks through at least one scenario
   end-to-end, including a self-correction step. S01 is the demo default.
2. **Accuracy measurement.** Every scenario ships with an expected-findings
   rubric. Hits, misses, and hallucinations are scored against it. Results
   feed [`docs/ACCURACY.md`](../ACCURACY.md).
3. **Judge verification.** A judge with a SIFT VM and no credentials can
   reproduce Tier 0 results in under 15 minutes. Optional tiers require
   matching credentials but never block the core run.

## The three scenarios

| ID  | Title                                                                    | Scope      | Tiers exercised |
|-----|--------------------------------------------------------------------------|------------|-----------------|
| S01 | [Single Windows host compromise](S01-single-windows-compromise.md)       | 1 host     | 0, 1 (optional) |
| S02 | [Multi-host lateral movement](S02-multi-host-lateral-movement.md)        | 3 hosts    | 0, 1, 2         |
| S03 | [Ransomware pre-detonation](S03-ransomware-pre-detonation.md)            | 1 host     | 0, 1, 3 (gated) |

S01 is the **floor** — it must run on every install. S02 and S03 progressively
exercise more of the tier model, and are expected to degrade gracefully when
optional tiers are missing (tickets not filed, containment skipped, etc.).

## Anatomy of a scenario page

Every scenario follows the same structure so results are comparable:

- **Story** — one-paragraph narrative. What happened, from the victim's view.
- **Environment** — OS versions, network layout, what SIFT sees.
- **Attacker timeline** — ground truth, ordered by wall-clock.
- **Artifacts to find** — the rubric. What a correct triage surfaces.
- **Expected agent approach** — the reasoning path a well-grounded agent
  takes. Not a script; an explanation.
- **Success rubric** — how the run is scored (hits / misses / hallucinations).
- **Dataset strategy** — synthetic, public, or both. License notes.
- **MITRE coverage** — techniques demonstrated.
- **Tiers exercised** — which tiers each phase of the run touches.

## What a scenario is not

- **Not a CTF.** There is no hidden flag. The goal is a defensible report, not
  a one-line answer.
- **Not a tutorial.** Scenarios assume the reader has done
  [Try it out](../getting-started/try-it-out.md).
- **Not a replacement for live-fire evaluation.** See
  [Datasets — public sources](../datasets/public-sources.md) for DFIR Report
  and similar cases the agent is also benchmarked against.

## Reproducibility contract

Each scenario declares:

- A pinned synthetic dataset version (or a public dataset with a checksum).
- The exact `preflight()` profile used.
- The SIFT tool versions the ground truth was generated against.

If any of those drift, the scenario page notes it and the accuracy numbers
are reset. This is the same discipline [evidence integrity](../architecture/evidence-integrity.md)
demands of the agent itself.

## Related

- [Datasets](../datasets/README.md) — how scenario data is produced
- [Use cases](../use-cases/README.md) — the profile each scenario runs under
- [Reference — MITRE coverage](../reference/mitre-coverage.md) — the full
  technique matrix across all three scenarios
