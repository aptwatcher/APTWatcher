# Scenarios — demo narratives

> Narrative walkthroughs that bind APTWatcher's primitives to concrete
> operator stories. Each scenario is reproducible from a cold checkout
> with the commands and inputs it ships.

The `docs/scenarios/` tree carries the reference rubric scenarios
(S01–S03). This directory (`scenarios/` at the repo root) is for demo
scenarios: scripts used to walk through a capability end-to-end at a
pitch session, a status review, or an internal rehearsal. They are
narrative-first, not rubric-first.

## Index

| ID  | Title                                                                 | Demonstrates |
|-----|-----------------------------------------------------------------------|--------------|
| S04 | [Offline to online bundle handoff](S04-offline-to-online-handoff.md)  | `core.bundle` export + import, signed Ed25519 handoff, `aptwatcher analyze --sign` and `aptwatcher publish` against the `stub` adapter |
| S05 | [Find evil in one shot (E01 to signed PDF bundle)](S05-find-evil-e01.md) | Cold-workstation one-shot triage: `aptwatcher run` against an E01 + memory dump on a 14.5-minute budget, ending in a signed IncidentBundle and a judge-readable report |

Each scenario file follows the same outline:

- **Story** — the narrative beat in one paragraph.
- **Environment** — offline / online hosts, transport assumptions.
- **Inputs** — synthetic findings + IOCs shipped with the scenario.
- **Commands** — exact CLI invocations, matched to the argparse
  surface of `src/agent_extension/*.py`.
- **Audit events** — the names that land in the offline and online
  audit logs at each step.
- **Success rubric** — pass / partial / fail bands.
- **Related** — cross-links into design notes, KB procedures, and
  source.

## Naming convention

`S<NN>-<kebab-slug>.md`. `NN` is zero-padded, `kebab-slug` is the
one-line headline. Pick a slug that will still read cleanly a year
from now (e.g. `offline-to-online-handoff`, not `phase-3-7-demo`).

## Related

- [`../docs/scenarios/README.md`](../docs/scenarios/README.md) —
  rubric scenarios S01–S03 (accuracy measurement, not demo scripts).
- [`../docs/design/`](../docs/design/) — design notes each demo
  scenario exercises.
- [`../knowledge/procedures/`](../knowledge/procedures/) — operator
  procedures referenced by demo scenarios.
