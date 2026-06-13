# Evidence integrity

> Forensic evidence is only useful if its chain of custody is intact.
> APTWatcher treats spoliation risk as a first-class property of every
> tool.

## Definitions

**Spoliation** — any action that modifies the evidence being analyzed in a
way that could affect its admissibility or interpretation. Reading a file
with a tool that updates `atime`. Mounting a disk image read-write. Running
a live command on a compromised host that writes to disk.

**Read-only** — the action does not modify the evidence. Default for
forensic tools when invoked correctly.

**State-changing** — the action modifies something. Could be the evidence
itself (bad) or operational state like a C2 socket being reset (acceptable
in Tier 3 with audit).

## The three risk levels

Every MCP tool declares its `spoliation_risk`:

| Risk | Meaning | Example tools |
|---|---|---|
| `read_only` | No side effects on evidence | `volatility_run`, `plaso_timeline`, `knowledge_search` |
| `state_changing_operational` | Changes operational state, not evidence | `rst_established_session`, `kill_c2_pipe` |
| `state_changing_evidence` | Touches evidence — reserved; banned by default | — |

`state_changing_evidence` tools are not shipped. If a future tool would
need to modify the evidence itself (e.g. decrypting an encrypted container
in place), it must be proposed, reviewed, and explicitly added with an
override flag beyond the tier system.

## Hash chain

Every `state_changing_operational` action produces a pre/post hash entry
in the audit log:

```json
{
  "event": "containment_action",
  "tool": "rst_established_session",
  "correlation_id": "cont-003",
  "pre_state_hash": "sha256:a1b2…",
  "post_state_hash": "sha256:c3d4…",
  "input": { "pid": 4128, "remote_addr": "…", "remote_port": 443 },
  "result": "rst_sent",
  "timestamp": "…"
}
```

Pre/post state captures the relevant system snapshot before and after — for
`rst_established_session`, that's the `ss -tnp` output filtered to the
target connection, hashed. Reviewers can verify the action was scoped to
what was claimed.

## Read-only by default

All Tier 0 tools are `read_only`. Tier 1 tools do not touch evidence
(they query external APIs). Tier 2 tools do not touch evidence (they file
tickets). Only Tier 3/4 have `state_changing_operational` tools, and those
tiers are opt-in.

A default install of APTWatcher can triage a case without any risk of
modifying the evidence. The operator must **explicitly** enable the tiers
that can act on operational state.

## What APTWatcher does not do

- Does not write to the evidence disk (images are mounted read-only)
- Does not install tools on the compromised host during live analysis (a
  senior analyst works from a response kit pre-staged by the IR lead)
- Does not delete or overwrite audit log entries (append-only)
- Does not run any tool that doesn't declare its spoliation risk

## Related

- [Audit logging](audit-logging.md) — the mechanism that captures the hash chain
- [Tier model](tier-model.md) — where state-changing actions live
