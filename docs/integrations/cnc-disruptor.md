# Integration: cnc_disruptor

> Tier 3 defensive containment and Tier 4 offensive containment live here.
> Wrapped, not vendored. **Nothing in this file runs without two explicit
> flags and a runtime confirmation**, and every action is recorded with
> pre/post state hashes in the audit log.

## What it is

`cnc_disruptor` is a collection of PowerShell and Python scripts at
`~/Dev/cnc_disruptor/` that perform C2-channel disruption.
Two categories:

- **Defensive** — operate on the compromised host only. Terminate a
  named-pipe C2 channel; RST an established outbound session; isolate a
  suspicious process.
- **Offensive** — operate on adversary infrastructure. Connect back to the
  attacker's team server and disrupt it. Legally and ethically charged.

APTWatcher wraps both categories behind typed MCP tools. It adds the
guardrails; it does not add the capability.

## Why this is an integration, not built in

Three reasons:

1. **Licensing / clean-room.** `cnc_disruptor` is the author's work; it
   can coexist in the same workspace. But keeping it separate preserves
   the cleaner narrative: APTWatcher is the orchestrator, cnc_disruptor is
   a capability that exists independently.
2. **Gating.** Capability that only activates behind a flag is easier to
   reason about — and to *not accidentally enable* — when it lives
   physically outside the main binary.
3. **Hackathon scope.** Tier 3/4 is not required for a winning submission;
   demonstrating that the agent *can* use containment behind hard
   guardrails is the point. Vendoring the scripts would muddy that.

## Tier 3 tools (defensive)

| MCP tool                                           | Target                  | Spoliation risk |
|----------------------------------------------------|-------------------------|-----------------|
| `kill_c2_pipe(pipe_name)`                          | Local named pipe        | state_changing_operational |
| `rst_established_session(pid, remote, port)`       | Local TCP session       | state_changing_operational |
| `isolate_process(pid, method="suspend" \| "kill")` | Local process           | state_changing_operational |

All three operate **on the host being analyzed**. None reach outbound.

### Requirements

- `--enable-containment` CLI flag at server startup
- Runtime confirmation per action (typed yes / no)
- Pre-state hash: relevant process metadata, open handles, or TCP state
  captured before the action
- Post-state hash: same capture after the action
- Both hashes recorded in the audit log with timestamps

If any of those is missing, the tool refuses. This is enforced in the
adapter, not by prompt. See
[evidence integrity](../architecture/evidence-integrity.md) for the
formal chain.

## Tier 4 tools (offensive)

| MCP tool                                      | Target                          | Spoliation risk |
|-----------------------------------------------|---------------------------------|-----------------|
| `disrupt_team_server(address, technique)`     | Adversary C2 server             | state_changing_external |
| `invalidate_staged_credentials(beacon_id)`    | Attacker-held cred material     | state_changing_external |

### Requirements

- `--enable-offensive` CLI flag **in addition to** `--enable-containment`
- Runtime warning banner that the operator must type an exact phrase to
  dismiss (not just "y")
- Per-action legal / ethical acknowledgment captured in the audit log

### Legal positioning

APTWatcher does not assess the legality of offensive containment. Legal
exposure varies materially by jurisdiction, by operator role, and by the
specific action. The agent makes the capability available behind the
gates above; it will not rationalize the legal question.

For the hackathon demo and for the production posture, **Tier 4 is off**.
It exists as a demonstration of the tier model's extensibility and to
prove the gating works under adversarial framing. It is not a recommended
feature.

## Config

```yaml
# config.yaml excerpt
containment:
  cnc_disruptor:
    enabled: false                 # Tier 3 master switch
    path: /opt/cnc_disruptor
    powershell_bin: /usr/bin/pwsh
    python_bin: /usr/bin/python3
    require_per_action_confirm: true
    audit_preflight: true
  offensive:
    enabled: false                 # Tier 4 master switch
    require_legal_ack: true
    legal_ack_phrase: "I accept responsibility for this action"
```

Both master switches default to `false`. Setting either to `true` in
config alone is not enough — the matching `--enable-*` flag at startup is
still required. Two keys must turn for each door.

## Audit record shape

Every containment action emits an audit record like:

```json
{
  "event_type": "containment_action",
  "tier": 3,
  "tool": "rst_established_session",
  "parameters": {
    "pid": 4412,
    "remote": "104.21.34.18",
    "port": 443
  },
  "pre_state": {
    "tcp_state": "ESTABLISHED",
    "process_state": "running",
    "hash": "sha256:abc..."
  },
  "post_state": {
    "tcp_state": "CLOSED",
    "process_state": "running",
    "hash": "sha256:def..."
  },
  "operator_confirmation": {
    "prompted_at": "2026-04-19T15:22:11Z",
    "confirmed_at": "2026-04-19T15:22:14Z",
    "confirmation_text": "yes"
  },
  "timestamp": "2026-04-19T15:22:14Z"
}
```

This record is the chain of custody for the state change. Without both
the pre/post hashes and the operator confirmation timestamp, the record
is rejected by the audit logger and the action is aborted.

## Graceful degradation

| Condition                                    | Behavior                                  |
|----------------------------------------------|-------------------------------------------|
| `cnc_disruptor` path missing                 | Tier 3/4 tools not advertised to the LLM  |
| `--enable-containment` flag absent           | Same — tools not visible                  |
| PowerShell or Python binary missing          | Per-tool failure, clear error, run continues |
| Pre-state capture fails                      | Tool aborts; no action taken              |
| Post-state capture fails after action ran    | Tool logs the failure; the action is **not** reversed, but the audit entry is marked incomplete — operator must investigate |

## Scenario mapping

- [S03 — Ransomware pre-detonation](../scenarios/S03-ransomware-pre-detonation.md)
  is the scenario where Tier 3 earns its place in the demo. The agent
  detects the injection, surfaces the named pipe, and *asks* before
  acting.
- S01 and S02 do not exercise Tier 3. Their compromises are old; there
  is nothing live to contain.

## Related

- [Tier model](../architecture/tier-model.md) — Tier 3 and Tier 4
  architectural gates
- [Evidence integrity](../architecture/evidence-integrity.md) — pre/post
  hash chain
- Upstream repo: `~/Dev/cnc_disruptor/`
