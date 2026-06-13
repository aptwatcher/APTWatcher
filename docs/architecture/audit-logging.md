# Audit logging

> Every action the agent takes is recorded in an append-only, structured
> log. The log is how we prove the report's chain of custody — and how we
> debug the agent when it gets something wrong.

## What the audit log is

A JSONL file (`logs/<incident_id>/audit.jsonl`) where each line is one
structured event. The file is opened in append mode, fsync'd after each
write, and never rewritten in place. If the file needs to be edited
after the fact — which it should not — the edit is performed by writing
a dedicated `audit_edit` event, never by mutating a prior line.

Append-only is the whole point. A mutable log has no evidentiary value.

## What gets logged

Four categories of events:

### 1. Preflight events

```json
{
  "event_type": "preflight",
  "incident_id": "s01-2026-04-19-1523",
  "profile": "windows-host-triage",
  "tool_inventory": {
    "volatility3": "2.8.0",
    "log2timeline": "20250410",
    "bulk_extractor": "2.0.0",
    "yara": "4.5.0",
    "RegRipper": "4.0"
  },
  "evidence_manifest": [
    {"path": "/mnt/evidence/FIN-WS-014/triage.zip", "sha256": "abc...", "size": 245678921}
  ],
  "tier_config": {"tier_0": true, "tier_1": true, "tier_2": false, "tier_3": false, "tier_4": false},
  "warnings": [],
  "timestamp": "2026-04-19T15:23:02Z"
}
```

### 2. Tool invocations

Every MCP tool call — read-only or not — writes one entry:

```json
{
  "event_type": "tool_call",
  "correlation_id": "call-0042",
  "incident_id": "s01-2026-04-19-1523",
  "tool": "volatility_run",
  "parameters": {
    "plugin": "windows.malfind",
    "image": "/mnt/evidence/FIN-WS-014/mem.raw"
  },
  "spoliation_risk": "read_only",
  "exit_code": 0,
  "output_hash": "sha256:def...",
  "duration_ms": 4721,
  "timestamp": "2026-04-19T15:28:41Z"
}
```

Raw output is not inlined; it is hashed and stored alongside the log at
`logs/<incident_id>/tool_outputs/<correlation_id>.out`. The hash
connects the two.

### 3. Findings

When the agent records a structured finding — an artifact it intends to
include in the report — it emits a `finding` event:

```json
{
  "event_type": "finding",
  "finding_id": "F-014",
  "incident_id": "s01-2026-04-19-1523",
  "summary": "Scheduled task MicrosoftEdgeUpdateTaskMachineUA with suspicious binary path",
  "mitre": ["T1053.005"],
  "confidence": 0.85,
  "evidence": [
    {"source": "registry:SOFTWARE\\Microsoft\\Windows\\...", "locator": "ValueName=...", "tool_call": "call-0037"},
    {"source": "Security.evtx", "locator": "event_id=4698 record=8121", "tool_call": "call-0041"}
  ],
  "reasoning": "Task name matches Edge updater pattern but binary path is C:\\ProgramData\\Contoso\\svchost.exe — not a Microsoft binary location.",
  "timestamp": "2026-04-19T15:32:15Z"
}
```

Every finding must cite at least one tool call. Findings without
citations are rejected by the self-correction gate (see
[self-correction](self-correction.md)).

### 4. State-changing events

Containment actions and any other `state_changing_operational` operation
produce a dedicated record with pre/post hashes:

```json
{
  "event_type": "containment_action",
  "correlation_id": "cont-003",
  "tool": "rst_established_session",
  "parameters": {"pid": 4128, "remote_addr": "104.21.34.18", "remote_port": 443},
  "pre_state_hash": "sha256:111...",
  "post_state_hash": "sha256:222...",
  "operator_confirmation": {
    "prompted_at": "2026-04-19T15:45:10Z",
    "confirmed_at": "2026-04-19T15:45:13Z",
    "confirmation_text": "yes"
  },
  "result": "rst_sent",
  "timestamp": "2026-04-19T15:45:13Z"
}
```

This is the formal chain of custody for any state change. See
[evidence integrity](evidence-integrity.md).

## Why JSONL and not a database

- **Append-only semantics are native to the format.** Each line is
  independent; nothing to rebalance, no B-tree invariants to maintain.
- **Forensic auditor tooling is text-friendly.** `grep`, `jq`, `awk`.
  No SQL client, no schema migration to reason about.
- **Corruption is bounded.** A corrupt line is one lost event; the
  rest of the file is still parseable.
- **Simpler to archive.** The log is a single file per incident.

The trade-off — no efficient random access by field — is acceptable.
Incidents produce at most a few thousand events; even a linear scan is
fast.

## Correlation IDs

Events that belong together share a `correlation_id`:

- `call-NNNN` for tool calls
- `cont-NNN` for containment actions
- `finding-NNNN` for reasoning chains that produced a finding
- `upd-NNN` for ticket updates

When the final report cites a finding, the citation resolves to the
`finding` event, which resolves to its `tool_call` events, which
resolve to their `tool_outputs/<correlation_id>.out` files. Every claim
in the report can be walked back to the bytes that support it.

## Redaction

Some parameters must be redacted before landing in the audit log:

- API keys and bearer tokens (replaced with `"<redacted:env=APTWATCH_API_KEY>"`)
- Full credential material captured from memory (only the presence and
  location are logged, never the material itself)
- Personally identifying fields beyond what the evidence requires

Redaction happens inside the adapter, before the log write. It is not
something the LLM can undo — the adapter never sees the un-redacted form
in the first place if it is an env-var-sourced secret.

## Rotation and retention

The audit log is **not** rotated during an incident. One incident, one
file. Rotation, archival, and retention are operational decisions the
deploying organization makes on the surrounding log directory — outside
APTWatcher's scope.

For the hackathon submission, example incident logs will ship in
`logs/` to satisfy Deliverable 8 (agent execution logs).

## How the log serves three audiences

- **The analyst** uses it to trace a surprising finding back to the
  tool call that produced it.
- **The auditor / judge** uses it to verify the chain of custody and
  rubric compliance.
- **APTWatcher itself** uses it in the self-correction pass, where it
  re-reads its own recent findings and asks whether the cited evidence
  actually supports them.

Of these, the third is the most novel and most underappreciated. An
agent that can introspect its own reasoning chain is the
architecture's real advantage — see [self-correction](self-correction.md).

## Related

- [Self-correction](self-correction.md) — how the agent uses the audit
  log to check itself
- [Evidence integrity](evidence-integrity.md) — the pre/post hash chain
- [Shared brain](shared-brain.md) — the `AuditEvent` types that populate
  the log
