---
title: Offline to Online Handoff
status: draft
---

# Offline to Online Handoff

> **Status**: draft, Phase 3.7 design-first. Author: APTWatcher core.
> **Scope**: portable handoff from an offline Protocol SIFT workstation to
> an online remediation surface (live host, EDR, XDR).
> **Related**: [`../ARCHITECTURE.md`](../ARCHITECTURE.md),
> [`./evidence-integrity.md`](./evidence-integrity.md),
> [`../architecture/audit-logging.md`](../architecture/audit-logging.md),
> [`./tier-gating.md`](./tier-gating.md),
> [`./analysis-output-pipeline.md`](./analysis-output-pipeline.md).

## Problem statement

Real defensive incident response is split across two worlds with
incompatible trust requirements.

**Offline world.** Acquisition and triage run on an air-gapped forensic
workstation (Protocol SIFT). Evidence integrity is the prime directive:
disk images, memory captures, pcaps, and log bundles must never touch
production; every analytical step must be read-only and auditable. This
is where APTWatcher's offline agent lives.

**Online world.** Remediation runs on live machines or on a management
plane (Defender XDR, CrowdStrike Falcon, SentinelOne, Umbrella, Zscaler,
local Defender / ClamAV). These surfaces require up-to-date IOCs,
concrete blocklists, process-kill and quarantine actions. Evidence
integrity is no longer the goal here; speed of containment is.

Three pressures justify a formal handoff pattern rather than ad-hoc
copy-paste.

1. **Airgap IR.** Regulated environments (OT, health, defense,
   classified) forbid outbound connections from the triage host. The
   offline agent must produce a signed, self-contained artifact a
   courier can carry online. Copy-paste of IOCs loses provenance.
2. **Evidence provenance.** The online operator must be able to
   answer "which triage run produced this block rule, on which
   evidence, by which operator, with what audit log?" — after the
   fact, in court if needed. A signed bundle carries that chain.
3. **Spread containment.** Once a campaign is mapped offline, the
   same IOC and YARA set must fan out across an estate of live hosts
   and EDR/XDR tenants in minutes. A normalized bundle lets one online
   agent push the same payload to many targets from one verified input.

APTWatcher bridges the two worlds with the **IncidentBundle** — a
versioned, signed, portable payload produced offline and consumed
online. The bundle is the contract; transport is the operator's choice.

## Deployment modes recap

`ARCHITECTURE.md` is authoritative. Summary:

- **Mode A — Direct Agent Extension.** `aptwatcher run` CLI, Claude
  Code, or OpenClaw drives the loop locally. Produces and consumes
  bundles; used both offline (triage) and online (remediation).
- **Mode B — Custom MCP Server.** `aptwatcher-mcp` stdio exposes typed
  tools. A calling MCP client orchestrates the loop; `bundle.export`
  and `bundle.verify` are typed MCP tools.
- **Mode C — Hybrid.** Mode A drives the loop, Mode B supplies the
  typed tool surface. Recommended for demos and production.

Handoff is a `core` capability (`src/core/bundle/`) consumed by every
surface. Offline host runs Mode A or C on the SIFT VM; online host
may run any mode, typically Mode A on a live endpoint or Mode B on a
management plane where the MCP client already brokers EDR access.

## IncidentBundle schema

Canonical JSON, pydantic-backed. `schema_version` is the compatibility
gate; a verifier that does not understand the declared version MUST
refuse the bundle rather than try to coerce fields.

### Top level

| Field | Type | Required | Constraints |
|---|---|---|---|
| `schema_version` | `str` | yes | Semver `"MAJOR.MINOR"`; first release `"1.0"`. |
| `incident_id` | `str` (UUIDv4 hex) | yes | Shared with offline audit log. |
| `generated_at` | `datetime` (UTC) | yes | ISO 8601, timezone-aware. |
| `expires_at` | `datetime` (UTC) | yes | Must exceed `generated_at`; recommended 30 days. |
| `producer` | `str` | yes | Free-form, e.g. `"APTWatcher/0.1.0 on SIFT-5.13"`. |
| `profile` | `str` | yes | Offline use-case profile. |
| `findings` | `list[Finding]` | yes | At least one; each carries citations. |
| `iocs` | `list[IOC]` | no | May be empty. |
| `yara_rules` | `list[YaraRule]` | no | Generated rules for observed TTPs. |
| `hashes` | `list[HashRecord]` | no | Known-bad binary hashes. |
| `remediation_playbook` | `list[RemediationStep]` | yes | Ordered, executable online. |
| `evidence_manifest` | `list[EvidenceFile]` | yes | SHA-256 manifest from preflight. |
| `audit_log_digest` | `str` | yes | SHA-256 of canonical audit log at `run_end`. |
| `signature` | `str` (128 hex) | yes | Detached Ed25519 over canonical-JSON of every other field. |
| `signer_pubkey_fingerprint` | `str` | yes | First 32 hex chars of SHA-256 over the signer public key. |

### Finding

Reuses `core.types.Finding` verbatim: `finding_id`, `summary`,
`mitre[]`, `confidence` (0.0-1.0), `evidence[]` (FindingCitation),
`reasoning`, `created_at`. Every finding MUST have at least one
citation whose `tool_call_id` exists in the offline audit log.

### IOC

```json
{
  "value": "185.234.247.12",
  "ioc_type": "ipv4",
  "first_seen": "2026-04-19T11:12:00Z",
  "last_seen": "2026-04-19T14:08:00Z",
  "attributions": [{"actor": "TA577", "campaign": "hostkey-dedik"}],
  "provenance": {
    "finding_id": "f-003",
    "tool_call_id": "call-0042",
    "source": "volatility:netscan"
  },
  "confidence": 0.85
}
```

`ioc_type` is the closed `IOCType` literal from `core.types`. `value`
is normalized (lowercased domains, defanged-restored URLs, canonical
hash casing). `provenance` is MANDATORY: an IOC without a back-link
to a finding and a tool call fails schema validation.

### YaraRule

```json
{
  "rule_name": "APT_hostkey_dedik_stager_v1",
  "meta": {
    "author": "APTWatcher",
    "date": "2026-04-19",
    "actor": "TA577",
    "incident_id": "a3b1...",
    "mitre": ["T1059.001", "T1055"],
    "severity": "high",
    "confidence": "medium"
  },
  "strings": [
    {"id": "$s1", "value": "XorDecodeStub", "provenance": "call-0031"}
  ],
  "condition": "uint16(0) == 0x5A4D and all of them",
  "rule_text": "rule APT_hostkey_dedik_stager_v1 { ... }"
}
```

`rule_text` is YARA-compiler-ready; the structured fields above it
mirror the rule for downstream tooling that prefers JSON.

### HashRecord

```json
{
  "algorithm": "sha256",
  "value": "e3b0c442...",
  "label": "dropper",
  "first_seen": "2026-04-19T11:05:00Z",
  "provenance": {"finding_id": "f-003", "tool_call_id": "call-0042"}
}
```

`algorithm` is one of `sha256 | sha1 | md5`. SHA-256 is required;
weaker algorithms are permitted only alongside a SHA-256 entry for the
same artifact.

### RemediationStep

See dedicated section below.

### EvidenceFile

Reuses the shape defined in `core.types.EvidenceFile` and produced by
`build_evidence_manifest()` during preflight. Downstream consumers
MUST NOT try to re-fetch evidence from these paths (the paths belong
to the offline VM); the manifest is purely for provenance.

## Lifecycle

Five stages. Each stage has explicit preconditions and postconditions
so the operator can verify the bundle crossed every gate cleanly.

### 1. Produce (offline)

- **Pre**: Offline triage reached `run_end` with at least one finding.
  `PreflightReport` persisted. Audit log paired (every `tool_call`
  start has a matching end).
- **Action**: `core.bundle.export.build_bundle(incident_id, config)`
  reads the audit log, rebuilds findings / IOCs / YARA rules /
  remediation playbook, pulls the evidence manifest from preflight,
  computes `audit_log_digest`.
- **Post**: Unsigned bundle object in memory. Schema validates. No
  file written yet.

### 2. Sign (offline)

- **Pre**: Unsigned bundle validates. Operator Ed25519 private key is
  accessible (kept outside the SIFT VM per evidence-integrity.md;
  loaded into memory for the signing call only).
- **Action**: Serialize the unsigned bundle (every field except
  `signature` and `signer_pubkey_fingerprint`) to canonical JSON
  (RFC 8785 / JCS). Produce a detached Ed25519 signature. Append
  `signature` and `signer_pubkey_fingerprint` to the object. Write
  to disk as `<incident_id>.bundle.json`.
- **Post**: Signed bundle on disk. Private key material removed from
  process memory. A `bundle_exported` audit event is appended to the
  offline log with the bundle file's SHA-256.

### 3. Transport (boundary)

- **Pre**: Signed bundle exists on the offline VM.
- **Action**: Operator copies the bundle off the SIFT VM. Transport is
  deliberately pluggable and out of scope for this design: USB sneaker
  net, signed file drop, git commit, GLPI attachment, Slack DM, email.
- **Post**: Bundle is on the online host. Transport integrity is NOT
  assumed; the signature verification in the next stage is what makes
  the bundle trustworthy, not the wire.

### 4. Verify (online)

- **Pre**: Online host has the bundle file and a trust store mapping
  `signer_pubkey_fingerprint` values to allowed public keys.
- **Action**: `core.bundle.import_.load_and_verify(path, trust_store)`:
  - Parse JSON, validate pydantic schema.
  - Check `schema_version` against supported set; reject unknown.
  - Look up `signer_pubkey_fingerprint` in trust store; reject unknown
    signers.
  - Recompute canonical JSON of every field except `signature` and
    `signer_pubkey_fingerprint`; verify detached Ed25519 signature.
  - Compare `generated_at` to `now()` and `expires_at`; reject expired.
  - Internal consistency: every IOC `provenance.finding_id` exists;
    every YaraRule `meta.incident_id` matches the top-level
    `incident_id`; every HashRecord provenance resolves.
- **Post**: Either a verified bundle is returned (with a
  `BundleTrust` record listing signer, verified_at, checks passed), or
  a typed `BundleVerificationError` is raised. No side effects yet.

### 5. Import and apply (online)

- **Pre**: Verified bundle in memory. Operator has granted
  `--enable-remediation` (Tier 3 flag). Target adapters are configured
  (live host executor and/or EDR/XDR connectors).
- **Action**: `core.bundle.apply.run_playbook(bundle, adapter, mode)`:
  - `mode="dry-run"`: every step prints the proposed action and
    returns a `DryRunReport`. No external call happens. This is the
    default.
  - `mode="execute"`: per-step execution with pre/post hash capture
    for host actions, typed return values for EDR pushers, pairwise
    audit events in the online audit log.
- **Post**: Online audit log contains one `remediation_step` event per
  step (success / partial / failed / skipped) and a final
  `remediation_summary` event keyed to the bundle's `incident_id`. A
  `remediation_report.json` is emitted next to the online audit log.

## Signature scheme

Ed25519 detached signature over canonical JSON. The pattern is identical
to the one described in
[`./evidence-integrity.md`](./evidence-integrity.md) §"Future work →
Detached signature on the audit log"; this document reuses it without
redesigning it. Three invariants:

- **Canonicalization**: RFC 8785 JSON Canonicalization Scheme (JCS).
  Keys sorted, no insignificant whitespace, UTF-8, numbers in shortest
  lossless form. Two honest implementations of the signer must produce
  byte-identical input.
- **Detached signature**: the signature does NOT cover itself. The
  signed payload is the canonical JSON of every field except
  `signature` and `signer_pubkey_fingerprint`. The signature and
  fingerprint are added afterward.
- **Key management**: private keys live OUTSIDE the SIFT VM. See
  evidence-integrity.md for rotation, storage (HSM / OS keyring /
  encrypted file), and revocation. This document assumes the key is
  available at signing time and does not re-specify key lifecycle.

`signer_pubkey_fingerprint` is the first 32 hex chars of SHA-256 over
the raw 32-byte public key. Trust stores map fingerprint to operator
identity and permitted scopes (e.g., "may produce bundles for the
EU-SOC tenant only").

## Remediation playbook format

A `RemediationStep` is the unit of online action. The shape is
deliberately action-agnostic so the same playbook can fan out to a
live host executor, an EDR pusher, or a DNS sinkhole adapter.

```json
{
  "step_id": "r-001",
  "action": "block_hash",
  "target": {
    "scope": "endpoint-defender",
    "selector": {"tenant": "contoso"}
  },
  "arguments": {
    "algorithm": "sha256",
    "value": "e3b0c442...",
    "label": "dropper"
  },
  "preconditions": [
    "bundle.signature_valid",
    "adapter.endpoint-defender.authenticated"
  ],
  "rollback": {
    "action": "unblock_hash",
    "arguments": {"algorithm": "sha256", "value": "e3b0c442..."}
  },
  "risk_level": "low",
  "dry_run_first": true,
  "depends_on": [],
  "idempotent": true,
  "notes": "Defender custom indicator, 30-day TTL."
}
```

Field definitions:

| Field | Type | Required | Constraints |
|---|---|---|---|
| `step_id` | `str` | yes | Unique per bundle; stable across re-runs. |
| `action` | `str` | yes | One of the registered online actions (see adapter table). |
| `target.scope` | `str` | yes | Adapter key (`live-host`, `endpoint-defender`, `crowdstrike-falcon`, `sentinelone`, `umbrella`, ...). |
| `target.selector` | `dict` | no | Adapter-specific (hostname, tenant, device group). |
| `arguments` | `dict` | yes | Action-specific payload. |
| `preconditions` | `list[str]` | no | Named checks the apply engine must pass before executing. |
| `rollback` | `dict` | no | Inverse action; may be absent when rollback is not meaningful (e.g., process kill). |
| `risk_level` | `"low" \| "medium" \| "high"` | yes | Drives the consent prompt in `apply --execute`. |
| `dry_run_first` | `bool` | yes | Recommended default is `true`. |
| `depends_on` | `list[str]` | no | Step IDs that must succeed first. |
| `idempotent` | `bool` | yes | True lets the apply engine retry safely. |

Named action vocabulary (initial release):

- `kill_process` (live-host)
- `quarantine_file` (live-host, Defender, ClamAV)
- `block_hash` (Defender, CrowdStrike, SentinelOne)
- `block_domain` (Umbrella, Zscaler, Defender)
- `block_ipv4` (Defender, CrowdStrike, SentinelOne)
- `dns_sinkhole` (live-host, Umbrella)
- `firewall_rule_add` (live-host)
- `push_yara_rule` (EDR platforms that accept custom YARA)
- `push_custom_detection` (Defender XDR, SentinelOne STAR)
- `open_ticket` (GLPI, ServiceNow — Tier 2 overlap)

Unknown actions are rejected at verify time; the bundle does not
"ship" actions the consumer cannot name.

## Online-side adapters

Online adapters share one Protocol interface in `core/bundle/adapters/`.
This document specifies the interface; concrete implementations are
deferred to Phase 4 and beyond.

```python
class RemediationAdapter(Protocol):
    name: str  # e.g., "live-host", "endpoint-defender"
    supported_actions: frozenset[str]

    def authenticate(self) -> None: ...
    def dry_run(self, step: RemediationStep) -> DryRunOutcome: ...
    def execute(self, step: RemediationStep) -> StepOutcome: ...
    def rollback(self, step: RemediationStep) -> StepOutcome: ...
```

Initial adapter targets:

| Adapter | Transport | Actions | Status |
|---|---|---|---|
| `live-host` (Python executor) | local subprocess + WMI / systemd-run | `kill_process`, `quarantine_file`, `firewall_rule_add`, `dns_sinkhole` | Phase 4 — first implementation |
| `endpoint-defender` | MS Graph Security API | `block_hash`, `block_domain`, `block_ipv4`, `push_custom_detection` | Phase 4 follow-up |
| `crowdstrike-falcon` | Falcon OAuth2 + IOC API | `block_hash`, `block_ipv4`, `block_domain` | Phase 5 |
| `sentinelone` | SentinelOne Threat Intelligence + STAR | `block_hash`, `push_yara_rule`, `push_custom_detection` | Phase 5 |
| `umbrella` | Cisco Umbrella Enforcement API | `block_domain`, `dns_sinkhole` | Phase 5 |
| `zscaler` | ZIA API | `block_domain`, `block_ipv4` | Phase 5 |
| `glpi` | glpi-mcp | `open_ticket` | Phase 4 (overlaps Tier 2) |

Every adapter ships with a stub implementation (mirrors the Tier 1
intel pattern: Protocol → stub → HTTP base → concrete) so the apply
engine can be tested end-to-end before any real credentials exist.

## Trust boundary

The bundle crosses an untrusted boundary. Nothing about the transport
guarantees authenticity — USB drives get swapped, Slack accounts get
compromised, git remotes get tampered with. The entire online trust
chain rests on the signature verification step.

Policy:

- **Verification is mandatory.** No apply path accepts an unverified
  bundle, even in dry-run. `core.bundle.import_.load_and_verify()` is
  the only public entry point; the raw parser is a private helper.
- **Unknown signer = reject.** The trust store is a closed
  fingerprint → identity mapping maintained out of band by the
  operator (typically a YAML file reviewed in pull requests).
- **Expired = reject.** `expires_at < now()` refuses the bundle.
  Operators who need to replay a historical bundle must re-issue a
  fresh signature.
- **Schema version unknown = reject.** A verifier that does not
  understand the declared `schema_version` refuses. Forward
  compatibility is deferred to a future major version with explicit
  migration rules.
- **Audit log digest mismatch (when audit log is colocated) =
  reject.** If the online operator also has access to the offline
  audit log, the `audit_log_digest` field MUST match. This catches
  post-hoc edits to the log.

## Failure modes

Every failure mode has a named typed exception and an online audit
event. None of them silently degrade.

| Failure | Detection | Typed error | Operator action |
|---|---|---|---|
| **Signature invalid** | Ed25519 verify returns false. | `BundleSignatureError` | Reject, alert. Possible tampering in transit. |
| **Unknown signer** | `signer_pubkey_fingerprint` not in trust store. | `BundleSignerUnknownError` | Add fingerprint to trust store after out-of-band validation, or reject. |
| **Expired bundle** | `expires_at <= now()`. | `BundleExpiredError` | Reissue from offline run. Do not extend `expires_at` client-side. |
| **Schema version unsupported** | `schema_version` not in allow-list. | `BundleSchemaVersionError` | Upgrade consumer or reissue with supported version. |
| **Schema validation failure** | Pydantic raises. | `BundleSchemaError` | Treat as corrupt; reissue from offline run. |
| **Internal consistency failure** | IOC provenance or YARA incident_id mismatch. | `BundleConsistencyError` | Treat as corrupt; reissue. |
| **Conflicting findings** | Two `Finding` records claim contradictory verdicts for the same IOC. | `BundleConflictError` (soft: warn, do not reject) | Operator reviews before `--execute`. |
| **Missing adapter** | `target.scope` resolves to no registered adapter. | `RemediationAdapterMissingError` | Configure adapter, or rerun with `--skip-scope <name>`. |
| **Precondition unmet** | Named check fails. | `RemediationPreconditionError` | Step is skipped; other independent steps proceed. |
| **Partial execution** | Some steps succeed, some fail. | No error — `remediation_summary` reports per-step status. | Operator decides whether to rollback, retry, or escalate. |
| **Adapter auth failure** | `authenticate()` raises. | `AdapterAuthError` | Fix credentials; bundle remains valid for retry. |
| **Idempotency conflict** | Non-idempotent step reported already-applied. | `RemediationIdempotencyError` | Operator inspects target; may need manual cleanup. |

## CLI surface

All commands are additions to the existing Typer app
(`src/agent_extension/cli.py`). They share the `--incident-root`,
`--audit-log`, and `--config` options with the rest of the CLI.

### `aptwatcher bundle export`

```
aptwatcher bundle export \
    --incident-id <uuid> \
    --output <path> \
    [--signing-key <path-or-env>] \
    [--expires-in-days 30] \
    [--no-sign]
```

Produces a signed bundle from a completed offline run. `--no-sign` is
for development only and emits a bundle with an empty `signature`;
such bundles fail verification and cannot be applied.

### `aptwatcher bundle verify`

```
aptwatcher bundle verify \
    --bundle <path> \
    [--trust-store <path>] \
    [--now <iso8601>]
```

Runs the full verification chain (signature, signer, expiry, schema,
internal consistency). Exits non-zero on any failure and prints a
diagnostic per check. `--now` lets CI pin the clock for reproducible
test fixtures.

### `aptwatcher bundle apply`

```
aptwatcher bundle apply \
    --bundle <path> \
    [--trust-store <path>] \
    [--adapter <name> ...] \
    [--dry-run | --execute] \
    [--step <id> ...] \
    [--skip-step <id> ...]
```

Default mode is `--dry-run`. `--execute` requires
`--enable-remediation` set in the config (Tier 3). The apply engine
verifies before applying; `verify` is not a prerequisite command,
but running it first is the recommended operator workflow because it
gives a dedicated exit code for CI gating.

## Scenario S04 — demo script skeleton

The pitch-day demo is a single end-to-end narrative. Script beats:

1. **Opening (00:00-00:30).** One-slide architecture diagram with the
   offline/online boundary highlighted.
2. **Offline VM — triage (00:30-02:00).** `aptwatcher run --profile
   windows-host-triage --evidence ./mem.raw --evidence ./disk.E01`
   shows preflight, the plan-execute-verify-self-correct loop, and
   findings landing with citations.
3. **Offline VM — export (02:00-02:30).** `aptwatcher bundle export
   --incident-id $I --output ./incident.bundle.json` prints the
   manifest, signs with the operator key, reports the bundle SHA-256.
4. **Transport (02:30-02:45).** Operator copies the bundle over
   (sneakernet, scp, or git commit — the demo accepts any).
5. **Online host — verify (02:45-03:15).** `aptwatcher bundle verify`
   shows each check passing; then a tampered bundle fails signature
   verification and an expired bundle fails expiry.
6. **Online host — dry-run (03:15-03:45).** `aptwatcher bundle apply
   --dry-run` prints every planned action with target and rollback.
7. **Online host — execute (03:45-04:30).** `aptwatcher bundle apply
   --execute --adapter live-host` kills the demo process, quarantines
   the demo file, adds a firewall rule; the stub `endpoint-defender`
   adapter prints a "would push" diagnostic.
8. **Close (04:30-05:00).** Show the online audit log with paired
   `remediation_step` events and the summary. Recap the trust boundary.

The demo runs against synthetic evidence and the stub EDR adapter;
no production tenant is touched. The recording IS the Phase 6
deliverable.

## Future work

- **EDR connector matrix.** Beyond the initial Defender / CrowdStrike /
  SentinelOne / Umbrella / Zscaler targets, add Microsoft Sentinel,
  Palo Alto Cortex XDR, Trellix, and open-source surrogates (Wazuh,
  Velociraptor) so the pattern is not platform-locked.
- **Revocation.** Signer key revocation is out of band today. A future
  minor version adds a `revocation_url` pointing to a signed CRL
  equivalent; verifiers consult it when online or fall back to a
  bundled revocation timestamp.
- **Bundle chaining.** Follow-up incidents often rely on the previous
  bundle's conclusions. `parent_incident_id` plus `predecessor_digest`
  would let a new bundle cryptographically chain to its predecessor,
  producing a tamper-evident incident lineage.
- **Partial-bundle subscriptions.** Consumers that only want IOCs
  should accept a stripped subset without breaking the signature.
  Requires a detached-signature-over-Merkle-root redesign; defer to v2.
- **Operator attestation.** Dual-control environments need a second
  signature from a reviewer role (analyst signs, SOC lead counter-signs
  before the bundle leaves the VM).
- **Acknowledgement reply.** Online side produces a `RemediationReceipt`
  — signed, schema-versioned, references the source `incident_id` —
  that travels back to the offline side for ground-truth feedback into
  the accuracy harness (Phase 4).

## References

- [`../ARCHITECTURE.md`](../ARCHITECTURE.md) — offline-online boundary.
- [`./evidence-integrity.md`](./evidence-integrity.md) — hash chain,
  Ed25519 key management, preflight manifest. Reused here.
- [`../architecture/audit-logging.md`](../architecture/audit-logging.md)
  — event catalog (`bundle_exported`, `remediation_step`, `remediation_summary`).
- [`./tier-gating.md`](./tier-gating.md) — `--enable-remediation` flag.
- [`./analysis-output-pipeline.md`](./analysis-output-pipeline.md) —
  YARA / Suricata / STIX / docx generators feeding the bundle.
- [`../reference/mcp-tools.md`](../reference/mcp-tools.md) —
  `bundle.export` / `bundle.verify` / `bundle.apply` MCP tools.
