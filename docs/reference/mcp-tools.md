# Reference: MCP tools

> The full tool inventory exposed by APTWatcher to the LLM, grouped by tier.
> Every tool declares its inputs, outputs, and spoliation risk. Tier 0 is
> always visible; other tiers are visible only when enabled in config.

This page is authoritative for what the agent can call. If a tool is not
here, the agent cannot use it — and if it is here but the current tier
config has the tier disabled, the agent cannot see it either.

## Schema conventions

All tools are described in the form:

```
tool_name(arg1: type, arg2: type = default) -> ReturnType
```

Inputs and outputs are JSON. Field names are `snake_case`. `null` is a
legitimate value — the adapter never guesses to fill in a missing field.

Every tool also declares:

- `tier` — 0, 1, 2, 3, or 4
- `spoliation_risk` — `read_only` | `state_changing_operational` |
  `state_changing_external`
- `gated_by` — list of flags / conditions required for the tool to be
  advertised to the LLM

## Tier 0 — Core forensic triage

Always visible. Zero external dependencies.

### `preflight(profile: str) -> PreflightReport`

Probes the SIFT tool inventory against a declared
[use case profile](../use-cases/README.md). Records tool versions to the
audit log. Aborts the run if a required tool is missing.

- `spoliation_risk`: `read_only`
- `gated_by`: none

Return: `PreflightReport` with tool → version map, profile match status,
staleness flags.

### `sift_update() -> UpdateOutcome`

Consent-gated refresh of SIFT packages, YARA rules, or Volatility symbol
tables. Never runs mid-incident without explicit operator approval.

- `spoliation_risk`: `state_changing_operational`
- `gated_by`: non-empty `consent_token` request field. The wrapper
  (`core.sift.update.run_sift_update`) raises `SiftUpdateConsentError`
  when the token is empty or whitespace, and emits a
  `sift_update_consent` audit event before any `apt-get` invocation.
  See `mcp-tool-schemas.md` section 3.13 for the full schema.

### `knowledge_search(query: str, top_k: int = 5) -> list[KBEntry]`

Retrieval over `knowledge/`. Returns entries with full front-matter
including `source_type` for attribution.

- `spoliation_risk`: `read_only`
- `gated_by`: none

### `extract_iocs(text: str) -> list[IOC]`

Defang + regex extraction. Ports the pattern from APT Watch's
`rss_monitor.py`. Handles IPv4, IPv6, domains, URLs, file hashes, email
addresses.

- `spoliation_risk`: `read_only`
- `gated_by`: none

### `volatility_run(plugin: str, image: str, args: dict = {}) -> VolatilityOutput`

Wrapped `volatility3` invocation. Common plugins: `windows.pslist`,
`windows.malfind`, `windows.netscan`, `linux.pslist`, `linux.bash`.

- `spoliation_risk`: `read_only` (memory image is mounted read-only)
- `gated_by`: profile must declare `memory_image` as an artifact category

### `plaso_timeline(image_or_bundle: str, output: str = "auto") -> TimelineHandle`

Wrapped `log2timeline.py`. Produces a `.plaso` database plus a JSONL
export. The agent reads the JSONL.

- `spoliation_risk`: `read_only`
- `gated_by`: profile must declare a timeline-capable artifact category

### `bulk_extractor_run(target: str, filters: list[str] = []) -> ExtractionReport`

Wrapped `bulk_extractor`. Useful for carving IoCs and files out of PCAPs,
memory images, and disk images.

- `spoliation_risk`: `read_only`
- `gated_by`: none

### `yara_scan(target: str, ruleset: str = "sift-default") -> list[YaraMatch]`

YARA over a file, directory, or memory image. Default ruleset is the
SIFT-provided baseline; custom rulesets may be loaded from
`knowledge/yara/`.

- `spoliation_risk`: `read_only`
- `gated_by`: none

### `registry_parse(hive_path: str, plugin: str) -> list[RegistryFinding]`

Wrapped RegRipper. Plugin names match RegRipper's — `schedtasks`,
`runkeys`, `userassist`, `usbstor`, and so on.

- `spoliation_risk`: `read_only`
- `gated_by`: profile must declare `registry` as an artifact category

### `audit_append(event: AuditEvent) -> AuditEventId`

Appends a structured event to the audit log. Not called by the LLM
directly; invoked by every other tool to record their own execution.

- `spoliation_risk`: `read_only` (writes only to the audit log, which is
  append-only and outside the evidence path)
- `gated_by`: none

See [audit logging](../architecture/audit-logging.md) for the format.

## Tier 1 — External threat intel

Visible only when `intel.*.enabled: true` for at least one provider, and only
when Tier 1 is enabled (`tiers.tier_1: true`). All Tier 1 tools are
`read_only` and gated on at least one enabled provider.

### Provider roster

Verdicts are produced by an aggregator that fans out to every configured
provider and folds the answers into one `IOCVerdict` (malicious > suspicious >
benign > unknown). Providers register only when enabled — keyed providers
additionally require their API-key env var to be set.

| Provider | Key | IOC types | Signal |
|---|---|---|---|
| `apt_watch` | none | ip/domain/url/hash/email | curated actor attribution |
| `dshield` | none | ip | SANS ISC reputation / threat feeds |
| `shodan_internetdb` | none | ip | exposure (ports, CVEs, tags) |
| `firehol` | none | ip | blocklist membership (incl. CIDR) |
| `ipsum` | none | ip | blocklist membership |
| `stevenblack` | none | domain | hosts blocklist membership |
| `virustotal` | `VIRUSTOTAL_API_KEY` | ip/domain/hash | multi-engine detections |
| `abuseipdb` | `ABUSEIPDB_API_KEY` | ip | abuse confidence score |
| `otx` | `OTX_API_KEY` | ip/domain/hash | AlienVault pulse count |
| `censys` | `CENSYS_API_TOKEN` | ip | host exposure / labels |

Keys are supplied via the env var named in `intel.<provider>.api_key_env`
(defaults shown above). Keys never live in config files or the audit log.

### `intel_lookup(value: str, ioc_type: str) -> IOCVerdict`

Fan-out lookup across every enabled provider that supports the IOC type;
returns one aggregated `IOCVerdict` with each provider answer preserved in
`sources`.

- `spoliation_risk`: `read_only`
- `gated_by`: Tier 1 enabled and at least one provider enabled
- `ioc_type` values: `ipv4`, `ipv6`, `domain`, `url`, `sha256`, `sha1`, `md5`, `email`

### `enrich_ip(value) / enrich_domain(value) / enrich_hash(value) -> IOCVerdict`

Convenience wrappers over `intel_lookup` that infer the IOC type
(`enrich_ip` picks v4/v6; `enrich_hash` infers md5/sha1/sha256 from length).

- `spoliation_risk`: `read_only`
- `gated_by`: same as `intel_lookup`

### `feed_threatfox(query: str) -> dict`

Search abuse.ch ThreatFox for an indicator (IP/domain/URL/hash). Returns the
match list; this is a *search verb*, not a per-IOC verdict. Honors an optional
`ABUSECH_API_KEY` to raise rate limits.

- `spoliation_risk`: `read_only`
- `gated_by`: Tier 1 enabled

### `feed_tweetfeed(value: str | None = None, tag: str | None = None) -> dict`

Fetch today's TweetFeed indicators, optionally filtered by exact value or tag.

- `spoliation_risk`: `read_only`
- `gated_by`: Tier 1 enabled

### `admin_version() / admin_health() / admin_providers_status() -> dict`

MCP-side observability: version + provider roster, readiness (Tier 1 flag and
count of active providers), and per-provider enabled/keyed/key-present status.
`admin_providers_status` never returns key values, only whether a key is set.

- `spoliation_risk`: `read_only`
- `gated_by`: Tier 1 enabled

### Planned (not yet implemented)

- `correlate_host_against_intel(host_evidence) -> list[IOCVerdict]` — batch
  every IOC in host evidence through `intel_lookup`.
- `threat_report_lookup(technique_id)` / `incident_lookup(host)` — backed by the
  MS Threat Analytics provider (scaffolded, not wired).
- `submit_ioc(...)` — feedback loop to APT Watch.

## Tier 2 — IR workflow integration

Visible only when `workflow.glpi.enabled: true`.

### `glpi_ticket_create(title: str, content_html: str, category: str, ...) -> TicketRef`

Files a ticket. Content must be HTML (see
[GLPI integration](../integrations/glpi.md) for the content rule).

- `spoliation_risk`: `state_changing_external` (writes to GLPI)
- `gated_by`: GLPI provider enabled; idempotency on `(scenario_id, host)`

### `glpi_ticket_update(id: int, content_html: str) -> TicketRef`

Adds a follow-up to an existing ticket.

- `spoliation_risk`: `state_changing_external`
- `gated_by`: GLPI provider enabled

### `glpi_kb_search(query: str) -> list[KBArticle]`

Searches the GLPI knowledge base for prior similar incidents.

- `spoliation_risk`: `read_only`
- `gated_by`: GLPI provider enabled

### `glpi_task_create(ticket_id: int, description_html: str) -> TaskRef`

Creates a follow-up task on a ticket. Used for items that need human
analyst action.

- `spoliation_risk`: `state_changing_external`
- `gated_by`: GLPI provider enabled

## Tier 3 — Defensive containment

Visible only with `--enable-containment` at startup **and**
`containment.cnc_disruptor.enabled: true` in config.

### `kill_c2_pipe(pipe_name: str) -> ContainmentResult`

Terminates a named-pipe C2 channel on the compromised host.

- `spoliation_risk`: `state_changing_operational`
- `gated_by`: `--enable-containment` flag + runtime confirmation + pre/post
  hash capture

### `rst_established_session(pid: int, remote_addr: str, remote_port: int) -> ContainmentResult`

Sends TCP RST for an established outbound session from the given PID.

- `spoliation_risk`: `state_changing_operational`
- `gated_by`: same as `kill_c2_pipe`

### `isolate_process(pid: int, method: str = "suspend") -> ContainmentResult`

Suspends or kills a suspicious process. `method` is `suspend` or `kill`.

- `spoliation_risk`: `state_changing_operational`
- `gated_by`: same as `kill_c2_pipe`

## Tier 4 — Offensive containment

Visible only with `--enable-offensive` at startup (which also requires
`--enable-containment`) **and** `offensive.enabled: true` in config.

### `disrupt_team_server(address: str, technique: str) -> ContainmentResult`

Disrupts an adversary C2 team server at a declared address.

- `spoliation_risk`: `state_changing_external`
- `gated_by`: `--enable-offensive` + legal-ack phrase + per-action confirm

### `invalidate_staged_credentials(beacon_id: str) -> ContainmentResult`

Where feasible, invalidates credential material the attacker has staged
for use.

- `spoliation_risk`: `state_changing_external`
- `gated_by`: same as `disrupt_team_server`

## How tier gating is advertised

In Mode B and Mode C, tier gating is architectural: disabled-tier tools
are **not advertised** to the LLM. The LLM literally cannot see them in
the tool list. In Mode A, disabled-tier CLI commands refuse to run. See
[tier model — how tiers are enforced](../architecture/tier-model.md#how-tiers-are-enforced).

## Related

- [Tier model](../architecture/tier-model.md)
- [SIFT tools reference](sift-tools.md)
- [Shared brain](../architecture/shared-brain.md) for `IOCVerdict`,
  `HostEvidence`, etc.
