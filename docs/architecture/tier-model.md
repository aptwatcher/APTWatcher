# Tier model — capability tiers

> Architectural guardrail against accidental capability expansion.
> Everything beyond core triage is opt-in.

## The five tiers

| Tier | Name                     | Default     | Requires         |
|------|--------------------------|-------------|------------------|
| 0    | Core forensic triage     | **enabled** | SIFT + Protocol SIFT |
| 1    | External threat intel    | opt-in      | API keys / MCP endpoints |
| 2    | IR workflow integration  | opt-in      | GLPI instance + credentials |
| 3    | Defensive containment    | opt-in      | `--enable-containment` flag |
| 4    | Offensive containment    | **gated**   | `--enable-offensive` flag + runtime consent |

## Tier 0 — Core forensic triage

Always on. No network egress beyond what SIFT itself already does.

**Tools** (examples — full list in [Reference](../reference/mcp-tools.md)):

- `preflight()` — SIFT tool inventory & use-case profile validation
- `sift_update()` — consent-gated package refresh
- `knowledge_search(query)` — retrieval over `knowledge/`
- `extract_iocs(text)` — defang + regex
- `volatility_run(plugin, image)` — wrapped memory analysis
- `plaso_timeline(image)` — wrapped timeline extraction
- `bulk_extractor_run(image, filters)` — wrapped artifact extraction
- `yara_scan(target, ruleset)` — wrapped signature matching
- `audit_append(event)` — structured finding log

**Guarantee**: a Tier 0-only install can triage a host with **zero external
dependencies**. Useful for air-gapped analysis.

## Tier 1 — External threat intel

Intel fan-out via the [APT Watch orchestration pattern](../design/tier1-intel-lookup-pattern.md).

**Tools**:

- `check_ioc(value, ioc_type)` — fan-out lookup across all configured providers
- `correlate_host_against_intel(host_evidence)` — multi-source cross-reference
- `(future) submit_ioc(...)` — contribute observations back to APT Watch

**Providers** (any subset; all optional):

- [APT Watch API](../integrations/apt-watch.md)
- [MS Threat Analytics MCP](../integrations/ms-threat-analytics.md)

**Graceful degradation**: missing credentials → the provider is silently
skipped, not errored. If *all* providers are missing, `check_ioc` returns
`verdict: unknown` rather than failing.

## Tier 2 — IR workflow integration

Connect the agent into a real ticketing / knowledge-base workflow.

**Tools**:

- `glpi_ticket_create(...)` — file a ticket with the agent's findings
- `glpi_ticket_update(id, ...)` — add follow-ups as the investigation evolves
- `glpi_kb_search(query)` — look up prior similar incidents in the KB

See [GLPI integration](../integrations/glpi.md).

**Content format**: GLPI fields expect HTML, not Markdown. The MCP tool
wrapper handles that conversion transparently.

## Tier 3 — Defensive containment

Scoped disruption of active compromise — **on the compromised host only**.

**Tools**:

- `kill_c2_pipe(pipe_name)` — terminates named-pipe C2 channels
- `rst_established_session(pid, remote_addr, remote_port)` — sends TCP RST
  for an established outbound session
- `isolate_process(pid, method)` — suspends or kills a suspicious process

All operations:

- Gated by the `--enable-containment` startup flag
- Require runtime confirmation per action
- Write pre-state + post-state hashes to the audit log
- Target **only** the host being analyzed

See [cnc_disruptor integration](../integrations/cnc-disruptor.md).

## Tier 4 — Offensive containment

Targeting adversary infrastructure.

**Gated behind**:

1. `--enable-offensive` startup flag *in addition to* `--enable-containment`
2. A runtime warning banner requiring typed confirmation
3. A per-action legal/ethical acknowledgment

**Scope concern**: offensive actions touch infrastructure the operator does
not own. Legal exposure varies by jurisdiction. APTWatcher does not assess
that legality — the operator does.

For the hackathon demo, Tier 4 stays off. It exists as a capability
demonstration of the tier model's extensibility, not as a recommended
production feature.

## How tiers are enforced

**In Mode B and Mode C**: tier gating happens at MCP server startup. The
server reads `config.yaml`, and tools for disabled tiers are **not
advertised** to the client. The LLM literally cannot see them.

**In Mode A**: tier gating is enforced at the CLI entry. Disabled-tier
commands refuse to run with a clear error. Slightly weaker (the agent
still sees the commands exist) but sufficient.

## Why this matters for judging

The hackathon rubric weights **architectural guardrails over prompt-based
guardrails**. The tier model is architectural: if Tier 3 is off, the
containment tools are not in the tool list the LLM sees. There is no
prompt it can bypass to reach them. See
[Architecture overview](README.md#answering-the-hackathon-criteria) for the
full mapping of guardrails.
