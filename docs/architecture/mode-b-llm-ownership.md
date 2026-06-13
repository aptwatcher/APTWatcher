# Mode B — LLM orchestration ownership

> Who drives the Planner / Verifier / SelfCorrector loop when APTWatcher is
> deployed as a standalone MCP server?

## The question

In Mode A (direct agent extension), the CLI owns the agent loop: it picks a
backend (`--backend {null,anthropic}`), constructs a `ModelClient`, wires it
into `LLMPlanner` / `LLMVerifier` / `LLMSelfCorrector`, and runs the loop
locally. The audit log, KB-context injection, preflight gating and error
handling all live in `src/agent_extension/cli.py`.

In Mode B (`src/mcp_server/`), the server exposes individual Tier 0 tool
wrappers (`run_volatility`, `run_log2timeline`, `run_psort`, `run_bulk_extractor`,
`run_sift_update`) plus KB lookup tools. The LLM that calls those tools is
**not** APTWatcher — it's the MCP client (Claude Desktop, Claude Code,
OpenClaw, or any custom MCP runtime).

This leaves an ambiguity: **should the MCP server also ship an agent-loop
tool (`run_profile`, analogous to `aptwatcher run` in Mode A)?**

## Decision

**No.** Mode B does not own LLM orchestration. It exposes tools and
knowledge; the calling LLM runtime owns the plan → execute → verify →
self-correct cycle.

## Rationale

### 1. Structural guardrail is the whole point of Mode B

The core promise of Mode B is that the agent is *structurally incapable* of
misusing the host — no shell, no arbitrary code execution, only the typed
Tier 0 wrappers. Bolting an in-server agent loop back onto that surface
would re-introduce the very attack surface Mode B exists to eliminate: an
LLM making autonomous decisions with credentials inside the evidence-
handling environment.

### 2. Audit responsibility follows orchestration

`core.audit.AuditLogger` produces an append-only JSONL trail of every
plan/execute/verify step. In Mode A, that trail lives on the analyst's
host — which is fine, because that's where the LLM decisions are being
made. If Mode B ran its own loop, we'd have two audit trails (server and
client), neither of which is authoritative, and the chain-of-custody claim
becomes ambiguous. Letting the MCP client own the loop keeps one audit
boundary.

### 3. Preflight gating stays local, tool-granular

Preflight in Mode A runs once before the full loop. In Mode B, each tool
wrapper already performs its own probe (`probe_tool`) before executing and
returns a structured error if the dependency is missing. That is the
right granularity for Mode B: the client calls a tool, the tool gates
itself, the client decides what to do next.

### 4. Credential locality

In Mode A, the Anthropic API key sits on the analyst's workstation — the
same host that's already trusted with the KB and the tool binaries. In
Mode B, the server is often air-gapped or sits inside the evidence VLAN.
Putting an API key there means punching an outbound HTTPS hole through a
boundary we just argued should stay closed. The MCP client, by contrast,
already has a trust relationship with its model provider.

### 5. Error-handling semantics differ

The Mode A loop catches `AnthropicAdapterError` and exits `1`. A Mode B
server cannot exit — it has to surface the failure back to the MCP client
as a structured tool error. The error model for "my internal LLM failed"
vs "my subprocess tool failed" is different enough that mixing them in one
server is a footgun.

## What this means in practice

**Mode A** (`aptwatcher run`):
- Owns the agent loop.
- Owns backend selection (`--backend null|anthropic`).
- Owns audit logging.
- Owns KB-context injection into the planner.

**Mode B** (`aptwatcher-mcp serve`):
- Exposes Tier 0 tool wrappers as MCP tools.
- Exposes KB search as an MCP tool.
- Exposes profile metadata as an MCP resource.
- Does **not** expose a `run_profile` agent-loop tool.
- Does **not** accept an API key for an LLM provider.

**Mode C** (hybrid):
- Mode A CLI is the agent driver.
- Mode B server provides a subset of the tool surface when the agent wants
  the MCP guardrail for specific steps (e.g., volatility runs that touch
  sensitive memory images).
- The agent loop still lives in Mode A. Mode B remains a passive tool
  provider.

## Cross-references

- `docs/architecture/shared-brain.md` — where the common logic lives.
- `docs/architecture/deployment-modes.md` — the three modes at a glance.
- `docs/architecture/audit-logging.md` — why there is exactly one
  audit trail per incident.
- `src/agent_extension/cli.py` — Mode A agent-loop entry point.
- `src/mcp_server/` — Mode B tool wrappers.

## Revisit criteria

This decision should be reopened if any of the following becomes true:

1. A supported MCP client ships without native tool-loop orchestration
   (today all of Claude Desktop, Claude Code, and OpenClaw orchestrate
   tool calls themselves).
2. An operational requirement appears for a fully headless deployment
   where the server must run the loop unattended (e.g., scheduled
   triage). In that case, the correct response is a fourth surface
   (`aptwatcher daemon`) that imports `core` the same way Mode A does,
   not a Mode B extension.
3. The MCP protocol gains a standardized "sub-agent" primitive that
   makes in-server loops auditable across trust boundaries.
