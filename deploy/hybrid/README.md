# Deploy — Mode C (Hybrid)

Mode C runs Mode A and Mode B simultaneously: the host agent (Claude
Code) uses the APTWatcher system prompt *and* attaches to the APTWatcher
MCP server as one of its tool sources. This is the recommended
deployment for the hackathon demo and for production triage.

Use this mode when:

- You want the typed safety of MCP tools *plus* the operator ergonomics
  of Claude Code slash commands.
- You're running the demo: Mode C shows both the agent's reasoning (Mode
  A) and the MCP tool calls (Mode B) side-by-side in the audit log.
- You want to expose APTWatcher to another MCP client (Claude Desktop
  on an analyst workstation) while the operator drives from Claude Code
  on the SIFT VM.

## Install

```bash
cd APTWatcher
uv sync
aptwatcher version && aptwatcher-mcp --help
```

## Configure both surfaces

**Prompt side** (Mode A): follow [`deploy/claude-code/README.md`](../claude-code/README.md).

**Server side** (Mode B): follow [`deploy/mcp-server/README.md`](../mcp-server/README.md).

Wire Claude Code to the MCP server by adding an MCP config entry that
points at `aptwatcher-mcp`. Claude Code's CLI exposes this via
`claude mcp add aptwatcher aptwatcher-mcp -- --config /abs/path/config.yaml`.

## Operator flow

```bash
# 1. Start a triage session. Claude Code loads the APTWatcher prompt
#    and auto-connects to the APTWatcher MCP server.
claude

# 2. Inside Claude Code:
#    > /preflight windows-host-triage /mnt/ev/mem.raw
#    (The prompt uses MCP tools; preflight ran via the server.)

# 3. Hand over the incident brief. The agent plans, runs SIFT tools,
#    drafts findings, runs self-correction, emits the report. Every
#    tool call lands in logs/<incident_id>/audit.jsonl.
```

## Why hybrid wins for the demo

- **Reasoning is visible** — Claude Code shows the plan + narration.
- **Tool calls are auditable** — MCP calls go through the typed server
  and land in the audit log with pre/post hashes for state-changing
  operations.
- **Tiers are enforced server-side** — the prompt can ask for a Tier 3
  tool, but if the server config has Tier 3 disabled the tool does not
  exist for this run. No prompt-based guardrail to bypass.

## Troubleshooting

- Double execution (tool runs twice): the prompt and the client agent
  both tried to invoke the same action via different routes. Keep tool
  invocation in the MCP layer; the prompt narrates and plans only.
- Prompt visible but MCP tools missing in the client: `aptwatcher-mcp`
  startup must succeed independently first; check stderr.

## References

- [Shared brain](../../docs/architecture/shared-brain.md)
- [Deployment modes](../../docs/design/deployment-modes.md)
- [Self-correction](../../docs/architecture/self-correction.md)
