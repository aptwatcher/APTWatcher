# Deployment modes

> Three ways to run APTWatcher. One brain.

For installation and usage, see:
- [Mode A — Direct Agent Extension](../getting-started/mode-a-direct-agent.md)
- [Mode B — Custom MCP Server](../getting-started/mode-b-mcp-server.md)
- [Mode C — Hybrid](../getting-started/mode-c-hybrid.md)

For deeper implementation detail: [design/deployment-modes.md](../design/deployment-modes.md).

## Comparison

| Aspect | Mode A | Mode B | Mode C |
|---|---|---|---|
| Setup complexity | Low | Medium | Medium |
| Guardrail kind | Prompt + typed CLI | Architectural | Layered |
| Agent has shell access | Yes (Claude Code `Bash`) | No | Yes (disciplined) |
| Output parsing before LLM | Per-CLI, JSON | MCP-level | Both |
| Agent runtimes supported | Claude Code, OpenClaw | Any MCP client | Claude Code + MCP |
| Recommended for demo | No | Optional cameo | **Yes** |
| Recommended for production | No | Yes (air-gapped) | **Yes** (general) |
| Recommended for audit review | Partial | Yes | Yes |

## When does each mode win?

**Mode A wins when** setup speed matters more than safety ceiling. You have
Claude Code; you want APTWatcher's intelligence; you trust the operator to
supervise. Fastest path to value.

**Mode B wins when** you need the agent to be *structurally incapable* of
misusing the host. Air-gapped analyst workstations. Evidence-handling
environments with strict chain-of-custody. Non–Claude-Code runtimes.

**Mode C wins when** you want both. The hackathon demo and most production
use cases fall here.

## One codebase, two entry points

```
src/
├── core/                 Shared brain — all business logic
├── agent_extension/      Mode A entry point (CLI callable from Claude Code)
└── mcp_server/           Mode B/C entry point (MCP server)
```

A deployment mode never owns business logic. If you're tempted to put
logic in `agent_extension/` or `mcp_server/`, it belongs in `core/`.

This is what makes the three-mode offering honest: it's not three
half-finished products, it's one product with three surfaces.
