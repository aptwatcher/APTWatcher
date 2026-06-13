# Mode B — Custom MCP Server

> Standalone MCP server exposing typed forensic, intel, and knowledge tools.
> Any MCP-capable client can consume them. Strongest architectural
> guardrails.

## When to use Mode B

- You want the highest possible safety ceiling — the agent cannot shell out
- You are bringing your own agent runtime (Claude Desktop, Cursor, Cline,
  a custom Python runner)
- You need output parsing before raw tool dumps hit the LLM context
- You value auditability over setup speed

## How it works

```
 ┌────────────┐      MCP (stdio)     ┌─────────────────────────┐
 │ Agent host │ ──────────────────▶  │ aptwatcher-mcp-server   │
 │ (any MCP   │                      │  ┌───────────────────┐  │
 │  client)   │ ◀──────────────────  │  │  src/core/ (brain)│  │
 └────────────┘   typed responses    │  └───────────────────┘  │
                                     └─────────────────────────┘
                                          │
                                          ├─ knowledge/  (KB grounding)
                                          ├─ SIFT tools (via subprocess)
                                          ├─ intel adapters (Tier 1)
                                          └─ audit log
```

The agent sees only typed tools. No `Bash`, no `Shell`, no raw file read.
Every tool parses its output and returns a structured JSON object.

## Install

Follow [common installation](installation.md), then start the server:

```bash
aptwatcher-mcp-server
# listens on stdio (MCP default)
```

## Connect your client

### Claude Desktop

Edit `~/.config/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "aptwatcher": {
      "command": "aptwatcher-mcp-server"
    }
  }
}
```

### Cursor / Cline / Aider

See each tool's MCP docs — the stdio command is the same:
`aptwatcher-mcp-server`.

### Custom Python runner

```python
from anthropic import Anthropic
# Plus any MCP client library.
# See deploy/mcp-server/examples/custom_runner.py
```

## Guardrails in Mode B

**Fully architectural:**

- The server exposes a fixed set of typed tools. Nothing else. Tools
  named `execute_shell`, `read_file`, `write_file` (unconstrained) do not
  exist.
- Every tool has a JSON schema. Inputs are validated before any subprocess
  runs. Outputs are parsed and normalized.
- The audit log is written by the server, not the agent — the agent cannot
  skip or edit entries.
- Tier flags gate which tools are even advertised to the client. If Tier 3
  is off, containment tools are not in the tool list the agent sees — they
  are structurally unreachable.

## Tool inventory

See [MCP tool inventory](../reference/mcp-tools.md) for the full typed
surface (inputs, outputs, tier, spoliation risk).

## Next

- [Try it out](try-it-out.md)
- [Mode C — Hybrid](mode-c-hybrid.md) — combine with Claude Code
- [Architecture — Evidence integrity](../architecture/evidence-integrity.md)
