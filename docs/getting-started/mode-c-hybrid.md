# Mode C — Hybrid (recommended)

> Claude Code as the agent host, APTWatcher MCP server providing typed
> intel / knowledge / audit tools. Layered guardrails — prompt-based
> where shell flexibility is genuinely useful, architectural everywhere else.

## When to use Mode C

- Almost always. This is the recommended mode for the demo video, for
  production IR use, and for hackathon judges.
- You get the ergonomics of Claude Code and the safety ceiling of the MCP
  server.

## How it works

Claude Code retains its `Bash` tool — a senior analyst sometimes needs
shell flexibility (a one-liner `grep` across `/var/log`, an ad-hoc
`strings | grep` on a memory dump). APTWatcher's prompt disciplines that
usage.

Everything that should **not** be shell-accessible runs through the MCP
server:

- Intel lookups (you don't want the agent curl-ing APIs directly)
- Knowledge-base queries (typed search over `knowledge/`)
- Audit-log writes (structurally enforced)
- Containment actions (tier-gated, confirmation-gated)

```
 ┌─────────────┐      Claude Code tools      ┌──────────────┐
 │  Claude Code│ ─── Bash, Read, Edit, … ──▶ │  SIFT VM     │
 │  (Mode A    │                             └──────────────┘
 │   surface)  │      MCP (stdio)            ┌──────────────────────────┐
 │             │ ──────────────────────────▶ │ aptwatcher-mcp-server    │
 │             │                             │  ┌─────────────────────┐ │
 │             │ ◀── typed responses ─────── │  │ src/core/  (brain)  │ │
 └─────────────┘                             │  └─────────────────────┘ │
                                             └──────────────────────────┘
```

## Install

Follow [Mode A](mode-a-direct-agent.md) *and* [Mode B](mode-b-mcp-server.md)
installs. Then register the MCP server with Claude Code:

```bash
claude mcp add aptwatcher stdio aptwatcher-mcp-server
```

Verify:

```bash
claude mcp list
```

You should see `aptwatcher` listed with its typed tools.

## Using it

Open Claude Code in the APTWatcher directory. The `CLAUDE.md` prompt is
auto-loaded; the MCP server's tools appear alongside Claude Code's native
tools.

Try:

```
/aptw-scenario s01
```

Or describe the task in natural language — the system prompt steers the
agent through preflight → triage → correlation → report.

## Guardrails in Mode C

| Guardrail | Source |
|---|---|
| Typed intel / knowledge / audit / containment tools | MCP server (architectural) |
| Output parsing before LLM context | MCP server (architectural) |
| Correlation-ID-stamped audit trail | MCP server (architectural) |
| Tier gating (what tools are even advertised) | MCP server (architectural) |
| SIFT tool orchestration & reasoning discipline | Prompt + CLAUDE.md (prompt-based) |
| Self-correction cadence | Prompt (prompt-based) |

The demo video uses Mode C because it lets judges see **both** guardrail
types active in one run. It also makes the architecture diagram honest:
our answer to "prompt vs architectural" is "layered, and here's which is
which."

## Next

- [Try it out](try-it-out.md)
- [Architecture overview](../architecture/README.md)
- [Scenarios](../scenarios/README.md) — pick one and run it in Mode C
