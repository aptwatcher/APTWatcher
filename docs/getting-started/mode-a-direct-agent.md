# Mode A — Direct Agent Extension

> Extend Claude Code (or OpenClaw) with APTWatcher's prompts, scripts,
> and knowledge base. Fastest to set up; guardrails are primarily
> prompt-based with structured CLI wrappers as a second layer.

## When to use Mode A

- You already have Claude Code running on SIFT
- You want the fastest path to a working agent
- You accept that the agent keeps shell access (`Bash` tool), and rely on
  prompt engineering + typed CLI wrappers for guardrails

## How it works

Claude Code reads a `CLAUDE.md` that:

- Installs APTWatcher's system prompt (senior-analyst reasoning + self-correction)
- Registers slash commands for the main workflows
- Points the agent at the CLI entry `aptwatcher` which dispatches to
  `src/agent_extension/` scripts, each importing `src/core/`

Every CLI script uses typed `argparse` — the agent can't pass malformed
arguments. Output is JSON, so the agent consumes structured data, not raw
text dumps.

## Install

Follow [common installation](installation.md), then:

```bash
cp deploy/claude-code/CLAUDE.md .
cp -r deploy/claude-code/commands ~/.claude/commands/aptwatcher
```

Open Claude Code in the directory — the `CLAUDE.md` is picked up automatically.

## Slash commands

| Command | Purpose |
|---|---|
| `/aptw-preflight` | Run SIFT environment check |
| `/aptw-triage <image_path>` | Triage a disk image using the current profile |
| `/aptw-scenario <id>` | Run an end-to-end scenario from `docs/scenarios/` |
| `/aptw-ioc <value>` | Look up an IOC (Tier 1 must be enabled) |
| `/aptw-report` | Generate a structured finding report |

Full list: [MCP tool inventory](../reference/mcp-tools.md) — the same tools
are reachable via CLI in Mode A.

## Guardrails in Mode A

**Primarily prompt-based**, with these structural elements:

- CLI arguments typed via argparse — bad args rejected at the boundary
- Output always JSON — agent parses, never regexes free text
- Audit logger wraps every CLI invocation — no untracked execution
- Tiered capability flags in `config.yaml` — containment stays off unless
  explicitly enabled

What Mode A does **not** give you (and Mode B does):

- Hard impossibility of running destructive shell commands (Bash is still
  available in Claude Code)
- MCP-level output parsing before the LLM's context sees it

If those matter for your evaluation: use [Mode C](mode-c-hybrid.md).

## Next

- [Try it out](try-it-out.md)
- [Mode B — Custom MCP Server](mode-b-mcp-server.md) — compare & contrast
- [Mode C — Hybrid](mode-c-hybrid.md) — the best of both
