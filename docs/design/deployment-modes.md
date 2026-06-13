# Deployment Modes — One Brain, Three Surfaces

> APTWatcher separates **what the agent knows and reasons about** from
> **how the agent is hosted**. The brain stays constant; the deployment
> surface is your choice.

---

## Why three modes

The FIND EVIL! hackathon accepts multiple architectural approaches, and real
users have different setups. Instead of picking one and excluding the rest,
APTWatcher ships all three, sharing a single core library.

| Mode | Name                      | Best for                                              |
|------|---------------------------|-------------------------------------------------------|
| A    | Direct Agent Extension    | Users already running Claude Code / OpenClaw          |
| B    | Custom MCP Server         | Users who want strict architectural guardrails        |
| C    | Hybrid                    | Judges and production — best of both                  |

## Shared brain (the "what")

All three modes use the same `src/core/` library, which provides:

- **Preflight** (`core/preflight.py`) — SIFT tool inventory, use-case profiles
- **Knowledge** (`core/knowledge.py`) — indexed search over `knowledge/`
- **Intel adapters** (`core/intel/`) — APT Watch, MS Threat Analytics, future
  providers — all returning a normalized `IOCVerdict`
- **IOC utilities** (`core/ioc_extract.py`) — defang, extract, normalize
- **Correlation** (`core/correlation.py`) — cross-reference observables against intel
- **Audit logger** (`core/audit.py`) — correlation-ID-stamped event stream
- **Types** (`core/types.py`) — `IOCVerdict`, `HostEvidence`, `Finding`, etc.

All three modes use the same prompt pack (`prompts/`):
- System prompt anchoring the agent in senior-analyst reasoning
- Self-correction checklists
- Procedural reasoning templates (per use-case profile)

## Mode A — Direct Agent Extension

**Surface**: Claude Code (or OpenClaw) reads a `CLAUDE.md`, gets slash
commands, invokes Python scripts under `src/agent_extension/` that import
from `src/core/`.

**Guardrails**: Prompt-based primarily, with structured tool wrappers as a
second layer. Scripts have typed argparse interfaces — the agent can only
call them with valid arguments.

**Install**: Clone repo, run `pip install -e .`, copy `deploy/claude-code/CLAUDE.md`
into your working directory. Done.

**Trade-off**: Fastest to set up. Agent has more freedom to misstep
(shell access via Bash tool remains). Prompt engineering carries more weight.

## Mode B — Custom MCP Server

**Surface**: A standalone MCP server (`src/mcp_server/`) exposes typed tools.
Any MCP-capable agent (Claude Desktop, Cursor, Cline, a custom runner) can
consume them.

**Guardrails**: Architectural. The agent can't shell out — only typed tools
exist. Tool outputs are parsed and summarized before reaching the LLM's
context window (big deal for forensic output dumps).

**Install**: Clone repo, run `pip install -e .`, run
`aptwatcher-mcp-server`, point your MCP client at its stdio endpoint.

**Trade-off**: Highest ceiling on safety, accuracy, and auditability. Also
the most work to build — every tool needs a schema, parser, and test.

## Mode C — Hybrid (recommended for production and demo)

**Surface**: Claude Code runs the agent loop and executes shell for SIFT
tools; the MCP server provides the typed intel/knowledge/audit tools it
shouldn't be handed shell access for.

**Guardrails**: Layered. Prompt-based for SIFT tool invocation (where shell
flexibility is genuinely useful for a senior analyst), architectural for
everything else (intel lookups, KB search, audit writes, containment).

**Install**: Follow Mode B install, then add the MCP server to Claude Code's
config with `claude mcp add aptwatcher stdio aptwatcher-mcp-server`.

**Trade-off**: Best of both. Slight config complexity. This is the mode we
use for the demo video and the one we recommend to judges.

---

## What this means for the codebase

```
src/
├── core/                    # Shared brain — imported by both entry points
├── agent_extension/         # Mode A entry point (CLI scripts)
└── mcp_server/              # Mode B entry point (MCP server)
```

**A deployment mode never owns business logic.** If you find yourself
writing logic in `agent_extension/` or `mcp_server/`, it belongs in `core/`.

---

## Impact on the 8 deliverables

- **Architecture diagram (#3)** must show the three modes and make the
  core/surface split explicit. This is the clearest possible answer to
  "identify pattern, distinguish prompt vs architectural guardrails".
- **Devpost description (#4)** frames the project as "one brain, three
  surfaces" — a clean pitch.
- **Try-it-out (#7)** ships three quick-starts, one per mode.
- **Demo video (#2)** uses Mode C (hybrid) as the primary flow, with a
  ~20s interlude showing the same task via pure Mode B to demonstrate
  architectural isolation.
