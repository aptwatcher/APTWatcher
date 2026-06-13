# Architecture

APTWatcher is built around one idea: **separate what the agent knows and
reasons about from how the agent is hosted.** The brain stays constant;
the deployment surface is pluggable.

## The one-diagram version

```
                     ┌────────────────────────────────┐
                     │        Agent runtime           │
                     │  (Claude Code, Claude Desktop, │
                     │   Cursor, custom Python, …)    │
                     └──────────────┬─────────────────┘
                                    │
               ┌────────────────────┼───────────────────────┐
               │                    │                       │
      ┌────────▼────────┐   ┌───────▼────────┐      ┌───────▼──────┐
      │  Mode A         │   │  Mode C        │      │  Mode B      │
      │  prompt +       │   │  hybrid        │      │  pure MCP    │
      │  CLI scripts    │   │  (recommended) │      │  server      │
      └────────┬────────┘   └───────┬────────┘      └───────┬──────┘
               │                    │                       │
               └────────────────────┼───────────────────────┘
                                    ▼
                    ┌────────────────────────────┐
                    │       src/core/  — BRAIN    │
                    │  preflight · knowledge ·    │
                    │  intel adapters · correlation│
                    │  IOC extract · audit · types│
                    └──────────────┬──────────────┘
                                   │
       ┌───────────────┬───────────┼──────────────┬────────────────┐
       ▼               ▼           ▼              ▼                ▼
  ┌────────┐     ┌──────────┐  ┌───────┐     ┌────────┐       ┌──────────┐
  │ Tier 0 │     │ Tier 1   │  │ Tier 2│     │ Tier 3 │       │ Tier 4   │
  │ SIFT + │     │ Intel    │  │ GLPI  │     │ Contain│       │ Offensive│
  │ KB     │     │ (APTWatch│  │       │     │ (pipe, │       │ (gated)  │
  │ (on)   │     │  + MS TA)│  │       │     │  RST)  │       │          │
  └────────┘     └──────────┘  └───────┘     └────────┘       └──────────┘
    always        opt-in        opt-in         opt-in          flag+warn
```

## Two axes, independent

**Deployment mode (A / B / C)** — *where the agent lives* and how it calls
tools.

**Capability tier (0 / 1 / 2 / 3 / 4)** — *what tools are even available*
and at what risk level.

A Mode B install with only Tier 0 enabled is a rock-solid, air-gapped,
local-only forensic agent — **the same codebase** as a Mode C install with
Tiers 0–2 enabled, which is a full IR workflow agent with ticketing and
live intel.

## Further reading

- [Deployment modes](deployment-modes.md) — what A, B, C mean in detail
- [Tier model](tier-model.md) — the capability tiers explained
- [Shared brain](shared-brain.md) — tour of `src/core/`
- [Mode B — LLM ownership](mode-b-llm-ownership.md) — why the MCP server doesn't own the agent loop
- [Evidence integrity](evidence-integrity.md) — spoliation risk & hash chains
- [Audit logging](audit-logging.md) — finding → tool call traceability
- [Self-correction](self-correction.md) — how the agent catches itself

## Answering the hackathon criteria

The judging rubric explicitly asks us to **"identify pattern, distinguish
prompt vs architectural guardrails."**

Our answer:

| Guardrail | Kind | Where it lives |
|---|---|---|
| Typed MCP tool signatures | Architectural | `src/mcp_server/` |
| Output parsing before LLM context | Architectural | MCP tool implementations |
| Tier gating (tools not advertised if disabled) | Architectural | MCP server startup |
| Evidence hash chain | Architectural | `src/core/audit.py` |
| Reasoning discipline / triage sequencing | Prompt | `prompts/system.md` |
| Self-correction cadence | Prompt | `prompts/self_correction.md` |
| Tool choice within a tier | Prompt | Reasoning templates |

Mode A leans on the bottom half; Mode B leans on the top half; Mode C uses
both. The point isn't that one kind of guardrail is universally better —
it's that **we know which is which**, and we can show judges exactly where
each one applies.
