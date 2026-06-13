# Getting started

Three routes in, depending on what you already have running.

## Choose your mode

| You have… | Start here |
|---|---|
| Claude Code already set up and you want to extend it | [Mode A — Direct Agent Extension](mode-a-direct-agent.md) |
| Any MCP-capable client and want strict architectural guardrails | [Mode B — Custom MCP Server](mode-b-mcp-server.md) |
| Claude Code and want the safest, most auditable setup | [Mode C — Hybrid](mode-c-hybrid.md) (recommended) |

Not sure? Mode C is the right default. It's what the demo video uses, and
it's what we suggest to hackathon judges.

## Before you install

You will need:

- **SANS SIFT Workstation** (Ubuntu 22.04 LTS variant) — host for the agent
  and the forensic tooling. See [sift-workstation install](https://www.sans.org/tools/sift-workstation/).
- **Python 3.12+** on the SIFT VM.
- **Protocol SIFT** installed (`curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash`).
- (Optional) API keys for Tier 1 intel sources — see
  [Integrations](../integrations/README.md).
- (Optional) A GLPI instance for Tier 2 workflow — see
  [GLPI](../integrations/glpi.md).

## Next

- [Installation](installation.md) — one-page install guide common to all modes.
- [Try it out](try-it-out.md) — 10-minute quick start that runs a sample
  scenario end to end.
