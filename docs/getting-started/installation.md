# Installation

> Works for all three deployment modes. Mode-specific steps come after.

## Prerequisites

- SANS SIFT Workstation (Ubuntu 22.04 LTS based)
- Python 3.12 or later
- Git
- Protocol SIFT installed

Verify:

```bash
python3 --version    # >= 3.12
git --version
which protocol-sift  # should exist after Protocol SIFT install
```

## Clone

```bash
git clone https://github.com/aptwatcher/APTWatcher.git
cd APTWatcher
```

## Install the shared brain

APTWatcher uses a single Python package (`aptwatcher`) that holds the
shared brain (`src/core/`), the MCP server entry point (`src/mcp_server/`),
and the agent-extension entry point (`src/agent_extension/`). One install
gives you all three.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

After install, you should have on your PATH:

- `aptwatcher-preflight` — run the SIFT environment probe
- `aptwatcher-mcp-server` — launch the MCP server (Mode B)
- `aptwatcher` — CLI entry for the agent-extension scripts (Mode A)

## Configuration

APTWatcher reads `config.yaml` at repo root (or `$APTWATCHER_CONFIG`).
A minimal starter:

```yaml
tiers:
  tier_0: true       # core forensic triage (always on)
  tier_1: false      # external threat intel
  tier_2: false      # IR workflow (GLPI)
  tier_3: false      # defensive containment
  tier_4: false      # offensive containment (requires second flag)

profile: windows-host-triage   # see docs/use-cases/

audit:
  log_dir: ./logs
  rotation: daily

# Only read if the matching tier is enabled
intel:
  apt_watch:
    base_url: https://api.aptwatch.org
    api_key_env: APTWATCH_API_KEY
  ms_threat_analytics:
    mcp_stdio_cmd: /usr/local/bin/ms-threat-analytics-mcp
```

Credentials are **never** read from this file — only the environment variable
names are. Export the actual secret in your shell:

```bash
export APTWATCH_API_KEY='…'
```

## Verify

Run the preflight probe:

```bash
aptwatcher-preflight --profile windows-host-triage
```

You should see a report listing each required tool with its version.
Missing tools → install them before proceeding. See
[Use cases](../use-cases/README.md) for what each profile requires.

## Next

Pick your mode:

- [Mode A — Direct Agent Extension](mode-a-direct-agent.md)
- [Mode B — Custom MCP Server](mode-b-mcp-server.md)
- [Mode C — Hybrid](mode-c-hybrid.md)

Or run the quick start: [Try it out](try-it-out.md).

!!! note "In development"
    APTWatcher is pre-alpha. Commands and config above reflect the target
    design; implementation is in progress. See the GitHub issue tracker
    for current status.
