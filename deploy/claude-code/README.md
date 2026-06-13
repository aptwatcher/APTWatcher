# Deploy — Mode A (Direct Agent Extension)

Mode A runs APTWatcher as a set of slash commands and a system prompt
inside a host agent (Claude Code, or any Claude-SDK-based agent).
No MCP server process; the agent calls `core` via the CLI.

Use this mode when:

- You're iterating on prompts and want fast feedback.
- You're presenting the agent to an operator who already lives inside a
  Claude Code session on the SIFT VM.
- You don't need other MCP-capable clients to reach APTWatcher.

## Requirements

- SANS SIFT Workstation (or Ubuntu 22.04+ with Protocol SIFT tools).
- Python 3.11+.
- Claude Code CLI installed and authenticated.
- Repo cloned to a known path (referred to below as `$APTW`).

## Install

```bash
cd "$APTW"
uv sync                             # or: pip install -e ".[dev]"
aptwatcher version                  # smoke-test the install
```

## Wire the prompt

Copy (or symlink) the APTWatcher system prompt into the host agent's
CLAUDE.md or equivalent:

```bash
cp "$APTW/prompts/system.md"    ~/.claude/CLAUDE-APTWatcher.md
cp "$APTW/prompts/self-correction-checklist.md" ~/.claude/
```

Then either start Claude Code from a directory whose CLAUDE.md imports
the APTWatcher prompt, or append the contents to the project CLAUDE.md
directly.

## Minimal operator flow

```bash
# 1. Preflight — always first.
aptwatcher preflight --profile windows-host-triage --evidence /mnt/ev/mem.raw

# 2. Hand off to Claude Code; paste the incident brief.
#    The agent plans, runs tools via shell, and writes findings.

# 3. After the agent runs self-correction and emits the report,
#    the audit log lives here:
ls logs/<incident_id>/audit.jsonl
```

## Troubleshooting

- `preflight` fails with *missing required tools*: install SIFT's
  `forensic-tools` meta-package or run `sudo apt install volatility3
  bulk-extractor plaso-tools yara`.
- `knowledge_search` returns nothing: point it at the populated KB with
  `--knowledge-root "$APTW/knowledge"`.

## References

- [Shared brain](../../docs/architecture/shared-brain.md)
- [Self-correction](../../docs/architecture/self-correction.md)
- [Use-case profiles](../../docs/use-cases/README.md)
