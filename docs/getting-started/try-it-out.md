# Try it out — 10-minute quick start

> The fastest path from "clone" to "APTWatcher triaged a host."

This runs scenario [S01 — Single Windows host compromise](../scenarios/S01-single-windows-compromise.md)
against a pre-built synthetic dataset, using **Mode C (Hybrid)**.

## You need

- SIFT Workstation VM with Protocol SIFT installed
- 10 minutes
- No API keys required (Tier 1 stays disabled)

## Steps

### 1. Clone & install (3 min)

```bash
git clone https://github.com/aptwatcher/APTWatcher.git
cd APTWatcher
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

### 2. Pull the sample dataset (2 min)

```bash
./scripts/fetch-sample-dataset.sh s01
# Downloads ~1.2 GB synthetic case into datasets/s01/
```

See [Datasets](../datasets/README.md) for what's in the archive.

### 3. Run preflight (30 sec)

```bash
aptwatcher-preflight --profile windows-host-triage
```

Expected: all Tier 0 tools green. If anything's missing, the preflight tells
you the exact install command.

### 4. Start the MCP server (background)

```bash
aptwatcher-mcp &
```

### 5. Run the demo

```bash
aptwatcher run-scenario s01 --mode hybrid
```

This launches Claude Code with APTWatcher's system prompt, attaches the MCP
server, and hands the agent the synthetic disk image + memory dump from
`datasets/s01/`. The agent should:

1. Run preflight and record tool versions in the audit log.
2. Plan its triage using the `windows-host-triage` profile.
3. Execute forensic tools through the MCP server.
4. Cross-reference observed IOCs locally (Tier 1 is off in this quick start).
5. Produce a structured finding report in `logs/s01-<timestamp>/report.md`.
6. Demonstrate at least one **self-correction event** where it catches a
   false lead.

Total agent runtime: **3–5 minutes** on typical SIFT VM specs.

### 6. Read the report

```bash
less logs/s01-*/report.md
```

And the audit trail:

```bash
less logs/s01-*/audit.jsonl
```

Every finding in the report has a correlation ID that traces back to a
specific tool invocation in the audit log.

## What to try next

- Enable Tier 1 with an APT Watch API key: [APT Watch integration](../integrations/apt-watch.md)
- Run the more complex scenarios: [S02](../scenarios/S02-multi-host-lateral-movement.md),
  [S03](../scenarios/S03-ransomware-pre-detonation.md)
- Switch to a pure [Mode B](mode-b-mcp-server.md) run to see the
  architectural-only path
- Bring your own dataset — see [Datasets](../datasets/README.md)

!!! note "In development"
    This quick start reflects the target experience. The `fetch-sample-dataset.sh`
    script and scenario harness are in development; see the GitHub issue
    tracker for status.
