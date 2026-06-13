# APTWatcher DFIR

> Autonomous Digital Forensics & Incident Response agent built on Protocol SIFT.
> Submission for the **FIND EVIL!** hackathon (SANS/GIAC, Apr 15 – Jun 15, 2026).

APTWatcher is a defensive AI agent that triages compromised hosts at machine
speed, correlates forensic artifacts across multiple intelligence sources, and
produces analyst-grade, audit-backed IR reports — without hallucinating and
without ever touching the evidence.

## Why

In 2025, the GTG-1002 campaign demonstrated a state-sponsored operation in
which an agentic LLM executed roughly 80–90% of the attack chain — recon,
initial access, lateral movement, data staging — without human keystrokes.
The traditional defender loop (a ticket, a human analyst, a multi-day triage
window) cannot match an adversary that completes its objective in minutes.
See the threat model in [`docs/SCOPE.md`](docs/SCOPE.md).

APTWatcher's answer is parity of speed, not parity of autonomy. It runs the
same primitives the attacker does — agentic orchestration, an MCP tool
surface, iterative plan-execute-verify loops — but constrained by a strict
read-only evidence mode, consent-gated state changes, and an append-only
signed audit log. The defender keeps authority over chain of custody and
publication; the agent supplies the speed.

## Quick start

One idempotent installer for any Linux host with Python 3.11+ (a SIFT
workstation gets the full toolchain probed automatically). It refuses to run
as root and never writes outside `~/APTWatcher`:

```bash
curl -fsSL https://raw.githubusercontent.com/aptwatcher/APTWatcher/main/install.sh | bash
source ~/APTWatcher/.venv/bin/activate
```

Three commands that work immediately — no forensic VM, no API keys, no real
evidence:

```bash
aptwatcher version    # build and environment info
aptwatcher profiles   # list the bundled triage profiles
aptwatcher eval       # run the accuracy harness against shipped fixtures
```

The full ten-minute judge-facing walkthrough — dry-run triage, analysis
bundle, stub publication, self-scoring — is in
[`docs/TRY-IT-OUT.md`](docs/TRY-IT-OUT.md).

## What's inside

| Component | Count | Notes |
|---|---|---|
| MCP tools | 51 | 42 tier-0 read-only forensic + 9 tier-1 intel |
| CLI subcommands | 9 | `version`, `profiles`, `preflight`, `knowledge-search`, `run`, `analyze`, `publish`, `eval`, `audit-render` |
| SIFT tool wrappers | 10/10 | volatility3, plaso, bulk_extractor, sleuthkit, yara, hayabusa, regripper, chainsaw, timesketch, sift_update |
| Knowledge base entries | 32 | clean-room authored, cited in findings |
| Accuracy fixtures | 8 | mean F1 1.000 on seed fixtures — this validates the plumbing, not field accuracy; see [`docs/ACCURACY.md`](docs/ACCURACY.md) |
| Publication adapters | 5 | Netcraft, MISP, GLPI, TAXII 2.1, stub — all dry-run by default |
| Tests | 742 passing | 1 skipped; ruff clean; mypy strict clean on `src/core`; Python 3.11+ |

## Architecture

APTWatcher ships as **three deployment modes sharing one brain**:

- **Mode A — Direct Agent Extension** for Claude Code / OpenClaw users
- **Mode B — Custom MCP Server** for strict architectural guardrails
- **Mode C — Hybrid** combining both (recommended)

The same curated knowledge base, intel adapters, audit logger, and
self-correction prompts back all three modes. See
[`docs/design/deployment-modes.md`](docs/design/deployment-modes.md).

Capabilities are tiered and opt-in:

| Tier | Capability | Default | Sources |
|------|---------------------------------|-------------|------------------------------------------|
| 0 | Core forensic triage | **enabled** | Protocol SIFT tools, `knowledge/` base |
| 1 | External threat intelligence | opt-in | APT Watch API, MS Threat Analytics MCP |
| 2 | IR workflow integration | opt-in | GLPI MCP (tickets, KB) |
| 3 | Defensive containment | opt-in | cnc_disruptor (pipe kill, session RST) |
| 4 | Offensive containment | **gated** | cnc_disruptor (legal/ethical warning) |

Tier 0 is read-only by construction; tier 1 and above require an explicit
`consent_granted` audit event before any tool fires. The full design is in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), and the operating contract
the agent itself runs under — the orchestrator brain, with the Prime
Directive, role allow-lists, and failure-mode playbook — is
[`CLAUDE.md`](CLAUDE.md).

## Demo

- [`demo/SCRIPT.md`](demo/SCRIPT.md) — the live demo script.
- [`docs/demo/WALKTHROUGH.md`](docs/demo/WALKTHROUGH.md) — annotated
  end-to-end walkthrough with expected output.
- [`docs/scenarios/`](docs/scenarios/README.md) — rubric scenarios S01–S03
  (single Windows compromise, multi-host lateral movement, ransomware
  pre-detonation).
- [`scenarios/`](scenarios/README.md) — demo scenarios S04–S05
  (signed offline-to-online bundle handoff; one-shot E01 triage to a signed
  IncidentBundle on a 14.5-minute budget).

## Submission docs

For hackathon judges, the four submission documents in one place:

- [`docs/TRY-IT-OUT.md`](docs/TRY-IT-OUT.md) — step-by-step local run against the
  shipped fixtures (no live deployment by design: read-only, offline).
- [`docs/DATASET.md`](docs/DATASET.md) — evidence dataset inventory, provenance,
  and clean-room policy.
- [`docs/ACCURACY.md`](docs/ACCURACY.md) — accuracy methodology, baseline, and
  honest limitations.
- [`docs/DEVPOST.md`](docs/DEVPOST.md) — the project narrative.

## Guardrails

- **Read-only by default.** All 42 tier-0 forensic tools never modify
  evidence and never emit outbound traffic. Derivatives go to `work/` and
  `out/`, never next to the artifact.
- **Consent gating.** Tier 1+ tools require a matching `consent_granted`
  audit event, enforced in the MCP server — a tool cannot bypass it. See
  [`docs/design/tier-gating.md`](docs/design/tier-gating.md).
- **Dry-run publication.** All five adapters default to `dry_run=True`;
  going live requires the `--live` flag plus a signed IncidentBundle.
- **Signed audit log.** Every plan/execute/verify/self-correct step emits an
  append-only, signed AuditEvent with token telemetry; render it with
  `aptwatcher audit-render`. Findings cite event IDs or they are not findings.
- **Signed bundles.** Ed25519-signed IncidentBundles carry results across the
  offline-to-online gap, with tamper detection on import. See
  [`docs/design/evidence-integrity.md`](docs/design/evidence-integrity.md).
- **No shell escapes.** Tools invoke binaries by absolute path with
  arg-vector calls — no `shell=True`, no `eval`, no string interpolation
  into a shell.

## APTWatcher DFIR is not APTWatch

The `DFIR` qualifier exists to disambiguate this project from a similarly named
one. APTWatcher DFIR (this project) is a **defensive digital-forensics and
incident-response agent**. APTWatch (`aptwatch.org`) is a separate threat
intelligence platform that exposes `api.aptwatch.org`. APTWatcher consumes that
API as one of its MCP tools — they are independent projects under the same brand
family. The package, CLI (`aptwatcher`), and repository keep the short name
`APTWatcher`; `APTWatcher DFIR` is the full display name.

## Status

In development. See [`SUBMISSION-CHECKLIST.md`](SUBMISSION-CHECKLIST.md) for
the pre-submission gate and the GitHub issue tracker for current work.

## License

MIT — see [`LICENSE`](LICENSE).
