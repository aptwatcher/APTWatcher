# APTWatcher DFIR Documentation

> Autonomous digital-forensics & incident-response agent for the SANS SIFT Workstation.
> Built on Protocol SIFT for the FIND EVIL! hackathon (SANS/GIAC, 2026).

This is the canonical documentation. Every page is plain Markdown — renders
natively on GitHub, and builds into a searchable static site via
[`mkdocs`](https://www.mkdocs.org) + [Material theme](https://squidfunk.github.io/mkdocs-material/).

---

## Start here

| If you are… | Read |
|---|---|
| A first-time user | [Getting started](getting-started/README.md) |
| A hackathon judge | [Getting started → Try it out](getting-started/try-it-out.md) and [Architecture](architecture/README.md) |
| A senior IR analyst | [Scenarios](scenarios/README.md) and [Use cases](use-cases/README.md) |
| A developer extending APTWatcher | [Architecture](architecture/README.md), [Reference](reference/README.md), and [`design/`](design/tier0-sift-lifecycle.md) |

## Navigation

### [Getting started](getting-started/README.md)
How to install and run APTWatcher in each deployment mode.

- [Installation](getting-started/installation.md)
- [Try it out — 10-minute quick start](getting-started/try-it-out.md)
- [Mode A — Direct Agent Extension](getting-started/mode-a-direct-agent.md)
- [Mode B — Custom MCP Server](getting-started/mode-b-mcp-server.md)
- [Mode C — Hybrid (recommended)](getting-started/mode-c-hybrid.md)

### [Architecture](architecture/README.md)
How APTWatcher is structured and why.

- [Overview](architecture/README.md)
- [Three deployment modes](architecture/deployment-modes.md)
- [Tiered capability model](architecture/tier-model.md)
- [Shared brain (`src/core/`)](architecture/shared-brain.md)
- [Evidence integrity](architecture/evidence-integrity.md)
- [Audit logging & traceability](architecture/audit-logging.md)
- [Self-correction & reasoning](architecture/self-correction.md)

### [Use cases](use-cases/README.md)
Pre-flight profiles that bound what tools the agent can reach for.

- [Windows host triage](use-cases/windows-host-triage.md)
- [Linux host triage](use-cases/linux-host-triage.md)
- [Memory-only analysis](use-cases/memory-only.md)
- [Timeline-only analysis](use-cases/timeline-only.md)
- [Network artifact analysis](use-cases/network-artifact.md)

### [Scenarios](scenarios/README.md)
End-to-end demo scenarios — each one comes with a dataset, an expected
agent approach, and a success rubric.

- [S01 — Single Windows host compromise](scenarios/S01-single-windows-compromise.md)
- [S02 — Multi-host lateral movement](scenarios/S02-multi-host-lateral-movement.md)
- [S03 — Ransomware pre-detonation](scenarios/S03-ransomware-pre-detonation.md)

### [Datasets](datasets/README.md)
How we generate synthetic test cases and which public datasets we use.

- [Dataset strategy](datasets/README.md)
- [Synthetic cases](datasets/synthetic.md)
- [Public sources (DFIR Report, CyberDefenders, etc.)](datasets/public-sources.md)

### [Integrations](integrations/README.md)
Optional external capabilities wired into the tier model.

- [APT Watch (Tier 1 intel)](integrations/apt-watch.md)
- [MS Threat Analytics (Tier 1 intel)](integrations/ms-threat-analytics.md)
- [GLPI (Tier 2 workflow)](integrations/glpi.md)
- [cnc_disruptor (Tier 3/4 containment)](integrations/cnc-disruptor.md)

### [Reference](reference/README.md)
Flat lookup tables.

- [MCP tool inventory](reference/mcp-tools.md)
- [Wrapped SIFT tools](reference/sift-tools.md)
- [MITRE ATT&CK coverage](reference/mitre-coverage.md)
- [Knowledge base index](reference/knowledge-index.md)

### [Design notes](design/tier0-sift-lifecycle.md)
Low-level implementation references — mostly for developers.

- [Tier 0 — SIFT lifecycle & preflight](design/tier0-sift-lifecycle.md)
- [Tier 1 — Intel lookup pattern](design/tier1-intel-lookup-pattern.md)
- [Deployment modes (detailed)](design/deployment-modes.md)

### Hackathon submission

- [Demo walkthrough — captured CLI output](demo/WALKTHROUGH.md)
- [Try it out (top-level)](TRY-IT-OUT.md)
- [Accuracy harness](ACCURACY.md)
- [Dataset notes](DATASET.md)
- [Devpost narrative](DEVPOST.md)

---

## Contributing

Corrections, additional scenarios, and new knowledge-base entries are
welcome — see the [clean-room content policy](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/README.md)
for what can and cannot go into the KB.

## License

[MIT](https://github.com/aptwatcher/APTWatcher/blob/main/LICENSE).
Third-party attributions are listed per integration page.
