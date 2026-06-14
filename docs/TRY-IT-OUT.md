# Try it out

> Ten minutes, a stock Python 3.11 environment, and one `git clone`. No
> forensic VM, no API keys, no real evidence. At the end of the walk you
> will have seen APTWatcher probe a host triage profile, generate a full
> analysis bundle from synthetic triage output, publish that bundle
> through a stub adapter, and score itself against eight scenario
> fixtures. This is the judge-facing happy path: if any step fails, the
> build is not green.

## Quick install (one-liner)

For a fresh SIFT workstation (or any Linux host with Python 3.11+ and
git), the repository ships an idempotent bootstrap script that probes
the forensic toolchain, clones the repo into `~/APTWatcher`, creates a
virtualenv, and installs the package in editable mode:

```bash
curl -fsSL https://raw.githubusercontent.com/aptwatcher/APTWatcher/main/install.sh | bash
```

> **Review `install.sh` before piping to bash on a workstation you care
> about.** That is the correct default stance for any curl-pipe
> installer, and it is doubly true on an evidence machine. The script
> refuses to run as root, never writes outside `~/APTWatcher` and its
> `.venv`, logs every network call (git clone, pip install), and only
> probes SIFT binaries -- it never attempts to install them. Re-running
> the script is safe: an existing clone is updated with `git pull`
> and the venv is reused.

If you prefer not to pipe, download and inspect first:

```bash
curl -fsSL -O https://raw.githubusercontent.com/aptwatcher/APTWatcher/main/install.sh
less install.sh
bash install.sh
```

After the script finishes, activate the venv and continue with the
happy paths below:

```bash
source ~/APTWatcher/.venv/bin/activate
aptwatcher --help
```

If you hit any failure in the one-liner path, fall back to the manual
steps in the **Install** section further down this page; they are the
canonical reference and they do the same thing the installer does, step
by step.

## What you're about to do

You will clone the repository, install it into a virtualenv, and drive
four commands end-to-end: `aptwatcher run --dry-run` (to see the
resolved planner inputs for a host-triage profile), `aptwatcher analyze`
(to fan a hand-authored findings-plus-IOCs JSON into a full rule /
report / IOC bundle), `aptwatcher publish --adapter stub --dry-run` (to
walk the bundle through the publication surface without touching a
network), and `aptwatcher eval` (to run the Phase 4 accuracy harness
against eight recorded scenario fixtures and print an F1 scorecard).
Every one of those commands uses deterministic fake clients and
synthetic evidence. You do not need a forensic VM, an Anthropic API
key, or any external service credentials to complete the 10-minute
walk. The audit log, the bundle contents, and the accuracy scorecard
are the three artifacts you will read at the end.

## Prerequisites

- **Python 3.11 or newer.** This is a hard requirement. The codebase
  uses `datetime.UTC`, which lands in `datetime` only in 3.11. On
  Python 3.10 or earlier, imports fail fast with
  `ImportError: cannot import name 'UTC'`. Verify with
  `python3 --version`.
- **git**, for the initial clone.
- **Roughly 500 MB of free disk**, most of which is the virtualenv and
  the packaged mkdocs theme. The repository itself is small.
- **Any operating system** that runs Python 3.11. The 10-minute path
  has no forensic-tool requirement, so you do not need Linux, and you
  do not need a forensic workstation VM. The only OS note is the venv
  activation command, which differs between POSIX shells and Windows
  `cmd.exe` / PowerShell; both forms appear below.

Optional, and explicitly outside the 10-minute path: if you happen to
already have a forensic workstation VM with the Tier 0 toolchain on
your `PATH` (volatility3, plaso, yara, hayabusa, bulk_extractor, zeek,
and friends), `aptwatcher preflight` will detect them and produce a
richer tool inventory. Nothing in this walkthrough depends on that. If
a tool is missing, `preflight` tells you exactly which binary it was
looking for, and `run --dry-run --allow-missing-tools` reports
"below-min" or "MISSING_REQUIRED" in the preflight summary without
aborting. (Without `--allow-missing-tools`, a failed preflight aborts
the run — dry or not — which is why the happy-path command below
includes the flag.)

## Install (target: two minutes)

Clone the repository, create and activate a virtualenv, install the
project in editable mode with the `dev` extras, and smoke-test the
console script. The repository URL below is the public GitHub slug and
will resolve once the repo flips to public for the judging period.

```bash
git clone https://github.com/aptwatcher/APTWatcher.git
cd APTWatcher
python3.11 -m venv .venv
source .venv/bin/activate              # POSIX: bash / zsh
# .venv\Scripts\activate                # Windows cmd.exe
# .venv\Scripts\Activate.ps1            # Windows PowerShell
pip install -e ".[dev]"
aptwatcher --help
```

The `--help` output should list the Typer subcommand surface. You are
looking for nine commands: `version`, `profiles`, `preflight`,
`knowledge-search`, `run`, `analyze`, `publish`, `eval`, and
`audit-render`. The first
four are inspection commands (they never touch a model, never execute
forensic tools, never write to disk outside of what you explicitly ask
for). `run` is the triage loop; `analyze` is the offline analysis
fan-out; `publish` is the online publication adapter driver; `eval`
is the accuracy harness; and `audit-render` turns a signed audit log
into a judge-readable timeline. If any of those commands is missing
from the help output, the install did not complete cleanly. Re-run
`pip install -e ".[dev]"` and check for a Python version mismatch
first — that is by far the most common cause.

One sanity check before moving on: `aptwatcher version` should print a
line of the form `aptwatcher 0.1.0a0` (or whatever the current alpha
version is). If you see an `ImportError` here instead, you are on
Python < 3.11 inside the venv — delete `.venv`, create it again with
`python3.11 -m venv`, and reinstall.

## Happy path 1: Dry-run the triage loop against a host-triage profile (target: two minutes)

The first happy path exercises `aptwatcher run` in `--dry-run` mode.
Dry-run does not execute the agent loop and does not instantiate any
model client; instead, it resolves the complete planner input bundle
(profile metadata, preflight tool inventory, knowledge-base context
excerpt) and prints exactly what the planner would see on a real run.
This is the cheapest way to confirm that the installation is wired up
and that the host-triage profile resolves cleanly.

Run:

```bash
aptwatcher run \
    --incident-id DEMO-001 \
    --profile windows-host-triage \
    --allow-missing-tools \
    --dry-run
```

`--incident-id` is required on `run`; it is the stable identifier
APTWatcher uses to namespace audit logs on a real run. In `--dry-run`
no audit log is actually written, but the flag is still required so
that you practice the real invocation shape. `--profile` selects the
use-case profile; `windows-host-triage` is the headline profile and
the one the accuracy fixtures also use. `--allow-missing-tools` is
needed on any machine that lacks the forensic toolchain, because a
failed preflight aborts even a dry run; on a fully provisioned SIFT
workstation you can drop it.

You should see, roughly in order:

- A cyan rule announcing `aptwatcher run --dry-run -- incident DEMO-001`.
- A **Resolved run inputs** table with rows for `incident_id`,
  `profile`, `backend` (defaults to `null`, the deterministic fake
  client), `model` (adapter default), `api_key_env` (unused at this
  backend), `knowledge_root` (`knowledge` relative to the repo),
  and `preflight_ok`.
- A **Profile metadata** table listing the profile description, the
  required and optional tools, and the required and optional artifact
  categories. For `windows-host-triage` you should see tools like
  `volatility3`, `log2timeline.py`, and `yara` in the required set.
- A **Preflight summary** line, one entry per probed tool, of the form
  `volatility3 2.x ok` or `RegRipper MISSING_REQUIRED` depending on
  whether the binary is on your `PATH`. On a vanilla developer laptop
  without the forensic toolchain installed, several tools will be
  `MISSING_REQUIRED` — that is expected, and with
  `--allow-missing-tools` the dry-run prints it without failing.
- A **KB context** section. With the default `--backend=null`, this is
  printed as `(none -- backend is null, knowledge root missing, or no
  hits)`. KB context is only threaded into the prompt when a real LLM
  backend is configured; the null path is deterministic and does not
  need it.
- A green rule saying `Dry run complete -- no audit log written, no
  model calls made`.

The dry-run is intentionally side-effect-free. It is the piece of the
demo that a judge can re-run any number of times without writing to
disk or spending any model tokens. If you want to see the full
inventory the preflight would produce on its own (without the
planner-input framing), the sibling command
`aptwatcher preflight --profile windows-host-triage` prints the tool
inventory as a standalone table.

## Happy path 2: Offline analysis bundle and stub publish (target: three minutes)

The second happy path is S04 — the offline-to-online bundle handoff —
compressed to its demo essentials. It takes a hand-authored JSON that
contains three synthetic findings and five IOCs, fans the input out
into a full analysis-output bundle (YARA rules, Suricata rules, STIX
IOCs, per-type IOC text files, analyst report, TTP assessment — Sigma
generation is a deferred Phase 4 stub and currently emits nothing),
and then walks the bundle through the publication surface
via the stub adapter. No real evidence, no real network, no real
credentials.

Create a working directory and a synthetic triage input:

```bash
mkdir -p /tmp/aptw-demo/triage
cat > /tmp/aptw-demo/triage/input.json <<'JSON'
{
  "findings": [
    {
      "finding_id": "f-001",
      "summary": "Sigma hit: suspicious service install on Security EVTX",
      "mitre": ["T1021.002"],
      "confidence": 0.80,
      "evidence": [
        {"source": "Security.evtx", "locator": "event_id=7045 record=55012", "tool_call_id": "call-0001"}
      ],
      "reasoning": "Service install off-hours from a non-admin parent process."
    },
    {
      "finding_id": "f-002",
      "summary": "YARA hit: packed loader stub in svchost memory region",
      "mitre": ["T1055"],
      "confidence": 0.72,
      "evidence": [
        {"source": "volatility3:yarascan", "locator": "pid=2148 addr=0x41000", "tool_call_id": "call-0002"}
      ],
      "reasoning": "Rule Packed_Loader_XorStub_v2 matched an RX region."
    },
    {
      "finding_id": "f-003",
      "summary": "bulk_extractor surfaced suspicious domain in pagefile",
      "mitre": ["T1071.001"],
      "confidence": 0.65,
      "evidence": [
        {"source": "bulk_extractor:domain.txt", "locator": "offset=0x1fa2c0", "tool_call_id": "call-0003"}
      ],
      "reasoning": "Domain cdn-metrics-update.biz sits near a phishing-kit referer."
    }
  ],
  "iocs": [
    {"value": "cdn-metrics-update.biz", "ioc_type": "domain", "verdict": "malicious"},
    {"value": "185.234.247.12", "ioc_type": "ipv4", "verdict": "malicious"},
    {"value": "10.8.14.77", "ioc_type": "ipv4", "verdict": "suspicious"},
    {"value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "ioc_type": "sha256", "verdict": "malicious"},
    {"value": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "ioc_type": "sha256", "verdict": "suspicious"}
  ]
}
JSON
```

The shape is exactly what `aptwatcher analyze` loads via
`_load_input_bundle()` in `src/agent_extension/analyze.py`. You can
point at any file of your own with the same shape; the repository does
not ship this particular JSON, it is crafted inline here so the demo
stays self-contained.

Now fan the input out into a bundle:

```bash
aptwatcher analyze \
    --input /tmp/aptw-demo/triage/input.json \
    --output-dir /tmp/aptw-demo/bundle \
    --campaign-tag DEMO-HANDOFF \
    --incident-id INC-DEMO-S04 \
    --language en \
    --sift-workstation demo-host
```

Note a couple of flag shapes here: `--language` accepts `en`, `fr`, or
`both` (the Typer validator rejects anything else); `--campaign-tag` is
used to name generated rules and to title generated reports;
`--sift-workstation` becomes a tag in the bundle manifest. The command
is deliberately quiet on success: expect four short lines of the form
`analyze: incident_id=...`, `analyze: findings=3 iocs=5`,
`analyze: outputs under /tmp/aptw-demo/bundle`, and
`analyze: manifest=/tmp/aptw-demo/bundle/generation_report.json`.

Peek at the directory tree `analyze` produced:

```
/tmp/aptw-demo/bundle/
├── findings.json
├── generation_report.json
├── iocs.json
├── manifest.json
├── iocs/
│   ├── bundle.stix.json
│   ├── community-submission.yml
│   ├── domain.txt
│   ├── ipv4.txt
│   └── sha256.txt
├── reports/
│   ├── ANALYSIS-INC-DEMO-S04.md
│   ├── Campaign_Report_INC-DEMO-S04.docx
│   └── TTP_INC-DEMO-S04.md
└── rules/
    ├── demo-handoff.suricata.rules
    └── demo-handoff.yar
```

Exact file names vary as the generators evolve, but the three
directories (`iocs/`, `reports/`, `rules/`) are stable, and
`generation_report.json` is the machine-readable manifest that records
what was produced. Skipping signing keeps the demo short; the full
signed-bundle flow with Ed25519 lives in the S04 scenario under the
top-level `scenarios/` directory of the repository.

Now walk the output through the publication surface. The publish
command consumes the sibling `findings.json` / `iocs.json` /
`manifest.json` files at the top of a bundle directory — and `analyze`
already wrote all three at the top of `/tmp/aptw-demo/bundle`, so no
staging step is needed. Drive the publish with the stub adapter in
dry-run mode:

```bash
aptwatcher publish \
    --bundle-dir /tmp/aptw-demo/bundle \
    --adapter stub \
    --dry-run
```

Two flag shapes worth noting. `--adapter` is repeatable; you can pass
it several times to simulate multiple downstream targets (the S04
scenario passes it three times for takedown, sharing, and ticketing
stand-ins). The allowed adapter names are `netcraft`, `misp`, `glpi`,
`taxii`, and `stub`; all but `stub` require live credentials and
network access, so the 10-minute walk sticks to `stub`. `--dry-run` defaults
to **true** on the `publish` command (a safety stance — it is the one
command in the suite that could, on non-stub adapters, touch a remote
service), so you can also pass `--no-dry-run` to exercise the "live"
path. Because the stub adapter never touches the network in either
mode, both are safe to run.

Expected output tail:

```
publish[stub]: dry-run
```

If you re-run with `--no-dry-run` the tail becomes `publish[stub]:
submitted`, and the stub's internal call log records the submission.
Either way, no packet leaves the machine.

## Happy path 3: Accuracy harness (target: two minutes)

The third happy path runs the Phase 4 accuracy harness against the
eight scenario fixtures that ship with the repository, from
`s_phishing_beacon` (a macro-delivered loader that beacons out to a C2
IP) and `s_credential_dump` (a local credential-access chain) through
lateral movement, DNS tunneling, Linux/macOS persistence, cloud IAM
escalation, and pre-encryption ransomware. Each fixture
contains a manifest, a seed findings/IOC file, a golden ground-truth
file, and a pre-recorded transcript that the harness replays through
`core.llm.FakeModelClient`. No live LLM call, no network.

Run:

```bash
aptwatcher eval \
    --fixtures-dir tests/accuracy/fixtures \
    --output-dir /tmp/aptw-demo/accuracy
```

Expected output shape (middle rows trimmed):

```
                         Accuracy report
┏━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━┓
┃ scenario                 ┃ f1_findings ┃ f1_iocs ┃ duration_ms ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━┩
│ s_cloud_iam_escalation   │ 1.000       │ 1.000   │ 7           │
│ s_credential_dump        │ 1.000       │ 1.000   │ 5           │
│ ...                      │ ...         │ ...     │ ...         │
│ s_ransomware_pre_encrypt │ 1.000       │ 1.000   │ 4           │
└──────────────────────────┴─────────────┴─────────┴─────────────┘
Mean F1: 1.000 (threshold 0.60)
Report JSON: /tmp/aptw-demo/accuracy/accuracy_report_<timestamp>.json
Report MD:   /tmp/aptw-demo/accuracy/accuracy_report_<timestamp>.md
```

The exact numbers will move as the fixture set grows; at the time of
writing, all eight scenarios score cleanly on exact-match scoring (see
[`ACCURACY.md`](ACCURACY.md) for what counts as a match). The command
exits 0 when the mean F1 is at or above
`--threshold` (default `0.6`), 1 when it falls below, and 2 when
`--fixtures-dir` does not exist or no scenarios were discovered under
it.

Two artifacts land under `--output-dir`: a machine-readable JSON and a
human-readable Markdown scorecard (plus an `audit/` directory holding
the per-scenario replay audit logs). Open the Markdown to see a
per-scenario breakdown, including which golden findings were matched
exactly, which were missed, and which predicted findings were
unmatched ("hallucinations", in accuracy-harness terms). That
scorecard is what you would ship alongside a release candidate.

The methodology — what is measured, why exact match for v1, how
confusion matrices are computed, what the known failure modes look
like — is documented in full in [`ACCURACY.md`](ACCURACY.md), and the
implementation-facing complement lives at
[`design/accuracy-harness.md`](design/accuracy-harness.md).

## Happy path 4: Run against the FIND EVIL provided dataset (on a SIFT workstation)

The three paths above need no forensic tools. This one is the real thing:
APTWatcher driving the SIFT toolchain over the hackathon's official
"Example Compromised System Data". It requires a SIFT workstation
(x86_64) with the toolchain provisioned — the bare recording box
deliberately has none, which is exactly why `preflight` refuses there.

### 1. Provision a SIFT workstation

Download the SIFT Workstation, then provision the canonical toolchain:

```bash
bash scripts/prepare-vm.sh          # installs volatility3, plaso, sleuthkit, yara, hayabusa, ...
source .venv/bin/activate
```

On an Apple Silicon Mac, run SIFT on an **x86_64 host** (a small cloud
Linux instance is fastest and avoids slow emulation) rather than
emulating locally. The autonomous in-VM path is in
[`RUNBOOK.md`](https://github.com/aptwatcher/APTWatcher/blob/main/RUNBOOK.md) (Phase 1b).

### 2. Stage the evidence (read-only)

Download the "Example Compromised System Data" from the hackathon
resources. The standard case is **"The Fred Rocba Case"** (Stark Research
Labs intrusion and IP theft) — a Windows host with two artifacts:

| Artifact | Size | Kind |
|---|---|---|
| `Rocba-Memory.raw` | ~18 GB | raw memory image |
| `rocba-cdrive.e01` | ~23 GB | EnCase disk image |

A disk-plus-memory Windows host maps to the `windows-host-triage`
profile. Per the Prime Directive, the evidence tree stays read-only:
point APTWatcher at it, never copy derivatives next to it.

> **Size matters.** ~41 GB total. Run this on a real or cloud **x86_64**
> SIFT box where the toolchain runs natively — emulating x86 on Apple
> Silicon makes Volatility/Plaso over a multi-GB image impractically slow.
> `preflight` itself only hashes the files (no tool execution), so it is
> the cheapest honest "green on the provided evidence" capture.

### 3. Preflight — now it comes back green

```bash
aptwatcher preflight --profile windows-host-triage -e Rocba-Memory.raw -e rocba-cdrive.e01
```

On a provisioned SIFT box this returns OK with every required tool
found — the same command that exits 1 on the bare recording box. Pick
the profile that matches the evidence (`windows-host-triage`,
`memory-only`, `timeline-only`, ...); `aptwatcher profiles` lists them.

### 4. Run the triage loop over the real evidence

Key-free structural pass (resolves and prints the plan, no LLM):

```bash
aptwatcher run --incident-id INC-ROCBA-001 --profile windows-host-triage \
    -e Rocba-Memory.raw -e rocba-cdrive.e01 --backend null --dry-run
```

Full agentic run (plan → execute → verify → self-correct with a live model):

```bash
export ANTHROPIC_API_KEY=...        # set in your shell only; never commit it
aptwatcher run --incident-id INC-ROCBA-001 --profile windows-host-triage \
    -e Rocba-Memory.raw -e rocba-cdrive.e01 --backend anthropic --model <model-id>
```

It prints the findings count and the path to the signed, append-only
audit log.

### 5. Inspect the judge-readable timeline

```bash
aptwatcher audit-render --incident-id INC-ROCBA-001
```

Every plan/execute/verify/self-correct step, with tool identities,
token usage, and per-step confidence. To carry the conclusions across
an air gap as a signed bundle, feed the findings into the analyze +
publish flow from Happy path 2.

## Where to look next

You have now seen the happy paths above. To go deeper:

- [`ARCHITECTURE.md`](ARCHITECTURE.md) is the canonical entry point for
  the tier model, the three deployment modes (Direct Agent Extension,
  Custom MCP Server, Hybrid), the shared-brain design, and the
  audit-log and self-correction guardrails. Start there if you want to
  understand *why* the surfaces look the way they do.
- [`../scenarios/`](../scenarios/) contains the narrative demo
  walkthroughs. `S04-offline-to-online-handoff.md` is the full version
  of happy path 2, including the Ed25519 signing and the tamper/swap
  adversarial sub-cases. The other `S0x-*.md` files are the
  single-host, multi-host, and ransomware-pre-detonation narratives.
- [`../knowledge/`](../knowledge/) is the clean-room knowledge base the
  LLM planner consults through the KB retrieval path. It is the
  grounding corpus. At the time of writing it holds 32
  curated entries across procedures, techniques, and tool hints; the
  `aptwatcher knowledge-search <query>` CLI is the fastest way to see
  what is in it.
- [`reference/mcp-tool-schemas.md`](reference/mcp-tool-schemas.md) is
  the full MCP surface reference. It enumerates every tool the Mode B
  server exposes (there are 42 at the current count), with input and
  output schemas. If you want to understand the exact contract between
  the shared brain and a Claude-SDK-based client, read that file.
- The `design/` directory under `docs/` is the design-notes drawer. It
  is where decisions and trade-offs are recorded.
  [`design/tier-gating.md`](design/tier-gating.md),
  [`design/self-correction-gates.md`](design/self-correction-gates.md),
  [`design/evidence-integrity.md`](design/evidence-integrity.md), and
  [`design/offline-to-online-handoff.md`](design/offline-to-online-handoff.md)
  are the four notes most directly relevant to the demo you just ran.

## Troubleshooting

A short list of the failure modes we have seen in practice:

- **`ImportError: cannot import name 'UTC' from 'datetime'`** — the
  venv is on Python < 3.11. Delete `.venv`, recreate it with
  `python3.11 -m venv .venv`, and reinstall with
  `pip install -e ".[dev]"`.
- **`aptwatcher: command not found`** (or `'aptwatcher' is not
  recognized as an internal or external command` on Windows) — the
  virtualenv is not active. Run the activation command for your shell
  again. If it is active and the command is still missing,
  `pip install -e ".[dev]"` probably did not complete; re-run and
  check the tail for an error.
- **`Preflight failed for profile '...'. Missing required: ...`** on
  `aptwatcher run` (with or without `--dry-run`) — the forensic
  toolchain is not on your `PATH`, and a failed preflight aborts the
  run even in dry-run mode. For the 10-minute happy path, pass
  `--allow-missing-tools` as shown above. If you genuinely want to
  execute the real loop, install the missing tools and re-run;
  `--allow-missing-tools` is for demos only, not real evidence.
- **"Binary not resolved" in a tool-call trace** — a forensic tool the
  planner wanted to invoke is not on `PATH`. Same mitigation as the
  previous bullet. None of the happy paths in this document hit this
  case because they either stay in dry-run or operate on synthetic
  JSON that never invokes a forensic binary.
- **Windows path separators in scenario JSON** — if you adapt one of
  the scenario files literally on Windows, you may need to quote paths
  that contain spaces or backslashes. The examples above use
  forward-slash paths under `/tmp/aptw-demo/` that work as-is on POSIX;
  on Windows, substitute a path the current user can write to (for
  example, `C:\temp\aptw-demo\`) and quote it when it contains a
  space.
- **`fixtures-dir not found: tests/accuracy/fixtures`** on
  `aptwatcher eval` — you ran the command
  from outside the repository root and the relative
  `tests/accuracy/fixtures` path did not resolve. Either `cd` into the
  repo root first, or pass an absolute path to `--fixtures-dir`.

If none of these match your symptom, the audit log is the next place
to look. `aptwatcher run` (without `--dry-run`) writes a JSONL audit
log under `--log-dir` (default `./logs/`) at
`logs/<incident_id>/audit.jsonl`; every preflight probe, planner step, verifier step,
self-correction, and tool call is captured. Even on a command that
aborted early, the audit log usually makes the cause obvious.

## What this demo does not show

Being explicit about the gaps is as important as showing the green
path. The 10-minute walk deliberately stops short of four things that
the full product supports:

- **Live LLM calls.** Every happy path here uses either the null
  planner (`--backend=null`, the default) or the replay fake client
  inside the accuracy harness. To drive a real model you would set
  `ANTHROPIC_API_KEY` in the environment and pass
  `--backend=anthropic` to `aptwatcher run` (without `--dry-run`).
  That path works, but it costs tokens and is not what the judge
  needs to verify that the agent is real; the dry-run and the
  replay fixtures together already pin down the behaviour.
- **Real forensic-tool execution.** The run loop can invoke
  volatility3, plaso, yara, hayabusa, bulk_extractor, and the rest of
  the Tier 0 surface against real evidence on a forensic workstation
  VM. The 10-minute path never exercises that, because requiring a
  forensic VM to review a hackathon submission would defeat the
  purpose.
- **Real publication to downstream services.** The `stub` adapter
  records its submissions internally and returns a success report.
  The `netcraft`, `misp`, `glpi`, and `taxii` adapters speak to the
  real services and would need live credentials (and, in some cases, a
  reachable MISP, GLPI, or TAXII instance). The bundle format and
  the publish contract are identical across all five adapters; only
  the transport is different.
- **The full three-deployment-mode story.** APTWatcher ships as three
  modes — Direct Agent Extension, Custom MCP Server, and Hybrid —
  sharing one brain. The 10-minute walk only exercises Mode A (the
  `aptwatcher` CLI). Modes B and C add an MCP server surface and a
  Claude-Code-plus-MCP wiring; see
  [`ARCHITECTURE.md`](ARCHITECTURE.md) and the
  [`getting-started/README.md`](getting-started/README.md) guides for the mode-specific
  install paths.

## Feedback

If any step in this document did not work as described, that is a bug
we want to know about. Please open an issue at
[`aptwatcher/APTWatcher/issues`](https://github.com/aptwatcher/APTWatcher/issues)
with the exact command you ran, the exact error output, and your
Python version (`python3 --version`). The 10-minute path is the first
thing a judge sees, and we treat regressions on it as release-blocking.
