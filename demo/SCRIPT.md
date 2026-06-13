# APTWatcher DFIR — 5-minute demo script

*Rehearsal target: 4:30 spoken, under 5:00 recorded with minor pauses.*

This is the rehearsal script for the hackathon submission video. The
cadence is minute-by-minute. Every command we read on camera is a
command we can also find in `docs/TRY-IT-OUT.md`, which was audited
against `src/agent_extension/cli.py`; if the two ever disagree,
TRY-IT-OUT.md wins.

Written walkthrough with captured output:
[`docs/demo/WALKTHROUGH.md`](../docs/demo/WALKTHROUGH.md) — every
command in this script, executed for real, with the actual output
transcribed. Condensed one-take recording plan:
[`SHOOTING-SCRIPT.md`](SHOOTING-SCRIPT.md).

## Pre-check (run ten minutes before recording)

We want a clean terminal, a clean repo, a green eval baseline, and two
fallback clips on disk. The checklist below is short because the
system is small.

- Repo: `cd $REPO_ROOT` on a freshly cloned copy. We run
  `git status --porcelain` and it must be empty. If it is not, we
  stash. The audit log directory (`logs/`) and any `demo/` output
  subdirectories from previous rehearsals get wiped: `rm -rf logs
  demo/S04-out demo/accuracy-out`. No trace of a previous take should
  remain on camera.
- Python version: `python3.11 --version` prints `Python 3.11.x` or
  newer. Any older interpreter fails fast on `datetime.UTC`; we do not
  want that failure on camera.
- Virtualenv: `.venv` is freshly created, activated, and the project
  is installed editable with the dev extras
  (`pip install -e ".[dev]"`). `aptwatcher --help` prints the eight
  registered subcommands: `version`, `profiles`, `preflight`,
  `knowledge-search`, `run`, `analyze`, `publish`, and `eval`. If any
  of those is missing, the install is bad and we abort the take.
- Version smoke: `aptwatcher version` prints the current alpha version.
- API keys: `ANTHROPIC_API_KEY` is explicitly **unset** in the shell
  that records the demo. We run the whole take against the null
  backend and the replay harness. `env | grep -i anthropic` on camera
  should return nothing.
- Keys for S04: an Ed25519 private key sits at
  `demo/keys/ed25519-priv.key`. If it is missing, we regenerate it
  with the one-liner from `scenarios/S04-offline-to-online-handoff.md`
  before the take (off-camera).
- Eval baseline: we run `aptwatcher eval --fixtures-dir
  tests/accuracy/fixtures --output-dir demo/accuracy-precheck
  --threshold 0.60` once, green, before starting. If the exit code is
  non-zero, we do not record.
- Terminal: dark theme, font size bumped to a readable point, history
  cleared (`history -c` in bash/zsh). We line up the commands in the
  shell history in reverse order so an up-arrow walks us through the
  take without typos.
- Fallback clips: three pre-recorded asciinema casts sit at
  `demo/fallbacks/act1.cast`, `act2.cast`, `act3.cast`. If a live take
  breaks, we cut to the matching clip in the editor.

## Wall-clock target -- 14.5-minute triage SLA

Rob T. Lee's 2026-04-21 presentation framed the target starkly:
historical triage on a compromised endpoint ran 96+ hours; an agentic
AI defender has to close the same loop in 14.5 minutes. APTWatcher
adopts 14.5 minutes (870 seconds) as the end-to-end budget, split into
Pre-check 30s, Plan 60s, Execute 540s, Verify 90s, Self-correct 90s,
Finalize 60s. We measure it with deterministic FakeModelClient replay
on fixture `s_ransomware_pre_encrypt` -- the richest full-pipeline
Windows scenario -- reference host Python 3.11+ on a SIFT workstation,
single run (not averaged) to match this script's live-demo framing.
Numbers here are the design budget; the reproduced measurement lives
in `docs/ACCURACY.md` and is re-run on the reference host before video
recording.

## 0:00 -- 1:00 :: Elevator pitch and what is different

*Screen: slide 1, the project name and a one-line tagline. No
terminal yet.*

We are APTWatcher, an autonomous defensive incident-response agent.
The product premise is simple. An analyst is drowning in alerts. The
agents the market has shipped so far are aimed at offensive tasks or
at general coding. Those that do aim at defensive incident response
tend to hallucinate findings, which is a failure mode that is strictly
worse than no agent at all. A confident liar poisons every downstream
decision an analyst makes on top of it.

APTWatcher answers that failure mode with four structural guardrails
that live in code, not in a prompt. First, the tier model: tier 0 is
read-only forensic triage and is on by default; tier 1 adds external
intel lookups; tier 2 adds ticketing; tier 3 and tier 4 cover
defensive and offensive containment and require an explicit operator
consent flag at runtime. A prompt cannot coax the agent into a tier
the configuration has disabled, because the gate is a refusal at the
tool boundary. Second, the self-correction gate: the emitter refuses
to publish findings until a self-correction pass has run on the
current finding set, and the safe default on any malformed corrector
output is to drop every finding that carries a block-severity issue.
Third, the audit log is a first-class product surface, JSONL and
append-only, with a correlation ID tying every tool-call start to its
end; a reviewer can reconstruct any run from the log alone. Fourth,
the knowledge base is clean-room: every entry declares a source type
from a closed set, every entry is citation-attributed, and a
forbidden-string grep gates every commit.

The headline shape of the product is the offline-to-online handoff.
Evidence stays on the air-gapped triage workstation; conclusions
travel online as a signed bundle. We will show that boundary live in
minute two. The rest of this demo is three happy paths: a triage
dry-run, the offline-to-online bundle, and the accuracy harness.

*Transition: close the slide, switch to terminal.*

## 1:00 -- 2:00 :: Live agent loop on a synthetic Windows host

*Screen: terminal, full-width, repo root visible in the prompt.*

We begin with preflight. Preflight probes the forensic toolchain on
`PATH`, classifies any evidence we pass it, and reports gaps. On a
vanilla developer laptop without volatility3, plaso, hayabusa, yara,
bulk_extractor, and friends installed, preflight will list several
tools as missing. That is expected: we are not running against real
evidence today, and the dry-run we follow up with accepts the gaps
without aborting.

```bash
aptwatcher preflight --profile windows-host-triage
```

We narrate: preflight resolves the `windows-host-triage` profile,
walks the required and optional tool lists, and prints a `Tool
inventory` table. Each row shows the tool name, the version it
detected, and whether it meets the declared minimum. Tools that are
not on `PATH` show as `MISSING_REQUIRED` or `MISSING_OPTIONAL`. We
point at the `Missing required tools:` line at the top and explain
that on a real triage workstation this is the gate that stops a
run before it touches evidence.

Now the dry-run of the triage loop itself. Dry-run resolves the full
planner input bundle -- profile metadata, preflight summary, KB
context excerpt, backend choice -- and prints exactly what the
planner would see. No model is called, no audit log is written, no
findings are produced. It is the cheapest way to show that the full
wiring resolves.

```bash
aptwatcher run \
    --incident-id DEMO-001 \
    --profile windows-host-triage \
    --dry-run
```

We narrate the output in order. A cyan rule announces `aptwatcher run
--dry-run -- incident DEMO-001`. The `Resolved run inputs` table
lists the incident id, the profile, the backend (`null`, which is our
deterministic skeleton client), the model field (adapter default),
the api key env var (unused at this backend), the knowledge root, and
the preflight ok status. We highlight `backend = null` on camera: the
whole demo runs without calling a real LLM. Next, the `Profile
metadata` table shows the profile description and the required and
optional tool and artifact categories. Next, the `Preflight summary`
line is the one-line-per-tool block the planner would read. Next,
the `KB context` section prints the `(none -- backend is null,
knowledge root missing, or no hits)` sentinel -- KB context threads
into the prompt only on a live backend. Finally, a green rule:
`Dry run complete -- no audit log written, no model calls made`.

We close this beat by pointing out two things on camera. One: every
command we just ran is safe to rerun as many times as a reviewer
wants; nothing mutates state. Two: when we flip to `--backend
anthropic` on a real workstation, the audit log path prints at the
end of the run and a reviewer can grep through it with `jq` to
reconstruct the loop.

## 2:00 -- 3:00 :: Offline to online handoff (S04)

*Screen: terminal stays. We move to `demo/` as the working tree.*

Scenario S04 is the offline-to-online bundle handoff. In a real
incident, the triage workstation is air-gapped. Evidence never leaves
it. What leaves it is a signed incident bundle -- a canonical JSON
payload covering the findings, the IOCs, the embedded audit slice,
and a manifest -- signed with a detached Ed25519 signature. The
online peer verifies the signature before a single remediation fires.

We stage the synthetic triage input the same way `docs/TRY-IT-OUT.md`
shows (three findings, five IOCs, hand-authored JSON). Then we fan
the input into a full analysis bundle, signing as we go.

```bash
aptwatcher analyze \
    --input demo/S04-inputs.json \
    --output-dir demo/S04-out \
    --campaign-tag S04-HANDOFF \
    --incident-id INC-DEMO-S04 \
    --operator "Demo Operator" \
    --language en \
    --sign \
    --private-key-path demo/keys/ed25519-priv.key \
    --sift-workstation demo-host
```

We walk through the directory tree the command produces:

- `demo/S04-out/rules/` with YARA, Suricata, and Sigma subdirectories;
- `demo/S04-out/iocs/` with STIX, community YAML, and per-type text
  files (`domains.txt`, `ips.txt`, `hashes.txt`);
- `demo/S04-out/reports/` with the English analyst report and the
  TTP assessment;
- `demo/S04-out/generation_report.json` as the machine-readable
  manifest of the fan-out;
- `demo/S04-out/incident-bundle/` with `manifest.json`,
  `findings.json`, `iocs.json`, `audit.jsonl`, and the detached
  `signature.json`.

We `cat` the tail of `signature.json` on camera and point at the
`signer_public_key` hex and the `signature` hex. Neither the private
key nor the raw seed ever appears -- that is the point. Then we
narrate the adversarial sub-case without running it: if a courier or
a middleman edits a single byte of `iocs.json`, the importer on the
online peer raises `BundleIntegrityError` on the per-file digest
check before it even reaches the signature verification. If the
courier swaps the signer entirely, the importer raises
`BundleSignatureError` against the pinned operator public key. Both
failure paths are covered in `scenarios/S04-offline-to-online-handoff.md`.

Now the online leg. We stage the three top-level publish inputs
(`findings.json`, `iocs.json`, `manifest.json`) from the verified
bundle -- in the real scenario the online host imports the bundle
through `core.bundle.importer`; for the demo we prepare the staging
directory manually -- and walk the result through the publication
surface with the stub adapter, dry-run by default.

```bash
aptwatcher publish \
    --bundle-dir demo/S04-out \
    --adapter stub \
    --dry-run
```

We narrate: `publish` is the one command in the suite that could, on
a non-stub adapter, touch a remote service, so `--dry-run` defaults
to **true**. The allowed adapter names are `netcraft`, `misp`, `glpi`,
and `stub`. The first three want live credentials; we stay on `stub`
for the demo. The tail of the output is a single line:

```
publish[stub]: dry-run
```

We point at it and say: no packet left the machine. The publish
surface is identical across adapters; only the transport changes.

## 3:00 -- 4:00 :: Accuracy harness and reproducible evidence

*Screen: terminal, new pane or fresh scroll.*

We promised an accuracy story and now we pay for it. The Phase 4
accuracy harness replays a canned transcript through the real
`AgentLoop` using a `FakeModelClient`. No live LLM call. No network.
Every run on every machine is bit-for-bit reproducible against the
committed fixtures. The scoring is exact-match on the finding triple
of tier, normalized title, and the MITRE frozenset; and exact-match
on the IOC pair of type and normalized value.

We run the harness against the committed fixture set, with the
threshold set to the pipeline floor (0.60) rather than the submission
gate (0.80). On the current commit the fixture set covers five
scenarios: `s_phishing_beacon` (a macro-delivered loader that beacons
out to a C2), `s_credential_dump` (an LSASS dump via `rundll32.exe`
and `comsvcs.dll`), plus `s_linux_persistence`,
`s_ransomware_pre_encrypt`, and `s_lateral_smb` as the three scenarios
added to widen per-tier rollup signal.

```bash
aptwatcher eval \
    --fixtures-dir tests/accuracy/fixtures \
    --output-dir demo/accuracy-out \
    --threshold 0.60
```

We narrate the output. The harness prints an `Accuracy report` table
with one row per scenario and columns for the finding F1, the IOC
F1, and the per-scenario duration in milliseconds. Below the table a
`Mean F1` line gives us the aggregate. Two report paths print at the
end: a machine-readable JSON and a human-readable Markdown. We
`cat demo/accuracy-out/*.md | head -n 30` on camera and point at the
per-scenario breakdown, the matched-findings column, the missed
column, and the unmatched-predictions column. The unmatched
predictions are what the accuracy doc calls hallucinations; a green
demo has an empty column there.

We make one point explicitly on camera, because it matters. The
fixture set uses RFC 5737 documentation IPs (`192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`) and `.invalid` domains. Nothing
in the harness touches a real host, a real domain, or a real
identifier. A reviewer can rerun the harness on a fresh clone and
get the same numbers. The fixtures committed to the repo are the
ground truth, and the git tag on them at the submission checkpoint
is immutable -- the accuracy document spells that out as a
threat-model commitment.

If the exit code is zero we keep going. If it is not, we do not
record the demo.

## 4:00 -- 5:00 :: MCP surface and close

*Screen: terminal, split view if convenient.*

We have shown Mode A -- the direct agent extension CLI -- for three
minutes. The product also ships Mode B, a standalone MCP server that
exposes the typed forensics tools over stdio, and Mode C, a hybrid
that drives Mode A's loop while leaning on Mode B for structural
guardrails on specific tool calls. All three modes share one core
package; the tool inventory is the same from any mode.

We surface the MCP tool count briefly. At the current commit the MCP
server registers forty-two tools covering memory forensics
(Volatility 3), timeline forensics (Plaso's log2timeline and psort),
Windows event-log triage (Hayabusa, Chainsaw), disk-image primitives
(Sleuthkit's mmls, fsstat, fls, icat), pattern matching (YARA),
artifact carving (bulk_extractor), Windows registry forensics
(RegRipper), the signed bundle exporter and importer, the rule
generators (YARA, Suricata, Sigma), the IOC exporters (STIX 2.1,
community YAML, per-type text), and the bilingual report renderer.
Every tool is pydantic-typed on input and output. The full schema
reference lives under `docs/reference/mcp-tool-schemas.md` and is
linked from the repo README.

*Closing narration, plain and direct.*

APTWatcher is a defensive incident-response agent with safety rails
built into the architecture. Tier 0 is read-only by default. Tier 3
and tier 4 actions require operator consent and emit state-changing
audit events that a reviewer can inspect after the fact. The
self-correction gate is a code-path invariant, not a prompt wish.
The accuracy harness gives us an F1 floor we can regression-test on
every pull request, and the committed fixtures make every run
reproducible. The offline-to-online handoff signs its bundles with
Ed25519 and verifies them before a single remediation fires.

All the code is MIT-licensed. The try-it-out page walks a judge
through this same demo in ten minutes on a stock Python 3.11. Links
are in the video description. Thank you for watching.

*Cut to end card: repo URL, license, submission id.*

## Fallback clips (pre-recorded)

If the live take breaks, we switch to the matching pre-recorded clip
in the editor. The three happy paths are each recorded as an
asciinema cast under `demo/fallbacks/`. The casts were recorded on
the same commit we demo from, against the same fixtures, with the
same terminal width. Each cast is under ninety seconds. The editor
cuts the cast in cleanly and we resume narrating over it.

- `demo/fallbacks/act1.cast`: the preflight + dry-run sequence from
  minute one. Falls back for terminal errors in the run command.
- `demo/fallbacks/act2.cast`: the analyze + publish sequence from
  minute two. Falls back for any filesystem or signing error.
- `demo/fallbacks/act3.cast`: the eval run from minute three. Falls
  back if the harness discovers zero scenarios or emits a
  non-deterministic transcript replay failure.

We re-record the casts any time a fixture or a CLI flag changes.
Stale casts are worse than no casts.

## Do-not-show list

Some strings never appear on camera, and we double-check before we hit
record.

- Real API keys of any kind, especially `ANTHROPIC_API_KEY`. We unset
  it before the take and confirm on camera with an `env` grep.
- Raw Ed25519 private-key bytes. The demo key lives at
  `demo/keys/ed25519-priv.key`; the file is referenced by path, never
  opened on camera.
- Any path that leaks our personal username beyond what the prompt
  already shows. We prefer a recording account with a neutral
  username.
- Any IP, domain, or hash that is not one of the synthetic values
  baked into the fixtures or into the S04 input JSON. The fixtures
  use RFC 5737 documentation IPs and `.invalid` domains by policy.
- Any real client name, real incident id from a past engagement, or
  real hostname. The demo uses `DEMO-001`, `INC-DEMO-S04`, and
  `demo-host` throughout.
- Any part of our personal notes, reference material, or non-public
  KB content. The repository's `knowledge/` tree is clean-room and
  publishable; no other corpus is on the recording machine.

## Re-takes and editing notes

We rehearse the full five-minute take end-to-end at least three
times before the real recording. The re-take discipline is: if we
fluff a command, we stop, reset the terminal, and start the whole
minute over. We do not attempt to edit a single word out of a take;
the audit-log narration has to match the command output frame for
frame, and a spliced take is too risky.

Practical tips we have collected:

- We type every command by pressing up-arrow through the pre-staged
  shell history. Typing commands live wastes seconds and introduces
  fumbles.
- We record the terminal with asciinema at a fixed width (120
  columns) and a fixed font size. A post-edit re-render in `agg`
  gives us a consistent GIF or MP4 without compression artifacts on
  the text.
- We highlight the audit-log path on screen every time it appears.
  That path is the single artifact a skeptical reviewer will want to
  read, and we make it impossible to miss.
- We avoid emoji, avoid cursor blink effects, and avoid animated
  syntax highlighters. The recording has to be readable on a phone
  at 720p.
- We keep a stopwatch in the corner of the editing session. At
  `0:55`, `1:55`, `2:55`, `3:55`, `4:45` we confirm the beat is on
  the expected minute. Drift of more than ten seconds triggers a
  re-take.
- We render the final cut at 1080p with the terminal at 120 columns.
  The thumbnail is the repo name plus the one-line tagline; no
  screenshot of prose.
- We upload the final cut unlisted first, share the link with one
  reviewer outside the project for a sanity pass, and only then
  flip it to public on the submission deadline.

The script above is the contract. If the project ships a new flag,
this script is updated in the same commit; if the flag renames, the
rename lands here before it lands in the take.
