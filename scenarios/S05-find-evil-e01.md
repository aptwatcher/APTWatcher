# S05 — Find evil in one shot (E01 to signed PDF bundle)

> The cold-workstation demo. An analyst sits down at a SIFT VM that has
> never seen this case, points APTWatcher at an E01 image plus a paired
> memory capture, walks away for fourteen minutes, and comes back to a
> signed IncidentBundle and a judge-readable PDF. Zero mid-run
> questions, zero pre-indexing. This is the shape of the submission
> demo recorded on 2026-04-21 by the hackathon keynote — one command,
> one cup of coffee, one report.

## Story

Monday 14:02 local. A regional MSSP hands the analyst a forensic image
drop from customer host `HOST-RD01` — a Windows 10 workstation flagged
by an upstream detection as a likely lateral-move destination. The
drop lives at `/cases/demo-s05/` and contains three files:
`host-rd01-cdrive.E01`, `host-rd01_memory.img`, and a short
`CLAUDE.md` that names the profile and the two artifacts. The analyst
runs one `aptwatcher` command with a 14.5-minute time budget, steps
away for coffee, and at 14:16 finds a signed IncidentBundle and a
rendered PDF waiting under `work/s05-run/`. The attribution fixture
names a clean-room synthetic actor, "Synthetic APT-S05". Nothing was
asked mid-run. No human judgement was solicited. The machine-speed
threat model in [`../docs/SCOPE.md`](../docs/SCOPE.md#threat-model)
demands exactly this cadence.

## Environment

- **Host**: single SIFT workstation VM. Python 3.11+ (3.10 is
  rejected at startup because `datetime.UTC` is unavailable). The VM
  can be fully air-gapped; no outbound network is required.
- **Tooling paths** (per the tool invocation contract in the repo
  [`CLAUDE.md`](../CLAUDE.md)): Volatility 3 at
  `python3 /opt/volatility3/vol.py`, `log2timeline.py` at
  `/usr/bin/log2timeline.py`, `psort.py` at `/usr/bin/psort.py`,
  `fls` and `icat` at `/usr/bin/`, `bulk_extractor` at
  `/usr/bin/bulk_extractor`, YARA at `/usr/bin/yara`, Hayabusa at
  `/opt/hayabusa/hayabusa`. Every wrapper honours its documented env
  override (`APTW_VOL3_BIN`, `APTW_PLASO_BIN`, etc.) if the canonical
  path is not where the VM puts it.
- **Case directory**: `/cases/demo-s05/` — read-only mount. The
  evidence never leaves this directory.
- **Working directory**: `work/s05-run/` — all derivatives, partials,
  audit log, rendered reports, and the signed bundle land here. The
  evidence tree is never written to.
- **Operator key**: Ed25519 seed at
  `~/.aptwatcher/keys/operator.ed25519`; the pinned public hex lives
  beside it at `operator.pub.hex`. The same key material S04 uses.

## Inputs

Three files at `/cases/demo-s05/`, fully synthetic, hand-authored to
exercise the full Windows-host-triage profile end-to-end.

| Path | Role | Shape |
|------|------|-------|
| `host-rd01-cdrive.E01` | Disk image | Windows 10 workstation C: volume in Expert Witness Format. Posed as a lateral-move destination: a scheduled-task persistence drop, a staged loader binary, and a registry Run key pointing at it. |
| `host-rd01_memory.img` | Memory dump | Raw memory capture taken concurrently with the disk acquisition. Contains two suspicious processes and a network artefact that cross-references the disk-side C2 domain. |
| `CLAUDE.md` | Case brain | Four-line file: profile name, two evidence filenames, operator identity. This is the file the agent reads first to know what it is looking at. It does not name the expected findings. |

### Expected IOC set (for accuracy scoring)

Five ground-truth indicators are hidden in the fixture. A pass run
surfaces all five; a partial run surfaces three or four.

| # | Type | Value shape | Lives in |
|---|------|-------------|----------|
| 1 | Suspicious process | Injected `svchost.exe` child with anomalous parent | Memory dump |
| 2 | Suspicious process | Unsigned binary running from `C:\ProgramData\` | Memory dump + disk |
| 3 | Registry persistence key | `HKLM\...\Run\` entry pointing at the ProgramData binary | Disk image (SYSTEM hive) |
| 4 | C2 domain | Single FQDN, resolvable offline as a fixture | Memory dump (connections) + pagefile |
| 5 | YARA-hittable binary | PE on disk matching a stock packed-loader rule shipped in `rules/` | Disk image |

Attribution inside the fixture tags the campaign "Synthetic APT-S05".
The label is clean-room synthetic; it does not map to any real-world
actor name. Any confidence tier attached to the attribution itself is
`indicator` at best — the fixture is not trying to teach the agent to
convict.

## Commands

### Aspirational one-shot form

This is the command the demo video reads on camera. Not every flag
ships today; see the next subsection for what is actually wired right
now.

```bash
aptwatcher run \
    --profile windows-host-triage \
    --case-dir /cases/demo-s05 \
    --evidence host-rd01-cdrive.E01,host-rd01_memory.img \
    --time-budget-seconds 870 \
    --output work/s05-run/ \
    --analyze --sign --report-format pdf
```

The intent is that `--case-dir` fixes the read-only evidence mount,
`--time-budget-seconds` pins the SLA from
[`../docs/ACCURACY.md`](../docs/ACCURACY.md#wall-clock-triage-sla),
`--output` redirects every derivative out of the evidence tree, and
`--analyze --sign --report-format pdf` fold the post-run analyze +
bundle-sign + report-render steps back into `run` so the operator
types one command instead of two.

Which flags ship today:

| Flag | Status | Notes |
|------|--------|-------|
| `--profile` | Ships | `run_command` in `src/agent_extension/cli.py`. |
| `--evidence` | Ships | Repeatable `-e` per file; comma-joined form is aspirational. |
| `--case-dir` | Aspirational | Today the evidence paths are absolute; a `--case-dir` root that rewrites relative paths is tracked in the issue tracker under "run: case-dir root". |
| `--time-budget-seconds` | Aspirational | Wired only on `aptwatcher eval` right now; back-port to `run` is tracked as "run: honour time-budget-seconds". |
| `--output` | Aspirational | `run` writes to `logs/` and the implicit working tree today; a single `--output` root that collects everything is tracked as "run: unified output root". |
| `--analyze --sign --report-format pdf` | Aspirational as combined flags on `run`. `--sign` ships on `analyze`. `--report-format pdf` does not ship — `analyze --language en|fr|both` renders Markdown today. PDF rendering is tracked as "analyze: pdf output adapter". |

### Today-working split form

Two commands. Same end state for the parts that are wired. Substitute
for the aspirational one-shot above until the tracker items close.

```bash
# 1. Triage: runs the agent loop against the disk + memory artefacts,
#    emits findings, writes the audit log under logs/.
aptwatcher run \
    --incident-id INC-20260421-S05001 \
    --profile windows-host-triage \
    --evidence /cases/demo-s05/host-rd01-cdrive.E01 \
    --evidence /cases/demo-s05/host-rd01_memory.img \
    --log-dir work/s05-run/logs

# 2. Analyze: fan the verified findings and IOCs into the full bundle
#    tree, sign with the operator key. Markdown report today; the
#    PDF step is a follow-up wrapper until the pdf adapter lands.
aptwatcher analyze \
    --input work/s05-run/triage-input.json \
    --output-dir work/s05-run/bundle \
    --incident-id INC-20260421-S05001 \
    --campaign-tag SYNTHETIC-APT-S05 \
    --operator "demo-analyst" \
    --language en \
    --sign \
    --private-key-path ~/.aptwatcher/keys/operator.ed25519 \
    --sift-workstation "sift-5.13-demo-s05"
```

The split is honest about where the seam sits today and where the
single-command experience is going. The demo script in
[`../demo/SCRIPT.md`](../demo/SCRIPT.md) uses the split form and
narrates the aspirational form as "what the final CLI will do".

## Expected wall-clock

Budget is 870 seconds (14.5 minutes) end to end, pinned by
[`../docs/ACCURACY.md`](../docs/ACCURACY.md#wall-clock-triage-sla).
Same per-stage breakdown the accuracy harness reports:

| Stage | Budget (s) | What happens here |
|-------|-----------:|-------------------|
| Pre-check    |  30 | Profile load, tool preflight at canonical absolute paths, KB subset warmup. |
| Plan         |  60 | Planner reads the profile's tool roster and the top-N KB entries; emits the initial tool-plan. |
| Execute      | 540 | Volatility 3 + Hayabusa + plaso + fls/icat + bulk_extractor + YARA scans. Bulk of the budget. |
| Verify       |  90 | Verifier cross-checks each finding against its source citation and the seed KB rules. |
| Self-correct |  90 | Up to three bounded retries per failed step; tier-downshift on the third failure. |
| Finalize     |  60 | Bundle assembly + Ed25519 sign + report render. |
| **Total**    | **870** | 14.5 minutes end to end. |

If the run overruns into the 870-1200s window it is a partial. Beyond
1200s it is a fail. The overrun rubric itself is a deliberate
downshift path, not a soft limit.

## Audit events

The ordered event types a judge sees when they run:

```bash
aptwatcher audit-render \
    --input work/s05-run/audit.jsonl \
    --format md
```

Expected sequence for a clean pass:

| Order | Event type | Emitted by | Notes |
|-------|-----------|------------|-------|
| 1 | `run_start` | `AgentLoop` | Incident id, profile, evidence sha256s. |
| 2 | `preflight` | `preflight()` | Canonical tool paths probed; missing tools recorded. |
| 3 | `profile_loaded` | Planner | Windows-host-triage profile resolved. |
| 4 | `kb_subset_loaded` | Planner | Top-N KB entries pulled via `KnowledgeBase.search`. |
| 5 | `plan_emitted` | Planner | Initial tool-plan with step ids. |
| 6..k | `tool_call` | Executor | One per tool invocation (Volatility 3, Hayabusa, plaso, fls, icat, bulk_extractor, yara). Expect 8-14 calls on a clean pass. |
| k+1..m | `finding` | Verifier | One per surfaced indicator; carries a `FindingCitation` back to the `tool_call` event id. |
| (optional) | `self_correction` | Self-corrector | 1-2 occurrences on a typical pass (profile mismatch, EVTX truncation). Each records the retry count and the tier-downshift, if any. |
| m+1 | `claim_verification` | Verifier | Aggregate: every finding has at least one citation; any uncited claim is dropped here, never silently kept. |
| m+2 | `analysis_emit` | Finalizer | Bundle tree written under `work/s05-run/bundle/`. |
| m+3 | `bundle_signed` | Finalizer | Signer public-key fingerprint recorded; never the private key. |
| m+4 | `run_end` | `AgentLoop` | Totals: stage timings, findings count, tier distribution. |

Each event is append-only and signed with the run's ephemeral key.
The rendered timeline in `work/s05-run/audit-timeline.md` cites event
ids the same way the narrative report does. A claim in the final PDF
without a backing event id is not a claim — it is a guess, and the
verifier is responsible for dropping it before `analysis_emit`.

## Success rubric

| Band | Criteria |
|------|----------|
| **Pass** | All 5 expected IOCs surface in the bundle's `iocs.json`. Report renders without error (Markdown today; PDF once the adapter lands). `import_bundle` returns cleanly against the pinned operator public key. Wall clock is at or below 870s. Every finding carries at least one `FindingCitation` into the audit log. |
| **Partial** | 3 or 4 of the 5 expected IOCs present. **Or** wall clock falls between 870s and 1200s. **Or** one or more findings are tier-downshifted (`confirmed` to `likely`, etc.) because of a bounded self-correction. The bundle still signs and verifies; the report still renders. |
| **Fail** | Fewer than 3 expected IOCs present. **Or** the bundle is unsigned or fails signature verification. **Or** report generation raises. **Or** wall clock exceeds 1200s. **Or** any `chain_of_custody_break` event fires mid-run — that is always a hard fail. |

Two adversarial sub-cases the demo walks through so the failure modes
are visible, not just asserted:

- **Evidence-tree write.** The agent is pointed at a `--output`
  directory that resolves inside `/cases/demo-s05/`. The preflight
  rejects the run before any tool fires, emits
  `chain_of_custody_break`, and exits non-zero.
- **Tampered bundle.** A judge flips one byte in
  `work/s05-run/bundle/incident-bundle/iocs.json` after the run. The
  follow-up `import_bundle` call raises `BundleIntegrityError` on the
  per-file digest check, before the signature step. Same invariant
  S04 guarantees; restated here so the one-shot demo inherits the
  same trust boundary.

## Dataset strategy

S05 is fully synthetic and clean-room. The disk image, memory dump,
and CLAUDE.md are hand-authored against documented Windows 10
forensic artefacts; no third-party evidence corpus is redistributed.
The attribution label "Synthetic APT-S05" is invented for this
scenario and does not map to any real-world actor naming. The YARA
rule the fixture intentionally trips is a stock packed-loader rule
shipped in this repository's `rules/` tree, not an imported
signature.

## Related

- Repo brain: [`../CLAUDE.md`](../CLAUDE.md)
- Submission scope: [`../docs/SCOPE.md#threat-model`](../docs/SCOPE.md#threat-model) (GTG-1002 class, machine-speed)
- SLA commitment: [`../docs/ACCURACY.md#wall-clock-triage-sla`](../docs/ACCURACY.md#wall-clock-triage-sla)
- Demo script: [`../demo/SCRIPT.md`](../demo/SCRIPT.md)
- Role decomposition design: [`../docs/design/subdomain-agents.md`](../docs/design/subdomain-agents.md)
- Companion scenario: [`S04-offline-to-online-handoff.md`](S04-offline-to-online-handoff.md)
- Scenarios index: [`README.md`](README.md)
