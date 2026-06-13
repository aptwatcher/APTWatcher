# Dataset inventory and provenance

## Why this doc exists

The hackathon rubric asks for clean data provenance — a reviewer should be
able to open one page and know, without spelunking the tree, what material
ships under the banner of "data" in this repository, where every piece of
it came from, and what it is safe to copy, reuse, or redistribute. This
page is that single source of truth. The authoritative policy text for
the clean-room knowledge base lives in the repository's top-level
`knowledge/README.md` and the
architectural discussion of grounding sources lives in
[`ARCHITECTURE.md`](ARCHITECTURE.md); the present document catalogues
what is actually on disk, explains how each category is licensed and
reviewed, and lists the reproducibility checks that any third party can
re-run from a cold clone.

## Dataset categories

APTWatcher ships four distinct kinds of data. They live in separate
directories, follow separate review rules, and serve separate purposes.

| Pillar | Path | Purpose | Count |
|---|---|---|---|
| Knowledge base | `knowledge/` | Curated, citation-attributed DFIR reference prose that the agent grounds its reasoning on. | 28 entries |
| Narrative scenarios | `scenarios/` and `docs/scenarios/` | Human-readable walkthroughs. Demo scripts at the repo root; rubric scenarios under `docs/`. | 1 demo + 3 rubric |
| Accuracy fixtures | `tests/accuracy/fixtures/` | Machine-scoreable golden fixtures consumed by `aptwatcher eval`. | 2 seed fixtures |
| Audit log samples | `logs/` (runtime-generated) | Per-incident JSONL audit trails produced by `core.audit`. | 0 committed |

None of the four pillars contains real incident data, real PII, or
third-party copyrighted course material. Everything shipped with the
repository is synthetic, hand-authored, or sourced from an upstream
licence the project can legally honour.

## Knowledge base (`knowledge/`)

### Scope and layout

At the time of writing the repository carries 28 Markdown entries under
`knowledge/`, excluding the policy `README.md`. They are organised by
forensic surface rather than by MITRE tactic, because the agent loads
them by artefact type and OS family first and by technique second. The
current tree covers:

- `knowledge/windows/` — persistence, credential access, lateral
  movement, impact, evasion entries keyed to Windows event logs,
  registry hives, and NTFS artefacts.
- `knowledge/linux/` — persistence, credential access, lateral
  movement, execution, and forensics triage entries keyed to systemd,
  auth logs, and SSH key material.
- `knowledge/macos/` — launchd persistence reference.
- `knowledge/network/` — HTTP/HTTPS C2 patterns, beaconing and DNS
  tunnelling, SMB/RPC lateral movement signal.
- `knowledge/memory/` — process injection and kernel-module rootkit
  indicators at the memory-image level.
- `knowledge/timeline/` — MFT timestomping and EVTX logon anomaly
  reference.
- `knowledge/mobile/` — one early iOS iMessage artefacts entry.
- `knowledge/procedures/` — seven operator playbooks covering
  ransomware triage, credential theft response, lateral-movement
  containment, C2 beacon identification, Windows persistence removal,
  memory triage live response, and timeline-building workflow.

### Frontmatter schema

Every entry begins with a YAML frontmatter block that the
`core.knowledge` loader validates against the `core.types.KBEntry`
Pydantic model. The required fields are:

- `id` — stable slug such as `kb-win-cred-kerberoast-001`.
- `title` — human-readable headline.
- `source_type` — one of the six allowed values (see below).
- `attribution` — credit string appropriate to the source type.
- `mitre_techniques` — list of ATT&CK technique and sub-technique IDs
  the entry discusses.
- `artifact_types` — free-form tags identifying the forensic artefacts
  the entry is indexed against (for example `ntfs-mft`,
  `memory_image`, `zeek_logs`).
- `tools` — list of tool names the procedure references.
- `last_updated` — ISO date of the most recent author review.

Entries that fail the schema cause `aptwatcher run` to refuse to start
the agent loop — malformed KB is treated as a preflight failure rather
than a soft warning, on the grounds that the agent's grounding layer
cannot be allowed to degrade silently.

### Allowed source types

The `source_type` field is a closed enumeration. Each value carries a
different licence and a different review burden, and the CI clean-room
scanner applies different rules to each.

- `author-original` — written from scratch by the project author for
  this repository. Licensed MIT alongside the rest of the project.
- `llm-synthesis` — drafted by an LLM (typically Claude) from its
  training knowledge and then reviewed and edited by the author. The
  attribution field records the LLM-assisted provenance; the
  `last_updated` field records the review date. Treated as original
  content under MIT for distribution purposes.
- `mitre-attack` — derived from the MITRE ATT&CK knowledge base.
  Attribution cites the technique IDs; the entry does not reproduce
  MITRE's descriptive text verbatim, only the identifiers and the
  project's own paraphrase.
- `nist` — derived from NIST Special Publications (for example
  SP 800-61r2 on incident handling and SP 800-86 on forensic
  acquisition). NIST publications produced by US federal employees
  are public domain in the United States; attribution cites the SP
  identifier and the section.
- `public-blog-summary` — a fair-use summary of a publicly available
  vendor or research blog post. Summaries only, never quotes longer
  than fifteen words, always a link to the upstream source, and
  never a reproduction of upstream screenshots, images, or code
  blocks.
- `dfir-report-cc` — content from a source that distributes under
  CC BY-SA 4.0. Entries of this type are licensed ShareAlike and
  are isolated from the MIT corpus so they do not contaminate the
  surrounding licence; see `knowledge/README.md` for the boundary
  rules.

### Clean-room policy

The project treats the knowledge base as load-bearing evidence: a KB
entry that reproduces copyrighted training material would contaminate
every downstream finding the agent emits. To prevent that, the CI
clean-room scanner rejects any entry whose content matches a list of
forbidden strings associated with proprietary certification and
training material. The authoritative list lives in the top-level
`knowledge/README.md` file and is
cross-referenced in [`ARCHITECTURE.md`](ARCHITECTURE.md); a
display-only sketch of the tripwire set is:

```
S*NS  GC*H  GC*A  FOR*00  FOR*08  O'R*illy  S*ngress  N*Starch  D*IR Report
```

Those display forms are hyphenated purely so this very page does not
trip its own grep gate. The live scanner matches the fully spelled
forms from the policy file. The intent is to prevent inadvertent
ingestion of course, certification, or publisher material that the
project has no right to redistribute, even when such material is
available to the author through legitimate study channels. When a
topic is covered only by a proprietary source, the rule is to write
the entry fresh from first principles, cite a public reference such as
a MITRE technique or a NIST SP, and flag it `author-original` or
`llm-synthesis`.

Attribution discipline is enforced at review time: every entry must
fill `attribution`, and `llm-synthesis` entries must name the class of
assistant that produced the draft and the date on which the human
review closed. Entries whose attribution field is empty, whose
`last_updated` is more than six months stale on a commit diff, or
whose body contains long verbatim sentences from an external source
are rejected by the review checklist before they reach a pull request.

### Sample entries

The following table is a small sample drawn from the live tree as of
the last commit. It is illustrative, not exhaustive; the authoritative
index is regenerated by the `core.knowledge` loader at start-up.

| ID | Source type | Topic |
|---|---|---|
| `kb-win-cred-kerberoast-001` | `author-original` | Kerberoasting — offline cracking of service-account credentials. |
| `kb-lin-pers-systemd-cron-001` | `author-original` | Systemd timers and cron as persistent Linux execution primitives. |
| `kb-net-c2-http-001` | `author-original` | HTTP and HTTPS command-and-control beaconing patterns. |
| `kb-mem-inj-hollowing-001` | `author-original` | Process hollowing indicators visible in memory images. |
| `kb-proc-ransomware-triage-001` | `author-original` | Ransomware incident — first-sixty-minutes triage playbook. |

## Narrative scenarios (`scenarios/` and `docs/scenarios/`)

The repository carries two parallel scenario trees with deliberately
different jobs.

`docs/scenarios/` carries the rubric scenarios S01, S02, and S03. S01
is a single-Windows-host compromise and is the floor — it has to run on
every install. S02 is a three-host lateral-movement case that
exercises Tier 0 and Tier 1 intel lookups. S03 is a ransomware
pre-detonation case that reaches into Tier 3 gating. Each page carries
a story paragraph, an environment description, an attacker timeline,
the rubric of findings an honest triage surfaces, and the expected
agent reasoning path. They exist for demo footage, for the Devpost
submission write-up, and for the judge's fifteen-minute verification
path.

`scenarios/` at the repository root carries the demo walkthroughs. At
the time of writing this tree contains one scenario, S04 (offline-to-
online bundle handoff), which drives the Phase 3.7 bundle demonstration:
an air-gapped triage workstation signs an incident bundle with an
Ed25519 key, a courier carries it across the air gap, and an online
workstation verifies the signature and fans the triage data out to
three stub publication adapters. S04 is the demo-night story, not a
machine-scored test; it proves the offline-to-online boundary works
end-to-end without requiring live credentials.

All scenarios are original writing produced for this repository.
They are licensed under the project's MIT licence. No third-party
case material is embedded; the host names, user names, and IP
addresses in every scenario are invented and sit inside the
RFC 5737 documentation ranges wherever an IPv4 value is required.

## Accuracy fixtures (`tests/accuracy/fixtures/`)

### Shape

Accuracy fixtures are the machine-scoreable counterpart to the
narrative scenarios. Each fixture lives in its own directory under
`tests/accuracy/fixtures/` and carries a fixed set of files the
harness knows how to consume.

- `manifest.yaml` — identifies the fixture, names the profile to load,
  and points at the other files. Required keys: `id`, `description`,
  `profile`, `transcript_path`, `golden_path`. Optional keys:
  `seed_findings_path`, `seed_iocs_path`, `kb_subset_globs`.
- `golden.json` — the ground truth. A list of expected findings (each
  with a title, a tier, and the MITRE IDs the agent must produce) and
  a list of expected IOCs (each with a normalised value and a type).
  The scorer matches findings on title and MITRE set and IOCs on
  normalised value.
- `transcript.json` — a canned sequence of `ModelResponse` payloads
  that `FakeModelClient` replays in order. Because the harness never
  contacts a real LLM, the transcript is the entire model behaviour
  for the run and is kept deliberately short — three to five calls is
  typical.
- `seed_findings.json` (optional) — findings the harness pre-seeds
  onto `AgentState` before the loop starts, so the transcript can
  finalise cleanly without having to synthesise the findings itself.
- `seed_iocs.json` (optional) — IOCs pre-seeded onto `AgentState` in
  the same style.

### Current fixtures

Two seed fixtures ship with the repository today. Both target the
`windows-host-triage` profile.

- `s_phishing_beacon` — a phishing email delivers a macro-laden
  document, the macro stages a loader, and the loader beacons to a
  known-bad IPv4 in the RFC 5737 `203.0.113.0/24` documentation range.
  The golden expects two findings (macro execution tagged T1566.001 and
  T1204.002; outbound C2 beacon tagged T1071.001) and two IOCs (the
  beacon IPv4 and the loader SHA-256).
- `s_credential_dump` — a privileged process dumps LSASS memory via a
  `rundll32` comsvcs MiniDump invocation on a Windows host. The golden
  expects two findings (the LSASS access itself tagged T1003.001 and
  the suspicious `rundll32` invocation tagged T1003.001 plus T1218.011)
  and one IOC (the dumper SHA-256).

### Labelling provenance

The goldens are hand-labelled by the project authors. The transcripts
are hand-crafted JSON files whose payloads are short structured
reasoning notes that steer `FakeModelClient` past the loop's finalise
gate without calling into an external model. There is no human
annotator pool, no crowd-sourced labelling, and no automated label
extraction from real incident data; the fixtures exist to exercise the
harness plumbing and to anchor the accuracy methodology, not to claim
representativeness against the space of real incidents. The honesty
discussion on that point lives in [`ACCURACY.md`](ACCURACY.md).

### Reproducibility

Fixture runs are deterministic by construction. Transcripts carry no
time-dependent content; the `FakeModelClient` consumes them in order
and raises on exhaustion rather than fabricating continuations; and
the scorer's matching rules are exact on MITRE IDs and case-normalised
on IOC values. Running

```
aptwatcher eval --fixtures-dir tests/accuracy/fixtures
```

on a fresh clone yields an identical scorecard across runs and across
machines, with F1 equal to 1.0 on both seed fixtures. That property is
what lets the suite sit on the submission-gate critical path.

### Growth plan

The fixture set is intentionally small at the moment. The Phase 4
roadmap in [`ACCURACY.md`](ACCURACY.md) targets five to ten fixtures
before the hackathon submission gate, with at least one fixture per
non-Windows profile (`linux-host-triage`, `memory-only`,
`timeline-only`, `network-artifact`) so the aggregate F1 score reflects
more than a single OS family. The process for adding a new fixture is
documented in section "How to add a new scenario" of `ACCURACY.md`.

## Audit log samples

Audit logs are runtime artefacts rather than shipped data. The
`core.audit` module writes them to `logs/<incident_id>/audit.jsonl`
whenever the agent loop executes, and the directory is created on
logger construction. No pre-recorded audit log is committed to the
repository — the `logs/` tree is `.gitignore`'d so that a live run on
any machine produces a locally authoritative trace rather than mixing
with sample material.

The wire format is JSON-Lines with UTF-8 encoding, `\n` line endings,
and no outer array. Every event carries a fixed envelope with an
event type, an incident ID, a correlation ID, a UTC timestamp, and a
payload. The authoritative byte-level specification is
[`design/audit-log-format.md`](design/audit-log-format.md), which also
tracks a known gap: the current envelope does not carry a
`schema_version` field, and the recommendation is to add
`"schema_version": "1.0"` to every line before the submission cut.
Consumers that parse audit logs are expected to tolerate an absent
`schema_version` and fall back to best-effort parsing of the five
fixed envelope keys.

When a judge reproduces a scenario end-to-end, the audit log for that
run is produced locally in their own `logs/` directory and can be
inspected with `jq`, `grep`, or any JSONL-aware tool. The incident
bundle produced by Phase 3.7 ships the audit log alongside the
findings and IOCs so a downstream verifier can trace every claim back
to a tool invocation.

## What this project does NOT ship

The negative space matters as much as the positive. Pulling this
repository does not give the user:

- real incident-response case data from any engagement, public or
  private;
- personally identifiable information, real credentials, API keys, or
  tokens;
- any third-party training-course material, certification textbook,
  or publisher excerpt (the clean-room policy in the top-level
  `knowledge/README.md` exists to keep that boundary firm);
- proprietary malware samples, packed binaries, or copies of adversary
  tooling;
- commercial threat-intelligence feeds, paid-vendor reports, or
  screenshots of licensed tools.

What a cold clone produces is synthetic, hand-authored, or explicitly
upstream-licensed content and nothing else. The repository is
distributable in full to any third party under the conditions of the
MIT licence.

## Licensing

The project as a whole is distributed under the MIT licence, as
declared in the top-level `LICENSE` file and in the `license` field of
`pyproject.toml`.

- Knowledge-base entries are licensed under MIT unless their
  `source_type` indicates a different upstream licence. `nist`
  entries cite content that is public domain in the United States;
  `dfir-report-cc` entries are isolated CC BY-SA 4.0 content (they do
  not contaminate the surrounding MIT corpus); `mitre-attack` entries
  cite technique IDs whose parent framework is licensed by MITRE under
  its own terms.
- Scenario narratives — both the demo tree at the repository root and
  the rubric tree under `docs/scenarios/` — are original writing,
  licensed MIT.
- Accuracy fixtures (manifests, goldens, transcripts, seed findings,
  seed IOCs) are original writing, licensed MIT.
- MITRE ATT&CK references carry MITRE's own licence for the technique
  framework; the project cites the IDs it needs and paraphrases the
  relevant behaviour, rather than reproducing MITRE's descriptive
  text.
- Runtime audit logs are produced by a user running the agent on their
  own host and belong to the user, not to this project.

## Reproducibility checklist

A reviewer who wants to confirm the data story from a cold clone
should be able to run this sequence and see it pass:

1. Clone the repository, create a Python 3.11 virtual environment, and
   install the project with the development extras:
   `pip install -e .[dev]`.
2. Run the accuracy harness against the shipped fixtures:
   `aptwatcher eval --fixtures-dir tests/accuracy/fixtures`. The
   command should exit `0` with an aggregate mean F1 of `1.0` on both
   seed scenarios. The emitted report under `./accuracy-runs/` records
   the scorecard for the run.
3. Load the knowledge base through the core loader, which validates
   every frontmatter block against the `core.types.KBEntry` Pydantic
   model. A malformed entry surfaces as a preflight error and fails
   the load rather than silently skipping.
4. Build the documentation site with `mkdocs build --strict`. The
   strict flag promotes dead links, missing nav entries, and template
   errors into build failures, which means a green build indicates
   that every page referenced by the nav tree — including this one —
   actually resolves.

None of these checks requires network access or non-trivial
credentials; all four run entirely offline on the SIFT VM used for
development.

## Contact and extension

Extending the dataset happens in one of three places depending on the
pillar being extended.

- **New KB entry.** Follow the schema and review rules in the
  top-level `knowledge/README.md`. Pick a
  `source_type`, fill `attribution` honestly, list the MITRE IDs the
  entry actually discusses, and run the clean-room scanner locally
  before opening a pull request. Drop the file into the subdirectory
  that matches its forensic surface and use the existing naming
  convention (`kb-<surface>-<topic>-<nnn>`).
- **New narrative scenario.** For a demo walkthrough, follow the
  template in the top-level `scenarios/README.md`
  and pick an `S<NN>-<kebab-slug>.md` filename that will still read
  cleanly a year from now. For a rubric scenario (S01–S03 and any
  successors), follow the outline under `docs/scenarios/README.md` so
  the story, environment, attacker timeline, rubric, and success
  bands stay comparable across scenarios.
- **New accuracy fixture.** Follow "How to add a new scenario" in
  [`ACCURACY.md`](ACCURACY.md). In short: create a directory under
  `tests/accuracy/fixtures/`, drop a `manifest.yaml` keyed to a
  profile, author a `golden.json` with a small number of findings and
  IOCs, record a short `transcript.json` that drives the loop to
  finalisation, and run `aptwatcher eval` locally to confirm the new
  fixture appears in the scorecard with a sensible score.

For anything that does not fit one of those three slots — a new
dataset class, a change to the clean-room policy itself, a new
source-type enumeration value — open an issue against the repository
and link back to this page so the provenance story stays consistent.
