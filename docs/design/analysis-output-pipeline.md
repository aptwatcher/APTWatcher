---
title: Analysis output pipeline
status: draft
---

# Analysis output pipeline

> **Status**: draft. Author: APTWatcher core.
> **Scope**: Phase 3.8 — rule generators, IOC exporters, report renderers,
> and publication adapters that run after triage self-correction closes.
> **Related**: [`../ARCHITECTURE.md`](../ARCHITECTURE.md),
> [`./evidence-integrity.md`](./evidence-integrity.md),
> [`./audit-log-format.md`](./audit-log-format.md),
> [`./offline-to-online-handoff.md`](./offline-to-online-handoff.md).

## Purpose

Once an incident run has produced a verified set of `Finding` + `IOC`
records and the self-correction gate has cleared report emission,
APTWatcher fans out one audit-anchored bundle into the set of shapes the
broader defender ecosystem already consumes. The pipeline inherits the
format conventions of the **APT Watch** (`apt-intel`) project so that
APTWatcher output is drop-in compatible with aptwatch.org's community
feed, MISP, STIX/TAXII consumers, Netcraft v3 take-downs, and downstream
EDR/XDR platforms.

This is a **clean-room** pattern adaptation. Formats and algorithms are
described here; no `apt-intel` code is copied into APTWatcher. The same
policy applied to the Tier 1 intel-lookup pattern
([`./tier1-intel-lookup-pattern.md`](./tier1-intel-lookup-pattern.md))
applies here.

## Pipeline shape

    Finding[] + IOC[] + HashRecord[] + Claim[] + timeline
            │
            ▼
     ┌──────────────────────────────────────────────────────────┐
     │                Analysis output pipeline                  │
     │                                                          │
     │  1. Rule generators                                      │
     │     ├─ YARA synthesizer       -> *.yar                   │
     │     ├─ Suricata synthesizer   -> auto-<campaign>.rules   │
     │     └─ Sigma synthesizer      -> *.sigma.yml (Phase 4)   │
     │                                                          │
     │  2. IOC exporters                                        │
     │     ├─ STIX 2.1 bundle        -> bundle.stix.json        │
     │     ├─ MISP event             -> misp-event.json (opt)   │
     │     └─ SOC CSV dumps          -> iocs/{type}.csv         │
     │                                                          │
     │  3. Report renderers                                     │
     │     ├─ Campaign .docx (EN)    -> Campaign_Report_*.docx  │
     │     ├─ Campaign .docx (FR)    -> Campaign_Report_*_FR.docx│
     │     ├─ Analyst narrative .md  -> ANALYSIS-*.md           │
     │     └─ TTP assessment .md     -> TTP_*.md                │
     │                                                          │
     │  4. Community submission                                 │
     │     └─ TEMPLATE.yaml adapter  -> community-submission.yml│
     │                                                          │
     │  5. Publication adapters                                 │
     │     ├─ Netcraft Report v3                                │
     │     ├─ STIX/TAXII push        (Phase 4)                  │
     │     ├─ MISP event push        (Phase 4)                  │
     │     ├─ AbuseIPDB              (Phase 4)                  │
     │     └─ GLPI attachment upload (Phase 4)                  │
     └──────────────────────────────────────────────────────────┘
            │
            ▼
       generation_report.json  (stats manifest + SID range + hashes)

Every stage reads from a single typed input bundle, writes a single
typed output, logs a `tool_call` pair, and contributes to the
`generation_report.json` manifest that travels with the
`IncidentBundle`.

## Input contract

The `analyze` stage receives a `TriageResult` snapshot assembled by the
agent loop from the verified audit log. Only fields with a matching
`FindingCitation` chain are passed through — unverified or
self-corrected-out claims are dropped at the gate, not at the renderer.

```python
class TriageResult(_Model):
    incident_id: str                  # matches audit.jsonl run
    profile: str                      # use-case profile
    generated_at: datetime            # UTC
    findings: list[Finding]           # citation-anchored
    iocs: list[IOC]                   # normalized value + type + provenance
    hashes: list[HashRecord]          # sha256/sha1/md5 + path + size
    claims: list[Claim]               # verifier-graded statements
    timeline: list[TimelineEvent]     # plaso-derived, may be empty
    evidence_manifest: list[EvidenceFile]  # from preflight
    mitre_techniques: list[str]       # aggregated ATT&CK IDs
    campaign_label: str | None        # optional operator-supplied tag
```

Each `IOC` carries at minimum `value`, `type` (`ipv4` | `ipv6` |
`domain` | `url` | `email` | `cidr` | `sha256` | `sha1` | `md5` |
`cve`), `confidence` (float 0-1), `first_seen`, `last_seen`, and a
`provenance` list pointing back to `correlation_id`s in the audit log.
The pipeline refuses to emit any rule or submission for an `IOC` whose
provenance list is empty.

## Rule generators

### YARA

One `.yar` file per logical rule family (campaign, malware family, or
TTP cluster). The generator takes observed byte patterns, API-resolution
hash constants, PE characteristics, and string artefacts from findings
and produces one or more `rule` blocks per file. Each rule ships a
**full meta block** aligned with the `conti-locker-v2.yar` reference
shape:

    rule <Family>_<Variant>_<Aspect>
    {
        meta:
            description    = "<one-line what this matches>"
            author         = "APTWatcher"
            date           = "YYYY-MM-DD"
            source         = "incident <incident_id>"
            actor          = "<actor or 'unknown'>"
            reference      = "https://aptwatch.org"
            hash_algorithm = "<MurmurHash2A | SHA-256 | ...>"
            severity       = "<critical | high | medium | low>"
            mitre_attack   = "<T1027,T1486,...>"
            incident_id    = "<run-id>"
            confidence     = "<0.0-1.0>"
            hash           = "<sample-sha256-if-applicable>"

        strings:
            // each string is commented with its provenance (file path,
            // offset, or audit correlation_id)
            $a = { ... }   // from finding-abc123, offset 0x240

        condition:
            <PE/ELF magic guard> and
            filesize < <N>MB and
            <strong-anchor> and
            <K> of ($h_*)
    }

Generator responsibilities:

- **String sourcing.** Accept byte sequences only if they appear in at
  least one `Finding.supporting_bytes` citation and the corresponding
  audit `correlation_id` is present. Refuse to emit strings built purely
  from LLM synthesis.
- **Condition templates.** Built from a small library — PE32 header
  guard, ELF header guard, script-file heuristics, filesize band,
  N-of-K string quorum. Every template has a unit test that scans a
  known-benign corpus and asserts zero hits.
- **Meta block.** Always includes the eight required keys above.
  Optional keys (`hash`, `note`, `tlp`) are appended when present.
- **Provenance comments.** Every `$name` string has a trailing comment
  with either the source file offset, the sample SHA-256, or the
  triage `correlation_id`. No unattributed constants.
- **Filename convention.** `yara/<family-slug>[-<variant>].yar`
  (kebab-case), matching the `conti-locker-v2.yar` pattern.
- **Test harness.** Every run compiles the output set with
  `yara-python` (`yara.compile(source=...)`) before the file is sealed.
  A compile failure aborts the generator with a structured error and
  leaves no partial file on disk. A lint pass then asserts every rule
  carries the required meta keys.

### Suricata

One file per campaign, named `auto-<campaign-slug>.rules`. File layout:
banner header, per-category section comments, one `alert` line per
rule, trailing summary. Pattern is adapted from the `apt-intel`
`suricata_generator.py` reference — read for approach, not copied.

    # ======================================================================
    # APTWatcher - Auto-Generated Suricata Rules
    # Campaign: <campaign-name>
    # Aliases:  <aliases-if-any>
    # Incident: <incident_id>
    # Generated: YYYY-MM-DD
    # Generator: aptwatcher-analyze 1.0
    # ======================================================================

    # --- C2 IP Detection ---
    alert ip $HOME_NET any -> 203.0.113.10 any (msg:"APTWATCH <Actor> C2 IP 203.0.113.10"; \
        classtype:trojan-activity; sid:2026XXXXXX; rev:1; \
        metadata:created_at 2026_04_19, actor <Actor>, campaign <Campaign>, \
        mitre_attack T1071.001;)

    # --- DNS Detection ---
    alert dns $HOME_NET any -> any any (msg:"APTWATCH <Actor> C2 domain evil.example"; \
        dns.query; content:"evil.example"; nocase; classtype:trojan-activity; \
        sid:2026XXXXXX; rev:1; \
        metadata:created_at 2026_04_19, actor <Actor>, campaign <Campaign>;)

    # ======================================================================
    # Total Rules: <N>
    # SID Range: <start> - <end>
    # ======================================================================

Rule categories (section comments) recognized by the generator:

- `C2 IP Detection` — `ipv4`, `ipv6`
- `DNS Detection` — `domain`
- `Hash Detection` — `sha256`, `sha1`, `md5` (on HTTP file upload)
- `URL Detection` — `url`
- `SMTP/Email Detection` — `email`
- `Delivery Infrastructure` — CIDR sweeps (generator-level option)

SID management:

- **SID range.** APTWatcher reserves a private SID block configured per
  deployment (default: `2026000000 - 2026999999`). No Suricata rule ever
  lands outside the block.
- **Allocation.** On each run, the generator scans every existing
  `*.rules` file in the output directory, parses every `sid:(\d+);`,
  and resumes from `max(existing) + 1`. SID allocation is serial and
  per-incident.
- **Rev increments.** If a rule body changes for the same IOC value,
  the generator keeps the SID and bumps `rev`. An IOC whose value
  disappears in a later run is **not** retracted — retraction is an
  explicit operator action (`aptwatcher retract <sid>`).
- **Skip-existing.** An IOC whose value already appears in any rule in
  the output directory is skipped, counted into `skipped_existing` in
  the stats manifest.
- **Confidence floor.** IOCs below a configurable confidence threshold
  (default 0.6 for campaigns, 0.5 for staging) are skipped and counted
  into `skipped_confidence`.

Dry-run validation:

- `suricata -T -c <temp-conf> -S <output-file>` is invoked in a
  sandbox directory before the file is sealed. A non-zero exit writes
  the offending rule body to the audit log and aborts the generator.
- A static linter first checks balanced quotes, presence of `sid:` and
  `rev:`, and SID membership in the reserved block.

### Sigma (Phase 4)

Sigma YAML for EVTX-anchored findings (feeds back into
hayabusa/chainsaw). Out of scope for the MVP; the generator module is
stubbed so the `--formats sigma` flag is recognized and no-ops with a
warning until it lands.

## IOC exporters

### STIX 2.1 bundle

Single-file JSON `bundle.stix.json` with `type: "bundle"` and a versioned
`id` (UUIDv4). Object mix:

- One `identity` object for APTWatcher (the creator).
- One `campaign` object per distinct campaign label.
- One `malware` object per malware family observed.
- One `indicator` object per `IOC`, with `pattern` built from the
  STIX 2.1 pattern language (`[ipv4-addr:value = '203.0.113.10']`,
  `[domain-name:value = 'evil.example']`,
  `[file:hashes.'SHA-256' = '<hex>']`, etc.).
- `relationship` objects linking `indicator -> indicates -> malware`
  and `indicator -> indicates -> campaign`.
- One `sighting` per finding, with `sighting_of_ref` pointing at the
  relevant indicator and `where_sighted_refs` pointing at the
  APTWatcher identity.

Bundle metadata carries `created_by_ref` on every object,
`labels: ["aptwatcher", "incident-<id>"]`, and `confidence` where
supported. TLP marking-definition references are included when the
operator supplied a `--tlp` flag.

### MISP-compatible JSON (optional)

Emitted only when `--formats misp` is passed. Shape is the MISP
`Event` JSON (`Event.info`, `Event.date`, `Event.threat_level_id`,
`Event.analysis`, `Event.Attribute[]`, `Event.Tag[]`). Each IOC becomes
one `Attribute` with `type`, `category` (`Network activity`, `Payload
delivery`, etc.), `value`, and `to_ids: true` when confidence clears
the per-type threshold. This file is directly importable via the MISP
UI or the `/events/add` API.

### Plain CSV for SOC consumers

Per-type dumps under `iocs/` mirroring the `apt-intel/iocs/*.txt`
convention but as CSV with a stable header row: `value,type,confidence,
first_seen,last_seen,source,incident_id,mitre`. Files:

- `iocs/ipv4.csv`, `iocs/ipv6.csv`, `iocs/domains.csv`, `iocs/urls.csv`
- `iocs/emails.csv`, `iocs/cidrs.csv`, `iocs/cves.csv`
- `iocs/hashes.csv` (type column distinguishes sha256 / sha1 / md5)

## Report renderers

### Bilingual `.docx` (EN primary, FR secondary)

A bilingual Word report is the headline operator-facing deliverable.
Two files are emitted per run — the English file is canonical; the
French file is a localized render of the same source — **identical
sectioning, identical tables, identical ordering**. No section is
present in one language but not the other.

Filename pattern, matching the `Campaign_Report_HOSTKEY_DEDIK_20260405`
reference:

    Campaign_Report_<NAME>_<YYYYMMDD>.docx       # English
    Campaign_Report_<NAME>_<YYYYMMDD>_FR.docx    # French

where `<NAME>` is an upper-snake-case campaign slug (`HOSTKEY_DEDIK`,
`BLACKSANTA`, `S01_RANSOMWARE_TRIAGE`) and `<YYYYMMDD>` is the
`generated_at` date in UTC.

Section order (both languages):

1. Executive Summary
2. Scope and Methodology
3. Timeline of Activity
4. Findings (each with citation to `correlation_id`)
5. TTPs and MITRE ATT&CK Mapping
6. Indicators of Compromise
7. Detection Rules Summary (YARA / Suricata counts + SID range)
8. Recommendations and Remediation Playbook
9. Appendix A — Evidence Manifest (SHA-256 table)
10. Appendix B — Audit Log Reference (incident_id + hash)

Template engine:

- Built on `python-docx` using a checked-in `.docx` template skeleton
  (`templates/campaign_report.docx`) with named styles (Heading 1-3,
  `FindingBlock`, `IOCTable`, `Caveat`).
- Localization dictionaries live in
  `templates/locales/{en,fr}.yaml` — section headers, boilerplate, and
  standard caveats are keyed; only operator-authored prose is
  duplicated. Prose fields on `Finding` and `Claim` carry optional
  `title_fr` / `summary_fr` keys; when absent, the EN text is reused
  with a visible `[FR traduction manquante]` marker so missing
  translations are obvious instead of silently dropped.
- Every numeric table (IOC counts, findings totals, evidence hashes)
  is generated from the same source data in both renders.

### Markdown analyst narrative (`ANALYSIS-*.md`)

The internal-facing research note. Shape adapted from
`ANALYSIS-interlock-infrastructure-overlap.md`. Frontmatter-style
metadata lives in a blockquote header:

    # <Campaign or Finding Cluster> — <Short Descriptor>

    > Date: YYYY-MM-DD
    > Analyst: APTWatcher (incident <incident_id>)
    > Status: Preliminary | Final
    > Classification: Internal research note | TLP:AMBER | TLP:GREEN

    ---

    ## Context
    ...

    ## Hypothesis
    ...

    ## IOCs Tested
    (tables of values with source + attribution columns)

    ## Results
    (direct matches, subnet overlaps, negative results)

    ## Findings
    (each citation-linked back to audit correlation_id)

    ## MITRE ATT&CK References
    ...

    ## Conclusion and Next Steps

One `.md` per narrative cluster (typically one per incident, but the
renderer supports multiple when the agent detects distinct storylines).

### TTP assessment (`TTP_*.md`)

Pattern note emitted when the agent detects a re-usable TTP across
findings. Shape adapted from
`TTP_Shell_Company_Infrastructure_Layering.md`:

    # TTP: <Name of the technique>

    > APTWatcher Intelligence Assessment - YYYY-MM-DD
    > Confidence: <HIGH | MEDIUM | LOW>
    > MITRE ATT&CK: <Txxxx.xxx>, <Txxxx>

    ---

    ## Pattern Summary
    ## Observed Pattern
    ## Case Studies
    ## Detection Opportunities
    ## References

Emitted only when the agent's verifier flags the finding cluster as
pattern-worthy (`claim.is_ttp_pattern = true`). One file per distinct
TTP.

## Community submission

A `community-submission.yaml` adapted from
`aptwatch/community/TEMPLATE.yaml`. Every field the template marks as
*Required* must be populated; optional fields are emitted only when
non-empty. Shape:

```yaml
author: aptwatcher-bot
source: https://aptwatch.org/incidents/<incident_id>
source_name: APTWatcher incident <incident_id>

apt_groups:
  - <Actor-if-attributed>

description: >
  Auto-generated from an APTWatcher triage run. Clean-room analysis
  of <profile>. See the campaign report for full context.

ipv4:
  - <value>
domains:
  - <value>
urls:
  - <value>
ipv6:
  - <value>
emails:
  - <value>
cidrs:
  - <value>
cves:
  - <value>
```

Validation:

- The generator validates against the `TEMPLATE.yaml` key set before
  write — unknown top-level keys are rejected (fail-fast).
- A file is only produced when at least one IOC section is non-empty.
- The file header carries an auto-generated `# DO NOT EDIT -
  generated by APTWatcher analyze` banner so operators know it is
  machine output.

## Publication adapters

Publication is **opt-in and never happens by accident**. The `publish`
subcommand walks a signed `IncidentBundle` from
[`./offline-to-online-handoff.md`](./offline-to-online-handoff.md) and
invokes one or more adapters listed on the command line.

### Netcraft Report API v3

Primary supported adapter. Pattern adapted from the reference
`netcraft_report.py`. Endpoints:

- `POST /report/urls` — bulk URL submission, batched (default batch size
  15, configurable).
- `GET /submission/{uuid}` — status polling.

Adapter responsibilities:

- Accept a `PublicationPlan` (list of `(url, country, reason,
  category)` tuples) extracted from the STIX bundle's `indicator`
  objects where the IOC type is `url` or `domain`.
- Group by category, submit in batches, capture the returned `uuid` per
  batch, and persist the mapping `(batch_uuid -> urls[])` in the
  publication ledger.
- Refuse to submit without a valid `--confirm-publish` flag on the CLI.
  Dry-run is the default; dry-run output is a full `stdout` preview and
  a JSON file mirroring what *would* have been sent.
- Retries on `5xx` with exponential backoff; `4xx` fails fast and
  surfaces the response body in the audit log (minus any API key).

### TAXII 2.1 push

Sibling to the STIX file exporter. Where `export_stix` writes a
`bundle.stix.json` to disk, `TaxiiAdapter` re-uses the same bundle
builder (`core.analysis.export_stix._build_identity` +
`_build_indicator`) and POSTs the rendered `{"objects": [...]}` payload
to a configured TAXII 2.1 collection. This lets APTWatcher feed
sharing communities that consume via TAXII (AIS, ISACs, sector-specific
collections) without a second round of serialization.

- Endpoint: `POST <server_url>/api/collections/<collection_id>/objects/`
- Headers: `Accept` + `Content-Type` both
  `application/taxii+json;version=2.1`, plus an
  `Authorization: Bearer <token>` header (or HTTP basic-auth when
  `--taxii-username` / `--taxii-password-env` are set).
- Success: `202 Accepted`. The `Location` header returned by the
  server (status resource) is stored as the publication target so the
  ledger can reconstruct per-submission polling later.
- Dry-run: the adapter never reads the bearer env var and never dials
  the network; it returns the rendered payload for eyeballing.
- Errors: `401` → `TaxiiPublicationError` with an "authentication"
  message, `403` → "forbidden", `4xx` / `5xx` → typed generic. The
  bearer token is never included in exception messages or the
  publication ledger row.

CLI flags: `--taxii-server-url`, `--taxii-collection-id`,
`--taxii-api-key-env` (default `APTW_TAXII_API_KEY`),
`--taxii-username`, `--taxii-password-env`.

### Future adapters (stubs only in Phase 3.8)

- **AbuseIPDB** — IP abuse report endpoint, same dry-run/confirm
  pattern.
- **VirusTotal** — relationship / comment submissions (no file upload
  from the offline VM).
- **MISP event push** — authenticated POST to `/events/add` with the
  MISP JSON already rendered by the exporter stage.
- **GLPI attachment upload** — attaches the `.docx` report to the
  originating ticket; the body field uses HTML (per the user's GLPI
  convention, never Markdown).

### Dry-run and consent gate

The CLI enforces three layers before any HTTP request leaves the
management host:

1. **Default is dry-run.** `aptwatcher publish ...` without
   `--confirm-publish` prints what it would do and exits 0.
2. **Per-adapter enable flag.** Each adapter must be named explicitly
   in `--targets netcraft,misp,...`. There is no "all targets" shortcut.
3. **Consent token.** For production targets, a short-lived consent
   token (same primitive used by `sift_update`) must be present. The
   token is logged as a `publication_consent` audit event tied to the
   bundle's `incident_id`.

A publication that passes all three still writes a full
`publication_ledger.jsonl` row per API call, with the request body
(keys redacted), response status, and wall-clock duration.

## CLI surface

    # Produce the full analysis output set for a completed incident
    aptwatcher analyze <incident_id> \
        [--formats yara,suricata,stix,docx,md,yaml,csv] \
        [--campaign-name <NAME>] \
        [--tlp clear|green|amber|red] \
        [--out <dir>]

    # Render only a subset (e.g., rules-only after a finding edit)
    aptwatcher analyze <incident_id> --formats yara,suricata --out <dir>

    # Publish a previously generated bundle to one or more adapters
    aptwatcher publish <bundle.json> \
        --targets netcraft[,misp,glpi,...] \
        [--dry-run | --confirm-publish] \
        [--since YYYY-MM-DD] \
        [--consent-token <token>]

    # Inspect publication status
    aptwatcher publish-status <submission_uuid> --target netcraft

Exit codes: `0` success, `2` validation error (schema, empty bundle,
unknown format), `3` generator failure (yara/suricata compile error),
`4` network / adapter error during publish. A non-`0` exit leaves no
partial file on disk — outputs are written to a staging directory and
`rename()`d in atomically once the entire format set is valid.

## Audit and provenance

Every generated artifact is tied to the audit log:

- A `tool_call` pair (`phase="start"` / `phase="end"`) wraps each
  generator and each adapter call. `correlation_id` is stable across
  the pair.
- The closing event carries `artifact_path`, `artifact_sha256`,
  `artifact_bytes`, and the generator version string.
- The `generation_report.json` manifest is the canonical summary,
  mirroring the `apt-intel` reference:

```json
{
  "schema_version": "1.0",
  "incident_id": "s01-2026-04-19-1523",
  "generated_at": "2026-04-19T15:51:12Z",
  "generator": "aptwatcher-analyze/1.0",
  "stats": {
    "total": 86,
    "skipped_existing": 12,
    "skipped_type": 3,
    "skipped_confidence": 4
  },
  "sid_range": {"start": 2026040001, "end": 2026040086},
  "files": {
    "yara/s01-ransomware-triage.yar": {"rules": 4, "sha256": "..."},
    "suricata/auto-s01.rules": {
      "rules": 12, "sid_start": 2026040001, "sid_end": 2026040012,
      "sha256": "..."
    },
    "stix/bundle.stix.json": {"objects": 47, "sha256": "..."},
    "reports/Campaign_Report_S01_20260419.docx":    {"sha256": "..."},
    "reports/Campaign_Report_S01_20260419_FR.docx": {"sha256": "..."},
    "community/community-submission.yaml":          {"sha256": "..."}
  }
}
```

The manifest and every artifact are fed into the
`IncidentBundle.artifacts[]` list defined in
[`./offline-to-online-handoff.md`](./offline-to-online-handoff.md), so
the bundle's detached Ed25519 signature covers every file the pipeline
emitted. Artifact integrity is re-verified on the online side before
any publication adapter runs — the evidence-integrity contract from
[`./evidence-integrity.md`](./evidence-integrity.md) is the single
source of truth for hash semantics.

Provenance also flows into the body of each artifact where the format
permits: YARA rules carry `source = "incident <incident_id>"` in meta,
Suricata rules carry `metadata:..., incident_id=<id>` (extension beyond
the `apt-intel` pattern), STIX objects carry
`created_by_ref -> aptwatcher-identity`, and the `.docx` report's
appendix B lists the `incident_id` and the first 16 bytes of the audit
log hash.

## Testing

Per-generator invariants enforced in `tests/analysis/`:

- **Golden-file tests.** For each generator, one committed
  `fixtures/<name>.golden.<ext>` from a synthetic `TriageResult`. The
  test asserts byte-equality after normalization (sorted keys, stable
  UUIDs, fixed `generated_at`). A diff on regeneration fails the test
  and forces a manual review of the generator change.
- **YARA compile.** `yara.compile(source=open(generated).read())` must
  succeed for every emitted `.yar`. A negative test injects a broken
  rule and asserts the generator aborts before writing.
- **Suricata dry-run.** `suricata -T -S <file>` is invoked in CI with
  a pinned Suricata version; non-zero exit fails the test. A static
  linter also runs for environments without Suricata installed.
- **STIX schema.** Every emitted bundle is validated against the
  `stix2` library's `validate.validate_instance()`; non-conforming
  output fails.
- **docx smoke test.** Every emitted `.docx` is opened with
  `python-docx`, the paragraph count is asserted non-zero, the section
  headings are asserted present in both locales, and the appendix
  evidence-manifest table is asserted to contain one row per
  `EvidenceFile`. No rendered PDF is produced in CI — `.docx` is the
  shippable artifact.
- **YAML submission.** The community YAML is parsed back, validated
  against the `TEMPLATE.yaml` key set, and round-tripped; a key drift
  between template and generator fails the test.
- **Netcraft adapter.** All HTTP is mocked via `respx` or `responses`;
  real network calls are forbidden in the unit test suite. One
  integration test, skipped by default, exercises the staging
  endpoint when `APTWATCHER_NETCRAFT_INTEGRATION=1` is set.

## Future work

- **Sigma synthesizer.** Planned for Phase 4. Depends on EVTX-anchored
  findings from the hayabusa/chainsaw wrapper (Phase 3.6).
- **Translation memory.** Cache FR translations keyed by `(claim_id,
  source_hash)` so the FR render is fast and deterministic across runs
  of the same incident.
- **Artifact diffing.** `aptwatcher analyze --against <previous-run>`
  to emit only the delta (new YARA rules, new SIDs, new IOCs) so the
  community submission is incremental.
- **TAXII 2.1 server mode.** Publish the STIX bundle via a TAXII
  collection endpoint run by APTWatcher itself for peer-to-peer
  federation.

## References

- [`../ARCHITECTURE.md`](../ARCHITECTURE.md) — system overview,
  offline-to-online boundary, analysis-output section.
- [`./evidence-integrity.md`](./evidence-integrity.md) — hash chain and
  refuse-to-overwrite semantics reused by every generator.
- [`./audit-log-format.md`](./audit-log-format.md) — `tool_call` event
  shape used to bracket generator and adapter calls.
- [`./offline-to-online-handoff.md`](./offline-to-online-handoff.md)
  — `IncidentBundle` shape; artifacts emitted here are attached there.
- [`./tier1-intel-lookup-pattern.md`](./tier1-intel-lookup-pattern.md)
  — same clean-room policy: pattern adapted from `apt-intel`, code is
  not copied.
FT_INTEGRATION=1` is set.

## Future work

- **Sigma synthesizer.** Planned for Phase 4. Depends on EVTX-anchored
  findings from the hayabusa/chainsaw wrapper (Phase 3.6).
- **Translation memory.** Cache FR translations keyed by `(claim_id,
  source_hash)` so the FR render is fast and deterministic across runs
  of the same incident.
- **Artifact diffing.** `aptwatcher analyze --against <previous-run>`
  to emit only the delta (new YARA rules, new SIDs, new IOCs) so the
  community submission is incremental.
- **TAXII 2.1 server mode.** Publish the STIX bundle via a TAXII
  collection endpoint run by APTWatcher itself for peer-to-peer
  federation.

## References

- [`../ARCHITECTURE.md`](../ARCHITECTURE.md) — system overview,
  offline-to-online boundary, analysis-output section.
- [`./evidence-integrity.md`](./evidence-integrity.md) — hash chain and
  refuse-to-overwrite semantics reused by every generator.
- [`./audit-log-format.md`](./audit-log-format.md) — `tool_call` event
  shape used to bracket generator and adapter calls.
- [`./offline-to-online-handoff.md`](./offline-to-online-handoff.md)
  — `IncidentBundle` shape; artifacts emitted here are attached there.
- [`./tier1-intel-lookup-pattern.md`](./tier1-intel-lookup-pattern.md)
  — same clean-room policy: pattern adapted from `apt-intel`, code is
  not copied.
