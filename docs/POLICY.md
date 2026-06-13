# Clean-room content policy

> Scope, carve-outs, and enforcement for the APTWatcher clean-room
> forbidden-string rule. This document is the authoritative contract the
> CI gate reads; every other doc that mentions the rule defers here.

## 1. Purpose

APTWatcher is a submission to the FIND EVIL! hackathon (SANS/GIAC,
2026). The hackathon rules require original authorship: the knowledge
corpus the agent grounds its reasoning on must not transclude paid
courseware, certification materials, publisher excerpts, or copyrighted
incident-response playbooks.

The clean-room policy expresses that rule as a mechanical gate. A fixed
list of strings is declared forbidden in scoped content areas; a CI
check sweeps those areas and fails the build on any hit. The list
targets names that reliably signal non-redistributable upstream
material:

- `SANS`, `GCIH`, `GCFA`, `FOR500`, `FOR508` — proprietary certification
  and courseware lineage.
- `NoStarch`, `Syngress` — publisher imprints whose book excerpts the
  project has no right to redistribute.
- `DFIR Report` — a specific third-party IR publication whose case
  writeups are licensed separately and must not be embedded verbatim in
  the KB corpus.

The rule is not a claim that these names are unmentionable in the
universe; it is a structural check that the KB body and the judge-facing
submission narrative are authored fresh, without leaning on copyrighted
source text.

## 2. Scope

The forbidden-string gate applies to:

- `knowledge/**/*.md` **body** — the markdown below the YAML
  frontmatter. Frontmatter `attribution` / `source_type` fields are
  allowed to reference upstream licenses (e.g. `dfir-report-cc`) since
  those are schema values, not prose.
- `docs/DATASET.md` — judge-facing dataset provenance narrative.
- `docs/DEVPOST.md` — judge-facing submission narrative.
- `docs/TRY-IT-OUT.md` — judge-facing walk-through narrative.

The gate does NOT apply to:

- `docs/POLICY.md` (this file). It names the forbidden strings
  because naming them is the policy.
- `knowledge/README.md`. It declares the forbidden list to
  contributors and is the authoritative policy text referenced from the
  KB entries themselves.
- CLI `--help` text and the `FastMCP` server `instructions` field. The
  product factually targets the SANS SIFT Workstation deployment
  platform; the help string names that platform.
- Pydantic `Literal` values and other inline code identifiers that are
  third-party API or schema names. The `source_type: "dfir-report-cc"`
  literal is a typed schema value, not prose; the same goes for
  identifiers in tool allow-lists.
- Internal working notes (session-state handoff, phased plan) are kept
  outside the published repository entirely. They are not part of the
  submission surface and are not subject to this gate.

## 3. Enumerated carve-outs (current repo state)

The following table enumerates every location in the published tree
where a forbidden string appears legitimately. New entries require a
PR (see section 5).

| String | File | Line | Category | Reason |
|---|---|---|---|---|
| SANS | `docs/README.md` | 3 | Product description | Factual statement of the deployment platform (SIFT Workstation). |
| SANS | `docs/README.md` | 4 | Product description | Factual statement of the hackathon identity (SANS/GIAC FIND EVIL! 2026). |
| DFIR Report | `docs/README.md` | 65 | Navigation label | Link text for the public-sources datasets page. |
| SANS | `docs/datasets/public-sources.md` | 46 | Dataset provenance | Section heading for the public SANS/GIAC DFIR materials discussion. |
| SANS | `docs/datasets/public-sources.md` | 48 | Dataset provenance | Describes what SANS publicly republishes from CTFs. |
| SANS | `docs/datasets/public-sources.md` | 75 | Out-of-scope declaration | Explicitly marks SANS courseware OUT OF SCOPE for ingestion. |
| DFIR Report | `docs/datasets/public-sources.md` | 32 | Dataset provenance | Section heading for CC BY-SA 4.0 public source. |
| DFIR Report | `docs/datasets/public-sources.md` | 95-96 | Dataset provenance | Table rows for candidate public cases under review. |
| SANS | `docs/datasets/README.md` | 14 | Dataset provenance | Factual enumeration of public dataset landscape. |
| DFIR Report | `docs/datasets/README.md` | 14 | Dataset provenance | Same enumeration. |
| SANS | `docs/getting-started/installation.md` | 7 | Product description | Platform requirement (SIFT Workstation). |
| SANS | `docs/getting-started/README.md` | 20-21 | Product description | Platform requirement + install link text. |
| DFIR Report | `docs/scenarios/S01-single-windows-compromise.md` | 132 | Scenario provenance | Names the public-variant parent case family. |
| DFIR Report | `docs/scenarios/S02-multi-host-lateral-movement.md` | 149 | Scenario provenance | Attribution for the analogous public case family. |
| DFIR Report | `docs/scenarios/README.md` | 52 | Navigation label | Cross-link to the public-sources dataset discussion. |
| SANS | `knowledge/README.md` | 8 | Policy declaration | Names SANS courseware as forbidden material. |
| DFIR Report | `knowledge/README.md` | 68-78 | Policy declaration | Declares the `dfir-report-cc` source type boundary. |
| SANS, GCIH, GCFA, FOR500, FOR508, Syngress, NoStarch | `knowledge/README.md` | 89-90 | Policy declaration | Names the forbidden list to contributors. |
| SANS | `src/agent_extension/cli.py` | 59 | CLI help string | Typer `help=` text names the deployment platform. |
| SANS | `src/mcp_server/server.py` | 125 | MCP instructions | FastMCP `instructions=` field names the deployment platform. |
| SANS | `src/core/sift/volatility.py` | 49 | Internal docstring | Describes where the tool binary ships. |

Carve-out row count: 20.

Notes:

- `README.md` at the repository root and `deploy/claude-code/README.md`
  contain forbidden strings, but are excluded from the submission surface
  (`mkdocs.yml` does not serve them) and from the gate scope in section 2.
  Listing their occurrences is not required for compliance.
- `prompts/system.md` similarly sits outside the gate scope.

## 4. Gate implementation

The gate lives at `scripts/clean_room_check.py` and is runnable with
no arguments from the repository root:

```
python3 scripts/clean_room_check.py
```

Exit codes:

- `0` — no violations.
- `1` — one or more violations, printed as `file:line: string` lines.

Pseudocode:

```
FORBIDDEN = ["SANS", "GCIH", "GCFA", "FOR500", "FOR508",
             "NoStarch", "Syngress", "DFIR Report"]

KB_GLOB = "knowledge/**/*.md"
SUBMISSION_DOCS = ["docs/DATASET.md", "docs/DEVPOST.md",
                   "docs/TRY-IT-OUT.md"]
KB_CARVE_OUTS = {"knowledge/README.md"}

for path in kb_files(KB_GLOB) if path not in KB_CARVE_OUTS:
    body = strip_frontmatter(path.read_text())
    for line_no, line in enumerate(body.splitlines(), 1):
        for needle in FORBIDDEN:
            if needle in line:
                report_violation(path, line_no, needle)

for path in SUBMISSION_DOCS:
    for line_no, line in enumerate(path.read_text().splitlines(), 1):
        for needle in FORBIDDEN:
            if needle in line:
                report_violation(path, line_no, needle)

exit 1 if violations else 0
```

The scanner does NOT walk `docs/POLICY.md`, `knowledge/README.md`,
`src/`, `deploy/`, or `prompts/`. Those paths are out of scope by
design — see section 2.

## 5. Review process

When a new file wants to introduce one of the forbidden strings, the
contributor:

1. Argues in the pull request description why the reference is
   legitimate. Acceptable categories are: product-description prose
   naming the deployment platform, dataset-provenance prose describing
   upstream licence posture, navigation labels, explicit policy
   declarations, CLI help / MCP instructions, or code-identifier values
   from typed schemas.
2. Adds a row to the table in section 3 of this document, with file,
   line (or line range), category, and reason.
3. Confirms the KB corpus itself stays clean — the carve-out mechanism
   is never a path to dropping forbidden prose into
   `knowledge/**/*.md`.

Reviewers block the PR if the justification reads as promotional or
uncited narrative rather than one of the six accepted categories above.

When an existing carve-out becomes stale — the file is removed, the
line moves, or the reference is rewritten away — the carve-out row is
deleted from section 3 in the same commit. The table is meant to match
the live tree.

## 6. Enforcement cadence

The gate runs at three points:

- **Pre-commit.** Developers run `python3 scripts/clean_room_check.py`
  locally before committing. A pre-commit hook invoking the script is
  recommended but not strictly required; the next gate catches anything
  that slips past.
- **CI on push.** Every push to any branch runs the script. A non-zero
  exit fails the CI build and blocks merge.
- **Pre-submission gate.** Before the hackathon submission is finalised,
  the script is run one last time against a clean checkout; a green
  result is one of the items on the submission checklist
  (`SUBMISSION-CHECKLIST.md`).

A green gate at all three points is a necessary condition for merge and
for submission. It is not by itself sufficient — the review process in
section 5 is the human gate that complements the mechanical one.
