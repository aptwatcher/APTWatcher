# Reference: Documentation audit report

> Final documentation integrity pass for the APTWatcher hackathon
> submission. This page summarises the state of the docs tree at the
> time of the audit and records any fixes applied during it.

Audit date: 2026-04-20. Re-verified: 2026-06-12 (pre-submission pass).

## 1. Orphan-page summary

All 62 Markdown files under `docs/` are reachable from `mkdocs.yml`
nav (re-checked 2026-06-12, after the Demo group and walkthrough were
added). **Zero orphan pages.**

## 2. Broken-link summary

Every relative `.md` link in the docs tree was resolved against the
filesystem (anchor fragments stripped; external / `mailto:` links
ignored; absolute paths resolved against `docs/`). **Zero broken
links.**

## 3. SIFT tool coverage status

Tier 0 wrappers present under `src/core/sift/` (10 of 10 expected):

| Wrapper           | Module                          | Documented in `sift-tools.md` |
|-------------------|---------------------------------|-------------------------------|
| `volatility`      | `core.sift.volatility`          | yes                           |
| `plaso`           | `core.sift.plaso`               | yes                           |
| `bulk_extractor`  | `core.sift.bulk_extractor`      | yes                           |
| `sleuthkit`       | `core.sift.sleuthkit`           | yes (added during audit)      |
| `yara_scan`       | `core.sift.yara_scan`           | yes                           |
| `hayabusa`        | `core.sift.hayabusa`            | yes                           |
| `regripper`       | `core.sift.regripper`           | yes                           |
| `chainsaw`        | `core.sift.chainsaw`            | yes                           |
| `timesketch`      | `core.sift.timesketch`          | yes (added during audit)      |
| `sift_update`     | `core.sift.update`              | yes                           |

**Coverage: 10 / 10 (100%).**

## 4. MCP tool coverage status

`src/mcp_server/server.py` registers 51 `@mcp.tool` handlers
(42 Tier 0 + 9 Tier 1 intel, the latter added after the original
audit). Each has a matching `### 3.x` section in
[`reference/mcp-tool-schemas.md`](mcp-tool-schemas.md) (3.1-3.51;
intel sections 3.43-3.51 added in the 2026-06-12 re-verification).

Sections added during this audit to close the gap:

- 3.35 `run_mmls`
- 3.36 `run_fsstat`
- 3.37 `run_fls`
- 3.38 `run_icat`
- 3.39 `run_yara_scan`
- 3.40 `list_hayabusa_output_formats`
- 3.41 `run_hayabusa_timeline`
- 3.42 `run_hayabusa_logon_summary`

**Coverage: 51 / 51 (100%).**

Section 4 of `mcp-tool-schemas.md` ("Tier 1-4 placeholders") was also
trimmed: the rows for `run_yara`, `run_hayabusa`, and `run_sleuthkit`
incorrectly claimed those tools were unregistered. They are
registered, and the stale rows have been removed.

## 5. Inbound-link status for the four hackathon docs

| Doc                 | Inbound links before audit | Inbound links after audit |
|---------------------|----------------------------|---------------------------|
| `docs/ACCURACY.md`  | 8                          | 9                         |
| `docs/TRY-IT-OUT.md`| 0 (body mentions only)     | 1                         |
| `docs/DATASET.md`   | 0                          | 1                         |
| `docs/DEVPOST.md`   | 0                          | 1                         |

The audit added a "Hackathon submission" subsection to
[`docs/README.md`](../README.md) linking all four pages, so each is
now discoverable from the docs landing page in addition to the nav.

## 6. mkdocs --strict result

`python3 -m mkdocs build --strict` exits `0` with no WARNING lines
after the fixes above. Two harmless INFO-level notes remain and are
intentional: `docs/TRY-IT-OUT.md` links to `../scenarios/` and
`../knowledge/` directories that sit *outside* the `docs/` tree (they
are repo-level directories). Those are not docs pages, so mkdocs
leaves the links alone with an info message. Neither counts as a
warning under `--strict`.

## 7. Fixes applied during this audit

- `mkdocs.yml`
  - Removed a duplicated `Demo script: demo/SCRIPT.md` nav entry.
  - Added `Audit report: reference/audit-report.md` under `Reference`.
- `docs/README.md`
  - Added a "Hackathon submission" subsection linking `TRY-IT-OUT.md`,
    `ACCURACY.md`, `DATASET.md`, and `DEVPOST.md`.
- `docs/reference/sift-tools.md`
  - Added inventory rows for `sleuthkit` (`mmls`, `fsstat`, `fls`,
    `icat`) and `timesketch_importer`.
  - Updated the "Implemented wrappers" status table so the shipped
    wrappers are no longer listed as planned.
  - Updated the status-as-of date to match the audit date.
- `docs/reference/mcp-tool-schemas.md`
  - Added sections 3.35 through 3.42 for the eight previously
    undocumented registered tools.
  - Removed the stale Section 4 rows that claimed YARA, Hayabusa, and
    Sleuth Kit wrappers were not registered.
  - Updated the Section 7 "Server file truncation" note to reflect the
    final section count (3.1-3.42).
- `docs/reference/audit-report.md` (this file) created and wired into
  the nav.

No prose outside the items above was rewritten; changes are
surgical.

## 8. Publication adapter roster

`src/agent_extension/publish.py` now declares
`ALLOWED_ADAPTERS = ("netcraft", "misp", "glpi", "stub", "taxii")` —
**5 entries**. The addition is the TAXII 2.1 push adapter
(`core.publish.taxii.TaxiiAdapter`), which POSTs the STIX bundle
produced by `core.analysis.export_stix` to a configured TAXII 2.1
collection. Publication adapters remain **CLI-only** — none of them
are registered as MCP tools.

## 9. Re-verification — 2026-06-12

Pre-submission pass, all checks repeated on a fresh environment
(Python 3.12):

- 62 docs pages, 0 orphans, 0 broken relative links (docs, README,
  demo, scenarios).
- `mkdocs build --strict` exit 0, 0 WARNING lines.
- `scripts/clean_room_check.py`: 0 violations.
- New since the original audit: `docs/demo/WALKTHROUGH.md` (Demo nav
  group), `demo/SHOOTING-SCRIPT.md`, `demo/ANNOUNCE.md`, expanded
  `README.md`, MCP intel tool schemas 3.43-3.51.
