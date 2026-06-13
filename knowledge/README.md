# Knowledge Base — Content & Licensing Policy

> **Hard rule**: APTWatcher is MIT-licensed and publicly distributed. This
> knowledge base MUST NOT contain any copyrighted material that the project
> does not have rights to redistribute.
>
> **The `~/Dev/docs` folder is OUT OF SCOPE as a content source.**
> It contains proprietary/copyrighted material (SANS courseware, books,
> licensed research). It may be consulted *by the author* as a reference for
> original writing, but its content must never be copied, pasted, or
> substantially paraphrased into this repo.

---

## Canonical convention (current corpus)

**Every entry currently in this knowledge base is clean-room author-original
and declares:**

```yaml
source_type: author-original
attribution: "APTWatcher team (clean-room)"
```

That is the single canonical convention for the committed corpus. The
content was written from scratch by the APTWatcher team for this repo;
no paragraphs were lifted, quoted, or substantially paraphrased from any
external source, and no LLM-synthesis pass was used to produce finished
prose that then shipped. Earlier drafts of a handful of entries carried
a `source_type: llm-synthesis` label aspirationally; that label was
normalized to `author-original` in Wave 13 because it misrepresented the
stricter clean-room authorship the entries actually reflected.

## Allowed `source_type` values (schema)

The loader (`src/core/knowledge.py`) accepts the following values in the
`source_type` front-matter field. They are listed here for schema
completeness — at the time of writing, only `author-original` is in use
in the committed corpus.

### 1. `author-original` (canonical — every current entry)
Written from scratch by the APTWatcher team for this repo. May be
informed by personal study, field experience, or external references,
but the prose is original clean-room authorship.
- **License**: MIT (repo license)
- **Attribution**: `"APTWatcher team (clean-room)"`

### 2. `llm-synthesis` (allowed by schema; unused in the corpus)
Reserved for content that is genuinely produced by an LLM from its
training knowledge and then reviewed by a human. Kept in the allowed
set for future use, but no current entry uses it.
- **License**: MIT (treated as original content; reviewer retains
  responsibility)
- **Attribution**: "LLM-assisted, author-reviewed"

### 3. `mitre-attack`
Content derived from the MITRE ATT&CK knowledge base.
- **License**: Apache 2.0 (MITRE)
- **Attribution**: MITRE ATT&CK, with technique IDs

### 4. `nist`
Content derived from NIST Special Publications (e.g., SP 800-61r2, SP 800-86).
- **License**: Public domain (US government work)
- **Attribution**: NIST SP ID + section

### 5. `public-blog-summary`
**Fair-use summaries** of publicly available blog posts (Microsoft, Mandiant,
CrowdStrike, The DFIR Report, etc.). Rules:
- Summaries only — never quote or paste paragraphs
- Link to the original source in every entry
- Paraphrase in author's/LLM's own words
- One short quote per source maximum, under 15 words, in quotation marks
- **No reproduction of screenshots, images, or code blocks** from the source

### 6. `dfir-report-cc`
Content from The DFIR Report distributed under CC BY-SA 4.0.
- **License**: CC BY-SA 4.0
- **Attribution**: "The DFIR Report — [article title]" + URL
- Note: CC BY-SA means this repo's use of that content is ShareAlike. We
  isolate these entries so they don't contaminate MIT-licensed content.
  Treat as reference-only unless we formally dual-license a subfolder.

---

## Forbidden content

- Anything from `~/Dev/docs` — **even if it looks generic**.
  That folder contains material we do not have rights to redistribute.
- SANS courseware (GCIH, GCFA, GCFE, FOR500/508/572/etc.) — proprietary.
- Book excerpts (any O'Reilly, Syngress, NoStarch, etc.).
- Paid threat intelligence reports (Mandiant M-Trends PDFs, etc.).
- Screenshots of paid tool UIs that include branded chrome.
- Dataset samples from paid corpora.

When in doubt: **write it yourself or have the LLM write it fresh.**

---

## Entry format

Every knowledge entry is a Markdown file with YAML front-matter:

```yaml
---
id: KB-001
title: Analyzing $MFT for File System Timeline
source_type: author-original
attribution: "APTWatcher team (clean-room)"
mitre_techniques: [T1070.006]
artifact_types: [ntfs-mft, filesystem-timeline]
tools: [analyzeMFT, mft2csv, log2timeline]
last_updated: 2026-04-19
---
```

Followed by structured sections the agent can search:
- **Purpose**
- **Prerequisites**
- **Procedure** (step-by-step)
- **Expected artifacts**
- **Common pitfalls / hallucination traps**
- **References** (external URLs only)

---

## Folder layout

- `knowledge/procedures/` — how-to guides (imaging, timeline, memory, etc.)
- `knowledge/techniques/` — per-MITRE-technique detection/analysis notes
- `knowledge/artifacts/` — per-artifact reference (registry hive, $MFT, amcache, etc.)

---

## Review cadence

Before first public commit, every file in `knowledge/` must be reviewed for:
1. `source_type` declared and truthful
2. No content lifted from `~/Dev/docs`
3. No long quotes (>15 words) from any single external source
4. All external URLs still live
5. MITRE IDs verified against current ATT&CK version
