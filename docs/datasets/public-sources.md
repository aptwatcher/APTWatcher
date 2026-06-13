# Datasets: Public sources

> External forensic cases the agent is benchmarked against. These provide
> the realism synthetic datasets cannot, at the cost of ground-truth
> fidelity. Each one is evaluated for license compatibility before
> inclusion.

## Why public cases

Synthetic datasets answer "does the agent do the known-good thing
reliably". Public cases answer "does the agent hold up against artifacts
it has never seen before". Both questions matter; neither is sufficient
alone.

Judges rightly distrust an agent evaluated only on its authors' own
datasets. Public cases are the tiebreaker.

## Candidate sources

Every candidate is checked for four properties before adoption:

1. **License** — CC BY-SA, CC BY, or more permissive. Anything
   "educational use only" or unclear is excluded.
2. **Ground-truth availability** — the case's writeup must enumerate
   enough artifacts for a meaningful rubric.
3. **Artifact depth** — the evidence must be deep enough to exercise at
   least one of APTWatcher's profiles end-to-end.
4. **Size** — the dataset must fit in the hackathon's practical
   constraints. Gigabyte-scale images are acceptable; petabyte-scale
   enterprise forensics dumps are not.

### The DFIR Report

- **Site**: `thedfirreport.com`
- **License**: case reports are freely readable; associated artifact
  packages are sometimes distributed under CC BY-SA 4.0, sometimes under
  case-specific terms. **Each case is checked individually**.
- **Status for APTWatcher**: a small subset of reports match S01 and S02
  shape closely enough to serve as public-overlay benchmarks. The
  specific cases selected are declared per-scenario in the dataset
  manifest with full attribution.
- **Integration path**: cases are cited, not re-hosted. The fetch script
  downloads from the upstream URL, verifies the hash, and then runs the
  agent.

### SANS / GIAC DFIR materials

- **Site**: SANS publishes a subset of DFIR CTF materials publicly after
  each event.
- **License**: varies by event. Each release is checked individually.
  Courseware is explicitly **out of scope** (see below).
- **Status for APTWatcher**: depending on license compatibility, one
  post-event CTF may be adopted as a supplementary benchmark for S02.

### Magnet Forensics' Weekly CTF

- **Site**: `magnetforensics.com/ctf`
- **License**: Magnet provides the images under terms that permit
  educational use and redistribution with attribution for most weekly
  releases.
- **Status for APTWatcher**: evaluated case by case. A Weekly CTF image
  that stresses the memory-only or timeline-only profile is a natural
  supplementary benchmark for S03.

### DFIR.net / Autopsy corpus

- **Site**: various; the Autopsy project ships several test images.
- **License**: mixed. Each image's specific license is verified.
- **Status for APTWatcher**: may provide regression-test datasets for
  the Linux host-triage profile.

## Hard exclusions

- **`~/Dev/docs`** — personal study library containing
  SANS courseware, books, and licensed research. Declared OUT OF SCOPE
  as a content source in [`knowledge/README.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/README.md).
  Zero material from this directory may appear in APTWatcher's
  datasets, knowledge base, or prompts — even paraphrased.
- **Any dataset without a clear license.** Absence of a license is a
  default "no".
- **Customer data, sanitized or otherwise.** Even anonymized real
  incident data from consulting engagements is excluded unless the
  original customer's written authorization is on record.

## Selection record

Cases actually adopted for the hackathon submission will be recorded
here once chosen. Selection happens in Phase 4 (accuracy testing) after
the synthetic datasets are producing clean results.

The list below is provisional and subject to license confirmation:

| Provisional case       | Covers scenario | License to verify | Status            |
|------------------------|-----------------|-------------------|-------------------|
| TBD — DFIR Report case matching S01 shape | S01 overlay | CC BY-SA 4.0      | Pending review    |
| TBD — DFIR Report case matching S02 shape | S02 overlay | CC BY-SA 4.0      | Pending review    |
| TBD — Magnet Weekly CTF memory-focused    | S03 overlay | Magnet terms      | Pending review    |

Final selections will be added with their exact attribution and hash
before submission.

## Ground-truth mapping

Public cases rarely come with rubric-shaped ground truth. The adoption
process involves:

1. Read the case's published writeup.
2. Extract the findings the writeup enumerates (usually techniques + key
   artifacts).
3. Draft a rubric in the same YAML format as synthetic cases.
4. Mark findings as `required: true` only where the writeup is explicit;
   everything else is `expected: true` (counts in scoring but is not
   hard-required).
5. List known hallucination traps — claims the writeup does **not**
   support but that are plausibly generated from the surface evidence.

This process is inherently more subjective than the synthetic rubric.
The scoring for public cases is therefore reported separately in
[`docs/ACCURACY.md`](../ACCURACY.md), never merged into the synthetic
numbers.

## Redistribution posture

APTWatcher does not redistribute any public dataset's bytes. The
`scripts/fetch_dataset.py` helper downloads from the upstream URL at run
time, verifies the hash against the manifest, and makes the data
available locally for the run. If the upstream source goes away, the
dataset is retired from the benchmark set. There is no lock-in to
bytes we are not licensed to re-host.

## Related

- [Synthetic cases](synthetic.md)
- [`knowledge/README.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/README.md) — clean-room
  policy
- [Evidence integrity](../architecture/evidence-integrity.md) — hash
  verification on fetched datasets
