# Datasets

> Two dataset strategies, one discipline. Synthetic cases for
> deterministic rubrics; public cases for live-fire validation. Every
> dataset declares its source, license, and ground-truth fidelity.

## Why two strategies

**Synthetic datasets** let us measure the agent against a complete
rubric. Every artifact the agent is expected to find is planted by a
generator we wrote, so ground truth is exact and reproducible. The cost
is realism — synthetic data can only be as nuanced as the generator.

**Public datasets** (DFIR Report, Magnet Weekly CTF, SANS DFIR Summit
CTFs, etc.) provide that missing nuance. Real attackers produce
artifacts synthetic generators miss. The cost is ground-truth fidelity —
public cases rarely enumerate every artifact the analyst is expected to
surface.

Used together, the two strategies cover both needs:

- Synthetic = floor. Determinism, reproducibility, hallucination
  detection.
- Public = ceiling. Realism, generalization, judge credibility.

## Contents

- [Synthetic cases](synthetic.md) — how scenario datasets are generated
- [Public sources](public-sources.md) — which external cases we benchmark
  against and their license status

## Dataset manifest

Every dataset — synthetic or public — ships with a `manifest.yaml`:

```yaml
dataset_id: s01-synthetic-v1
scenario: s01
type: synthetic
version: 1.0.0
generator: scripts/generate_s01.py
generator_commit: <git_sha>
evidence_files:
  - path: evidence/FIN-WS-014/triage.zip
    sha256: abc...
    size_bytes: 245678921
  - path: evidence/FIN-WS-014/mem.raw
    sha256: def...
    size_bytes: 4294967296
ground_truth: truth/s01-findings.yaml
mitre_techniques: [T1566.002, T1003.001, T1021.001, T1053.005, T1036.005, T1074.001]
license: MIT
attribution: "APTWatcher project"
```

For public datasets, `license` is the upstream license and `attribution`
credits the upstream author. Nothing ships without a manifest.

## Reproducibility contract

- Synthetic datasets are pinned by version. Version bumps are explicit
  and recorded; they invalidate any prior accuracy measurement against
  the older version.
- Public datasets are pinned by hash. If upstream changes the file, the
  hash mismatch is caught at `preflight()` and the run refuses to start.
- Every accuracy result in [`docs/ACCURACY.md`](../ACCURACY.md) cites
  the exact `dataset_id` it was measured against.

## Storage

Small datasets (<100 MB each) live in the repo under `datasets/`. Larger
datasets (memory images, disk images) are referenced by URL and hash,
downloaded on demand by a `scripts/fetch_dataset.py` helper. The download
path verifies the hash before the file is accepted.

## What datasets are not

- **Not training data.** APTWatcher does not fine-tune on these
  datasets. The agent is the base model plus prompts plus tools; the
  datasets are the evaluation surface.
- **Not shareable regardless of source.** Each public dataset's license
  governs its redistribution. The repo cites; it does not re-host
  license-incompatible material.

## Related

- [Scenarios](../scenarios/README.md) — which scenario each dataset
  supports
- [Try it out](../getting-started/try-it-out.md) — the 10-minute run uses
  the S01 synthetic dataset
