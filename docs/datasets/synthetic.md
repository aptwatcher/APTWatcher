# Datasets: Synthetic cases

> Author-crafted, reproducible, fully-attributable datasets. Every
> artifact the agent should find is planted deliberately. Every artifact
> that exists in the dataset is declared in the ground-truth manifest.

## Why synthetic

- **Deterministic rubrics.** The ground truth is known exactly, which
  makes hallucination detection reliable. A real case's "what should
  have been found" is almost always fuzzier than a rubric deserves.
- **Reproducibility.** A judge running the demo gets the same bytes the
  author saw. No upstream drift, no redaction-induced ambiguity.
- **Licensing.** Synthetic data is MIT-licensed with APTWatcher. Public
  forensic datasets typically are not; shipping the full files in-repo
  is rarely allowed. Synthetic has no such problem.
- **Sensitive-content control.** Synthetic ransomware samples can
  substitute shellcode with inert sentinel patterns that still satisfy
  YARA rules. No live malware ships with the hackathon submission.

## Generation model

Each synthetic dataset is produced by a script under
`datasets/generators/`. The scripts are deterministic — same seed, same
dataset. The seed is part of the manifest.

```
datasets/
├── generators/
│   ├── generate_s01.py
│   ├── generate_s02.py
│   └── generate_s03.py
├── s01-synthetic-v1/
│   ├── manifest.yaml
│   ├── evidence/
│   │   └── FIN-WS-014/
│   │       ├── triage/              # KAPE-style bundle
│   │       ├── mem.raw               # memory capture (sentinel shellcode)
│   │       └── disk.E01              # (optional, if shipped)
│   └── truth/
│       └── s01-findings.yaml         # ground-truth rubric
├── s02-synthetic-v1/…
└── s03-synthetic-v1/…
```

## What the generators produce

A generator is the conjunction of three things:

1. **Environment state.** Simulated registry hives with installed
   software, scheduled tasks, user profiles; a filesystem layout with
   realistic Windows or Linux structure; an event log corpus spanning
   the attack window.
2. **Attack trace.** Authentication events, execution artifacts
   (prefetch, AMCache, SRUM equivalents), created scheduled tasks,
   dropped binaries, staged files. The exact inflection points from the
   scenario's ground-truth timeline.
3. **Memory artifacts.** For memory-bearing scenarios, a Volatility-
   analyzable image with injected processes (sentinel shellcode), open
   sockets, named-pipe handles, and command-line buffers populated to
   match the scenario.

## The sentinel-shellcode policy

For S03 and any future scenario involving malware in memory: the
injected bytes are **not** real malware. They are sentinel patterns
chosen to:

- Match the YARA rules a realistic Cobalt Strike / ransomware loader
  would match (so `yara_scan` finds them).
- Be analytically inert (no executable payload, no live C2 infrastructure
  referenced).
- Be unambiguously identifiable as synthetic to anyone who reads the
  bytes — the first 16 bytes are an ASCII banner `APTWATCHER_SYN_` so the
  intent is obvious.

This is the compromise that makes it acceptable to ship
memory-with-malware-shaped-data in a public MIT repo. Real malware
samples never ship.

## Ground-truth rubric format

```yaml
# truth/s01-findings.yaml
scenario: s01
dataset_id: s01-synthetic-v1
findings:
  - id: F01
    summary: "Phishing link click at 2026-04-10 17:42"
    mitre: T1566.002
    evidence:
      - source: "browser_history.sqlite"
        locator: "urls.id=2847"
        claim: "Visit to lookalike M365 login"
    required: true
  - id: F02
    summary: "RDP logon from external IP during non-business hours"
    mitre: T1021.001
    evidence:
      - source: "Security.evtx"
        locator: "event_id=4624 record=9421"
        claim: "Logon type 10 from 185.220.103.118"
    required: true
  # …
hallucination_traps:
  - "Claim of exfiltration (no egress flow exists in this dataset)"
  - "Claim of second user account (no other user touched this host)"
```

`required: true` findings must be surfaced for a Pass. `hallucination_traps`
are claims a poorly-grounded agent commonly makes on this scenario; if
the agent produces one, it is a hard-fail.

## Versioning

`<dataset_id>-v<major>.<minor>.<patch>`:

- **Patch** — metadata corrections, no evidence byte changes. Backward
  compatible with prior runs.
- **Minor** — added or clarified rubric items. Old runs remain
  comparable; new items are counted separately.
- **Major** — evidence bytes changed. Resets the accuracy measurement.
  New version explicitly noted in the project changelog.

## Generator testability

Each generator has a matching test under `tests/generators/` that:

1. Runs the generator with a pinned seed.
2. Hashes the produced files.
3. Compares against expected hashes in the generator's lockfile.

If a generator drifts without a version bump, CI catches it.

## What synthetic cannot model

- **True adversary creativity.** Real attackers try things no generator
  writes. Public cases cover that.
- **Unusual environments.** A synthetic host is a generic Windows 11
  install; real enterprises have non-default GPOs, custom agents,
  legacy cruft. The agent must handle those in public cases.
- **Timing realism.** Synthetic timestamps are clean; real forensic
  data has NTP drift, zero-padded fields, and clock anomalies.

These gaps are why public cases complete the picture.

## Related

- [Public sources](public-sources.md)
- [Scenarios](../scenarios/README.md)
- [Evidence integrity](../architecture/evidence-integrity.md)
