---
id: kb-tl-mft-timestomp-001
title: "NTFS $MFT timestomping — SI vs FN divergence in filesystem timelines"
source_type: author-original
attribution: "APTWatcher team (clean-room)"
mitre_techniques:
  - T1070.006
artifact_types:
  - filesystem
  - ntfs_mft
  - plaso_timeline
tools:
  - log2timeline.py
  - psort.py
  - analyzeMFT
  - mft2csv
last_updated: "2026-04-19"
---

## What $MFT timestomping is

Every file on an NTFS volume has a Master File Table record, and that
record stores two independent timestamp quartets (MACB: Modified,
Accessed, Changed/MFT-changed, Born). One quartet lives in the
`$STANDARD_INFORMATION` (SI) attribute; the other lives in
`$FILE_NAME` (FN). The operating system exposes the SI set via the
`SetFileTime` Win32 API, which means any user-mode process with write
access to the file can rewrite SI at will. The FN set is different:
the NTFS driver updates it only on namespace operations — create,
rename, move across directories, or hardlink creation — and there is
no documented user-mode API to forge it without triggering one of
those operations.

Adversaries exploit the asymmetry. After dropping a binary into
`C:\Windows\System32\` or a similar directory full of old files, they
call `SetFileTime` to backdate SI so the artifact blends into the
surrounding timeline. FN is typically left at the real creation time,
because rewriting it would require either a kernel primitive or a
rename dance that leaks other evidence. The resulting SI/FN mismatch
is what timeline analysis keys on.

## How to detect it

The workflow is a plaso super-timeline: `log2timeline.py` ingests the
disk image or the extracted `$MFT` into a `.plaso` store, and
`psort.py` emits a sorted CSV or l2tcsv where each MFT record yields
up to eight events (four SI, four FN). The analyst then pivots on
those events.

Signals worth triaging:

- SI and FN timestamps on the same record disagree by more than a
  few seconds of clock drift. A benign rename will desynchronise the
  quartets slightly, but a multi-year gap is not benign.
- SI timestamps predate the volume's format date. Impossible without
  tampering, because the file cannot have existed before the filesystem.
- SI creation time predates the parent directory's creation time. Also
  impossible on a clean filesystem: a file cannot be born into a
  directory that does not yet exist.
- All four SI values end in `.0000000` nanoseconds. The NTFS driver
  writes sub-second precision; most timestomping tools round to
  whole seconds, leaving a statistical tell.
- FN timestamps sit inside a tight window (the real drop) while SI
  spreads across years (the cover story).

Comparison table:

| Field set | Writable from user mode? | Updated by          | What a mismatch suggests                          |
|-----------|--------------------------|---------------------|---------------------------------------------------|
| SI MACB   | Yes (`SetFileTime`)      | Any user-mode write | If older than FN: backdating to hide a drop       |
| FN MACB   | No (namespace ops only)  | NTFS driver         | If older than SI: recent rename/move, often OK    |
| SI == FN  | n/a                      | Both at create      | Normal for an untouched newly created file        |

When plaso's MFT parser lacks the precision you need — for instance if
you want to inspect the full `$FILE_NAME` attribute list, non-resident
runs, or orphaned records — fall back to `analyzeMFT` or `mft2csv`
against the raw `$MFT` extract. Both emit per-record CSV with both
SI and FN quartets and are useful for confirming a plaso hit.

## What APTWatcher records

A timestomp finding cites:

1. The MFT record number for the suspect file
   (locator=`mft_record=<n>`, source=path-in-image plus SHA-256 of
   the extracted `$MFT`).
2. Both timestamp quartets verbatim: `si_mtime`, `si_atime`,
   `si_ctime`, `si_btime` and `fn_mtime`, `fn_atime`, `fn_ctime`,
   `fn_btime`, each as ISO-8601 with nanoseconds retained.
3. The parent directory's MFT record and `fn_btime`, included when
   SI's birth time precedes it (source=same `$MFT`,
   locator=`parent_mft_record=<n>`).
4. A nanosecond-precision flag set to true when all four SI values
   terminate in `.0000000`, indicating whole-second rounding.
5. The volume format date from `$Volume` / `$LogFile` if the SI
   quartet predates filesystem creation.

## Confidence calibration and pitfalls

Several legitimate operations mimic timestomping. Archive extraction
with `tar -p`, `unzip -DD`, or 7-Zip's "keep timestamps" mode reapplies
old mtimes via `SetFileTime`, producing SI older than FN by design.
`robocopy /COPY:T` and `xcopy /K` preserve source timestamps the same
way. Build systems such as Bazel, Buck, or Make occasionally reset
mtimes for cache keying. None of these are malicious, yet all produce
the canonical SI-predates-FN pattern.

Discriminators that push back towards malice:

- SI predates the volume format date. Archive tools cannot fabricate
  that because the receiving filesystem is newer.
- The file is an executable in a system directory with no package-
  manager lineage (no matching MSI, no WinSxS manifest, no amcache
  entry aligned to the SI time).
- Prefetch or amcache place the first execution of the binary after
  the FN birth time, contradicting the backdated SI entirely.

APTWatcher caps a single-record timestomp finding at
`confidence=0.6`. Full confidence requires at least one corroborating
artifact — a prefetch `.pf` whose created time disagrees with SI, an
amcache `InventoryApplicationFile` entry, a Security 4688 or Sysmon 1
process-create event, or a Defender/EDR telemetry record — that
independently places the file's real first-seen time inside the FN
window rather than the SI window.
