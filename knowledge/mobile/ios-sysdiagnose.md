---
id: kb-mobile-ios-sysdiagnose-001
title: "iOS sysdiagnose triage collection + parsing"
source_type: author-original
attribution: "APTWatcher team (clean-room)"
mitre_techniques: []
artifact_types:
  - log_archive
  - plist
tools:
  - sysdiagnose
  - plistlib
  - log show
last_updated: "2026-04-20"
---

## What a sysdiagnose captures

`sysdiagnose` is an Apple-provided diagnostic bundle that collects a
broad snapshot of operating-system state: process lists, power logs,
crash reports, network configuration, a slice of the unified log,
installed-application metadata, and a number of plist-encoded state
files. For mobile triage it is often the only collection path that
does not require a paired computer, an MDM tunnel, or an acquisition
tool vendor agreement.

Triggering it on a modern iPhone requires a hardware-button chord:
press and hold volume-up, volume-down, and the side (sleep/wake)
button together for roughly one second, then release. The device
vibrates briefly; the capture runs in the background for several
minutes. The resulting bundle lands in Settings → Privacy &
Security → Analytics & Improvements → Analytics Data, listed under a
name that begins with `sysdiagnose_` and ends with the device model
and timestamp. The bundle can be shared off-device via AirDrop, the
Files app, or a paired Mac.

## What is inside the tarball

Once extracted, the bundle is a tree of several hundred files. The
directories and files that carry the most triage value are:

- `SysdiagnoseLogs/` — a bounded excerpt of the unified log, already
  scoped to the hours around the trigger time.
- `logs/mobile_activation.log` — device activation and restore
  history; attackers who rehome a device or re-pair it leave marks
  here.
- `logs/AppInstalls*` — installation and update records for App Store
  and enterprise-signed applications, including bundle identifiers,
  version strings, and install timestamps.
- Knowledge C data DB (`KnowledgeC.db`, SQLite) when present —
  per-application usage, screen-on events, device-lock events; useful
  for building a user-activity timeline.
- `logs/shutdown.log` — panic and shutdown records. Unexpected
  shutdowns clustered around suspected compromise windows are worth
  surfacing.
- Pairing records under `MobileDevice/` — the set of host computers
  the device trusts, each with its own UDID-derived record.

For unified-log slices inside the bundle, re-run queries offline by
pointing `log show --archive <path>` at the extracted log archive
subdirectory. The same predicate language applies as on a live host.

## Parsing and interesting signals

Most state files are binary plists. Python's `plistlib` reads both
binary and XML plists with `plistlib.load(f)` — no external tooling
required. Run it against the pairing-record directory to enumerate
every trusted host: each record carries a host certificate and a
hostname. A pairing record for a host the user does not recognise,
especially one added recently, is a strong escalation signal.

Examine the running-process list captured in `ps.txt` (or the
equivalent per-bundle file) for names associated with jailbreak
frameworks and userland tweak loaders — `launchd.jb`, `jailbreakd`,
`Substrate`, `libhooker`, `Substitute`, `ElleKit`. Their presence on
a device the user claims is stock is an integrity finding on its own.

## Custody caveats

`sysdiagnose` is live-collected on the device by the user. It is not
a forensic image; timestamps on files inside the bundle are
collection-time, not original-event time, and the unified-log slice
is bounded and can miss older events. Record the SHA-256 of the
tarball as received, who collected it, and how it was transferred.
Treat it as evidence of on-device state at the moment of trigger,
not as an authoritative history of the device. For investigations
that may reach a courtroom, pair it with a full backup or an image
obtained through a controlled acquisition path.
