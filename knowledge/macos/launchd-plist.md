---
id: kb-osx-pers-launchd-plist-001
title: "macOS launchd persistence — LaunchAgents and LaunchDaemons .plist"
source_type: author-original
attribution: "APTWatcher team (clean-room)"
mitre_techniques:
  - T1543.001
  - T1547.011
artifact_types:
  - filesystem
  - launchd_plists
  - unified_logs
tools:
  - plutil
  - launchctl
  - log
last_updated: "2026-04-19"
---

## What launchd persistence is

`launchd` is the init and service-management process on macOS: PID 1,
responsible for starting and supervising system services, per-user
agents, and XPC helpers. It reads job definitions from property-list
(`.plist`) files in a small set of well-known directories, and each
parsed plist becomes a job that can be scheduled, triggered, or held
alive by the supervisor.

Attackers abuse this by dropping a plist of their own into one of:

- `/Library/LaunchDaemons/` — runs as `root`, system scope, starts at
  boot before any user is logged in.
- `/Library/LaunchAgents/` — runs as the logged-in user, system scope
  (applies to every account on the host).
- `~/Library/LaunchAgents/` — runs as that user, per-user scope, no
  admin privilege needed to drop.
- `/System/Library/LaunchDaemons/` and `/System/Library/LaunchAgents/`
  — SIP-protected on a healthy host; only reachable if SIP is disabled
  or if the attacker has a signed helper that can stage there.

A typical persistence plist declares a `Label` (reverse-DNS string that
identifies the job), a `ProgramArguments` array (argv for the binary to
launch), `RunAtLoad` (spawn on parse), and one or more triggers such as
`StartInterval` (periodic), `WatchPaths` (spawn when a path changes),
`StartOnMount`, or `KeepAlive` (respawn on exit). When launchd loads
the plist it spawns the binary with the rights of the scope the plist
lives in — this is why a writable `/Library/LaunchDaemons/` is
effectively a root-persistence primitive.

## How to detect it

Triage starts with a directory listing of the four user-writable or
admin-writable paths, plus a comparison of each plist's metadata
against the binary it launches.

Mechanics:

- Enumerate `/Library/LaunchDaemons/`, `/Library/LaunchAgents/`,
  `~/Library/LaunchAgents/` for each user, and — where SIP state is
  uncertain — the `/System/Library/Launch*` paths.
- Decode each plist with `plutil -p <file>` (handles both XML and
  binary plists) to pull `Label`, `ProgramArguments`, `RunAtLoad`,
  `KeepAlive`, `StartInterval`, `WatchPaths`, `ProgramArguments[0]`.
- On a live host, `launchctl list` and `launchctl print
  system/<label>` show the currently loaded job state.
- Correlate with unified logs:
  `log show --predicate 'subsystem == "com.apple.xpc.launchd"' --last 30d`
  to see repeated spawns or errors tied to a specific label.

Anomaly signals that lift a finding out of the baseline:

- Recent mtime on a plist in `/Library/LaunchDaemons/` while the
  surrounding OS-shipped plists all share an install-era timestamp.
- `ProgramArguments[0]` pointing outside the normal macOS binary
  locations (`/usr/libexec/`, `/usr/local/`, `/opt/`,
  `/Applications/<AppName>.app/Contents/`) — especially user-writable
  locations like `/tmp`, `/private/var/tmp`, `~/Library/`, or a hidden
  dotfile directory.
- `Label` that mimics an Apple reverse-DNS convention
  (`com.apple.<foo>`) while `codesign -dv` on the target binary shows
  no Apple authority or reports the binary as unsigned.
- `RunAtLoad: true` combined with `KeepAlive: true` on an unknown
  binary — this is the "spawn now, respawn forever" pattern.
- Unified-log entries showing launchd repeatedly respawning the same
  unsigned binary after crashes (classic `KeepAlive` loop).

Path / scope reference:

| Path                              | Scope           | Runs as         | Common abuse                                |
|-----------------------------------|-----------------|-----------------|---------------------------------------------|
| `/Library/LaunchDaemons/`         | System          | root            | Root-persistence, boot-time backdoor        |
| `/Library/LaunchAgents/`          | System (agents) | logged-in user  | Per-session payload across all accounts     |
| `~/Library/LaunchAgents/`         | Per-user        | that user       | Unprivileged foothold, userland loader      |
| `/System/Library/Launch{Daemons,Agents}/` | OS-shipped | root or user    | Rare; requires SIP off or signed staging    |

## What APTWatcher records

For each suspicious plist, a finding cites numbered artifacts so a
reviewer can reproduce the conclusion:

1. Absolute plist path, SHA-256 of the plist bytes, and mtime.
2. Decoded plist fields: `Label`, `ProgramArguments`, `RunAtLoad`,
   `KeepAlive`, and any trigger keys present (`StartInterval`,
   `WatchPaths`, `StartOnMount`).
3. SHA-256 of the target binary referenced by
   `ProgramArguments[0]`, plus file size and mtime.
4. Codesign authority string for the binary as reported by
   `codesign -dv --verbose=4`, or the literal value `unsigned` when
   the binary carries no signature.
5. Any unified-log locator
   (`log show ... --predicate 'subsystem == "com.apple.xpc.launchd"'`)
   that shows launchd spawning the referenced label, with the log
   timestamp range used.

## Confidence calibration and pitfalls

The four directories are also home to a large population of
legitimate jobs: Homebrew services (`homebrew.mxcl.*`), Microsoft
AutoUpdate (`com.microsoft.autoupdate*`), Google's Keystone updater
for Chrome, Adobe Creative Cloud helpers, Dropbox, 1Password, VPN
clients, printer drivers, and vendor telemetry agents. Many of these
ship with `RunAtLoad: true` and `KeepAlive: true`, and several use
reverse-DNS labels that look like system components at a glance.

Rules of thumb:

- Presence of a plist in `/Library/LaunchDaemons/` or
  `~/Library/LaunchAgents/` is not, by itself, suspicious. Do not
  tier up on directory membership alone.
- Tier up only when at least one of the following holds: the target
  binary is unsigned or signed by an unknown authority; the `Label`
  spoofs an Apple reverse-DNS namespace but the binary is not
  Apple-signed; the plist mtime is a clear outlier against the host's
  OS-install baseline.
- Cap confidence near `0.5` on a single plist in isolation. Lift
  above that only when the target binary itself corroborates (unknown
  SHA-256 not seen elsewhere in the fleet, unsigned, or linked to a
  prior finding such as a suspicious download or a staged dropper).
- A plist that launches a signed Apple binary (e.g. `/bin/bash`,
  `/usr/bin/osascript`) with attacker-controlled arguments is a
  living-off-the-land variant — inspect `ProgramArguments[1..]` and
  any referenced script path, since codesign on argv[0] will look
  clean.
