---
id: kb-osx-persistence-launchagent-001
title: "macOS persistence via LaunchAgent plist"
source_type: author-original
attribution: "APTWatcher team (clean-room)"
mitre_techniques:
  - T1543.001
artifact_types:
  - plist
  - log_archive
tools:
  - launchctl
  - log show --predicate
  - sysdiagnose
  - plutil
last_updated: "2026-04-20"
---

## What LaunchAgent persistence is

`launchd` is the supervisor process on macOS and learns about jobs by
reading property-list files from a small, well-known set of
directories. A LaunchAgent is a user-scoped job; a LaunchDaemon is a
system-scoped job. Attackers lean on LaunchAgents because the per-user
variant requires no administrator privilege to drop — any process
running as the current user can write to `~/Library/LaunchAgents/` and
have its payload spawned at the next login or, with `launchctl
bootstrap`, on the spot.

The three persistence paths that matter for triage are:

- `~/Library/LaunchAgents/` — per-user, unprivileged, runs as that
  user whenever they log in.
- `/Library/LaunchAgents/` — system-wide agents, still runs in the
  logged-in user context but applies to every account on the host.
- `/Library/LaunchDaemons/` — system-wide daemons, runs as root at
  boot before any interactive login.

A plist declares at minimum a `Label` (reverse-DNS identifier), a
`ProgramArguments` array that is effectively argv for the spawned
binary, and one or more triggers. The most common persistence triggers
are `RunAtLoad` (spawn immediately on load) and `KeepAlive` (respawn
when the process exits). Periodic scheduling uses `StartInterval` or
`StartCalendarInterval`; path-based triggers use `WatchPaths` or
`StartOnMount`.

## Triage procedure

Enumerate the three directories for each local user, not just the
operator's account. `ls -la` is enough for the initial listing; use
`plutil -p <file>` to decode the plist — `plutil` handles both XML
and binary plists without complaining about format. For each plist
extract `Label`, `ProgramArguments`, `RunAtLoad`, `KeepAlive`, any
interval or watch keys, and the full path of `ProgramArguments[0]`.

Diff the result against a known-clean baseline captured from a gold
image or from a peer host in the same fleet. The diff should be done
by `Label` and by `ProgramArguments[0]` hash, not by filename, because
attackers commonly mimic Apple reverse-DNS labels while pointing the
program arguments at their own binary.

For every referenced binary, run `codesign -dv --verbose=4 <path>` and
record the authority string. A plist that claims `com.apple.*`
heritage while pointing at an unsigned binary, or at a binary signed
by a developer ID that does not match the label's vendor, is the core
persistence pattern. Hash the binary with `shasum -a 256` and carry
that hash forward into fleet-wide lookup.

Correlate with the unified log for a window around the plist mtime:

```
log show --predicate 'subsystem == "com.apple.xpc.launchd"' --last 30d
```

Repeated spawn-and-exit cycles for the same `Label` are the signature
of a `KeepAlive` loop around a crashing or short-lived payload. When
the host is uncooperative, `sysdiagnose` packages a full launchd state
snapshot plus unified-log excerpts and is the recommended collection
when the investigator cannot keep a shell open on the host.

## Pitfalls

The LaunchAgent directories are densely populated by legitimate
software: Homebrew services, Microsoft AutoUpdate, Google Keystone,
Adobe helpers, VPN clients, password managers. Directory membership
alone is not a finding. Tier up only when the codesign authority is
missing or mismatched, when the plist mtime is an outlier against the
host's install-era baseline, or when the label spoofs an Apple
namespace on a non-Apple binary.
