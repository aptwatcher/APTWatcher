---
id: kb-lin-pers-systemd-cron-001
title: "Systemd timers and cron — persistent Linux execution primitives"
source_type: author-original
attribution: "APTWatcher team (clean-room)"
mitre_techniques:
  - T1053.003
  - T1053.006
  - T1543.002
artifact_types:
  - filesystem
  - syslog_or_journalctl
  - auditd_logs
tools:
  - systemctl
  - journalctl
  - find
  - auditd
last_updated: "2026-04-19"
---

## What systemd timers and cron persistence look like

Cron and systemd timers are the two canonical ways to schedule recurring execution on Linux, and both are abused for persistence because they survive reboots, blend into the baseline, and often run as root. An operator who lands on a host will usually pick whichever scheduler already has the most noise to hide in.

Cron state lives in a handful of predictable spots. Per-user crontabs sit under `/var/spool/cron/crontabs/<user>` (Debian family) or `/var/spool/cron/<user>` (RHEL family). System-wide jobs live in `/etc/crontab` and the drop-in directory `/etc/cron.d/`. The `/etc/cron.hourly`, `cron.daily`, `cron.weekly`, and `cron.monthly` directories are executed by `run-parts` on a schedule, so a script dropped there with the execute bit is effectively a timer. `anacron` fills in missed runs on desktops and laptops, and `at` provides one-shot scheduling through `/var/spool/at/`.

Systemd timers are unit files with a `.timer` suffix paired with a `.service` unit that declares the `ExecStart=` payload. System-scope units live in `/etc/systemd/system/` (admin-authored), `/run/systemd/system/` (transient, cleared on reboot), and `/usr/lib/systemd/system/` (package-shipped). User-scope units live in `~/.config/systemd/user/` and run under a per-user `systemd --user` instance when the user has a lingering session or `loginctl enable-linger` is set. A timer can trigger on calendar events (`OnCalendar=`) or on monotonic offsets from boot, activation, or the last run — the latter makes low-and-slow beaconing easy to arrange.

## How to detect it

Enumeration is cheap. `systemctl list-timers --all` shows every registered timer with its next/last trigger and bound unit; `systemctl list-unit-files --type=service --state=enabled` enumerates enabled services. For the user scope, repeat with `--user` or `--machine <user>@.host`. On the cron side, `ls -la /etc/cron* /var/spool/cron/` plus a loop over `crontab -l -u <user>` for every real account in `/etc/passwd` covers the standard locations.

File metadata is the strongest triage signal. A `.timer` or `.service` file with an mtime inside the incident window, owned by root but pointing `ExecStart=` at a script under `/tmp`, `/var/tmp`, `/dev/shm`, or a user home is a high-value lead. Same for crontab entries whose command includes base64, `curl | sh`, `python -c`, or a path under `/tmp`. `find /etc/systemd/system /etc/cron.d -newer /etc/shadow -type f` is a quick way to surface recently planted files.

Runtime evidence shows up in the journal and audit log. `journalctl -u <unit>` replays every invocation; the generic line `systemd[1]: Started <unit>` on an unexpected cadence (for example, every 7 minutes, or at 03:17 every morning) is worth pivoting on. Under auditd, an `execve` rule keyed to `comm=cron` or `ppid=1` with an unexpected `exe=` is the corroborating event.

| Vector                             | Primary artifact                                  | Detection cue                                                      |
|------------------------------------|---------------------------------------------------|--------------------------------------------------------------------|
| User crontab                       | `/var/spool/cron/crontabs/<user>`                 | Recent mtime, suspicious command, user that normally has no cron   |
| System crontab / drop-in           | `/etc/crontab`, `/etc/cron.d/*`                   | File not owned by a package, odd interpreter, world-writable target|
| `run-parts` directories            | `/etc/cron.{hourly,daily,weekly,monthly}/*`       | Script added outside package manager transactions                  |
| System systemd timer               | `/etc/systemd/system/*.timer` + `.service`        | `ExecStart=` pointing at `/tmp`, `/home`, or hex-named binary      |
| Transient systemd unit             | `/run/systemd/system/*`                           | Any unit present that is not a known runtime generator output      |
| User systemd timer                 | `~/.config/systemd/user/*.timer`                  | Enabled for account with `linger=yes` set recently                 |
| `at` job                           | `/var/spool/at/a*`                                | Any entry on a server that does not otherwise use `at`             |

## What APTWatcher records

For every finding raised under this use case, the agent should attach the following citations so a human reviewer can reach the same conclusion without re-running triage:

1. Full path, sha256, size, mtime, ctime, and `stat`-derived uid/gid/mode of the unit file or crontab.
2. Raw contents of the unit or crontab line, with the resolved `ExecStart=` target (or cron command) normalized.
3. For the referenced executable or script: path, sha256, mtime, and package-manager ownership check (`dpkg -S` / `rpm -qf`) — unowned files are a material signal.
4. Output of `systemctl show <unit>` capturing `FragmentPath`, `UnitFileState`, `ActiveState`, `ExecMainPID`, and `TriggeredBy`.
5. Journal locator for recent invocations: the exact `journalctl _SYSTEMD_UNIT=<name> _PID=<n>` query plus the last N matching records.
6. If a process was observed: parent and grandparent lineage (pid, ppid, comm, exe, cmdline) captured at detection time, so the link from `systemd` or `cron` down to the payload is preserved.
7. Ownership anomaly note when a root-owned unit points at a path writable by a non-root user (classic privilege-escalation-on-next-tick pattern).
8. Auditd correlation: any `SYSCALL` / `EXECVE` records whose `ppid` resolves to `cron`, `crond`, `systemd`, or a `systemd --user` instance within the finding window.

## Confidence calibration and pitfalls

Legitimate systemd timers are abundant on any modern distro — `apt-daily.timer`, `apt-daily-upgrade.timer`, `fwupd-refresh.timer`, `man-db.timer`, `logrotate.timer`, `fstrim.timer`, `systemd-tmpfiles-clean.timer`, and vendor-specific units for Snap, Flatpak, or cloud agents. Cron is similarly noisy with `logrotate`, `mlocate`, `sysstat`, and distribution upkeep scripts. A finding built only on "this timer exists" is almost always a false positive. Raise confidence above 0.5 only when there is (a) a concrete anomaly — recent mtime inside the incident window, an `ExecStart=` target outside standard binary directories, an unknown unit name not shipped by any installed package, or a user-writable payload invoked as root — and (b) at least one corroborating signal such as a matching journal invocation, an auditd `execve`, or a suspicious network connection from the child process. Transient units under `/run/systemd/system/` and user-scope timers on service accounts that should never have a login session both deserve an automatic bump in priority.
