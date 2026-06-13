---
id: kb-lin-cred-suid-001
title: "Suspicious SUID / SGID binaries — Linux privilege escalation primitive"
source_type: author-original
attribution: "APTWatcher team (clean-room)"
mitre_techniques:
  - T1548.001
  - T1068
artifact_types:
  - filesystem
  - syslog_or_journalctl
  - auditd_logs
tools:
  - find
  - stat
  - auditd
  - debsums
  - rpm
last_updated: "2026-04-19"
---

## What SUID / SGID abuse is

The set-user-ID and set-group-ID permission bits change whose identity a
program runs under. When the SUID bit is set on an executable, the kernel
runs the resulting process with the effective UID of the file's owner
rather than the caller's UID; SGID does the same thing for the group.
A binary owned by `root` with mode `4755` therefore executes as root no
matter which unprivileged user invokes it. This is how legitimate tools
such as `passwd`, `sudo`, and `mount` can perform privileged work on
behalf of ordinary users.

Attackers reuse the same mechanic in two recognisable patterns:

1. **Living-off-the-land abuse.** A legitimate SUID binary already
   present on the system is coaxed into spawning a shell or writing a
   file as root. Classic examples are `find . -exec /bin/sh \;` when
   `find` is SUID, escaping to a shell from `vim` via `:!`, or older
   `nmap` versions that accepted `--interactive`. Weak `sudoers`
   entries — NOPASSWD on interpreters, editors, or package managers —
   land in the same category because they grant the same "run as root"
   primitive without needing a bit flipped on disk.
2. **Implanted SUID binary.** The attacker compiles or copies a small
   executable, runs `chown root:root` and `chmod 4755`, and now has a
   reusable root primitive that outlives the shell they originally
   used. This is attractive after an initial `sudo` or kernel exploit
   because it survives reboots, does not require keeping a process
   alive, and blends into a directory full of real SUID binaries.

Either pattern yields the same endpoint: an unprivileged session that
can become root on demand, which is why SUID surveying belongs in
every Linux triage.

## How to detect it

The first move is a full inventory of SUID and SGID files and a diff
against what the distribution package set should install.

| Detection source         | Command                                                            | What a hit looks like                                                                 |
|--------------------------|--------------------------------------------------------------------|---------------------------------------------------------------------------------------|
| Filesystem sweep (SUID)  | `find / -xdev -perm -4000 -type f 2>/dev/null`                     | A binary in `/tmp`, `/home`, `/dev/shm`, or any writable path; unknown name in `/usr/bin` |
| Filesystem sweep (SGID)  | `find / -xdev -perm -2000 -type f 2>/dev/null`                     | SGID on a script-like wrapper or in a user-writable directory                          |
| Ownership sanity check   | `find / -xdev -perm -4000 -type f ! -user root 2>/dev/null`        | Any SUID file not owned by root — almost always suspect                                |
| Package integrity (deb)  | `debsums -c`                                                       | `changed file` on a binary that also carries SUID                                      |
| Package integrity (rpm)  | `rpm -Va --nomtime --nosize`                                       | `S.5....T.` or `..5.....` against a SUID file                                          |
| auditd                   | `auditctl -a always,exit -F arch=b64 -S execve -F euid=0`          | `execve` of a SUID binary whose parent is `nginx`, `apache2`, cron, or unknown service |

Ownership rules keep the noise manageable. Any SUID file not owned by
`root` should be treated as suspicious until proven otherwise. Any
root-owned SUID file living outside the well-known paths — `/usr/bin`,
`/usr/sbin`, `/bin`, `/sbin`, and vendor directories such as
`/opt/<app>/` — earns the same scrutiny. A `find` pass that excludes
those paths usually produces a short list worth reviewing by hand.

Package verification (`debsums -c` on Debian/Ubuntu, `rpm -Va` on
RHEL-family) catches the case where an attacker replaces the contents
of a shipped SUID binary in place rather than dropping a new file.
A changed checksum on `/usr/bin/passwd` is a much louder signal than
a changed mtime on a config file.

Finally, auditd gives runtime context. Watching `execve` calls with
`euid=0` that originate from web servers, cron, or service accounts
that should not be spawning interactive tools will surface both
living-off-the-land abuse and post-exploitation use of an implanted
binary. Adding a filesystem watch — `auditctl -w /etc/passwd -p wa` —
catches downstream writes that typically follow a successful
escalation.

## What APTWatcher records

A SUID finding cites the following, numbered per flagged file:

1. Absolute path of the binary, SHA-256 of its contents, mtime, and
   the output of `stat -c '%U:%G %a'` (source=`filesystem`,
   locator=`path=<abs path>`).
2. Package ownership resolved via `dpkg -S <path>` or `rpm -qf <path>`;
   files with no owning package are recorded as `"unpackaged"` and
   scored higher.
3. If package integrity tooling flagged the file, a baseline-diff
   entry recording the expected vs. observed checksum
   (source=`debsums` or `rpm -Va`, locator=`path=<abs path>`).
4. Any auditd `execve` record that shows the binary running with an
   abnormal parent — web server, database, cron with no matching
   schedule, unknown service account (source=`auditd`,
   locator=`msg=audit(<ts>:<serial>)`).

## Confidence calibration and pitfalls

Baseline drift is the dominant source of false positives. A minimal
Debian install, a CentOS workstation, and a container image all have
different legitimate SUID inventories; Nix systems put SUID helpers
under `/run/wrappers/bin`, and Docker-in-Docker or rootless-container
setups add further wrappers. Without a per-distro and per-role
baseline, a raw count of SUID binaries means very little.

Within that noise, not all signals are equal. An unknown-path SUID
binary — something living under `/tmp`, `/var/tmp`, `/dev/shm`, a user
home directory, or any world-writable location — is a much stronger
indicator than an altered package file. Package verification
genuinely false-positives when an admin reapplies capabilities or
repackages a binary after an update, and `rpm -Va` output is noisy on
long-lived hosts.

APTWatcher therefore caps a SUID finding at roughly `confidence=0.6`
when the only evidence is suspicious mtime plus unusual ownership or
location. Tier-up to a higher confidence requires at least one of:

- A match against a known GTFOBins-style abuse pattern for the
  binary (for example, SUID on an interpreter or editor that is not
  normally shipped with that bit set).
- An auditd `execve` record showing the binary running under a parent
  that has no legitimate reason to invoke it.
- A failed package integrity check **combined with** a recent mtime
  that does not line up with any package upgrade in the apt or dnf
  history.

Any one of those corroborators pushes the finding into the range where
responder action — isolate, collect, and compare against the
organisation's golden image — is warranted.
