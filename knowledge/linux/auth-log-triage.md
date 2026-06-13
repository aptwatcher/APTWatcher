---
id: kb-linux-auth-triage-001
title: "Linux authentication log triage"
source_type: author-original
attribution: "APTWatcher team (clean-room)"
mitre_techniques:
  - T1110
  - T1078.003
  - T1021.004
  - T1556.003
artifact_types:
  - linux_logs
  - disk_image
tools:
  - grep
  - journalctl
  - utmpdump
  - auditd
last_updated: "2026-04-19"
---

# Linux authentication log triage

## What auth logging captures

Authentication logging on Linux records the outcome of every attempt to
establish an identity on the system. This includes interactive SSH sessions,
local console logins, `su` and `sudo` elevations, PAM session open/close
events, cron job context switches, and, when enabled, systemd-logind seat
management. During an incident these logs are often the fastest way to
answer three questions: who authenticated, from where, and when did the
first successful compromise occur. They also reveal the shape of the
attack — spray, targeted brute force, reused credentials, or a pivot from
an already-trusted host.

Auth logs are typically plain text on disk and duplicated in the systemd
journal on modern distributions. They rotate (logrotate), are sometimes
compressed (`.gz`), and may be forwarded off-host via syslog or journal
remote. Treat on-host copies as potentially tampered if the attacker
achieved root; always compare with any centralized copy.

## Log locations and formats

| File / source                          | Distro family         | Format            | Notes                                       |
|----------------------------------------|-----------------------|-------------------|---------------------------------------------|
| `/var/log/auth.log`                    | Debian, Ubuntu        | syslog text       | Written by rsyslog/syslog-ng from `authpriv`|
| `/var/log/auth.log.1`, `.2.gz`, ...    | Debian, Ubuntu        | syslog text       | Rotated archives                            |
| `/var/log/secure`                      | RHEL, CentOS, Fedora  | syslog text       | Same role as auth.log                       |
| `/var/log/secure-YYYYMMDD`             | RHEL (dateext)        | syslog text       | Rotation naming depends on logrotate config |
| `journalctl` (systemd journal)         | Most modern distros   | binary journal    | Durable across logrotate, richer metadata   |
| `/var/log/wtmp`                        | All                   | utmp binary       | Successful logins and reboots               |
| `/var/log/btmp`                        | All                   | utmp binary       | Failed logins                               |
| `/var/run/utmp` (or `/run/utmp`)       | All                   | utmp binary       | Currently logged-in users                   |
| `/var/log/lastlog`                     | All                   | lastlog binary    | Last login per UID                          |
| `/var/log/audit/audit.log`             | All (if auditd)       | auditd text       | Kernel-level, when auditd is configured     |

Key journal unit filters:

```bash
journalctl _SYSTEMD_UNIT=sshd.service
journalctl _SYSTEMD_UNIT=systemd-logind.service
journalctl _SYSTEMD_UNIT=sudo.service       # rare, most sudo goes to authpriv
journalctl SYSLOG_FACILITY=10               # authpriv facility
journalctl _COMM=sshd
journalctl _COMM=sudo
```

Time-bounded extraction:

```bash
journalctl --since "2026-04-18 22:00" --until "2026-04-19 04:00" \
           _SYSTEMD_UNIT=sshd.service -o short-iso
```

## Triage workflow

Given a suspected compromise timestamp `T0`, pivot outward in this order.

1. **Normalize time.** Confirm host timezone and clock drift.
   `timedatectl`, `date -u`, and compare with a trusted NTP source. Express
   `T0` in UTC going forward to avoid DST confusion.

2. **Freeze logs.** Copy `/var/log/auth.log*`, `/var/log/secure*`,
   `/var/log/wtmp`, `/var/log/btmp`, `/var/log/lastlog`, and export the
   journal before anything else:
   ```bash
   journalctl -o export > /evidence/journal-export.bin
   journalctl --output-fields=_HOSTNAME,_SYSTEMD_UNIT,MESSAGE,_SOURCE_REALTIME_TIMESTAMP \
              _SYSTEMD_UNIT=sshd.service -o json > /evidence/sshd.json
   ```

3. **Bracket the window.** Extract `T0 - 24h` to `T0 + 2h` from the auth
   stream. Longer baselines help establish "normal" for the same user or
   jumpbox.

4. **Enumerate successful logins.** Identify every `Accepted password` or
   `Accepted publickey` event in the window. Note username, source IP,
   key fingerprint (if logged), and `pid`. Cross-reference to `wtmp`.

5. **Enumerate failures and bursts.** Count `Failed password` and
   `Invalid user` entries per source IP per minute. Any success that
   follows a cluster of failures for the same account is a brute-force
   hit until disproven (T1110).

6. **Follow the session.** For each suspicious `sshd` PID, follow the
   child events: `pam_unix(sshd:session): session opened for user X`,
   subsequent `sudo` or `su` escalations, and the matching
   `session closed`. The PID anchors lateral work done inside that TTY.

7. **Pivot to shell history and process artifacts.** Once the session
   timeframe and UID are known, move to `.bash_history`, `/proc` remnants
   (if still live), audit logs, and filesystem timestamps around `T0`.

8. **Determine the entry vector.** Password? Stolen key? Agent
   forwarding abuse (T1021.004)? A PAM bypass (T1556.003)? Valid domain
   account on a Linux host (T1078.003)? The grep patterns below help
   classify.

## Key patterns to grep

All examples assume `$LOG=/var/log/auth.log` (substitute `/var/log/secure`
on RHEL-family hosts). Regex is extended (`grep -E`).

| Pattern                                      | Command                                                                                     | Meaning                                                        |
|----------------------------------------------|---------------------------------------------------------------------------------------------|----------------------------------------------------------------|
| Successful password login                    | `grep -E 'sshd.*Accepted password for' $LOG`                                                | User authenticated with a password                             |
| Successful public key login                  | `grep -E 'sshd.*Accepted publickey for' $LOG`                                               | User authenticated with a key; fingerprint often logged        |
| Failed password                              | `grep -E 'sshd.*Failed password for' $LOG`                                                  | Wrong password; counts per IP drive brute-force detection      |
| Invalid user (account does not exist)        | `grep -E 'sshd.*Invalid user ' $LOG`                                                        | Username spray; common in opportunistic scans                  |
| Preauth disconnects                          | `grep -E 'sshd.*Disconnected from .* \[preauth\]' $LOG`                                     | Scanner noise or fingerprinting                                |
| Reverse-DNS failure                          | `grep -E 'sshd.*reverse mapping checking .*POSSIBLE BREAK-IN ATTEMPT' $LOG`                 | PTR/A mismatch; not itself malicious but worth noting          |
| sudo success                                 | `grep -E 'sudo:.*COMMAND=' $LOG`                                                            | Who ran what as whom                                           |
| sudo failure                                 | `grep -E 'sudo:.*authentication failure' $LOG`                                              | Wrong sudo password or policy denial                           |
| su elevation                                 | `grep -E 'su(\[|:).*(session opened|FAILED)' $LOG`                                          | Local elevation attempts                                       |
| PAM session open                             | `grep -E 'pam_unix\(.*:session\): session opened for user' $LOG`                            | Anchors a logical session to a PID and UID                     |
| PAM session close                            | `grep -E 'pam_unix\(.*:session\): session closed for user' $LOG`                            | End of session                                                 |
| Accepted from unusual RFC1918                | `grep -E 'Accepted (password\|publickey) for .* from 10\\.' $LOG`                           | Internal source; expected only from known jumpboxes            |
| Root login over SSH                          | `grep -E 'Accepted (password\|publickey) for root' $LOG`                                    | Should normally be denied by `PermitRootLogin no`              |

Source-IP frequency (top failed sources in the window):

```bash
grep 'Failed password' $LOG \
  | grep -oE 'from [0-9]+(\.[0-9]+){3}' \
  | sort | uniq -c | sort -rn | head
```

Successful logins after many failures from the same IP (brute-force hit):

```bash
awk '
  /Failed password/   { split($0,a," from "); ip=a[2]; split(ip,b," "); fails[b[1]]++ }
  /Accepted password/ { split($0,a," from "); ip=a[2]; split(ip,b," ");
                        if (fails[b[1]] >= 10) print "HIT:", b[1], fails[b[1]], $0 }
' $LOG
```

Rapid-burst detection (per-minute rate per source):

```bash
grep -E 'Failed password|Invalid user' $LOG \
  | awk '{ print $1, $2, $3, $(NF-3) }' \
  | awk '{ sub(/:..$/,"",$3); print $1,$2,$3,$4 }' \
  | sort | uniq -c | sort -rn | head
```

## Binary utmp/wtmp/btmp artifacts

Plain-text logs can be truncated or tampered with; the binary artifacts
provide a secondary view.

- **`/var/run/utmp`** — currently logged-in users. Read with `who`, `w`.
- **`/var/log/wtmp`** — historical successful logins and reboots.
- **`/var/log/btmp`** — failed login attempts (readable by root only).
- **`/var/log/lastlog`** — sparse file indexed by UID with the last
  recorded login per account.

Commands:

```bash
last                      # wtmp, most recent first
last -F                   # include full year and seconds
last -i                   # show numeric IPs instead of hostnames
last -f /mnt/evidence/var/log/wtmp     # parse an offline copy
last reboot               # system boot history
lastb                     # btmp (failed logins), root only
lastlog                   # per-user last login summary
lastlog -u alice          # only a given user
```

Offline parsing with `utmpdump` produces a text representation suitable
for diffing and grepping. The format preserves type, PID, line (TTY),
user, host, IP, and timestamps:

```bash
utmpdump /mnt/evidence/var/log/wtmp > wtmp.txt
utmpdump /mnt/evidence/var/log/btmp > btmp.txt
grep -E '\[7\] ' wtmp.txt              # type 7 = USER_PROCESS
```

Watch for:

- A wtmp record with no matching sshd `Accepted` line in auth.log.
- Timeline gaps (e.g., missing hours) that suggest log truncation.
- Login entries from hosts that should never initiate SSH inbound.
- Non-zero-length `btmp` on a host that exposes no public SSH.

## Correlating with auditd

If `auditd` is running, it observes syscalls and login events below the
level that userspace can easily forge. Useful during triage:

```bash
systemctl is-active auditd
auditctl -l                              # list active rules
ausearch -m USER_LOGIN --start today     # login outcomes
ausearch -m USER_AUTH,USER_ACCT,CRED_ACQ # PAM-adjacent events
ausearch -ui 1001 --start recent         # everything for UID 1001
aureport --auth                          # auth summary
aureport --login -i                      # login summary, interpreted
aureport --tty                           # recorded TTY input if pam_tty_audit is on
```

Pivoting from an auth.log finding:

1. Get the UID for the suspect username:
   `id -u alice`.
2. Pull every audit event for that UID around `T0`:
   `ausearch -ui 1001 --start "04/19/2026 02:00" --end "04/19/2026 04:00" -i`.
3. Correlate audit `exe=` and `cwd=` fields with `sudo` COMMAND entries
   and with `.bash_history` timestamps (if `HISTTIMEFORMAT` was set).
4. If `pam_tty_audit` was enabled for the user or group, recover the
   actual keystrokes with `aureport --tty` and `ausearch -m TTY`.

Example targeted audit rules that pay off in IR (add in a lab, not
blindly in production):

```bash
auditctl -w /etc/passwd   -p wa -k identity
auditctl -w /etc/shadow   -p wa -k identity
auditctl -w /etc/sudoers  -p wa -k sudoers
auditctl -w /root/.ssh/   -p wa -k root_ssh
auditctl -w /etc/pam.d/   -p wa -k pam
```

## Confidence and pitfalls

- **Source IPs lie.** NAT, corporate proxies, and jumpboxes collapse many
  real users behind one address. A single "suspicious" IP may be the
  legitimate egress of an entire office. Validate against asset
  inventory before declaring attribution.
- **Jumpbox volume is noisy.** A bastion host legitimately sees heavy
  inbound SSH from internal ranges. Baseline its normal rate and user
  set before treating volume as an IOC.
- **Clock skew.** A host that drifted by minutes will not line up with
  firewall or EDR events. Always verify `timedatectl` and, for offline
  images, the `/etc/localtime` link and any NTP state files.
- **Log tampering.** A root-level attacker can truncate `auth.log`,
  clobber `btmp`, or wipe journal files under `/var/log/journal/`.
  Missing data is itself a finding; compare on-host with any central
  collector (syslog server, SIEM) and with filesystem timestamps of the
  rotated files.
- **PAM misconfiguration looks like compromise.** A recently modified
  file under `/etc/pam.d/` or a stray `pam_permit.so` line (T1556.003)
  can let logins through with no auth at all. Check
  `stat /etc/pam.d/*` and `rpm -Va` or `debsums -c` where available.
- **Key-based auth hides the user.** `Accepted publickey for alice from
  203.0.113.5 ... ssh2: RSA SHA256:...` identifies the key, not the
  human. Map fingerprints to `~/.ssh/authorized_keys` entries and
  cross-check with the key-management system of record.
- **Rotation and compression.** Do not forget `.gz` archives:
  `zgrep 'Accepted' /var/log/auth.log.*.gz`. On RHEL with `dateext`,
  filenames include dates rather than numeric suffixes.
- **journald persistence.** On some distros the journal is volatile and
  lives only in `/run/log/journal/`. After reboot it is gone. Check
  `Storage=` in `/etc/systemd/journald.conf` and `journalctl --disk-usage`.
- **Container and namespace noise.** Containers running sshd have their
  own PID namespace; PIDs in the log are host-visible but processes may
  live in a cgroup that complicates follow-up. Capture
  `/proc/<pid>/cgroup` while the session is live if at all possible.

A finding from auth logs alone is rarely conclusive. Treat it as the
pivot point: strong enough to generate a hypothesis, weak enough that it
must be confirmed against at least one independent artifact (auditd,
network flow, EDR telemetry, or filesystem timeline) before attribution.
