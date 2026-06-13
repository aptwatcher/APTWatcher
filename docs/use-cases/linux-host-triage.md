# Use case: Linux host triage

> Linux-specific analogue to [Windows host triage](windows-host-triage.md).
> Different artifacts, different tools, same discipline.

## When to use

- A Linux server (bare metal or VM) is suspected of compromise.
- You have a disk image **or** a live-response triage bundle (`UAC`, `LinPEAS
  audit mode`, or equivalent) plus a memory capture (`LiME` / `AVML`).
- Common triggers: cryptomining detection, reverse-shell callbacks, webshell
  uploads to a public-facing server.

## Profile declaration

```yaml
profile: linux-host-triage
required_tools:
  - volatility3 >= 2.4
  - log2timeline.py >= 20240504
  - bulk_extractor
  - yara
  - chkrootkit
optional_tools:
  - rkhunter
  - lynis
  - auditd-parser
artifact_categories:
  required:
    - syslog OR journalctl_export
    - /etc (users, cron, systemd units)
    - /var/log
    - bash_history (per user)
    - process_tree (ps or memory-derived)
  optional:
    - memory
    - auditd_logs
    - filesystem_mtime_delta
tier_prerequisites:
  tier_1: optional
  tier_2: optional
  tier_3: gated_by_flag
```

## What the agent does under this profile

1. **Preflight** + inventory. Confirms the tool set and records kernel /
   distro versions (artifact provenance).
2. **Timeline.** Plaso covers the major Linux artifact sources: syslog,
   auth.log, journalctl exports, cron, apt/dpkg history.
3. **Persistence sweep.** Systemd units, cron entries (user + system),
   SSH `authorized_keys`, `.bashrc` / `.bash_profile` / `.profile` per user,
   `/etc/rc.local` (legacy), `/etc/ld.so.preload`.
4. **User account audit.** `/etc/passwd` + `/etc/shadow` cross-checked; any
   UID 0 account other than root is flagged.
5. **Shell history.** Per-user bash history cross-referenced with auth.log
   sessions. Missing history where sessions exist is itself a signal.
6. **Webshell scan** on common web roots (`/var/www/`, `/srv/www/`,
   `/usr/share/nginx/html/`) via yara + known-webshell indicators.
7. **Memory triage** (if present). Linux Volatility plugins: `linux.pslist`,
   `linux.psaux`, `linux.bash`, `linux.check_syscall`, `linux.check_modules`.
8. **Report** with MITRE mapping.

## Linux-specific anti-patterns

- **Trusting `ps` output** from the live triage bundle. A rootkit can hide
  its processes from userspace tools. The agent cross-checks against memory
  (`linux.pslist`) whenever a memory image is available, and flags the
  discrepancy when it exists.
- **Assuming no persistence outside `/etc`.** Systemd user units
  (`~/.config/systemd/user/`) and container-level persistence (a compromised
  image in a running container) are frequently missed. The agent checks
  both.
- **Treating logrotate gaps as benign.** A sudden log-rotation gap around a
  suspicious time window is a defense-evasion signal, not noise.

## What it cannot do

- **Kubernetes-level analysis.** If the host is a K8s node, cluster-level
  evidence (audit logs, etcd state) is outside the scope of this profile.
- **BPF-based rootkit detection.** Detecting eBPF rootkits reliably requires
  kernel-level tooling beyond what SIFT ships. The agent notes the gap.
- **Full container forensics.** Container images are surfaced but not
  analyzed layer-by-layer in this profile.

## Failure modes

- **No auth.log or equivalent**: aborts. Authentication evidence is core to
  Linux triage.
- **Memory capture was taken with an incompatible profile**: the memory
  artifacts section is skipped with a logged warning. Disk-level analysis
  proceeds.
- **Read-only mount fails**: aborts. The profile never mounts the image
  read-write; if read-only is not possible, evidence integrity cannot be
  guaranteed.

## Related

- [Windows host triage](windows-host-triage.md)
- [Memory only](memory-only.md)
- [Reference — SIFT tools](../reference/sift-tools.md)
