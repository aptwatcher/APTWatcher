---
id: kb-linux-ssh-lateral-001
title: "SSH key-based lateral movement on Linux"
source_type: author-original
attribution: "APTWatcher team (clean-room)"
mitre_techniques:
  - T1021.004
  - T1098.004
  - T1552.004
  - T1563.001
artifact_types:
  - disk_image
  - linux_logs
tools:
  - grep
  - journalctl
  - auditd
  - sshd
last_updated: "2026-04-19"
---

# SSH key-based lateral movement on Linux

SSH is the default remote-administration channel on Linux, and its public-key
authentication model makes it a high-value lateral-movement primitive. Once an
attacker has code execution on one host, stealing or planting keys provides
password-less, logged-as-legitimate access across the rest of the estate.

## How SSH key pivoting works

An attacker with a foothold on host A typically performs one or more of the
following moves:

1. **Harvest existing private keys** from `~/.ssh/id_*`, `~/.ssh/id_*.pub`,
   `/root/.ssh/`, backup archives, and user home directories that were mounted
   from NFS or a shared filesystem.
2. **Harvest agent sockets.** A forwarded `ssh-agent` socket exposed through
   `$SSH_AUTH_SOCK` can be reused by any process running as that user, allowing
   an attacker to authenticate to downstream hosts without ever touching the
   private key file.
3. **Plant a new public key** into `~/.ssh/authorized_keys` on host B (either
   directly, or by pushing it through a config-management tool whose
   credentials were stolen on host A).
4. **Configure a pivot** via `~/.ssh/config` using `ProxyJump` or
   `ProxyCommand` so that the operator's tooling transparently chains through
   the compromised host.
5. **Repeat** against adjacent hosts, often following the natural trust graph
   — developer workstation to build server to production, or jump host to
   target tier.

The attraction for an attacker is that the resulting sessions look like normal
administrative activity in most log sources; the authentication succeeds, the
user maps to a real account, and no password is ever typed.

## Artifacts to hunt

| Artifact | Location | What to look for |
|---|---|---|
| Authorized keys | `~/.ssh/authorized_keys`, `~/.ssh/authorized_keys2` | New entries outside of a known change window; keys with no comment, a bare UUID, `root@kali`, `kali@kali`, `user@localhost`, or a hostname that does not exist in the fleet |
| Per-user override | `/etc/ssh/sshd_config.d/*`, `AuthorizedKeysFile` directives pointing to writable paths | Redirection of the authorized-keys lookup to a path under `/tmp`, `/var/tmp`, `/dev/shm`, or a user-writable location |
| Known hosts | `~/.ssh/known_hosts`, `/etc/ssh/ssh_known_hosts` | Host entries appearing after the suspected compromise time; entries for internal hosts a given user has no business reaching |
| Client config | `~/.ssh/config` | Stanzas adding `ProxyJump`, `ProxyCommand`, `IdentityFile` pointing to `/tmp` or `/dev/shm`, `StrictHostKeyChecking no`, `UserKnownHostsFile /dev/null` |
| Private keys | `~/.ssh/id_*`, backup tarballs, git repositories, Ansible vault files | Unexpected new keys, world-readable keys, keys with recent `atime` indicating exfil read |
| sshd logs | `/var/log/auth.log`, `/var/log/secure`, `journalctl -u ssh` / `-u sshd` | `Accepted publickey for <user> from <ip> port <p> ssh2: <alg> SHA256:<fp>` events, session opens/closes, source IPs |
| Audit trail | `auditd` (`/var/log/audit/audit.log`) | Writes to `~/.ssh/authorized_keys`, `~/.ssh/config`, `/etc/ssh/*` by unexpected processes |
| Shell history | `~/.bash_history`, `~/.zsh_history`, `/root/.bash_history` | Commands like `ssh-keygen`, `ssh-copy-id`, `echo ... >> authorized_keys`, `cat id_rsa`, piping keys through `base64` |

## Detection workflow

Start from a suspected source host and expand outward.

1. **Timeline the source host.** Establish the earliest plausible compromise
   time (process anomaly, webshell drop, suspicious login). Everything after
   that timestamp is within the investigation window.
2. **Enumerate private-key access.** Collect `atime`/`mtime` on all
   `~/.ssh/id_*`, `~/.ssh/*.pem`, and any keys referenced by `~/.ssh/config`.
   Recent `atime` without a corresponding legitimate session is a strong
   signal that the key was read by an attacker.
3. **Dump `known_hosts`.** New entries post-compromise indicate outbound SSH
   from this host. Each entry is a lateral-movement candidate target.
   ```bash
   stat -c '%y %n' ~/.ssh/known_hosts
   awk '{print $1}' ~/.ssh/known_hosts | cut -d, -f1 | sort -u
   ```
4. **Review the client config.** Any `Host` stanza added in the window with
   `ProxyJump`, `ProxyCommand`, or a non-standard `IdentityFile` is suspect.
5. **Pull outbound SSH sessions.** On the source host, correlate
   `auditd` `execve` records for `/usr/bin/ssh` and `/usr/bin/scp` with the
   timeline. On the network side, NetFlow / Zeek `ssh.log` entries from this
   host to internal destinations expand the candidate target list.
6. **Pivot to candidate targets.** On each candidate host, grep
   `auth.log`/`secure` for `Accepted publickey` events whose source IP matches
   the compromised host and whose timestamp is after the window start.
   ```bash
   grep -E "Accepted (publickey|keyboard-interactive/pam)" /var/log/auth.log \
     | grep "from <source_ip>"
   ```
7. **Map authorized_keys diffs.** On each candidate target, diff the current
   `~/.ssh/authorized_keys` against the last known-good backup or
   config-management render. Any added line is a suspect planted key.
8. **Compute blast radius.** Combine (known_hosts additions) ∪ (publickey
   acceptances from the source IP) ∪ (authorized_keys changes during the
   window) to produce the list of hosts that require triage.

## sshd Accepted publickey correlation

The single most useful log line for this investigation is `sshd`'s
`Accepted publickey` event, which includes the fingerprint of the key that
authenticated. To have fingerprints logged, `sshd` must run at
`LogLevel VERBOSE` (the default is `INFO`, which does **not** log the
fingerprint):

```
# /etc/ssh/sshd_config
LogLevel VERBOSE
```

A VERBOSE event looks like:

```
sshd[12345]: Accepted publickey for alice from 10.4.2.7 port 52344 ssh2: \
    ED25519 SHA256:AbCdEf0123456789...
```

From there:

1. Extract the fingerprint from each event.
2. On every host where that user has an `authorized_keys` entry, compute the
   fingerprint of each installed key and compare:
   ```bash
   ssh-keygen -lf ~alice/.ssh/authorized_keys
   ```
3. The key whose fingerprint matches the log entry is the one that was used.
   If that key is not in the inventory of keys issued to `alice`, the
   authentication used a planted or stolen key.
4. Search every `authorized_keys` file across the estate for that fingerprint
   to find all hosts the attacker could have reached with it:
   ```bash
   for f in /home/*/.ssh/authorized_keys /root/.ssh/authorized_keys; do
     [ -f "$f" ] && ssh-keygen -lf "$f" | grep -F "<fingerprint>" \
       && echo "  -> $f"
   done
   ```

If VERBOSE logging was not enabled before the incident, fingerprints are not
available retroactively. In that case fall back to source-IP correlation and
authorized_keys diffs.

## Containment checklist

Short-term (hours):

- [ ] **Identify the compromised key(s).** By fingerprint if VERBOSE logging
      was on; otherwise by process of elimination from authorized_keys diffs.
- [ ] **Remove the key from every `authorized_keys` on the estate.** Do this
      via configuration management so it cannot be reintroduced. Grep for the
      public-key material string, not just the comment.
- [ ] **Expire any related user's password and force a re-auth** to break
      sessions that may still be live.
- [ ] **Kill active sessions** authenticated by the bad key: `loginctl
      terminate-session`, `who`, `pkill -KILL -u <user>` as appropriate.
- [ ] **Disable agent forwarding globally** (`AllowAgentForwarding no` in
      `sshd_config`) until the investigation is complete. Agent forwarding is
      what lets a single compromised bastion session metastasize.
- [ ] **Rotate the private keys** for every identity that authenticated from
      or through a known-compromised host in the window.

Medium-term (days):

- [ ] **Centralize authorized_keys via `AuthorizedKeysCommand`.** Point
      `sshd_config` at a trusted helper (LDAP, IdP, internal key service) so
      that editing `~/.ssh/authorized_keys` on a host is no longer sufficient
      to create access:
      ```
      AuthorizedKeysFile none
      AuthorizedKeysCommand /usr/local/sbin/fetch-authorized-keys %u
      AuthorizedKeysCommandUser nobody
      ```
- [ ] **Add `from=` restrictions** on each key so it only works from known
      source networks:
      ```
      from="10.0.0.0/8,!10.0.99.0/24" ssh-ed25519 AAAA... alice@corp
      ```
- [ ] **Force `StrictHostKeyChecking yes`** on administrative tooling so that
      attacker-introduced `known_hosts` entries cannot silently trust a
      rogue host.
- [ ] **Enforce short-lived SSH certificates** (`TrustedUserCAKeys`) instead
      of long-lived static keys. This is the durable fix: a stolen cert
      expires on its own.
- [ ] **Remove per-host `authorized_keys` writability.** Consider
      `chattr +i ~/.ssh/authorized_keys` for service accounts that should
      never have keys added, combined with `auditd` alerting on any
      modification attempt.

Long-term (weeks):

- [ ] **Deploy `auditd` rules on all `.ssh` paths.** Example:
      ```
      -w /etc/ssh/sshd_config -p wa -k ssh_config
      -w /etc/ssh/sshd_config.d -p wa -k ssh_config
      -a always,exit -F dir=/home -F perm=wa -F path_suffix=/.ssh/authorized_keys -k authkey
      -a always,exit -F path=/root/.ssh/authorized_keys -F perm=wa -k authkey
      ```
- [ ] **Alert on authorized_keys change events outside Ansible/Salt
      deploy windows.** Changes at 03:12 on a Sunday by a non-management
      agent are the signal.
- [ ] **Baseline expected `ProxyJump` chains.** Any host acting as a jump
      point should be known; new `ProxyJump` targets appearing in user
      configs should page.

## Indicator table

| Indicator | Severity | Notes |
|---|---|---|
| New `authorized_keys` entry with no comment, UUID-only comment, or `*@kali` comment | High | Attacker-generated keys rarely bother with a meaningful comment |
| `IdentityFile` in `~/.ssh/config` pointing at `/tmp`, `/dev/shm`, `/var/tmp` | High | Legitimate keys live under `~/.ssh` |
| `StrictHostKeyChecking no` and `UserKnownHostsFile /dev/null` in a user config | High | Classic tradecraft to avoid known_hosts noise |
| `Accepted publickey` from an unexpected source IP for a service account | High | Service accounts should only authenticate from CI/CD ranges |
| New `known_hosts` entries post-compromise-timestamp | Medium | Confirms outbound SSH; pivot target list |
| Recent `atime` on `id_rsa` / `id_ed25519` without a matching legitimate login | Medium | Evidence of key theft; compare with session records |
| `ssh-keygen`, `ssh-copy-id`, `cat id_rsa` in a non-admin shell history | Medium | Manual-attacker tradecraft |
| `SSH_AUTH_SOCK` set in the environment of a shell spawned by a web service | High | Agent-forwarding reuse across a privilege boundary |
| `AuthorizedKeysFile` overridden in `sshd_config.d/*.conf` to a user-writable path | Critical | Full backdoor — host trusts keys from an attacker-writable file |
| `authorized_keys` modified by a process that is not `sshd`, `sudo`, the config-management agent, or the owning user's interactive shell | High | Requires `auditd` with `path_suffix` rule above |

## Confidence and pitfalls

- **CI/CD and deploy keys.** Build systems legitimately push keys to target
  accounts, and they often do so at odd hours. Exclude the CI/CD source
  ranges and agent identities from the "new authorized_keys outside a
  change window" alert, but do **not** exclude them from the audit trail
  itself — CI/CD credentials get stolen too.
- **Ansible, SaltStack, Puppet, Chef.** Legitimate config-management will
  rewrite `authorized_keys` wholesale on each run, which looks identical
  to an attacker overwrite. The fix is to compare the rendered template
  against the file on disk: if they match, the change was legitimate; if
  they diverge, the host was modified out of band.
- **Multi-user bastions.** On a shared jump host, many users will have
  many known_hosts entries, and `Accepted publickey` events from the
  bastion's IP toward the fleet are normal. Scope by user, not by source
  IP, when triaging a bastion.
- **Developer workstations with legitimate `ProxyJump`.** Developers may
  legitimately chain through a bastion. Alert on new chains, not on the
  existence of chains.
- **LogLevel INFO pre-incident.** If `sshd` was not at VERBOSE before the
  incident, key fingerprints are not in the historical logs. The first
  containment action should be to raise `LogLevel` to VERBOSE so that
  ongoing authentications can be correlated while the investigation
  proceeds.
- **Rotated keys vs revoked keys.** Rotating a user's key pair does not
  remove the attacker's planted key from downstream `authorized_keys`
  files. Revocation (removing the attacker's key from every file it
  landed in) is a separate action and must be explicit.
- **`authorized_keys2` is still honored by some builds.** Do not grep
  only `authorized_keys`; also check `authorized_keys2` and any path
  referenced by `AuthorizedKeysFile` in `sshd_config` and its drop-ins.
