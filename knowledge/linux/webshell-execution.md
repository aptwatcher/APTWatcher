---
id: kb-linux-webshell-exec-001
title: "Webshell execution on Linux"
source_type: author-original
attribution: "APTWatcher team (clean-room)"
mitre_techniques:
  - T1505.003
  - T1059.004
  - T1190
  - T1036.005
artifact_types:
  - disk_image
  - linux_logs
tools:
  - find
  - grep
  - auditd
  - yara
last_updated: "2026-04-19"
---

# Webshell execution on Linux

## What webshell execution looks like

A webshell is a server-side script (PHP, JSP, ASPX, Python CGI, Perl CGI) dropped
inside a web application's document root or a writable upload directory. When the
attacker requests the file over HTTP(S), the web server interpreter executes it
and typically forks an operating-system command through `system()`, `exec()`,
`passthru()`, `popen()`, `shell_exec()`, `Runtime.exec()`, `ProcessBuilder`, or
equivalent language primitives.

The observable chain on a Linux host is:

1. A POST (sometimes GET) request reaches an interpreter-backed URL.
2. The interpreter process (`php-fpm`, `apache2` with mod_php, `tomcat`,
   `uwsgi`, Passenger) calls `fork()` + `execve()`.
3. A child process owned by the web-server account (`www-data`, `apache`,
   `nginx`, `tomcat`, `httpd`) runs `sh`, `bash`, `python`, `perl`, or `nc`.
4. Command output is marshalled back into the HTTP response body, often
   base64-encoded or wrapped in a delimiter string.

The forensic fingerprint is therefore a web-server UID executing a shell. On a
healthy server, that pairing should be rare: legitimate LAMP/LEMP stacks seldom
need to spawn `/bin/sh` from an HTTP request handler.

## Process-tree signature

On a live host, the quickest triage is a full forest view:

```bash
ps -ef --forest
pstree -p -u
```

Look for a shell or scripting interpreter whose parent is a web-tier process
and whose UID matches the web-server account. Typical patterns:

| Parent process    | Runs as    | Suspicious child              | Notes                                    |
|-------------------|------------|-------------------------------|------------------------------------------|
| `apache2`         | `www-data` | `sh -c id`, `bash -i`         | mod_php or mod_cgi invocation            |
| `httpd`           | `apache`   | `sh`, `python -c`, `perl -e`  | RHEL/CentOS/Alma/Rocky default naming    |
| `php-fpm: pool`   | `www-data` | `sh`, `bash`, `nc`            | Most common on Debian/Ubuntu NGINX sites |
| `nginx: worker`   | `nginx`    | rarely direct; via fastcgi    | Shell child of raw nginx is strong IOC   |
| `tomcat`/`java`   | `tomcat`   | `sh`, `bash`, `whoami`        | JSP webshell or deserialization RCE      |
| `uwsgi`           | `www-data` | `sh`, `python`                | Flask/Django apps with RCE               |
| `python` (gunicorn)| `www-data`| `sh`, `bash -c`               | WSGI app executing OS commands           |

Short-lived commands like `id`, `uname -a`, `whoami`, `uptime`, `ip a`, and
`cat /etc/passwd` appearing as web-tier children are high-signal recon markers.

On a disk image, there is no live process list. Reconstruct the tree from:

- `/var/log/journal/*` (systemd-journald) with
  `journalctl -D /mnt/evidence/var/log/journal --output=short-iso`.
- `/var/log/audit/audit.log` (auditd) filtered by the web-tier UID.
- `/var/log/apache2/` or `/var/log/httpd/` access logs correlated by timestamp.
- Shell histories: `~www-data/.bash_history`, `~/.python_history`, tomcat's
  home — rarely populated, but occasionally left writable.

## Web access log patterns

Access logs are the highest-yield artifact because they survive even when the
webshell file has been deleted. Useful columns: request method, URI, status,
bytes sent, user-agent, `Content-Length`.

Indicators worth grepping for:

- POST requests to files inside an upload, cache, or temp directory:
  `POST /uploads/avatar.php`, `POST /tmp/u.php`, `POST /wp-content/uploads/2024/*.php`.
- GET or POST to PHP/JSP files that are not part of the application (names like
  `shell.php`, `cmd.php`, `x.php`, `1.php`, `info.php`, `up.jsp`, `cmd.jsp`,
  `help.aspx`).
- URIs that embed base64 or hex payloads in the query string.
- User-agents that are default library strings (`curl/`, `python-requests/`,
  `Go-http-client`, empty UA) targeting the same unusual endpoint repeatedly.
- A POST with a large `Content-Length` but a very small response body, or the
  reverse — a short POST that returns kilobytes of data.
- The same source IP hitting only one or two URIs over and over, usually with
  200 responses and varying body sizes (command-and-response rhythm).
- Requests that arrive outside normal traffic envelopes for the site —
  e.g., a marketing brochure site receiving POSTs at 03:00.

Helpful one-liners against Apache/NGINX combined logs:

```bash
# POSTs to PHP files, ranked by frequency
awk '$6 ~ /POST/ && $7 ~ /\.php/ {print $7}' /var/log/apache2/access.log \
  | sort | uniq -c | sort -rn | head -30

# Rare URIs (seen < 5 times) that returned 200
awk '$9 == 200 {print $7}' /var/log/nginx/access.log \
  | sort | uniq -c | awk '$1 < 5 {print}'

# Requests from a single IP across many URIs
awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head

# Long query strings (potential inline payload)
grep -E '\?[^ ]{200,}' /var/log/nginx/access.log
```

When triaging a disk image, copy `access.log*` and any rotated `.gz` archives
to your analysis VM and index them with `zgrep` or ingest into a lightweight
log pipeline. Correlate by minute boundaries with auditd `execve` events.

## Filesystem hunt commands

Webshells are usually new files — or unexpectedly modified legitimate files —
inside the document root or a writable upload path. Prioritise recency, owner,
and permission anomalies.

```bash
# Files modified in the last 60 minutes under the web root
find /var/www -type f -mmin -60 -printf '%TY-%Tm-%Td %TH:%TM  %u:%g  %m  %p\n'

# Files created in the last 7 days, any scripting extension
find /var/www /srv/www /opt/tomcat/webapps -type f -mtime -7 \
  \( -name '*.php' -o -name '*.phtml' -o -name '*.php5' -o -name '*.php7' \
     -o -name '*.jsp' -o -name '*.jspx' -o -name '*.war' \
     -o -name '*.aspx' -o -name '*.cgi' -o -name '*.pl' -o -name '*.py' \) \
  -printf '%TY-%Tm-%Td %TH:%TM  %u:%g  %p\n' | sort

# Script files owned by the web user (uploads rather than packages)
find /var/www -type f \( -name '*.php' -o -name '*.jsp' \) \
  \( -user www-data -o -user apache -o -user nginx -o -user tomcat \) -ls

# Scripts with an execute bit set in the web root (rarely needed)
find /var/www -type f -name '*.php' -perm /111 -ls

# Suspiciously named scripts anywhere on disk
find / -xdev -type f \
  \( -iname 'shell*.php' -o -iname 'cmd*.php' -o -iname 'c99*.php' \
     -o -iname 'r57*.php' -o -iname 'wso*.php' -o -iname 'b374k*.php' \
     -o -iname '*.jspx' -o -iname 'cmd*.jsp' -o -iname 'jsp*.jsp' \) 2>/dev/null

# Tiny PHP files — many one-line webshells are under 200 bytes
find /var/www -type f -name '*.php' -size -200c -ls

# PHP files containing canonical sink functions (behavioural grep, no payload)
grep -RInE 'eval[[:space:]]*\(|assert[[:space:]]*\(|system[[:space:]]*\(|\
passthru[[:space:]]*\(|shell_exec[[:space:]]*\(|proc_open[[:space:]]*\(|\
popen[[:space:]]*\(' /var/www 2>/dev/null

# Double extensions and tricks (image.php.jpg, shell.phtml, ...)
find /var/www -type f \( -iname '*.php.*' -o -iname '*.jpg.php' \
   -o -iname '*.png.php' -o -iname '*.phtml' \) -ls
```

For disk-image work, mount the partition read-only and repoint the paths at the
mount (`/mnt/evidence/var/www`). Preserve MAC times by using `-noatime` on the
loop mount. Record hashes of any candidate webshell before moving it so that
YARA or VirusTotal lookups can be cross-referenced later.

A minimal YARA-style triage using `grep -l` is fine for first pass; save real
YARA rules for the lab. Focus the first pass on: inline eval sinks, base64
decode wrapping eval, obfuscated variable-variable patterns, and common
operator keywords in JSP (`Runtime.getRuntime().exec`, `ProcessBuilder`).

### Common families at the behavioural level

These are described so analysts can recognise the shape, not reproduce them.

- **China Chopper-style one-liner PHP**: a single tag that reads one POST
  parameter and passes it to a dynamic evaluator. Very small file, often under
  100 bytes. HTTP signature: POST with exactly one form field whose value is a
  base64 or raw PHP snippet.
- **WSO / b374k**: full-featured management shells presenting a menu UI
  (file manager, SQL client, reverse-shell launcher). Files are several
  hundred kilobytes, heavily packed/obfuscated, with long base64 or gzinflate
  blobs. HTTP signature: GETs to a single PHP URL returning large HTML pages
  with a login form branded with the family name, followed by POSTs carrying a
  session cookie.
- **c99 / r57**: older PHP families still in the wild. Similar UI approach,
  identifiable by signature strings like `c99shell`, `r57shell` in the source.
- **JSP webshells (cmd.jsp, JspSpy, behinder JSP variants)**: use
  `Runtime.getRuntime().exec()` or `ProcessBuilder`. HTTP signature: POST or
  GET to a `.jsp` with a `cmd=` or single short parameter; responses often
  return the raw stdout.
- **Behinder / Godzilla / AntSword clients**: encrypted traffic between
  attacker tool and shell. HTTP signature: POST with a fixed
  `Content-Type: application/x-www-form-urlencoded`, large binary-looking body,
  and a consistent cookie or header acting as the key identifier.

## Auditd exec monitoring

Auditd converts the process-tree heuristic into a durable log line. The idea is
to record every `execve()` initiated by the web-server UID.

```bash
# Identify the numeric UID of the web user
id -u www-data   # Debian/Ubuntu, typically 33
id -u apache     # RHEL family, typically 48
id -u nginx      # often 101 or 33 depending on distro
id -u tomcat     # often 91
```

Install rules under `/etc/audit/rules.d/50-webshell.rules`:

```text
## Execve by Debian/Ubuntu Apache/PHP-FPM
-a always,exit -F arch=b64 -S execve -F euid=33 -k webshell
-a always,exit -F arch=b32 -S execve -F euid=33 -k webshell

## Execve by RHEL httpd
-a always,exit -F arch=b64 -S execve -F euid=48 -k webshell
-a always,exit -F arch=b32 -S execve -F euid=48 -k webshell

## Execve by nginx worker (if the worker UID matches)
-a always,exit -F arch=b64 -S execve -F euid=101 -k webshell

## Execve by Tomcat
-a always,exit -F arch=b64 -S execve -F euid=91 -k webshell-tomcat
```

Load the rules:

```bash
augenrules --load
auditctl -l | grep webshell
```

Query during triage:

```bash
# Every execve tagged as webshell in the last day
ausearch -k webshell -ts recent -i | less

# Summarise executables spawned by the web user
ausearch -k webshell -i | awk -F'exe=' '/exe=/ {print $2}' \
  | awk '{print $1}' | sort | uniq -c | sort -rn

# Disk-image equivalent
ausearch -if /mnt/evidence/var/log/audit/audit.log -k webshell -i
```

Each `SYSCALL` + `EXECVE` record pair gives the `ppid`, `pid`, `auid`
(login UID, usually -1 for daemons), `uid`/`euid`, `comm`, `exe`, and the
argv. Filter out the benign set for the specific application (image/magick
invocations from image-upload features, ClamAV scans, Composer hooks) before
alerting.

Pair auditd with systemd-journald's `_SYSTEMD_UNIT=` filter to slice only
the apache2 / php-fpm / nginx / tomcat service scope:

```bash
journalctl _SYSTEMD_UNIT=apache2.service --since "24 hours ago"
journalctl _SYSTEMD_UNIT=php8.2-fpm.service _COMM=sh --since "24 hours ago"
```

## Indicator table

| Indicator                                                           | Source                                  | Why it matters                                                                 |
|---------------------------------------------------------------------|-----------------------------------------|--------------------------------------------------------------------------------|
| `sh` / `bash` / `python` / `perl` / `nc` child of `apache2`, `httpd`, `php-fpm`, `nginx`, `tomcat`, `uwsgi` | `ps`, auditd, journald   | Core webshell execution pattern — web UID is executing OS commands.            |
| Script file under `/var/www` modified within minutes of a suspicious POST | `find -mmin`, `access.log`             | Ties a filesystem drop to an HTTP-visible delivery event.                      |
| `.php`/`.jsp`/`.aspx` file owned by `www-data`/`apache`/`nginx`/`tomcat` | `find -user`, `stat`                  | Application scripts should normally be owned by deploy user, not the web user. |
| POST to a rarely-requested URI returning HTTP 200 with variable body sizes | `access.log`                           | Command-and-response rhythm of an interactive webshell.                        |
| Query string or POST body carrying base64/hex > ~200 bytes         | `access.log`, proxy logs                | Encoded command payloads destined for `eval()`/`exec()`.                       |
| `execve` of `/bin/sh -c ...` with `euid=www-data`                   | auditd key `webshell`                   | Durable, queryable evidence of shell invocation from the web tier.             |
| Tiny PHP file (under ~200 bytes) containing an eval sink            | `find -size`, `grep`                    | One-line webshell fingerprint.                                                 |
| Double-extension file (e.g., `.php.jpg`, `.phtml`) in an uploads path | `find`                                | Upload-filter bypass technique common to commodity shells.                     |
| Web user's `.bash_history` with `id`, `uname`, `curl`, `wget` commands | Filesystem                             | Interactive use of a shell spawned by the web tier.                            |
| Long-lived `nc`/`bash -i` child of a web-tier process              | `ps`, `ss -tpn`                         | Webshell has been upgraded to a reverse shell.                                 |
| JSP or WAR file dropped into `webapps/` outside a release window    | `find`, deploy tracking                 | Tomcat webshell installation.                                                  |
| HTTP 200 responses to requests for files that do not exist in the legitimate app manifest | `access.log` + source of truth | Planted file served successfully.                                               |

## Confidence and pitfalls

High confidence comes from stacking indicators: a recent unknown PHP file,
owned by `www-data`, POSTed to from a bare-library user-agent, correlated one
second later with an auditd `execve` of `/bin/sh -c id` under `euid=33`. Any
one of those alone is softer.

Legitimate behaviours that produce false positives:

- **CGI-based applications**: some legacy apps (mail front-ends, print
  portals, ticketing tools) really do invoke `/bin/sh` from the web tier.
  Learn the baseline of expected commands per host before alerting.
- **Image processing pipelines**: WordPress, Drupal, Nextcloud, and Matomo
  shell out to `convert`, `gs`, `ffmpeg`, `exiftool`, and `unoconv`. These are
  noisy auditd hits but have stable argv shapes.
- **Package-manager and composer hooks**: deployments can briefly fork `sh`
  from the web user if a cache-warming step is run through an HTTP endpoint.
  Tie events to a change-management window.
- **Monitoring and APM agents**: New Relic, Datadog, and Elastic agents may
  execute helper binaries under the web UID; whitelist by full path, not just
  `comm`.
- **Backup and sync cron jobs**: jobs that run as `www-data` to read the web
  root can produce `find`, `tar`, `rsync` exec events. These are cron children,
  not HTTP children — auditd's `ppid` chain will show `cron` rather than
  `apache2`/`php-fpm`, so differentiate on parent.
- **Developer shells on staging**: ops staff sometimes `sudo -u www-data bash`
  to troubleshoot. `auid` will be the operator's login UID, not `-1`, which
  distinguishes interactive admin activity from webshell invocation.
- **WAF-injected test traffic**: scanners such as internal DAST tools hit
  `/shell.php`, `/cmd.php`, and similar probe URIs. Confirm that 200 responses
  actually correspond to real files on disk before escalating.

When in doubt, pivot from the suspected webshell file to: its inode's creation
time, the exact access-log line that delivered it (often a POST to an
`upload.php`-style endpoint minutes earlier), and the auditd trail of what was
executed afterwards. Those three tied together are the durable story.
