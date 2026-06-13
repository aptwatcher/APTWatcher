---
id: kb-net-c2-http-001
title: "HTTP/HTTPS C2 patterns"
source_type: author-original
attribution: "APTWatcher team (clean-room)"
mitre_techniques:
  - T1071.001
  - T1573.002
  - T1090.004
  - T1568.002
artifact_types:
  - pcap
  - zeek_logs
  - suricata_eve
tools:
  - zeek
  - suricata
  - tshark
last_updated: "2026-04-19"
---

# HTTP/HTTPS C2 patterns

HTTP and HTTPS remain the dominant transports for command-and-control because
they blend with legitimate web traffic, traverse most egress filters, and are
well supported by commodity and bespoke implants alike. Detection from network
artifacts requires combining timing analysis, header inspection, TLS
fingerprinting, and destination reputation because no single signal is
sufficient on its own.

## What HTTP C2 looks like

A typical HTTP(S) C2 channel exhibits some combination of the following
behaviors, most of which are observable from passive network telemetry:

- Periodic check-ins (beacons) from the implant to the controller, often with
  a small fixed-size request and a small (or empty) response when no tasking
  is queued.
- Occasional larger transfers when tasking or results move in either
  direction. These "jobs" break the otherwise regular beacon cadence.
- Requests that carry identifiers (session id, campaign id, victim id) in
  cookies, URI paths, query parameters, or custom headers.
- Use of a single destination host, or a small rotating pool, rather than the
  diffuse destination set typical of a user browsing the web.
- For HTTPS, a TLS client fingerprint that is consistent across sessions and
  does not match any browser installed on the host.

The detection goal is not to identify a specific implant family from the
wire, but to flag the flow as anomalous enough to warrant triage against
host telemetry.

## Zeek field-level hunts

Zeek produces the richest per-request metadata. The three most valuable logs
for HTTP C2 hunting are `conn.log`, `http.log`, and `ssl.log`.

A baseline `http.log` review query:

```bash
zeek-cut -d ts id.orig_h id.resp_h method host uri user_agent \
                status_code request_body_len response_body_len \
  < http.log \
  | sort -k1
```

What to look for in each field:

| Field | Hunt value |
|-------|------------|
| `ts` | Inter-arrival times per `(id.orig_h, id.resp_h, host)` tuple; a tight distribution indicates beaconing |
| `id.orig_h` | Repeat offenders hitting the same destination; correlate with host inventory |
| `id.resp_h` | Cross-reference with passive DNS and threat intel; flag rare destinations |
| `method` | High ratio of POST to GET on a single host is unusual for end-user browsing |
| `host` | Mismatch between Host header and SNI or resolved DNS name suggests fronting |
| `uri` | High-entropy paths, hard-coded GUIDs, long base64-ish tokens |
| `user_agent` | Empty, hard-coded, or mismatched with the host OS profile |
| `status_code` | Long runs of 200 with near-identical `response_body_len` |
| `response_body_len` | Small fixed sizes followed by an occasional burst |

For TLS, pivot into `ssl.log`:

```bash
zeek-cut -d ts id.orig_h id.resp_h server_name ja3 ja3s \
                version cipher established \
  < ssl.log
```

Key joins:

- `server_name` (SNI) vs the resolved DNS name seen in `dns.log` for the same
  `id.resp_h` a few seconds earlier. A large divergence suggests domain
  fronting or direct-to-IP connections with a forged SNI.
- `ja3` grouped by `id.orig_h`: a host that presents a JA3 seen nowhere else
  in the environment is interesting even without a known-bad list.
- `ja3s` grouped by `id.resp_h`: server-side fingerprints can cluster
  attacker infrastructure that rotates domains but reuses the same TLS
  library and configuration.

For `conn.log`, the relevant fields for beacon analysis are `ts`, `duration`,
`orig_bytes`, `resp_bytes`, `orig_pkts`, `resp_pkts`, and `conn_state`.

## Beaconing detection

Beaconing is a timing problem. The canonical approach:

1. Group flows by `(id.orig_h, id.resp_h)` or `(id.orig_h, host)` if
   pivoting through `http.log`.
2. Compute inter-arrival times between consecutive connections in the group.
3. Look for a tight central tendency (low standard deviation relative to the
   mean) and a low coefficient of variation.
4. Apply a minimum sample count (e.g. 10+ connections over the window) to
   avoid noise.

Jitter is the standard obfuscator. Operators configure the implant to pick a
random offset (commonly expressed as a percentage of the sleep time) on each
callback. The inter-arrival distribution becomes roughly uniform over
`[sleep * (1 - jitter), sleep * (1 + jitter)]` rather than a delta
function. Detection strategies that handle jitter:

- Fit a uniform distribution to the inter-arrival series and test goodness
  of fit; uniform fits indicate scheduled-with-jitter traffic.
- Compute a Fourier transform of the connection timestamps; scheduled
  traffic shows spectral peaks even when jittered, whereas genuine user
  browsing produces a noisy spectrum.
- Bucket inter-arrivals into histograms and look for a single dominant bin
  (or contiguous range of bins for jittered beacons) that contains the bulk
  of the mass.

A `conn.log` aggregation starter:

```bash
zeek-cut -d ts id.orig_h id.resp_h duration orig_bytes resp_bytes \
  < conn.log \
  | awk '{ key=$2" "$3; print $1, key, $4, $5, $6 }' \
  | sort -k2,2 -k1,1n
```

Feed the resulting per-pair series into a timing analyzer (rita, aimod, or a
small pandas script) that scores each pair on regularity, low byte volume,
and long observation window.

## User-Agent / URI / Host anomalies

| Anomaly | What to look for | Why it matters |
|---------|------------------|----------------|
| Empty User-Agent | `user_agent` field missing or blank in `http.log` | Most browsers and legitimate clients set a UA; empty UAs are overwhelmingly automation or implants |
| Hard-coded UA strings | Repeated identical UA across hosts that do not share a browser install profile | Many implants ship with a default UA that stays constant |
| UA vs OS mismatch | Windows host presenting a `curl/` or Linux UA | Suggests a scripted client rather than the user's browser |
| Outdated UA | UA advertising a Chrome/Firefox version several years old | Common in templated C2 profiles that were not updated |
| High-entropy URI paths | Long random-looking tokens, base32/base64 segments, hex blobs | Implant encoding session data or commands in the path |
| Hard-coded GUIDs in URI | Same GUID across many hosts, or a GUID where a session id would be expected | Default profile artifact |
| Content-Type mismatch | `POST` with `Content-Type: text/html` or `image/jpeg` | Real browsers POST `application/x-www-form-urlencoded`, `multipart/form-data`, or JSON |
| Host header != SNI | HTTPS Host header differs from SNI for the same flow | Classic domain-fronting residue |
| Host header != DNS | Host header resolves to an IP the client never queried | Direct-to-IP connection with a forged Host header |
| Very short or very long URIs | Single-character paths or URIs over several kilobytes | Outside the normal distribution for web browsing |
| Missing Referer chain | Deep-path POSTs with no preceding GET | No navigation sequence; not user-driven |

## TLS fingerprinting (JA3 / JA4)

JA3 hashes the client's TLS ClientHello fields (version, ciphers,
extensions, elliptic curves, EC point formats). JA3S hashes the server's
ServerHello. JA4 is a newer family that encodes the same idea with improved
stability across minor client changes and adds variants for HTTP (JA4H) and
TCP (JA4T). For defensive use, the hash value itself matters less than
whether it clusters.

Categorical fingerprint families commonly encountered in red-team and
commodity tooling (described generically; verify current hashes against
curated feeds rather than memorizing values):

| Category | Characteristic | Notes |
|----------|----------------|-------|
| Default Windows .NET TLS stack | Used by many C# implants that rely on `HttpClient` or `WebRequest` | Fingerprint tends to be consistent across .NET versions and rare on user endpoints outside of enterprise apps |
| Default Go `crypto/tls` stack | Used by many Go-based implants and tooling | Distinct and stable; cross-check against known Go-based legitimate software before flagging |
| Default Python `requests` / `urllib` stack | Used by scripted tooling and some implants | Common in both malicious and legitimate automation; requires context |
| Curl / libcurl | Used by shell-based droppers and some living-off-the-land flows | Fingerprint differs from browser stacks and varies with curl version |
| JVM default stack | Used by Java-based agents and some scanners | Rare on typical user endpoints |
| Custom OpenSSL builds | Used by bespoke implants that link OpenSSL directly | Often unique per campaign; pivot on rarity rather than match |
| Mimicked browser profiles | Tools that deliberately copy Chrome/Firefox fingerprints to blend in | Detection shifts to JA3S, timing, and content anomalies |

Operational guidance:

- Build a baseline of JA3/JA4 values seen in your environment and their
  prevalence per host and per destination.
- Alert on first-seen JA3 for a given host, especially when paired with a
  first-seen destination or a low-reputation domain.
- Do not block solely on JA3; the same hash can appear in both a common
  library and an implant that uses that library.

## Suricata rule categories

Suricata's Emerging Threats ruleset and equivalents carry several rule
families that fire on HTTP C2 patterns. Understanding the family helps
triage the alert:

| Rule prefix | Typical content | Triage implication |
|-------------|-----------------|--------------------|
| `ET TROJAN` | Known implant URIs, User-Agents, or header patterns | High-confidence lead; correlate with host telemetry immediately |
| `ET MALWARE` | Known malware C2 signatures | Similar to TROJAN; often overlaps |
| `ET POLICY` | Policy-violating but not inherently malicious (e.g. remote access tools, tunnelling utilities) | Medium confidence; context matters — a sanctioned admin tool can trigger these |
| `ET INFO` | Informational matches (e.g. curl from a user network) | Low on its own; valuable in combination |
| `ET HUNTING` | Experimental or hunting-focused rules | Expect false positives; feed into enrichment rather than paging |
| `ET CURRENT_EVENTS` | Time-limited rules tied to active campaigns | Usually high relevance while active, expire quickly |

Eve JSON fields to extract when triaging a hit:

- `alert.signature`, `alert.signature_id`, `alert.category`
- `http.hostname`, `http.url`, `http.http_user_agent`,
  `http.http_method`, `http.status`, `http.length`
- `tls.sni`, `tls.ja3.hash`, `tls.ja3s.hash`, `tls.subject`,
  `tls.issuerdn`, `tls.fingerprint`
- `flow.bytes_toserver`, `flow.bytes_toclient`, `flow.pkts_toserver`,
  `flow.pkts_toclient`, `flow.start`, `flow.end`

A practical pivot is to join Suricata alerts to Zeek `conn.log` by
five-tuple and timestamp to get the full flow context, then to `http.log`
and `ssl.log` for header and TLS detail.

## Indicator table

| Indicator | Artifact | Confidence | Notes |
|-----------|----------|------------|-------|
| Fixed-period beacon (low CV of inter-arrivals, 10+ samples) | `conn.log`, `http.log` | Medium-high | Strong signal when combined with small fixed response sizes |
| Jittered beacon (uniform-distributed inter-arrivals) | `conn.log` | Medium | Requires spectral or distribution-fit analysis |
| Empty or hard-coded User-Agent | `http.log` | Medium | Many legitimate agents also lack a browser UA |
| UA vs host OS mismatch | `http.log` + asset inventory | Medium-high | Requires reliable host OS data |
| High-entropy URI tokens | `http.log` | Medium | Cross-check with Content-Type and method |
| POST-heavy ratio to a single host | `http.log` | Medium | Useful per-destination, noisy globally |
| Content-Type mismatch with method/body | `http.log` | High | Strong indicator of structured-data exfil over HTTP |
| Host header vs SNI mismatch | `http.log` + `ssl.log` | High | Classic fronting or forged-Host pattern |
| SNI vs DNS mismatch | `ssl.log` + `dns.log` | High | Suggests direct-to-IP with forged SNI or fronting |
| Rare JA3/JA4 for the environment | `ssl.log` | Medium | Best combined with destination rarity |
| Newly-registered or recently-changed domain | DNS + WHOIS enrichment | Medium-high | Common for staged campaigns |
| Self-signed or recently-issued certificate on direct-IP flow | `ssl.log`, `x509.log` | Medium | Low-cost infrastructure marker |
| Repeated 200s with near-identical small body size | `http.log` | Medium | Beacon with no tasking queued |
| Long-lived flows with low byte volume and periodic keepalives | `conn.log` | Medium | Tunnel or WebSocket C2 |

## Confidence and pitfalls

Every indicator above has legitimate-traffic look-alikes. False-positive
sources to account for before escalating:

- **Cloud provider telemetry and device management.** Endpoint protection,
  MDM agents, and cloud management clients beacon at fixed intervals with
  small bodies, use hard-coded User-Agents, and talk to a small set of
  destinations. Maintain an allowlist of sanctioned agents per asset class.
- **OS and software update checks.** Windows Update, package managers,
  browser auto-update, and application update pings look very beacon-like.
  They typically hit well-known vendor domains on a schedule measured in
  minutes to hours.
- **Analytics and telemetry beacons.** Pixel trackers, RUM agents, and
  product analytics SDKs generate high volumes of small POSTs with JSON
  payloads. They are especially common from browsers and mobile apps.
- **SaaS platforms behind shared infrastructure.** CDNs and large SaaS
  providers host many tenants behind the same IPs and certificates. A rare
  destination by IP may be a common destination by hostname.
- **Legitimate automation.** CI runners, monitoring agents, backup clients,
  and research scanners inside the environment can look like implants on
  the wire.
- **Corporate proxies and TLS interception.** A proxy may rewrite JA3, UA,
  and Host headers, flattening fingerprints across the fleet and hiding
  per-host anomalies. Know where the inspection points are before
  interpreting fingerprints.

Raise confidence by stacking independent signals: a rare JA3 from a host
that has never spoken to the destination before, which also beacons with
low jitter and carries a hard-coded UA, is a very different finding from
any one of those signals on its own. Always correlate network findings
with endpoint telemetry before declaring a compromise; the network view
alone rarely distinguishes a novel legitimate tool from a novel implant.
