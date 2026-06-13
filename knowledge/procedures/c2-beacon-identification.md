---
id: kb-proc-c2-beacon-id-001
title: "C2 beacon identification — from anomaly to attribution"
source_type: author-original
attribution: "APTWatcher team (clean-room)"
mitre_techniques:
  - T1071
  - T1071.001
  - T1071.004
  - T1573
  - T1572
  - T1568
  - T1090
artifact_types:
  - network_capture
  - memory_image
  - dns_logs
  - proxy_logs
  - evtx
tools:
  - volatility3
  - bulk_extractor
  - yara
  - plaso
last_updated: "2026-04-19"
---

## Purpose

This procedure walks an incident responder from a raw timing or
protocol anomaly to a defensible statement that a given flow is a
command-and-control (C2) beacon, then on to campaign-level
attribution when the evidence supports it. It is the playbook
APTWatcher follows when a network anomaly first surfaces.

## Prerequisites

- A pcap, NetFlow/IPFIX export, or Zeek `conn.log`/`dns.log`/`ssl.log`
  bundle covering the window of interest.
- Optional but strong: a memory image of the suspected victim host
  taken close in time to the observed network activity.
- Proxy logs (Squid/Bluecoat/Zscaler/Defender for Cloud Apps) and
  Windows `Security.evtx` + `Sysmon.evtx` from the same host if the
  environment forwards them.
- A working `volatility3`, `tshark`, `zeek`, `yara`, `suricata`, and
  `plaso` install. `bulk_extractor` is optional for carving URLs
  and network artefacts from raw images.
- Baseline knowledge of the environment: known telemetry endpoints,
  EDR heartbeat cadence, NTP peers, update-service hostnames. This
  is what keeps false-positive rate tolerable.

## 1. Beacon detection fundamentals

A C2 beacon is a periodic, low-volume check-in from an implant to
operator infrastructure. Good beacons hide inside noise by choosing
a common protocol, a plausible destination, and a plausible-looking
cadence. The detectable residue falls into five buckets.

### Periodicity and jitter

Beacons repeat. Human browsing does not repeat on a fixed clock.
Compute the inter-arrival time between connections sharing the
tuple `(src_ip, dst_ip, dst_port)` and look at the coefficient of
variation (CV = stddev / mean). Implants with 10% jitter have a CV
near 0.1; implants with 50% jitter land near 0.5. Anything under
~0.5 over twenty or more connections is suspicious; under 0.2 is
almost certainly automated.

### Payload size bands

Implant heartbeats cluster into narrow size bands because the
tasking protocol emits fixed-structure messages. Legitimate HTTP
traffic shows wide distributions (full pages, images, XHR bursts).
Histogram `orig_bytes` and `resp_bytes` per destination; a pair of
sharp spikes ("always ~180 bytes out, ~220 bytes in") is a strong
hint.

### TLS JA3 / JA3S fingerprints

JA3 hashes the ordered list of TLS ClientHello parameters; JA3S
hashes the ServerHello. Implants built on a custom TLS stack or an
older library often present a JA3 that no browser or legitimate
application in the environment produces. Flag:

- A JA3 seen from more than one unrelated internal host to the same
  external destination.
- A JA3 that a process-aware source (Sysmon event ID 3, EDR
  telemetry) ties to a non-browser binary.
- A JA3S from the server that is rare globally (check against
  public JA3S feeds and your own baseline).

### HTTP(S) header anomalies

Even over HTTPS, proxy logs and TLS-inspected flows give you
`User-Agent`, `Host`, path, and method. Implant HTTP libraries
frequently emit:

- Static, slightly-off `User-Agent` strings ("Mozilla/4.0" with
  obsolete .NET CLR tokens, or a current Chrome UA paired with
  TLS 1.0).
- A single `Host` reused across many otherwise-unrelated URIs.
- GET requests with large cookies and no `Referer`.
- POST bodies whose `Content-Length` is identical across calls.

### DNS tunneling and covert channels

DNS tunnelling abuses the fact that recursive resolvers happily
forward queries to any authoritative server. Operators encode
tasking into subdomain labels and responses into `TXT`, `CNAME`,
`NULL`, or chained `A`-record answers. Variants:

- ICMP tunnelling — echo request/reply payloads carry data. Look
  for long, high-entropy payloads in `icmp.data`.
- DNS-over-HTTPS (DoH) — the lookup itself is encrypted to a public
  resolver (Cloudflare 1.1.1.1, Google 8.8.8.8, Quad9). The local
  DNS server sees no query; the HTTPS flow to the resolver is the
  only evidence. Unusual DoH endpoints (not the organisation's
  sanctioned resolvers) are the main tell.
- Fast-flux and domain generation — see T1568 notes below.

## 2. Triage approach

Work outside-in: cheap statistical filters first, expensive content
inspection second.

### Timing analysis on flows or pcaps

On Zeek output, bucket `conn.log` by `(id.orig_h, id.resp_h,
id.resp_p)` and compute `count`, `mean_interval`, `stddev_interval`,
`jitter_ratio`. Keep tuples with `count >= 20` and `jitter_ratio
<= 0.5`.

From a raw pcap, the quickest periodicity probe:

```bash
tshark -r capture.pcap -Y "ip.src == 10.0.0.42 && ip.dst == 203.0.113.7" \
  -T fields -e frame.time_epoch -e frame.len > flows.tsv
```

Then feed `flows.tsv` into a short script that computes mean,
standard deviation, and a fast Fourier transform of the event
series. A strong peak away from DC in the FFT is a signature of a
periodic process.

Identify the activity window. Many implants only beacon during
business hours (to blend in) or only overnight (to avoid the user).
A window that matches the victim's working hours slightly better
than random is worth noting.

### Entropy and size clustering

Build two histograms per destination: bytes-out and bytes-in.
Uniform, multi-modal distributions with two or three sharp modes
and no tail are the fingerprint of a fixed-protocol beacon. Compute
Shannon entropy on the first 64 bytes of each TLS application-data
record (where visible) or on HTTP bodies; payloads with entropy
very close to 8 bits/byte over many connections hint at an
encrypted custom channel rather than a real application.

### TLS fingerprint extraction

Zeek's `ssl.log` carries `ja3`, `ja3s`, `server_name`, and
`subject`. Extract with:

```bash
zeek-cut -d ts uid id.orig_h id.resp_h server_name ja3 ja3s \
  subject issuer < ssl.log | sort -u
```

Look for:

- Issuers that are "Let's Encrypt" paired with a certificate whose
  validity window is under 14 days and whose SAN is a recently
  registered domain.
- SNI values that do not match any `dns.log` query from the same
  client in the preceding minute (possible domain fronting or
  direct-to-IP connections with forged SNI).
- Self-signed certs on port 443 to a residential or VPS ASN.

### DNS beaconing signatures

In `dns.log`:

- Leftmost labels pushed toward 63 octets or FQDNs near 253 octets.
- Shannon entropy over ~3.8 bits/char on the leftmost label.
- Sustained high QPS from one client to one second-level domain.
- Elevated `NXDOMAIN` ratio — DGA beacons (T1568.002) burn through
  pseudo-random names until they hit a live one.
- Rapid-cycle `A`/`NS` answers with very low TTLs (fast-flux,
  T1568.001).
- Rare qtypes in your environment (`TXT`, `NULL`) where the
  baseline is overwhelmingly `A`/`AAAA`.

```bash
zeek-cut -d ts uid id.orig_h query qtype_name rcode_name < dns.log \
  | awk -F'\t' '$5=="NXDOMAIN"{print $3"\t"$4}' | sort | uniq -c \
  | sort -rn | head
```

## 3. Memory-side confirmation

Once a suspect flow is identified, pivot to the host's memory image
to tie the network behaviour to a process.

```bash
vol -f victim.mem windows.netscan.NetScan
vol -f victim.mem windows.netstat.NetStat
vol -f victim.mem windows.pslist.PsList
vol -f victim.mem windows.malfind.Malfind
```

Steps:

1. Run `windows.netscan.NetScan` and filter for the suspect
   destination IP/port. Record PID, process name, and local port.
2. Cross-reference the PID against `windows.pslist.PsList` and
   `windows.pstree.PsTree`. A legitimate image name with an
   anomalous parent (`winword.exe -> rundll32.exe -> ...`) is a
   red flag.
3. Run `windows.malfind.Malfind` against that PID. RWX private
   regions near the network syscall surface, or regions with `4D
   5A` magic bytes in a process that should not be JIT-compiling,
   raise confidence sharply.
4. Run `yara` against the memory image with rules for known C2
   loaders (Cobalt Strike beacon, Sliver, Havoc, Brute Ratel,
   Metasploit Meterpreter — public rules exist for all of these).
   A YARA hit inside the same PID that owns the suspect socket is
   near-conclusive.
5. `bulk_extractor` can carve URLs and domain strings from raw
   memory if volatility3 plugins miss them:

```bash
bulk_extractor -o be_out -E net -E url victim.mem
```

## 4. MITRE ATT&CK mapping

- **T1071 Application Layer Protocol** — umbrella for C2 over
  common application protocols.
- **T1071.001 Web Protocols** — HTTP(S)-based C2.
- **T1071.004 DNS** — DNS-based C2.
- **T1573 Encrypted Channel** — custom or standard crypto over the
  transport (JA3/JA3S fingerprinting, certificate oddities).
- **T1572 Protocol Tunneling** — tunneling one protocol inside
  another (ICMP tunnel, DNS tunnel, SSH tunnel).
- **T1568 Dynamic Resolution** — DGAs, fast-flux, DNS calculation.
  Sub-techniques `.001` fast flux, `.002` DGA, `.003` DNS
  calculation.
- **T1090 Proxy** — internal/external/multi-hop proxies masking
  true destination. Relevant when the first-hop destination is a
  compromised residential host or a VPS relay.

Record the most specific technique that fits. Do not tag `T1071`
when `T1071.004` applies.

## 5. From detection to attribution

"Beacon" and "APT Watch campaign hit" are two different claims.

A finding is labelled **beacon-consistent** when timing,
size-banding, and a protocol fingerprint all agree but no external
corroboration exists. Confidence ceiling: ~0.5.

Tier up to **named campaign** only when at least one of:

- A destination IOC (IP, domain, JA3, certificate SHA-256) matches
  a reputable public or private threat feed indexed in
  APTWatcher's `check_ioc` tier.
- A memory-side YARA hit corresponds to a family already associated
  with the campaign.
- Multiple hosts in the same incident exhibit the same JA3 and
  beacon-pair statistics pointing at the same upstream.
- TTPs on the host — parent-child, persistence mechanism, lateral
  movement tool — match the campaign's documented tradecraft.

Handoff into the analysis pipeline:

1. Emit the beacon-consistent finding with full citations (Zeek
   `uid`s, pcap byte ranges, volatility3 `correlation_id`).
2. Call `check_ioc` on each candidate indicator (dst IP, domain,
   SLD, JA3, JA3S, certificate hash).
3. If a hit comes back, call the APT Watch campaign correlation
   step with the enriched IOC set. The correlator returns a
   campaign ID + confidence, which the finding then cites.
4. Never overwrite the network-only confidence with the campaign
   confidence; store both.

## 6. Pitfalls — chasing noise

The largest contributors to false positives:

- **CDN heartbeats and health checks.** Cloudflare, Akamai, Fastly,
  AWS load balancers all emit highly periodic low-byte flows.
- **Legitimate telemetry.** Windows Update, Defender cloud lookups,
  Office telemetry, Chrome Safe Browsing, mobile MDM check-ins.
- **NTP and time sync.** Port 123 UDP, near-perfect periodicity.
  Whitelist by destination, not by timing.
- **EDR and backup agents.** CrowdStrike Falcon, SentinelOne,
  Defender for Endpoint, Carbon Black, Veeam — all beacon.
- **Anti-malware cloud lookups** produce high-entropy DNS labels
  (hash-as-subdomain) by design.
- **Fast-flux confusion.** Major CDNs and streaming services rotate
  `A` records with short TTLs for load balancing; the network
  shape overlaps with malicious fast-flux. Use ASN and registrar
  age to disambiguate — a week-old domain on a bulletproof-hosting
  ASN is not Netflix.

Maintain an allow-list of known-benign destinations and JA3s per
environment. A finding that matches the allow-list is downgraded
to informational and kept for audit, not discarded silently.

## 7. Common operator mistakes

- **Blocking the C2 before extracting all IOCs.** Once the
  destination is sinkholed or firewalled, you lose the chance to
  observe further tasking, additional stagers, or backup channels.
  Collect first, block second, in coordination with IR leadership.
- **Trusting a single domain or IP lookup.** Reputation services
  disagree and go stale. Require at least two independent sources
  before tagging an indicator as malicious with high confidence.
- **Collapsing the timeline.** Beacons exist over hours or days;
  pulling only a 10-minute pcap around the EDR alert will miss the
  cadence. Pull wider windows from flow storage.
- **Ignoring the reverse direction.** Size-banding on bytes-in is
  as informative as bytes-out and often cleaner because operator
  tasking messages are more uniform than implant check-ins.
- **Assuming HTTPS means blind.** Proxy logs and JA3/JA3S still
  fingerprint the client and server stack without decrypting the
  payload.
- **Treating "no YARA hit" as "not malicious."** Novel loaders
  produce no public YARA hits on day one.

## 8. Handoff artifacts

The IOC set this procedure produces feeds three downstream
pipelines:

- **YARA** — for in-memory shellcode and file-on-disk detection.
  Write or select rules targeting strings, loader constants, and
  decryption routines observed in the memory dump. Test with
  `yara -s rules.yar victim.mem` before committing.
- **Suricata** — network signatures for the observed JA3, JA3S,
  TLS SNI, HTTP header pattern, or DNS label shape. Validate:

```bash
suricata -T -c suricata.yaml -S rules/c2-beacon.rules
```

- **STIX 2.1 bundle** — for sharing with community feeds (MISP,
  OpenCTI, ISAC peers). Bundle `indicator`, `malware`,
  `attack-pattern` (one per MITRE technique recorded), and
  `relationship` objects. Sign and timestamp before export.

Every artifact carries back-references to the originating
evidence: pcap filename + frame numbers, Zeek `uid`s, memory image
hash, volatility3 `correlation_id`. Without those back-references
the finding is not reproducible and APTWatcher will not promote it
above informational.

## Expected artifacts

- A timing cluster report: tuple, count, mean interval, jitter
  ratio, activity window.
- A size-band histogram per destination.
- A list of JA3/JA3S hashes with client counts and destinations.
- A DNS-anomaly report: querier, SLD, QPS, NXDOMAIN ratio, mean
  label length, mean entropy, qtype distribution.
- A volatility3 process-to-socket mapping for the suspect host.
- Any YARA matches tied to the PID owning the suspect socket.
- A STIX bundle with `indicator` objects for every extracted IOC.

## Common pitfalls / hallucination traps

- Do not assert "Cobalt Strike beacon" from timing alone. Timing is
  protocol-family evidence, not family evidence.
- Do not attribute to an APT group from a single IP match. Groups
  reuse infrastructure sparingly; infrastructure reuse is one
  signal among many.
- Do not treat DNS-over-HTTPS traffic to a sanctioned resolver as
  automatically safe — the client could still be tunneling inside
  it. Look at volume and periodicity to the resolver, not just the
  resolver's identity.
- Do not conflate "encrypted" with "malicious." Most enterprise
  traffic is encrypted; the discriminator is shape, not secrecy.

## References

- MITRE ATT&CK T1071, T1573, T1572, T1568, T1090 (attack.mitre.org).
- Zeek logs reference (docs.zeek.org).
- Volatility3 plugin reference (volatility3.readthedocs.io).
- Suricata rule-writing guide (suricata.readthedocs.io).
- STIX 2.1 specification (oasis-open.org).
