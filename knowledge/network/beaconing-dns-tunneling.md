---
id: kb-net-c2-beacon-dns-001
title: "C2 beaconing and DNS tunneling — network-side indicators"
source_type: author-original
attribution: "APTWatcher team (clean-room)"
mitre_techniques:
  - T1071.004
  - T1572
  - T1090
  - T1573
artifact_types:
  - network_traffic
  - dns_logs
tools:
  - zeek
  - tshark
  - suricata
  - rita
last_updated: "2026-04-19"
---

## What C2 beaconing and DNS tunneling are

Beaconing is the periodic check-in behaviour of an implant: the
compromised host opens a short connection to the operator's
infrastructure at a (roughly) fixed cadence, asks whether there is any
tasking, and closes. Most modern agents add jitter — a random offset
around the base interval — so the cadence is not *exactly* constant,
but the distribution is still narrow compared to legitimate human
browsing.

DNS tunneling is a transport trick: because DNS is almost always
allowed outbound and rarely inspected, a payload can be encoded into
the labels of DNS queries and the answers in `A`, `AAAA`, `TXT`,
`CNAME`, or `NULL` records. The compromised host makes queries under
an attacker-controlled second-level domain (SLD); the authoritative
server for that SLD decodes them and answers with more data. Both
command-and-control and slow exfiltration are feasible this way.

## How to detect it

### Beaconing signals (zeek `conn.log`)

- Repeated `(id.orig_h, id.resp_h, id.resp_p)` tuples where the
  inter-arrival time has a **low coefficient of variation** (std / mean
  typically under ~0.3 after jitter).
- Small, symmetric payloads: `orig_bytes` and `resp_bytes` both in the
  low-kilobyte range, connection `duration` under a few seconds.
- Long-lived observation window: the same tuple repeats over hours or
  days, not just minutes.
- Tools: `rita beacon`, custom Zeek scripts, or a `tshark`-driven
  periodogram on packet timestamps.

### DNS tunneling signals (zeek `dns.log`)

- Query label length pushed toward the 63-octet per-label / 253-octet
  FQDN limits.
- High Shannon entropy in the leftmost labels (encoded / base-N data
  looks random compared to normal English-ish subdomains).
- Sustained high queries-per-second from a single client to a single
  SLD.
- Elevated `NXDOMAIN` ratio from one client (tunnels frequently
  generate misses by design).
- Unusual `qtype` mix: `TXT` or `NULL` where `A`/`AAAA` dominate in the
  rest of the network.

### TLS / JA3 signals (zeek `ssl.log` / `x509.log`)

- The same JA3 client fingerprint seen from multiple unrelated victim
  hosts, or a JA3 that does not match the process that "should" be
  running (e.g., a browser JA3 appearing from a non-browser PID upstream).
- Self-signed certificates, certs valid only for a few days, or an
  SNI that does not match the certificate `CN`/`SAN`.

### Signal → log → field reference

| Signal                          | Zeek log        | Field(s)                                  | Rule of thumb                          |
|---------------------------------|-----------------|-------------------------------------------|----------------------------------------|
| Periodic callback               | `conn.log`      | `ts`, `id.*`, `duration`                  | CV(inter-arrival) < 0.3, N > 20        |
| Tiny heartbeat payload          | `conn.log`      | `orig_bytes`, `resp_bytes`                | both < ~2 KB over many sessions        |
| Long DNS label                  | `dns.log`       | `query`                                   | leftmost label > 40 chars              |
| High entropy query              | `dns.log`       | `query`                                   | Shannon entropy > ~3.8 bits/char       |
| NXDOMAIN burst, one client      | `dns.log`       | `rcode_name`, `id.orig_h`, `query`        | NXDOMAIN > ~40% of queries to one SLD  |
| Rare qtype for environment      | `dns.log`       | `qtype_name`                              | `TXT`/`NULL` anomaly vs baseline       |
| Reused JA3 across victims       | `ssl.log`       | `ja3`                                     | same hash, >=3 distinct clients        |
| SNI / CN mismatch               | `ssl.log`+`x509`| `server_name`, `subject`                  | mismatch + short validity window       |

## What APTWatcher records

A beaconing or DNS-tunnel finding cites:

1. The Zeek `uid` of each sampled connection in the cluster
   (source=`zeek:conn.log`, locator=`uid=<id>`), with the `(id.orig_h,
   id.resp_h, id.resp_p)` tuple.
2. Inter-arrival statistics for the cluster: `count`, `mean_interval`,
   `stddev_interval`, `jitter_ratio = stddev/mean`.
3. For DNS findings: the tuple `(querier, sld, query_count,
   nxdomain_ratio, mean_label_len, mean_entropy)`
   (source=`zeek:dns.log`).
4. Any JA3 hash shared across the cluster, with the count of distinct
   `id.orig_h` that presented it (source=`zeek:ssl.log`).
5. Cross-references to host-side findings on the same `id.orig_h`
   (unusual parent-child, new persistence, unsigned binary) when
   available — these drive the tiering decision below.

## Confidence calibration and pitfalls

Periodicity is not malice. Legitimate beacon-shaped traffic is
everywhere:

- NTP, Windows time sync, Kerberos re-auth.
- OS and application telemetry (Windows diagnostic data, crash
  reporters, update checkers).
- Endpoint agent heartbeats — EDR, MDM, backup, monitoring.
- CDN and load-balancer health checks, captive-portal probes.
- Chat and collaboration keep-alives (WebSocket pings).

For DNS, known-odd-but-benign patterns include anti-malware cloud
lookups (hash queries that look like high-entropy labels by design),
telemetry SDKs embedded in mobile apps, and some CDN resolver chains
that generate transient `NXDOMAIN` as part of normal negotiation.

APTWatcher's rule:

- A clean periodicity cluster with no host-side corroboration and no
  threat-intel hit on the destination is labelled **consistent with**
  C2 at `confidence <= 0.4`. It is a lead, not a verdict.
- Tier up to `confidence >= 0.7` only when **either** (a) the
  destination (IP, domain, SLD, or JA3) has independent threat-intel
  corroboration, **or** (b) the same `id.orig_h` also shows host-side
  TTPs — anomalous parent-child, new autostart entry, unsigned binary
  in a user-writable path, credential access.
- Always cross-reference the organisation's allow-list of known
  telemetry and EDR endpoints before emitting a finding. A matched
  allow-list entry downgrades the finding to informational and records
  the match for auditability.
