---
id: kb-net-beacon-jitter-dns-tunneling-001
title: "Network beaconing and DNS tunneling triage"
source_type: author-original
attribution: "APTWatcher team (clean-room)"
mitre_techniques:
  - T1071.004
  - T1572
artifact_types:
  - pcap
  - zeek_logs
  - dns_query_logs
tools:
  - zeek
  - rita
  - tshark
  - python
last_updated: "2026-04-20"
---

## Beacon detection in Zeek conn.log

An implant beacon is a repeating connection from a single internal
host to a single external endpoint at a cadence the operator
controls. Triage works on `conn.log`: group by
`(id.orig_h, id.resp_h, id.resp_p)` over a window of hours to days,
compute the inter-arrival times between successive connections in
each group, and look at the distribution.

The two statistics that carry the signal are the mean inter-arrival
(the base cadence the operator configured) and the jitter — the
standard deviation, or equivalently the coefficient of variation
`stddev / mean`. Most implants add jitter to evade naive periodicity
scans, but the jitter percentage is bounded (typical defaults in the
20 to 50 percent range around the base interval). A group with a
coefficient of variation under 0.3 over twenty or more connections is
highly non-human. Human-driven browsing over the same destination
would show a coefficient of variation well over 1.0 as the user
alternates idle and active periods.

Byte-volume stability is the second pillar. A beacon's `orig_bytes`
and `resp_bytes` per connection should be small (typically under a
few kilobytes) and should fall inside a narrow distribution, because
the implant is sending essentially the same heartbeat each time.
Legitimate periodic traffic — software updaters, telemetry — tends
to show large variance in bytes as payloads change across check-ins.

A Python analysis pass that reads `conn.log` via Zeek's JSON output,
aggregates per-tuple, and emits jitter-ratio and byte-variance
features is the standard APTWatcher workflow. `rita` implements a
variant of this algorithm natively; its default thresholds of
twenty-four connections minimum over twenty-four hours, with a score
weighted across interval consistency and byte consistency, are a
reasonable starting baseline.

## DNS tunneling markers

Tunnels encode data in the labels of DNS queries and in the payloads
of `TXT`, `NULL`, or `CNAME` responses. The queries are therefore
structurally different from normal DNS:

- The leftmost label of each query approaches the 63-octet per-label
  limit, because the tunnel maximises usable bytes per query.
- Shannon entropy on the leftmost label runs high — roughly 3.8 bits
  per character and above — because the label is encoded binary
  rather than English-ish text.
- The per-client query rate against a single second-level domain is
  sustained at levels that normal clients never generate.
- Record-type distribution skews. `TXT` and `NULL` are rare in
  benign traffic; a single client driving a `TXT`-heavy conversation
  to a single SLD is a strong marker.
- Elevated `NXDOMAIN` ratios appear as a side-effect of some
  encoding schemes that deliberately query non-resolvable subdomains
  to signal state.

Zeek's `dns.log` exposes all of the fields needed: `query`,
`qtype_name`, `rcode_name`, `id.orig_h`. A simple aggregation per
`(id.orig_h, sld)` that computes query count, mean label length, mean
Shannon entropy, and NXDOMAIN ratio surfaces candidate tunnels.
`tshark` with `-T fields -e dns.qry.name` supports the same analysis
directly from `pcap` when Zeek is not available.

## Ruling out benign beacon-shaped traffic

CDN refresh schedules, NTP, Kerberos re-auth, Windows time sync,
EDR heartbeats, backup agents, and captive-portal probes all produce
beacon-shaped flows. The deciding factors are destination reputation
and host-side corroboration: a clean periodicity cluster to a
commodity cloud endpoint, without any matching host-side anomaly
(unexpected parent-child, new autostart, unsigned binary), is worth
recording at low confidence but not escalating. Cross-correlate with
the organisation's proxy logs — a beacon that terminates at the
corporate egress proxy with a clean user-agent and a recognised
upstream is more likely a software updater than a C2 channel.
Threat-intel hits on the destination IP, domain, or SLD are what
turn a lead into a finding.
