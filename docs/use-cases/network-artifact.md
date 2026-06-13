# Use case: Network artifact

> PCAP, netflow, firewall logs, DNS queries. No host image required. The
> agent answers "what does the network say", not "what happened on the
> host". Pair with another profile when both questions matter.

## When to use

- A perimeter alert (firewall, IDS, DNS security) kicked off the
  investigation and host evidence is not yet available.
- Beacon detection work: identify C2 patterns in captured traffic.
- Exfiltration volumetric analysis.
- Supplementing host work when the host-side answer is "file was staged"
  and the network question becomes "did it leave".

## Profile declaration

```yaml
profile: network-artifact
required_tools:
  - zeek OR tshark OR suricata
  - yara
  - bulk_extractor  # for carving from PCAP
optional_tools:
  - rita             # beaconing analysis
  - chopshop         # protocol decoding
  - maltrail
  - passivedns
artifact_categories:
  required:
    - at_least_one:
        - pcap
        - netflow (v5, v9, or IPFIX)
        - firewall_logs
        - dns_logs
  optional:
    - proxy_logs
    - tls_ja3_bundle
    - suricata_alerts
tier_prerequisites:
  tier_1: strongly_recommended  # IOC lookups carry most of the value
  tier_2: optional
  tier_3: not_applicable
```

Tier 1 is `strongly_recommended` rather than `required` because the agent
still produces useful heuristics without it — but the intel corroboration
is what turns heuristics into findings.

## What the agent does under this profile

1. **Preflight** + inventory. PCAP file hashes, capture time windows, and
   sensor source (if declared) go to the audit log.
2. **Protocol breakdown.** Zeek-style `conn.log`, `dns.log`, `http.log`,
   `ssl.log` equivalents. For netflow-only inputs, the agent works at the
   flow level.
3. **Beacon candidates.** Periodic connection patterns (interval +
   jitter matching known beacons) are surfaced. `rita` when available;
   heuristic detection otherwise.
4. **DNS anomalies.** DGA-style query patterns, long TXT lookups, and
   high-entropy subdomains are flagged.
5. **TLS fingerprints.** JA3/JA3S or JA4 if collected; cross-reference
   with known-malicious fingerprint lists where available.
6. **Carved artifacts.** `bulk_extractor` pulls IoCs, URLs, and files
   directly from the PCAP where not TLS-protected. Files are hashed, not
   executed.
7. **Egress volumetrics.** Per-host outbound byte totals in the capture
   window. The agent flags anything that stands out distributionally —
   explicitly avoiding fixed thresholds, which are brittle across
   environments.
8. **Tier 1 lookup.** Every external IP, domain, and hash runs through
   `check_ioc()`. Results attach to the flow / DNS / TLS finding they
   came from.
9. **Report.** Findings phrased at network confidence — e.g., *"Periodic
   beacon pattern to 104.xx.xx.xx, consistent with C2; intel providers
   rate the endpoint as..."* The host-side claim (which process beaconed)
   is **not** in scope and the report says so.

## What it cannot do

- **Attribute network activity to a specific process.** Without a host
  image, the agent will not name the beaconing process. It can say "the
  source IP is 10.x.y.z" and "the pattern is consistent with a Cobalt
  Strike HTTP beacon"; it cannot say "spoolsv.exe was beaconing".
- **Decrypt TLS.** Without a pre-master secret log or a MITM proxy dump,
  TLS content is opaque. The agent works at the metadata level (SNI, JA3,
  timing, volumetrics) and states that explicitly.
- **Confirm compromise.** Network evidence alone rarely confirms
  compromise. The agent phrases findings as indicators, not conclusions.

## The volumetric honesty rule

Egress volume is the easiest thing to sensationalize and the easiest thing
to get wrong. The agent applies three constraints:

1. **No fixed thresholds.** A "10 MB/day is suspicious" rule is wrong in
   at least half of all environments.
2. **Distribution-aware flagging.** A host's egress is flagged only if it
   is statistically anomalous against its own historical baseline **or**
   against same-role peers in the same capture.
3. **Business context request.** If the capture includes DHCP/DNS
   identification of a host as a backup server (name, SMB share patterns),
   large egress alone is not flagged. The agent asks for role
   confirmation in the report when it would materially change the
   finding.

## Failure modes

- **PCAP larger than available memory / disk**: the agent refuses to load
  the full file and instead does a streaming pass with zeek/tshark. If
  even that fails, the run aborts with a sizing recommendation.
- **Netflow without matching firewall or DNS logs**: the agent proceeds
  but flags that destination attribution (resolving IPs to domains at
  query time) is unavailable.
- **Time range mismatch with host evidence** (when paired): cross-profile
  correlation is downgraded to low confidence. Same rule as timeline-only
  clock skew.

## Scenario mapping

No scenario uses this profile as primary. Scenarios pair it with the
host-triage profile when both network and host evidence are in scope.
In the hackathon demo, network-artifact is not exercised; it is documented
for completeness and to anchor the roadmap beyond the submission.

## Related

- [Timeline only](timeline-only.md)
- [Integration: APT Watch](../integrations/apt-watch.md)
- [Integration: MS Threat Analytics](../integrations/ms-threat-analytics.md)
