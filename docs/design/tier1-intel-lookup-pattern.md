# Tier 1 Intel — Lookup Pattern (adapted from APT Watch)

> Reuse the validated multi-source orchestration pattern from
> `~/Dev/APT_Analytics/apt-intel/scripts/validate.py`.
> Adapt for runtime MCP tool calls rather than batch queue processing.

---

## Pattern summary (from APT Watch)

APT Watch's `validate.py` already solves the hard problems:

1. **Fan-out across N providers** (Shodan, AbuseIPDB, VirusTotal, OTX, Censys,
   DShield, ThreatFox, FireHOL, Steven Black).
2. **Graceful degradation** — runs only providers with configured keys.
   Missing keys → skip, don't error.
3. **Per-provider rate limiting** — each source has its own delay.
4. **Aggregated verdict** — consolidates results into a single score/state.
5. **Transaction logging** — every call is recorded.

This maps cleanly to the Tier 1 requirement: "optional, disabled by default,
works with whatever subset of providers the user has configured."

## Adaptation for APTWatcher MCP tools

### `check_ioc(value: str, ioc_type: str) -> IOCVerdict`

**Input**:
```json
{
  "value": "185.220.101.42",
  "ioc_type": "ipv4"  // ipv4, ipv6, domain, url, sha256, sha1, md5, email, cve
}
```

**Providers** (each optional, tier-gated):
- APT Watch API (`api.aptwatch.org`) — our own curated intel
- MS Threat Analytics MCP — Microsoft telemetry
- (Future) any provider added to config

**Output**:
```json
{
  "value": "185.220.101.42",
  "ioc_type": "ipv4",
  "verdict": "malicious",   // malicious | suspicious | benign | unknown
  "confidence": 0.92,
  "attribution": ["APT28", "FancyBear"],
  "first_seen": "2025-11-12T...",
  "last_seen": "2026-04-17T...",
  "sources": [
    {"provider": "aptwatch", "hit": true, "campaign": "HOSTKEY_DEDIK", "score": 85},
    {"provider": "ms_threat_analytics", "hit": true, "severity": "high"}
  ],
  "providers_queried": ["aptwatch", "ms_threat_analytics"],
  "providers_skipped": ["virustotal"],   // key not configured
  "cache_hit": false
}
```

**Key design choices**:
- Verdict aggregation: weighted by per-provider confidence + agreement count.
- If zero providers are available (Tier 1 disabled), return
  `verdict: "unknown"` with `providers_queried: []` — don't error.
- Every call goes through the audit logger with a correlation ID.
- Results cached in-process for the current incident (avoid re-hitting
  rate-limited APIs for the same IOC).

### `extract_iocs(text: str, types: List[str] = None) -> List[IOC]`

Ports the regex patterns from `rss_monitor.py`:
- IPv4/IPv6 with defanging normalization (`185[.]220[.]101[.]42` → `185.220.101.42`)
- Domains with `[.]` / `hxxp://` normalization
- File hashes (md5/sha1/sha256) with length-based detection
- URLs with scheme defanging (`hxxp` → `http`)
- Emails
- CVEs

**Purpose**: feed raw forensic tool output (e.g., strings from a memory dump,
bulk_extractor output, email headers) into the IOC pipeline without the agent
having to handcraft regex each time.

### `correlate_host_against_intel(host_evidence: HostEvidence) -> CorrelationReport`

Ports the `scan_crossref.py` logic but for an IR host triage instead of a
Nessus scan:

**Input**: a set of observables from the host (outbound IPs, resolved domains,
hashes of dropped files, URL strings from memory, etc.).

**Output**: a correlation report identifying which observables match known APT
infrastructure, with attribution (campaign, threat actor, ASN owner,
hosting provider).

This is the **multi-source correlation engine** from the hackathon starter
idea #2, realized.

### (Future) `submit_ioc(observable, context) -> SubmissionStatus`

When APTWatcher finds a new IOC during triage that doesn't match any intel
source, optionally submit it back to APT Watch's (in-progress) submission
system. Closes the feedback loop: APTWatcher contributes to the intel
corpus that APTWatcher uses. Out of scope for MVP; note in backlog.

---

## Rate limiting strategy

From `validate.py` (adapt, don't copy):

```python
RATE_LIMITS = {
    "aptwatch":             1.0,   # own infra, be polite
    "ms_threat_analytics":  2.0,   # Graph API limits
    "virustotal":          20.0,   # 4/min free tier
    "abuseipdb":            1.5,   # 1000/day free
    "shodan_internetdb":    1.5,   # 1/sec
    "otx":                  0.5,
}
```

In the MCP server, this is a per-provider token bucket.

---

## Open questions

- **Credential management**: env vars (like APT Watch) or a dedicated
  secrets file? Recommendation: env vars first (simpler for demo), add
  secrets-file option later.
- **Cache lifetime**: per-incident, per-session, or persistent? Starting
  per-incident (in-memory only) for evidence-integrity auditability.
- **MS Threat Analytics MCP integration style**: do we proxy its tools
  transparently, or wrap them with a consistent adapter? Recommendation:
  adapter pattern, so every intel source has the same `IOCVerdict` output
  shape regardless of provider.
