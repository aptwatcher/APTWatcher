# Integration: APT Watch

> Primary Tier 1 intel provider. Powers `api.aptwatch.org`. Same author as
> APTWatcher, different project — **integration is API-only, no code
> coupling**. The orchestration pattern from APT Watch's `validate.py` is
> adapted (not copied) for the Tier 1 lookup path.

## What it provides

APT Watch is a threat-intelligence platform with its own RSS monitor,
multi-source IOC validation, and SQLite-backed correlation database. For
APTWatcher, it answers three questions per IOC:

- **Is this IOC known to any of our aggregated sources?**
- **What is the consensus verdict across those sources?**
- **Is there a campaign or actor attribution?**

The normalized return shape is `IOCVerdict` (see
[shared brain](../architecture/shared-brain.md)).

## What APTWatcher uses it for

- `check_ioc(value, ioc_type)` — single IOC lookup. Primary consumer.
- `correlate_host_against_intel(host_evidence)` — batch correlation of
  every IOC surfaced in a host triage against APT Watch's aggregated
  sources.
- `(future) submit_ioc(...)` — feedback loop to APT Watch when APTWatcher
  finds something the platform should know about. Deferred to post-MVP.

The design pattern (fan-out, per-provider rate limits, graceful
degradation) is documented in
[Tier 1 intel lookup pattern](../design/tier1-intel-lookup-pattern.md).

## Auth & endpoints

```yaml
# config.yaml excerpt
intel:
  apt_watch:
    enabled: true
    base_url: https://api.aptwatch.org
    api_key_env: APTWATCH_API_KEY
    rate_limit:
      requests_per_minute: 60
      burst: 10
    timeout_seconds: 10
    cache_ttl_seconds: 900
```

Credentials are never written to the config file. `APTWATCH_API_KEY` must
be exported in the environment before the MCP server starts. If the env
var is absent when the adapter initializes, APTWatcher logs
`apt-watch: credentials absent, provider disabled` and continues with
whatever other providers are configured.

## Request shape

```json
POST /v1/ioc/check
{
  "value": "185.220.103.118",
  "ioc_type": "ipv4",
  "context": {
    "source": "aptwatcher",
    "scenario_id": "s01",
    "host": "FIN-WS-014"
  }
}
```

## Response shape (normalized by the adapter to `IOCVerdict`)

```json
{
  "value": "185.220.103.118",
  "ioc_type": "ipv4",
  "verdict": "malicious",
  "confidence": 0.82,
  "first_seen": "2024-11-02T00:00:00Z",
  "last_seen": "2026-04-11T14:33:00Z",
  "sources": [
    {"name": "APTWatch-aggregator", "verdict": "malicious", "score": 0.9},
    {"name": "rss_monitor.torexit", "verdict": "suspicious", "score": 0.6}
  ],
  "attributions": [
    {"actor": "unknown", "campaign": "residential-vpn-bruteforce"}
  ]
}
```

Missing fields are preserved as `null`. The adapter never invents values
to satisfy the `IOCVerdict` schema.

## Rate limiting

The adapter uses a per-provider token bucket (same pattern APT Watch's
`validate.py` uses internally). The limits above are conservative
defaults. If APTWatcher saturates the bucket during a run, subsequent
calls queue rather than drop — up to a 30-second overall ceiling per
provider per lookup batch. Past that, the adapter returns
`verdict: unknown` for the unresolved IOCs and the run continues.

## Caching

Results are cached in-memory for the duration of a single incident run
(default TTL 15 min). Cache key is `(value, ioc_type)`. There is no
cross-run persistent cache — that would invert the freshness contract
with APT Watch.

## Graceful degradation

| Condition                       | Behavior                                           |
|---------------------------------|----------------------------------------------------|
| `APTWATCH_API_KEY` unset        | Provider skipped at startup; no retries            |
| Endpoint unreachable            | Exponential backoff 3×, then provider marked stale |
| HTTP 4xx (auth failure)         | Provider disabled for the rest of the run         |
| HTTP 5xx / timeout              | Retried; falls through to other providers          |
| Rate limit exhausted            | `verdict: unknown` for unresolved IOCs             |

If APT Watch is the only Tier 1 provider configured and it is unavailable,
`check_ioc()` returns `verdict: unknown` with `sources: []`. The run
completes; the report notes the intel gap explicitly.

## Not APTWatch

A recurring confusion: **APTWatcher** (this project) is the defensive IR
agent. **APTWatch** (the website / API) is the threat-intel platform. They
share an author and a brand family but are separate projects with separate
repos and licenses. APTWatcher integrates with APT Watch the same way it
integrates with any external intel source — through a versioned HTTP API.

## Cross-project ideas surfaced

Ideas that would improve APT Watch itself, observed while building the
APTWatcher integration, are logged in
`~/Dev/APT_Analytics/TODO.md` under the
"Ideas surfaced while building APTWatcher" section.

## Related

- [Tier 1 intel lookup pattern](../design/tier1-intel-lookup-pattern.md)
- [Shared brain — IOCVerdict](../architecture/shared-brain.md)
- [MS Threat Analytics integration](ms-threat-analytics.md)
