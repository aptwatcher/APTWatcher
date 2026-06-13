# Integration: MS Threat Analytics

> Second Tier 1 intel provider. Sits on Microsoft Graph — Defender XDR
> Threat Intelligence, Threat Analytics reports, security incidents, and
> alerts. Repo at `~/Dev/ms-threat-analytics-mcp`.

## What it provides

The MS Threat Analytics MCP server wraps six Microsoft Graph endpoints
behind a uniform tool surface. For APTWatcher, it answers:

- **Has Microsoft's intel seen this IOC?**
- **Is there a Threat Analytics report covering the observed TTPs?**
- **Does the organization already have an open Defender incident
  referencing this host or hash?**

APTWatcher consumes it as an **upstream MCP server** in Mode C, and as a
subprocess-invoked MCP client in Mode B. The server itself is not vendored.

## What APTWatcher uses it for

- **IOC enrichment** — same `check_ioc()` fan-out path as APT Watch, with
  MS Threat Analytics registered as a parallel provider.
- **Incident cross-check** — before APTWatcher files a GLPI ticket
  ([Tier 2](glpi.md)), it queries Defender for an existing incident on
  the same host. If one exists, the GLPI ticket links to it rather than
  creating a duplicate investigation thread.
- **Threat Analytics report lookup** — when MITRE techniques surface in
  the triage, the agent asks if Microsoft has a published Threat Analytics
  report covering the same techniques. Helpful for judges and for
  analysts building context.

## Required Graph scopes

Application or delegated, depending on auth mode:

- `ThreatIntelligence.Read.All`
- `ThreatIndicators.Read.All`
- `ThreatHunting.Read.All`
- `ThreatAssessment.Read.All`
- `SecurityIncident.Read.All`
- `SecurityAlert.Read.All`

These match the upstream MCP's `README` verbatim. Admin consent is
required for all of them.

## Auth modes

The upstream MCP supports three auth modes. APTWatcher respects whichever
one is configured there — it does not re-implement auth:

| Mode                  | Use when                                                |
|-----------------------|---------------------------------------------------------|
| `client_credentials`  | Headless server, service principal with secret          |
| `az_cli`              | Analyst workstation already signed in via `az login`    |
| `device_code`         | Interactive triage workstation, no CLI, one-time auth   |

For the hackathon demo, `client_credentials` is used. Judges without a
tenant can skip this integration entirely — Tier 1 falls back to APT Watch
alone, or to unknown verdicts if neither is configured.

## Config

```yaml
# config.yaml excerpt
intel:
  ms_threat_analytics:
    enabled: true
    mcp_endpoint: stdio:///opt/ms-threat-analytics-mcp/run.sh
    auth_mode: client_credentials
    tenant_id_env: MS_TENANT_ID
    client_id_env: MS_CLIENT_ID
    client_secret_env: MS_CLIENT_SECRET
    rate_limit:
      requests_per_minute: 30
      burst: 5
    timeout_seconds: 15
    cache_ttl_seconds: 1800
```

Credentials never live in `config.yaml`. The three env vars are read at
adapter startup; missing any one disables the provider with a logged
warning, not an error.

## Tool mapping

What APTWatcher calls → what the MCP server exposes:

| APTWatcher adapter call        | Upstream MCP tool                    |
|--------------------------------|--------------------------------------|
| `check_ioc(ip, "ipv4")`         | `ti_indicator_search`                |
| `check_ioc(hash, "sha256")`     | `ti_indicator_search`                |
| `threat_report_lookup(tech_id)` | `threat_analytics_reports_by_technique` |
| `incident_lookup(host)`         | `security_incidents_by_host`         |

The adapter translates in both directions. The upstream MCP's JSON schemas
are the source of truth; the adapter normalizes responses into
`IOCVerdict` for intel results and `IncidentRef` for incident cross-checks.

## Verdict normalization

Microsoft's `threatType` enum does not map one-to-one to APTWatcher's
verdict values. The adapter uses this mapping:

| Graph `threatType`     | `IOCVerdict.verdict`  |
|------------------------|-----------------------|
| `botnet`, `c2`, `malicious` | `malicious`     |
| `phishing`             | `malicious`           |
| `suspicious`           | `suspicious`          |
| `watchlist`            | `suspicious`          |
| (absent)               | `unknown`             |

Confidence is carried through as `(Graph confidence) / 100`. If Microsoft
does not provide a confidence, the adapter sets it to `null` — never
guesses.

## Graceful degradation

Same matrix as [APT Watch](apt-watch.md):

- Missing credentials → provider skipped, logged.
- Upstream MCP unreachable → backoff, then provider marked stale.
- Rate limit exhausted → unresolved IOCs return `verdict: unknown`.

If MS Threat Analytics is the only configured Tier 1 provider and it is
unavailable, the run continues. The gap is noted in the report.

## Why two Tier 1 providers

APT Watch is the author's brand and the platform APTWatcher was originally
imagined around. Microsoft Threat Analytics is what many judges and
production analysts already have credentials for. Shipping with both
configurable demonstrates:

- The Tier 1 pattern really is provider-agnostic.
- The normalization layer works across vendors.
- The fan-out / graceful-degradation machinery is not just theoretical.

Judges choose one, the other, both, or neither.

## Related

- [APT Watch integration](apt-watch.md)
- [Tier 1 intel lookup pattern](../design/tier1-intel-lookup-pattern.md)
- Upstream MCP: `~/Dev/ms-threat-analytics-mcp/`
