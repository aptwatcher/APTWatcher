# Integrations

> Four optional integrations extend APTWatcher beyond core triage. Each one
> maps to a [tier](../architecture/tier-model.md); each is opt-in; each
> degrades gracefully when its credentials are absent.

## The four integrations

| Integration                                       | Tier | Role                                     | Ships with APTWatcher? |
|---------------------------------------------------|------|------------------------------------------|------------------------|
| [APT Watch](apt-watch.md)                         | 1    | Threat intel (IOC lookup, submissions)   | No — API client only   |
| [MS Threat Analytics](ms-threat-analytics.md)     | 1    | Microsoft Defender XDR + Graph intel     | No — upstream MCP      |
| [GLPI](glpi.md)                                   | 2    | Ticketing + IR knowledge base            | No — upstream MCP      |
| [cnc_disruptor](cnc-disruptor.md)                 | 3/4  | Defensive/offensive containment          | No — wrapped scripts   |

"Ships with APTWatcher?" is intentional. None of the four are vendored.
APTWatcher is the orchestrator; the integrations are the orchestrated.
This keeps the clean-room discipline intact and avoids license-compatibility
issues.

## Integration shape

All four integrations follow the same architectural shape:

1. **Adapter** in `src/core/adapters/<name>.py` implements the minimum
   contract (`IOCVerdict` for Tier 1, `TicketRecord` for Tier 2,
   `ContainmentResult` for Tier 3/4).
2. **Config block** in `config.yaml` declares the endpoint, auth mode, and
   tier enablement.
3. **Credential loading** from environment variables by preference,
   secrets file as fallback. The config never carries credentials.
4. **Graceful degradation** when credentials are missing: the adapter is
   skipped, not errored. A missing Tier 1 provider leaves Tier 0 findings
   intact.
5. **Audit entries** for every call. Every outbound request is logged with
   its parameters (redacted), latency, and result verdict.

## Tier 1 vs Tier 2/3/4 integration concerns

**Tier 1** adapters are read-mostly. They query, receive, and hand back
normalized verdicts. Idempotency is the provider's problem. Rate limiting
is APTWatcher's problem (see
[Tier 1 intel lookup pattern](../design/tier1-intel-lookup-pattern.md)).

**Tier 2** adds write operations — filing tickets, updating GLPI records.
The integration layer enforces *one ticket per incident per host* to
prevent runaway ticket creation if the agent loops. Ticket updates are
idempotent on the `reference_id` the adapter assigns.

**Tier 3/4** add state-changing operations against the compromised host
(Tier 3) or adversary infrastructure (Tier 4). The architectural
guardrails for these are covered in
[evidence integrity](../architecture/evidence-integrity.md) and
[cnc_disruptor integration](cnc-disruptor.md).

## What you need for each integration

| Integration         | Credentials / setup                                                                 |
|---------------------|-------------------------------------------------------------------------------------|
| APT Watch           | API key (env var `APTWATCH_API_KEY`), base URL                                      |
| MS Threat Analytics | Azure AD app registration with 6 Graph scopes; `client_credentials` / `az_cli` / `device_code` |
| GLPI                | GLPI instance URL + app token + user token; config file `glpi-mcp/config.json`      |
| cnc_disruptor       | Host-local scripts (PowerShell + Python); no credentials; runtime confirmation flag |

Links to each integration's full page spell out the exact environment
variables, config entries, and expected responses.

## Hackathon note

Judges without credentials for any of these can still evaluate APTWatcher
end-to-end using Tier 0 + the synthetic datasets. The integrations
demonstrate architectural extensibility; they are not required for the
core accuracy measurement.

## Related

- [Tier model](../architecture/tier-model.md)
- [Shared brain](../architecture/shared-brain.md) — types (`IOCVerdict`,
  `TicketRecord`) the adapters return
