# Integration: GLPI

> Tier 2 workflow integration. Files APTWatcher's triage reports as
> real tickets in a real ticketing system, and searches the IR knowledge
> base for prior similar incidents. Upstream MCP at
> `~/Dev/glpi-mcp`.

## What it provides

GLPI is an open-source ITSM / helpdesk platform. For APTWatcher, it is
the target of the "file your own report" demo — the moment when the
agent's output stops being a text blob and becomes a tracked ticket an
analyst can triage, a supervisor can assign, and an auditor can find.

The upstream MCP wraps GLPI's REST API (`apirest.php`) behind typed
tools. APTWatcher consumes them through the standard MCP integration
path (Mode B: subprocess / Mode C: registered MCP client).

## What APTWatcher uses it for

- **Ticket creation** at the end of a triage run, with the full report
  as the ticket's content.
- **Ticket updates** as new findings surface — e.g., after a Tier 1
  lookup returns late, or after a Tier 3 action completes.
- **Task creation** for human analyst follow-up (e.g., "confirm the VPN
  gateway logs cover the egress window").
- **KB search** before starting a triage, looking for prior incidents
  with overlapping IOCs, hosts, or techniques.
- **Follow-up logging** for intermediate findings that are not
  report-worthy but should be preserved.

## The HTML content rule

This is non-negotiable and it applies to every content field APTWatcher
writes to GLPI:

> **All content fields must be rendered as HTML, not Markdown.** Use
> `<p>`, `<strong>`, `<em>`, `<ul>/<li>`, `<ol>/<li>`, `<h2>/<h3>`,
> `<code>`, `<pre>`, `<br>`. Never use `#`, `**`, `*`, backtick fences,
> or any other Markdown syntax.

This constraint comes from GLPI's rich-text field behavior. The
report-rendering layer inside APTWatcher has a dedicated HTML formatter;
Markdown is never emitted to GLPI even when the analyst passes
Markdown-flavored input upstream. The GLPI adapter refuses to write a
content field it detects as Markdown.

Rationale: GLPI saves the raw HTML and re-renders it on view. Markdown
characters appear literally in the ticket. An agent that files
`## Findings` as a ticket body looks broken to the analyst opening the
ticket.

## Config

```yaml
# config.yaml excerpt
workflow:
  glpi:
    enabled: true
    mcp_endpoint: stdio:///opt/glpi-mcp/.venv/bin/python -m glpi_mcp
    config_file: /etc/aptwatcher/glpi-mcp.config.json
    default_entity_id: 0
    default_itil_category: "Security / Incident Response"
    default_urgency: 4      # high
    default_impact: 4       # high
    default_priority: 4     # high
    ticket_title_template: "[APTWatcher] {scenario_id} — {host} — {summary}"
    idempotency:
      one_ticket_per: (scenario_id, host)
      update_existing: true
```

The upstream MCP reads its own credentials from its own `config.json`
(`glpi-mcp/config.json`). APTWatcher never handles GLPI credentials
directly.

## Ticket lifecycle

1. **Pre-triage KB search.** `glpi_kb_search(query)` runs against the
   knowledge base for the incident fingerprint (host name, known IOCs,
   technique set). Matches are surfaced to the agent as prior context.
2. **Ticket creation.** At the end of Tier 0, `glpi_ticket_create()` is
   called with:
   - Title from the template
   - Content rendered as HTML per the content rule
   - Category, urgency, impact, priority from config
   - Entity and requester from config or agent-inferred
3. **Ticket updates.** Each significant subsequent finding calls
   `glpi_ticket_update(id, ...)` with an HTML follow-up. Tier 1 intel
   that arrives late and Tier 3 containment outcomes both use this path.
4. **Tasks.** `glpi_task_create(ticket_id, ...)` spawns analyst follow-ups
   where the agent identifies work that requires a human decision.

## Idempotency

A common failure mode for ticket-filing agents is the same run creating
the same ticket twice (e.g., on retry). APTWatcher's GLPI adapter
enforces one ticket per `(scenario_id, host)` pair. On a duplicate call,
the existing ticket is updated instead of a new one being created.

If the analyst explicitly wants a new ticket (e.g., a second, distinct
incident on the same host), the run specifies a new `scenario_id` at
invocation and the constraint is satisfied naturally.

## Output example (HTML content)

```html
<h2>APTWatcher triage summary — S01 — FIN-WS-014</h2>
<p><strong>Status:</strong> Consistent with credential-theft phishing
followed by RDP persistence. No evidence of exfiltration.</p>

<h3>Findings</h3>
<ul>
  <li><strong>Initial access:</strong> Phishing click at 2026-04-10 17:42
      (<em>T1566.002</em>).</li>
  <li><strong>Persistence:</strong> Scheduled task
      <code>MicrosoftEdgeUpdateTaskMachineUA</code> created Sat 02:18
      (<em>T1053.005</em>).</li>
  <li><strong>Credential access:</strong> LSASS dump via signed
      <code>procdump64.exe</code> (<em>T1003.001</em>).</li>
</ul>

<h3>Evidence integrity</h3>
<p>Full audit log at <code>logs/s01/audit.jsonl</code>. All hashes
verified against pre-mount state.</p>
```

Rendered inside GLPI, this looks like a properly formatted incident
report. Rendered as Markdown (the wrong way), it looks like noise.

## Graceful degradation

| Condition                           | Behavior                                                |
|-------------------------------------|---------------------------------------------------------|
| `glpi-mcp` not reachable            | Tier 2 disabled at startup; report printed to stdout only |
| Auth failure on upstream MCP        | Tier 2 disabled; clear error logged                      |
| Rate limit / HTTP 429               | Exponential backoff; falls back to stdout after 3 retries |
| Content field contains Markdown     | Adapter aborts the write, logs the offending field      |

## Scenario mapping

- [S02 — Multi-host lateral movement](../scenarios/S02-multi-host-lateral-movement.md)
  is the primary Tier 2 demonstration: one ticket per incident with
  three hosts in the narrative.
- [S01](../scenarios/S01-single-windows-compromise.md) and
  [S03](../scenarios/S03-ransomware-pre-detonation.md) file tickets
  optionally; the rubric does not require it.

## Related

- [Tier model](../architecture/tier-model.md)
- [Integrations overview](README.md)
- Upstream MCP: `~/Dev/glpi-mcp/`
