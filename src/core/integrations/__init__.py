"""
Tier 2 — IR workflow integrations (tickets, incidents, downstream systems).

Adapters here translate external ticketing / incident systems into the
shared brain's value objects (`TicketRef`, `IncidentRef`). They never
own business logic — the shared brain decides what to do with an
enriched ticket; integrations just fetch and normalize.

GLPI is the reference implementation. Future additions: Defender for
IncidentRef, ServiceNow, Jira.

References:
- docs/architecture/shared-brain.md
- docs/architecture/tier-model.md
"""

from __future__ import annotations

from core.integrations.glpi import (
    EnrichedTicket,
    GLPIResolverError,
    GLPITicketRefResolver,
    MCPSubprocessGLPIResolver,
    StubGLPIResolver,
)

__all__ = [
    "EnrichedTicket",
    "GLPIResolverError",
    "GLPITicketRefResolver",
    "MCPSubprocessGLPIResolver",
    "StubGLPIResolver",
]
