"""
Integrations namespace.

Holds adapter modules for external systems — APT Watch (Tier 1), MS Threat
Analytics (Tier 1), GLPI (Tier 2), CnC Disruptor (Tier 3/4). Each adapter
is a thin HTTP/MCP client; they never import from `mcp_server` or
`agent_extension` and never own state. Configuration comes from
`core.config.APTWatcherConfig`.

This scaffold is an empty namespace package — the adapters are wired in
later commits. Kept so `pyproject.toml`'s wheel target resolves.

References:
- docs/integrations/README.md
- docs/integrations/apt-watch.md
- docs/integrations/ms-threat-analytics.md
- docs/integrations/glpi.md
- docs/integrations/cnc-disruptor.md
"""

from __future__ import annotations

__all__: list[str] = []
