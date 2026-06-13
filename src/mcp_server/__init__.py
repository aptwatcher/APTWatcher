"""
APTWatcher — Mode B surface (Custom MCP Server).

Exposes the shared brain as MCP tools over stdio. Keeps tool signatures
small and typed; all business logic stays in `core`. A host agent (Claude
Code or any MCP-capable client) calls these tools; APTWatcher's own
self-correction discipline is enforced inside `core`, not here.

References:
- docs/architecture/shared-brain.md
- docs/deployment/mode-b.md
- docs/reference/mcp-tools.md
"""

from __future__ import annotations

__version__ = "0.1.0a0"

__all__ = ["__version__"]
