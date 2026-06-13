"""
APTWatcher — Mode A surface (Direct Agent Extension).

Thin CLI that imports from `core` and renders output for a human operator.
Mode A is the bare-minimum deployment: no MCP server, no ticketing, just
the shared brain wrapped in a Typer app so you can run `aptwatcher` on a
SIFT VM with zero config.

References:
- docs/architecture/shared-brain.md
- docs/deployment/mode-a.md
"""

from __future__ import annotations

__version__ = "0.1.0a0"

__all__ = ["__version__"]
