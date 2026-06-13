"""
Publication adapters for APTWatcher (Phase 3.8 task #65).

Each adapter consumes a signed IncidentBundle's findings + IOCs and
pushes a shape of them to an external system:

- `NetcraftAdapter`          Netcraft Report v3 take-down queue.
- `MispAdapter`              MISP event push (`/events/add`).
- `GLPIAttachmentAdapter`    GLPI ticket attachment upload (via glpi-mcp).
- `StubPublicationAdapter`   In-memory recorder for tests / dry-runs.
- `TaxiiAdapter`             TAXII 2.1 collection POST.

All adapters satisfy the `PublicationAdapter` Protocol and return a
`PublicationResult`. Failures surface as `PublicationError`.

See `docs/design/analysis-output-pipeline.md` for the publication
pipeline contract and the CLI-level consent / dry-run semantics.
"""

from __future__ import annotations

from core.publish.glpi_attachment import (
    AttachmentTransportResult,
    GLPIAttachmentAdapter,
)
from core.publish.misp import MispAdapter
from core.publish.netcraft import NetcraftAdapter
from core.publish.protocol import (
    PublicationAdapter,
    PublicationError,
    PublicationResult,
    PublicationStatus,
)
from core.publish.stub import StubPublicationAdapter
from core.publish.taxii import TaxiiAdapter, TaxiiPublicationError

__all__ = [
    "AttachmentTransportResult",
    "GLPIAttachmentAdapter",
    "MispAdapter",
    "NetcraftAdapter",
    "PublicationAdapter",
    "PublicationError",
    "PublicationResult",
    "PublicationStatus",
    "StubPublicationAdapter",
    "TaxiiAdapter",
    "TaxiiPublicationError",
]
