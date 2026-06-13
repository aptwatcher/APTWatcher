"""
GLPI attachment upload adapter.

Takes a signed `IncidentBundle`'s artifact directory (rules/, reports/,
iocs/, bundle.json) and pushes each file as an attachment on an existing
GLPI ticket via the `glpi-mcp` subprocess adapter.

The invocation pattern follows `core.integrations.glpi`'s
`MCPSubprocessGLPIResolver`: a CLI is shelled out to, stdin carries a
JSON-formatted MCP tool call (`glpi.attachment.add`), and stdout is
parsed for the created attachment id.

All subprocess I/O is funneled through an injectable `transport`
callable so unit tests never spawn a real `glpi-mcp` process.

GLPI content-field rule is respected: this adapter only attaches
binary files; it does NOT write any Markdown body to the ticket. If a
future enhancement adds a ticket-body update, it MUST produce HTML
(see `core.integrations.glpi._h`).
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from core.publish.protocol import (
    PublicationAdapter,
    PublicationError,
    PublicationResult,
)
from core.types import Finding, IOCVerdict

__all__ = ["GLPIAttachmentAdapter", "AttachmentTransportResult"]


def _utc_iso_now() -> str:
    return datetime.now(tz=UTC).isoformat().replace("+00:00", "Z")


@dataclass
class AttachmentTransportResult:
    """Shape returned by the injected transport for tests."""

    returncode: int
    stdout: str = ""
    stderr: str = ""


# The injected transport signature: takes the command list and the JSON
# payload for stdin, returns an `AttachmentTransportResult`.
AttachmentTransport = Callable[[list[str], str], AttachmentTransportResult]


class GLPIAttachmentAdapter:
    """
    Upload IncidentBundle artifacts (rules, reports, iocs) as attachments
    on an existing GLPI ticket.
    """

    name: str = "glpi"

    def __init__(
        self,
        *,
        ticket_id: int,
        bundle_dir: Path,
        glpi_mcp_command: list[str] | None = None,
        timeout: float = 60.0,
        transport: AttachmentTransport | None = None,
    ) -> None:
        if ticket_id <= 0:
            raise ValueError(f"ticket_id must be positive, got {ticket_id!r}")
        self._ticket_id = ticket_id
        self._bundle_dir = Path(bundle_dir)
        self._glpi_mcp_command = list(glpi_mcp_command or ["glpi-mcp", "--stdio"])
        self._timeout = timeout
        self._transport = transport

    # ------------------------------------------------------------------

    def publish(
        self,
        *,
        findings: list[Finding],
        iocs: list[IOCVerdict],
        incident_id: str,
        campaign_tag: str,
        dry_run: bool = True,
    ) -> PublicationResult:
        files = self._collect_files()
        correlation_id = f"glpi-{uuid.uuid4().hex}"

        if dry_run:
            return PublicationResult(
                adapter=self.name,
                target=str(self._ticket_id),
                submitted_at=_utc_iso_now(),
                correlation_id=correlation_id,
                status="dry_run",
                details={
                    "ticket_id": self._ticket_id,
                    "bundle_dir": str(self._bundle_dir),
                    "files": [str(f.relative_to(self._bundle_dir)) for f in files],
                    "file_count": len(files),
                    "incident_id": incident_id,
                    "campaign_tag": campaign_tag,
                },
            )

        if not files:
            raise PublicationError(
                f"glpi attachment publish: bundle_dir is empty or missing: "
                f"{self._bundle_dir}"
            )

        responses: list[dict[str, Any]] = []
        for file_path in files:
            payload = _build_mcp_call(
                ticket_id=self._ticket_id,
                file_path=file_path,
                incident_id=incident_id,
                campaign_tag=campaign_tag,
            )
            responses.append(self._invoke(payload))

        return PublicationResult(
            adapter=self.name,
            target=str(self._ticket_id),
            submitted_at=_utc_iso_now(),
            correlation_id=correlation_id,
            status="submitted",
            details={
                "ticket_id": self._ticket_id,
                "bundle_dir": str(self._bundle_dir),
                "file_count": len(files),
                "files": [str(f.relative_to(self._bundle_dir)) for f in files],
                "responses": responses,
            },
        )

    # ------------------------------------------------------------------

    def _collect_files(self) -> list[Path]:
        """Return a stable, sorted list of files under `bundle_dir`."""
        if not self._bundle_dir.exists() or not self._bundle_dir.is_dir():
            return []
        out: list[Path] = []
        for entry in sorted(self._bundle_dir.rglob("*")):
            if entry.is_file():
                out.append(entry)
        return out

    def _invoke(self, payload: dict[str, Any]) -> dict[str, Any]:
        stdin_body = json.dumps(payload)
        cmd = list(self._glpi_mcp_command)

        if self._transport is not None:
            try:
                result = self._transport(cmd, stdin_body)
            except Exception as exc:  # noqa: BLE001
                raise PublicationError(
                    f"glpi attachment transport failure: {exc}"
                ) from exc
            return _handle_result(result, payload)

        try:
            completed = subprocess.run(  # noqa: S603
                cmd,
                input=stdin_body,
                capture_output=True,
                text=True,
                check=False,
                timeout=self._timeout,
            )
        except FileNotFoundError as exc:
            raise PublicationError(
                f"glpi-mcp CLI not found: {cmd[0]!r}"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise PublicationError(
                f"glpi-mcp attachment.add timed out after {self._timeout}s"
            ) from exc

        result = AttachmentTransportResult(
            returncode=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
        )
        return _handle_result(result, payload)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_mcp_call(
    *,
    ticket_id: int,
    file_path: Path,
    incident_id: str,
    campaign_tag: str,
) -> dict[str, Any]:
    size = file_path.stat().st_size if file_path.exists() else 0
    sha256 = _sha256_of(file_path) if file_path.exists() else ""
    return {
        "tool": "glpi.attachment.add",
        "arguments": {
            "ticket_id": ticket_id,
            "filename": file_path.name,
            "path": str(file_path),
            "size_bytes": size,
            "sha256": sha256,
            "comment": (
                f"APTWatcher incident {incident_id}"
                + (f" -- {campaign_tag}" if campaign_tag else "")
            ),
        },
    }


def _handle_result(
    result: AttachmentTransportResult,
    payload: dict[str, Any],
) -> dict[str, Any]:
    if result.returncode != 0:
        stderr_tail = (result.stderr or "").strip()[:500]
        raise PublicationError(
            f"glpi-mcp attachment.add exited {result.returncode}: "
            f"{stderr_tail or 'no stderr'}"
        )
    stdout = (result.stdout or "").strip()
    if not stdout:
        return {"payload": payload, "response": None}
    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError:
        return {"payload": payload, "response_raw": stdout}
    return {"payload": payload, "response": parsed}


def _sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# Protocol runtime check (uses a throw-away bundle dir).
_PROTOCOL_CHECK: PublicationAdapter = GLPIAttachmentAdapter(
    ticket_id=1, bundle_dir=Path(),
)
del _PROTOCOL_CHECK
