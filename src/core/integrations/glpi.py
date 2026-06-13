"""
GLPI ticket-ref resolver.

APTWatcher's shared brain references tickets through the thin
`core.types.TicketRef` shape. When the agent needs to correlate a
finding with ticket metadata (title, requester, category, priority),
it asks the configured `GLPITicketRefResolver` for an `EnrichedTicket`.

Two implementations live here:

- `StubGLPIResolver`      In-memory, for tests and offline demos.
- `MCPSubprocessGLPIResolver`  Shells out to the `glpi-mcp` CLI as an
                               MCP tool call, via an injectable
                               runner so tests never spawn a real
                               subprocess.

**GLPI content-field rule (per user preference):** any payload this
module *writes back* into GLPI (ticket comments, followups, solutions,
tasks) must be HTML-formatted, never Markdown. Only read-side helpers
live in this file today. Write-side helpers, when added, must honor
the `to_glpi_html()` formatter on `EnrichedTicket` and never pass
Markdown through.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from core.types import TicketRef

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class GLPIResolverError(RuntimeError):
    """Base class for glpi-mcp integration failures."""


class GLPINotFoundError(GLPIResolverError):
    """The ticket ID does not exist (or is not visible to the session)."""


class GLPIAuthError(GLPIResolverError):
    """The glpi-mcp session could not authenticate."""


class GLPIBackendError(GLPIResolverError):
    """glpi-mcp CLI exited non-zero or returned malformed JSON."""


# ---------------------------------------------------------------------------
# EnrichedTicket value object
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EnrichedTicket:
    """
    The ticket view APTWatcher actually reasons over. Immutable.

    `ref` is the pointer the shared brain stores; the other fields are
    enrichment cached for the duration of one incident.
    """

    ref: TicketRef
    title: str
    requester: str | None = None
    category: str | None = None
    priority: str | None = None
    status: str | None = None
    description: str | None = None
    created_at: str | None = None
    extra: Mapping[str, Any] = field(default_factory=dict)

    # HTML output helper — honors the GLPI content-field rule.
    def to_glpi_html_summary(self) -> str:
        """
        Render a one-paragraph HTML summary suitable for pasting into a
        GLPI followup. Output is sanitized to GLPI-compatible tags only.
        """
        parts = [f"<p><strong>Ticket #{self.ref.ticket_id}</strong>: {_h(self.title)}</p>"]
        meta_bits: list[str] = []
        if self.requester:
            meta_bits.append(f"<li>Requester: {_h(self.requester)}</li>")
        if self.category:
            meta_bits.append(f"<li>Category: {_h(self.category)}</li>")
        if self.priority:
            meta_bits.append(f"<li>Priority: {_h(self.priority)}</li>")
        if self.status:
            meta_bits.append(f"<li>Status: {_h(self.status)}</li>")
        if meta_bits:
            parts.append("<ul>" + "".join(meta_bits) + "</ul>")
        return "".join(parts)


def _h(value: str) -> str:
    """Minimal HTML escaping for GLPI content fields."""
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class GLPITicketRefResolver(Protocol):
    """
    Contract for turning a `TicketRef` into an `EnrichedTicket`.

    Resolvers MUST:
    - Return an `EnrichedTicket` whose `ref` matches the argument.
    - Raise `GLPINotFoundError` for unknown ticket IDs.
    - Raise `GLPIAuthError` if the underlying session can't authenticate.
    - Raise `GLPIBackendError` for anything else (including malformed
      responses). Never leak raw transport exceptions.
    """

    def resolve(self, ref: TicketRef) -> EnrichedTicket: ...

    def close(self) -> None: ...


# ---------------------------------------------------------------------------
# Stub — in-memory
# ---------------------------------------------------------------------------


@dataclass
class StubGLPIResolver:
    """Deterministic in-memory resolver for tests and offline demos."""

    tickets: dict[int, EnrichedTicket] = field(default_factory=dict)
    _closed: bool = False

    def resolve(self, ref: TicketRef) -> EnrichedTicket:
        if ref.provider != "glpi":
            raise GLPIBackendError(
                f"stub resolver only supports provider='glpi', got {ref.provider!r}"
            )
        enriched = self.tickets.get(ref.ticket_id)
        if enriched is None:
            raise GLPINotFoundError(f"ticket {ref.ticket_id} not found in stub")
        return enriched

    def close(self) -> None:
        self._closed = True


def make_stub(
    entries: Iterable[tuple[int, str]],
    *,
    base_url: str | None = None,
) -> StubGLPIResolver:
    """Shorthand for `StubGLPIResolver` with `(ticket_id, title)` pairs."""
    store: dict[int, EnrichedTicket] = {}
    for ticket_id, title in entries:
        url = (
            f"{base_url.rstrip('/')}/ticket/{ticket_id}"
            if base_url is not None
            else None
        )
        store[ticket_id] = EnrichedTicket(
            ref=TicketRef(provider="glpi", ticket_id=ticket_id, url=url),
            title=title,
        )
    return StubGLPIResolver(tickets=store)


# ---------------------------------------------------------------------------
# Subprocess adapter — shells out to the glpi-mcp CLI
# ---------------------------------------------------------------------------


SubprocessRunner = Callable[[list[str]], "subprocess.CompletedProcess[str]"]


def _default_runner(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


@dataclass
class MCPSubprocessGLPIResolver:
    """
    Shells out to the glpi-mcp CLI to resolve a `TicketRef`.

    The concrete invocation is:

        <cli_path> get_ticket --ticket-id <id>

    expecting JSON on stdout matching the shape returned by
    `glpi-mcp`'s `get_ticket` tool. Every transport dependency is
    injectable so tests don't spawn real subprocesses.
    """

    cli_path: str = "glpi-mcp"
    base_url: str | None = None
    runner: SubprocessRunner = field(default=_default_runner)
    _closed: bool = False

    def resolve(self, ref: TicketRef) -> EnrichedTicket:
        if ref.provider != "glpi":
            raise GLPIBackendError(
                f"glpi resolver called with provider={ref.provider!r}"
            )
        if self._closed:
            raise GLPIBackendError("resolver is closed")

        cmd = [self.cli_path, "get_ticket", "--ticket-id", str(ref.ticket_id)]
        try:
            completed = self.runner(cmd)
        except FileNotFoundError as exc:
            raise GLPIBackendError(
                f"glpi-mcp CLI not found: {self.cli_path!r}"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise GLPIBackendError(
                f"glpi-mcp get_ticket timed out: {exc}"
            ) from exc

        rc = completed.returncode
        stdout = (completed.stdout or "").strip()
        stderr = (completed.stderr or "").strip()

        if rc == 404 or _looks_like_not_found(stderr):
            raise GLPINotFoundError(
                f"ticket {ref.ticket_id} not found (rc={rc})"
            )
        if rc in (401, 403) or _looks_like_auth(stderr):
            raise GLPIAuthError(
                f"glpi-mcp auth failed (rc={rc}): {stderr or 'no stderr'}"
            )
        if rc != 0:
            raise GLPIBackendError(
                f"glpi-mcp get_ticket failed (rc={rc}): {stderr or 'no stderr'}"
            )
        if not stdout:
            raise GLPIBackendError("glpi-mcp get_ticket returned empty stdout")

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise GLPIBackendError(
                f"glpi-mcp returned non-JSON stdout: {exc}"
            ) from exc

        if not isinstance(data, dict):
            raise GLPIBackendError(
                f"glpi-mcp get_ticket returned unexpected type: {type(data).__name__}"
            )

        return self._from_payload(ref, data)

    def close(self) -> None:
        self._closed = True

    # --- Payload mapping -------------------------------------------------

    def _from_payload(
        self,
        ref: TicketRef,
        payload: Mapping[str, Any],
    ) -> EnrichedTicket:
        title = _take_str(payload, "name", "title", default="(untitled)")
        requester = _take_str(payload, "requester_name", "requester")
        category = _take_str(payload, "itilcategory_name", "category")
        priority = _take_str(payload, "priority_name", "priority")
        status = _take_str(payload, "status_name", "status")
        description = _take_str(payload, "content", "description")
        created_at = _take_str(payload, "date_creation", "created_at", "date")

        resolved_url = ref.url
        if resolved_url is None and self.base_url:
            resolved_url = f"{self.base_url.rstrip('/')}/ticket/{ref.ticket_id}"
        resolved_ref = (
            ref
            if resolved_url == ref.url
            else TicketRef(
                provider="glpi", ticket_id=ref.ticket_id, url=resolved_url
            )
        )

        return EnrichedTicket(
            ref=resolved_ref,
            title=title or "(untitled)",
            requester=requester,
            category=category,
            priority=priority,
            status=status,
            description=description,
            created_at=created_at,
            extra={k: v for k, v in payload.items() if k not in _KNOWN_KEYS},
        )


_KNOWN_KEYS = {
    "name",
    "title",
    "requester_name",
    "requester",
    "itilcategory_name",
    "category",
    "priority_name",
    "priority",
    "status_name",
    "status",
    "content",
    "description",
    "date_creation",
    "created_at",
    "date",
}


def _take_str(
    payload: Mapping[str, Any],
    *keys: str,
    default: str | None = None,
) -> str | None:
    for k in keys:
        v = payload.get(k)
        if isinstance(v, str) and v:
            return v
        if isinstance(v, (int, float)):
            return str(v)
    return default


def _looks_like_not_found(stderr: str) -> bool:
    s = stderr.lower()
    return "not found" in s or "does not exist" in s or "404" in s


def _looks_like_auth(stderr: str) -> bool:
    s = stderr.lower()
    return (
        "unauthorized" in s
        or "forbidden" in s
        or "authentication" in s
        or "401" in s
        or "403" in s
    )


def which_cli(cli_path: str = "glpi-mcp") -> str | None:
    """Thin wrapper around shutil.which for operator-facing health checks."""
    return shutil.which(cli_path)


# Protocol runtime check
_PROTOCOL_CHECK: GLPITicketRefResolver = StubGLPIResolver()
del _PROTOCOL_CHECK
