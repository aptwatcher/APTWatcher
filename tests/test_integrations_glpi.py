"""
Tests for the GLPI resolver: stub + subprocess adapter.

Every subprocess test injects a fake runner so no real CLI is spawned.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable

import pytest

from core.integrations.glpi import (
    EnrichedTicket,
    GLPIAuthError,
    GLPIBackendError,
    GLPINotFoundError,
    GLPITicketRefResolver,
    MCPSubprocessGLPIResolver,
    StubGLPIResolver,
    make_stub,
    which_cli,
)
from core.types import TicketRef

# ---------------------------------------------------------------------------
# Stub resolver
# ---------------------------------------------------------------------------


def test_stub_is_a_resolver_at_runtime() -> None:
    s = StubGLPIResolver()
    assert isinstance(s, GLPITicketRefResolver)


def test_stub_returns_enriched_ticket() -> None:
    stub = make_stub([(4242, "Phishing campaign")], base_url="https://glpi.example")
    ref = TicketRef(provider="glpi", ticket_id=4242, url=None)
    result = stub.resolve(ref)
    assert isinstance(result, EnrichedTicket)
    assert result.ref.ticket_id == 4242
    assert result.title == "Phishing campaign"
    assert result.ref.url == "https://glpi.example/ticket/4242"


def test_stub_raises_not_found_for_unknown_id() -> None:
    stub = StubGLPIResolver()
    with pytest.raises(GLPINotFoundError):
        stub.resolve(TicketRef(provider="glpi", ticket_id=1))


def test_stub_rejects_non_glpi_provider() -> None:
    stub = StubGLPIResolver()
    ref = TicketRef.model_construct(provider="other", ticket_id=1, url=None)  # type: ignore[arg-type]
    with pytest.raises(GLPIBackendError):
        stub.resolve(ref)


def test_stub_close_is_idempotent() -> None:
    stub = StubGLPIResolver()
    stub.close()
    stub.close()
    assert stub._closed is True


def test_enriched_ticket_html_summary_escapes_and_uses_glpi_tags() -> None:
    et = EnrichedTicket(
        ref=TicketRef(provider="glpi", ticket_id=9, url=None),
        title="<script>alert(1)</script>",
        requester="Jane & Co",
        category="Incident",
        priority="High",
    )
    html = et.to_glpi_html_summary()
    assert "**" not in html
    assert "##" not in html
    assert "```" not in html
    assert "&lt;script&gt;" in html
    assert "Jane &amp; Co" in html
    assert "<p>" in html
    assert "<strong>" in html
    assert "<ul>" in html
    assert "<li>" in html


# ---------------------------------------------------------------------------
# Subprocess adapter — with injected runner
# ---------------------------------------------------------------------------


def _completed(
    *,
    rc: int = 0,
    stdout: str = "",
    stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=["glpi-mcp"],
        returncode=rc,
        stdout=stdout,
        stderr=stderr,
    )


def _runner(
    response: subprocess.CompletedProcess[str],
    *,
    captured: list[list[str]] | None = None,
) -> Callable[[list[str]], subprocess.CompletedProcess[str]]:
    def _call(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        if captured is not None:
            captured.append(cmd)
        return response
    return _call


def test_subprocess_resolver_happy_path() -> None:
    payload = {
        "id": 42,
        "name": "Suspicious login",
        "requester_name": "dom",
        "itilcategory_name": "Sécurité",
        "priority_name": "High",
        "status_name": "new",
        "content": "<p>User logged in from foreign IP.</p>",
        "date_creation": "2026-04-18 22:10:00",
        "custom_field": "vendor-extra",
    }
    captured: list[list[str]] = []
    resolver = MCPSubprocessGLPIResolver(
        cli_path="glpi-mcp-test",
        base_url="https://glpi.example",
        runner=_runner(_completed(stdout=json.dumps(payload)), captured=captured),
    )
    et = resolver.resolve(TicketRef(provider="glpi", ticket_id=42, url=None))

    assert captured == [["glpi-mcp-test", "get_ticket", "--ticket-id", "42"]]
    assert et.title == "Suspicious login"
    assert et.requester == "dom"
    assert et.category == "Sécurité"
    assert et.priority == "High"
    assert et.status == "new"
    assert "foreign IP" in (et.description or "")
    assert et.created_at == "2026-04-18 22:10:00"
    assert et.extra == {"id": 42, "custom_field": "vendor-extra"}
    assert et.ref.url == "https://glpi.example/ticket/42"


def test_subprocess_resolver_preserves_existing_ref_url() -> None:
    payload = {"name": "X"}
    resolver = MCPSubprocessGLPIResolver(
        cli_path="glpi-mcp-test",
        base_url="https://glpi.example",
        runner=_runner(_completed(stdout=json.dumps(payload))),
    )
    existing = TicketRef(
        provider="glpi", ticket_id=7, url="https://other.example/t/7"
    )
    et = resolver.resolve(existing)
    assert et.ref.url == "https://other.example/t/7"


def test_subprocess_resolver_maps_404_returncode_to_not_found() -> None:
    resolver = MCPSubprocessGLPIResolver(
        cli_path="glpi-mcp", runner=_runner(_completed(rc=404))
    )
    with pytest.raises(GLPINotFoundError):
        resolver.resolve(TicketRef(provider="glpi", ticket_id=9, url=None))


def test_subprocess_resolver_maps_stderr_not_found_to_not_found() -> None:
    resolver = MCPSubprocessGLPIResolver(
        cli_path="glpi-mcp",
        runner=_runner(_completed(rc=2, stderr="Ticket does not exist")),
    )
    with pytest.raises(GLPINotFoundError):
        resolver.resolve(TicketRef(provider="glpi", ticket_id=9, url=None))


def test_subprocess_resolver_maps_401_to_auth_error() -> None:
    resolver = MCPSubprocessGLPIResolver(
        cli_path="glpi-mcp", runner=_runner(_completed(rc=401, stderr="Unauthorized"))
    )
    with pytest.raises(GLPIAuthError):
        resolver.resolve(TicketRef(provider="glpi", ticket_id=9, url=None))


def test_subprocess_resolver_maps_stderr_auth_to_auth_error() -> None:
    resolver = MCPSubprocessGLPIResolver(
        cli_path="glpi-mcp",
        runner=_runner(_completed(rc=3, stderr="authentication failed")),
    )
    with pytest.raises(GLPIAuthError):
        resolver.resolve(TicketRef(provider="glpi", ticket_id=9, url=None))


def test_subprocess_resolver_wraps_unknown_failure_as_backend_error() -> None:
    resolver = MCPSubprocessGLPIResolver(
        cli_path="glpi-mcp",
        runner=_runner(_completed(rc=5, stderr="kaboom")),
    )
    with pytest.raises(GLPIBackendError):
        resolver.resolve(TicketRef(provider="glpi", ticket_id=9, url=None))


def test_subprocess_resolver_raises_on_empty_stdout() -> None:
    resolver = MCPSubprocessGLPIResolver(
        cli_path="glpi-mcp", runner=_runner(_completed(stdout=""))
    )
    with pytest.raises(GLPIBackendError):
        resolver.resolve(TicketRef(provider="glpi", ticket_id=9, url=None))


def test_subprocess_resolver_raises_on_non_json_stdout() -> None:
    resolver = MCPSubprocessGLPIResolver(
        cli_path="glpi-mcp", runner=_runner(_completed(stdout="not json"))
    )
    with pytest.raises(GLPIBackendError):
        resolver.resolve(TicketRef(provider="glpi", ticket_id=9, url=None))


def test_subprocess_resolver_raises_on_non_object_payload() -> None:
    resolver = MCPSubprocessGLPIResolver(
        cli_path="glpi-mcp", runner=_runner(_completed(stdout="[1, 2, 3]"))
    )
    with pytest.raises(GLPIBackendError):
        resolver.resolve(TicketRef(provider="glpi", ticket_id=9, url=None))


def test_subprocess_resolver_handles_timeout() -> None:
    def runner(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=30)
    resolver = MCPSubprocessGLPIResolver(cli_path="glpi-mcp", runner=runner)
    with pytest.raises(GLPIBackendError):
        resolver.resolve(TicketRef(provider="glpi", ticket_id=9, url=None))


def test_subprocess_resolver_handles_missing_cli() -> None:
    def runner(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError(cmd[0])
    resolver = MCPSubprocessGLPIResolver(cli_path="missing", runner=runner)
    with pytest.raises(GLPIBackendError):
        resolver.resolve(TicketRef(provider="glpi", ticket_id=9, url=None))


def test_subprocess_resolver_rejects_non_glpi_provider() -> None:
    resolver = MCPSubprocessGLPIResolver(
        cli_path="glpi-mcp", runner=_runner(_completed(stdout="{}"))
    )
    ref = TicketRef.model_construct(provider="other", ticket_id=1, url=None)  # type: ignore[arg-type]
    with pytest.raises(GLPIBackendError):
        resolver.resolve(ref)


def test_subprocess_resolver_close_blocks_further_calls() -> None:
    resolver = MCPSubprocessGLPIResolver(
        cli_path="glpi-mcp", runner=_runner(_completed(stdout="{}"))
    )
    resolver.close()
    with pytest.raises(GLPIBackendError):
        resolver.resolve(TicketRef(provider="glpi", ticket_id=9, url=None))


def test_which_cli_returns_none_for_missing_binary() -> None:
    assert which_cli("definitely-not-a-real-binary-xyz") is None


def test_subprocess_resolver_falls_back_to_alt_keys() -> None:
    payload = {
        "title": "Fallback title",
        "requester": "someone",
        "category": "General",
        "priority": "Low",
        "status": "closed",
        "description": "alt desc",
        "created_at": "2026-04-01",
    }
    resolver = MCPSubprocessGLPIResolver(
        cli_path="glpi-mcp", runner=_runner(_completed(stdout=json.dumps(payload)))
    )
    et = resolver.resolve(TicketRef(provider="glpi", ticket_id=11, url=None))
    assert et.title == "Fallback title"
    assert et.requester == "someone"
    assert et.category == "General"
    assert et.priority == "Low"
    assert et.status == "closed"
    assert et.description == "alt desc"
    assert et.created_at == "2026-04-01"


def test_subprocess_resolver_defaults_title_when_missing() -> None:
    resolver = MCPSubprocessGLPIResolver(
        cli_path="glpi-mcp", runner=_runner(_completed(stdout=json.dumps({"id": 1})))
    )
    et = resolver.resolve(TicketRef(provider="glpi", ticket_id=1, url=None))
    assert et.title == "(untitled)"
