"""
Tests for `aptwatcher run` — the end-to-end skeleton command.

The run command wires preflight + audit + AgentLoop. We mock preflight so
the tests don't need real SIFT binaries, and verify (1) the exit code
honours the preflight gate, (2) an audit log is written with the expected
events, (3) --allow-missing-tools overrides a failed preflight.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from agent_extension.cli import app
from core.types import PreflightReport, ToolVersion


def _ok_report() -> PreflightReport:
    return PreflightReport(
        profile="windows-host-triage",
        tool_inventory=[ToolVersion(name="volatility3", version="2.5", path="/fake/vol", meets_minimum=True)],
        missing_required=[],
        missing_optional=[],
        evidence_manifest=[],
        tier_config={"tier_0": True},
        warnings=[],
        ok=True,
    )


def _failed_report() -> PreflightReport:
    return PreflightReport(
        profile="windows-host-triage",
        tool_inventory=[],
        missing_required=["volatility3"],
        missing_optional=[],
        evidence_manifest=[],
        tier_config={"tier_0": True},
        warnings=[],
        ok=False,
    )


def test_run_exits_1_when_preflight_fails(tmp_path: Path) -> None:
    runner = CliRunner()
    with patch("agent_extension.cli.preflight", return_value=_failed_report()):
        result = runner.invoke(
            app,
            [
                "run",
                "--incident-id", "inc-cli-fail",
                "--profile", "windows-host-triage",
                "--log-dir", str(tmp_path / "logs"),
            ],
        )
    assert result.exit_code == 1
    assert "Preflight failed" in result.stdout + (result.stderr or "")


def test_run_writes_audit_log_and_reports_zero_findings(tmp_path: Path) -> None:
    runner = CliRunner()
    logs = tmp_path / "logs"
    with patch("agent_extension.cli.preflight", return_value=_ok_report()):
        result = runner.invoke(
            app,
            [
                "run",
                "--incident-id", "inc-cli-ok",
                "--profile", "windows-host-triage",
                "--log-dir", str(logs),
            ],
        )
    assert result.exit_code == 0, result.stdout + "\n" + (result.stderr or "")
    log_path = logs / "inc-cli-ok" / "audit.jsonl"
    assert log_path.exists()
    lines = [json.loads(line) for line in log_path.read_text().splitlines() if line.strip()]
    event_types = {e["event_type"] for e in lines}
    # We expect at least these events.
    assert {"run_start", "preflight", "self_correction", "report_emit", "run_end"} <= event_types
    assert "Findings:    0" in result.stdout
    assert "null planner" in result.stdout


def test_run_allow_missing_tools_overrides_preflight(tmp_path: Path) -> None:
    runner = CliRunner()
    logs = tmp_path / "logs"
    with patch("agent_extension.cli.preflight", return_value=_failed_report()):
        result = runner.invoke(
            app,
            [
                "run",
                "--incident-id", "inc-cli-override",
                "--profile", "windows-host-triage",
                "--log-dir", str(logs),
                "--allow-missing-tools",
            ],
        )
    assert result.exit_code == 0
    assert (logs / "inc-cli-override" / "audit.jsonl").exists()
    # Preflight summary still reports "not ok".
    assert "not ok" in result.stdout


# ---------------------------------------------------------------------------
# --backend flag wiring
# ---------------------------------------------------------------------------


def test_run_backend_anthropic_without_api_key_exits_2(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    runner = CliRunner()
    with patch("agent_extension.cli.preflight", return_value=_ok_report()):
        result = runner.invoke(
            app,
            [
                "run",
                "--incident-id", "inc-no-key",
                "--profile", "windows-host-triage",
                "--log-dir", str(tmp_path / "logs"),
                "--backend", "anthropic",
            ],
        )
    assert result.exit_code == 2
    combined = result.stdout + (result.stderr or "")
    assert "anthropic" in combined.lower()
    assert "API key" in combined or "api key" in combined or "API KEY" in combined


def test_run_unknown_backend_exits_2(tmp_path: Path) -> None:
    runner = CliRunner()
    with patch("agent_extension.cli.preflight", return_value=_ok_report()):
        result = runner.invoke(
            app,
            [
                "run",
                "--incident-id", "inc-bad-backend",
                "--profile", "windows-host-triage",
                "--log-dir", str(tmp_path / "logs"),
                "--backend", "nonsense",
            ],
        )
    assert result.exit_code == 2
    combined = result.stdout + (result.stderr or "")
    assert "Unknown backend" in combined
    assert "nonsense" in combined


def test_run_backend_anthropic_wires_llm_strategies(
    tmp_path: Path, monkeypatch,
) -> None:
    """
    End-to-end: patch AnthropicModelClient so no network I/O happens,
    patch the three LLM strategies so the loop uses null-ish stand-ins
    that record construction calls. Assert the flags reach the factory.
    """
    monkeypatch.setenv("APTW_TEST_KEY", "sk-xyz")

    class _DummyClient:
        def __init__(self, **kw) -> None:
            self.kwargs = kw
            self.closed = False

        def close(self) -> None:
            self.closed = True

    created: dict[str, object] = {}

    def fake_client_factory(**kwargs):
        c = _DummyClient(**kwargs)
        created["client"] = c
        return c

    def stub_planner(**kwargs):
        created["planner_kwargs"] = kwargs
        from core.agent_loop import _NullPlanner
        return _NullPlanner()

    def stub_verifier(**kwargs):
        created["verifier_kwargs"] = kwargs
        from core.agent_loop import _NullVerifier
        return _NullVerifier()

    def stub_selfc(**kwargs):
        created["selfc_kwargs"] = kwargs
        from core.agent_loop import _NullSelfCorrector
        return _NullSelfCorrector()

    runner = CliRunner()
    logs = tmp_path / "logs"
    with patch("agent_extension.cli.preflight", return_value=_ok_report()), \
         patch("agent_extension.cli.AnthropicModelClient", side_effect=fake_client_factory), \
         patch("agent_extension.cli.LLMPlanner", side_effect=stub_planner), \
         patch("agent_extension.cli.LLMVerifier", side_effect=stub_verifier), \
         patch("agent_extension.cli.LLMSelfCorrector", side_effect=stub_selfc):
        result = runner.invoke(
            app,
            [
                "run",
                "--incident-id", "inc-llm",
                "--profile", "windows-host-triage",
                "--log-dir", str(logs),
                "--backend", "anthropic",
                "--model", "claude-test-123",
                "--api-key-env", "APTW_TEST_KEY",
            ],
        )

    assert result.exit_code == 0, result.stdout + "\n" + (result.stderr or "")
    # Client built with model + api_key
    client = created["client"]
    assert isinstance(client, _DummyClient)
    assert client.kwargs["model"] == "claude-test-123"
    assert client.kwargs["api_key"] == "sk-xyz"
    # Strategies built with client + audit
    assert created["planner_kwargs"]["client"] is client
    assert created["verifier_kwargs"]["client"] is client
    assert created["selfc_kwargs"]["client"] is client
    assert created["planner_kwargs"]["audit"] is not None
    # Summary reflects the backend
    assert "Backend:" in result.stdout
    assert "anthropic" in result.stdout
    # Client closed after loop
    assert client.closed is True


def test_run_default_backend_is_null(tmp_path: Path) -> None:
    """Default --backend=null should still use null strategies and print
    the 'null planner' hint in the summary."""
    runner = CliRunner()
    with patch("agent_extension.cli.preflight", return_value=_ok_report()):
        result = runner.invoke(
            app,
            [
                "run",
                "--incident-id", "inc-default",
                "--profile", "windows-host-triage",
                "--log-dir", str(tmp_path / "logs"),
            ],
        )
    assert result.exit_code == 0
    assert "Backend:" in result.stdout
    assert "null" in result.stdout
    assert "null planner" in result.stdout


# ---------------------------------------------------------------------------
# KB context injection (task #42)
# ---------------------------------------------------------------------------


def test_profile_search_query_concatenates_profile_fields() -> None:
    from agent_extension.cli import _profile_search_query
    from core.types import ProfileDefinition

    p = ProfileDefinition(
        name="windows-host-triage",
        description="Standard Windows host triage.",
        required_tools=["vol.py"],
        optional_tools=["plaso"],
        required_artifact_categories=["memory"],
        optional_artifact_categories=["registry"],
    )
    q = _profile_search_query(p)
    # Every field surface should appear in the query.
    for needle in ["windows-host-triage", "Standard Windows", "vol.py", "plaso",
                   "memory", "registry"]:
        assert needle in q


def test_format_kb_context_truncates_long_bodies() -> None:
    from agent_extension.cli import _format_kb_context
    from core.types import KBEntry

    entries = [
        KBEntry(
            id="kb-001",
            title="Process injection patterns",
            source_type="author-original",
            attribution="APTWatcher",
            mitre_techniques=["T1055", "T1055.012"],
            artifact_types=["memory"],
            tools=["volatility3"],
            last_updated="2026-04-01",
            body="x" * 1000,
            path="knowledge/kb-001.md",
        ),
        KBEntry(
            id="kb-002",
            title="Short note",
            source_type="author-original",
            attribution="APTWatcher",
            mitre_techniques=[],
            artifact_types=[],
            tools=[],
            last_updated="2026-04-01",
            body="brief",
            path="knowledge/kb-002.md",
        ),
    ]
    out = _format_kb_context(entries, body_chars=50)
    assert "kb-001 :: Process injection patterns" in out
    assert "T1055, T1055.012" in out
    # The long body is truncated.
    assert "x" * 50 not in out  # 50-char raw body would appear verbatim
    assert "…" in out
    # Short entry reports "—" for empty MITRE and keeps its body intact.
    assert "kb-002 :: Short note (MITRE: —) :: brief" in out


def test_format_kb_context_empty_list_returns_empty_string() -> None:
    from agent_extension.cli import _format_kb_context
    assert _format_kb_context([]) == ""


def test_kb_context_for_profile_returns_empty_when_root_missing(
    tmp_path: Path,
) -> None:
    from agent_extension.cli import _kb_context_for_profile
    from core.types import ProfileDefinition

    p = ProfileDefinition(
        name="test", description="", required_tools=[],
    )
    result = _kb_context_for_profile(
        profile=p,
        knowledge_root=tmp_path / "does-not-exist",
    )
    assert result == ""


def test_run_backend_anthropic_threads_kb_context_into_planner(
    tmp_path: Path, monkeypatch,
) -> None:
    """
    End-to-end wiring: when --backend=anthropic with a real knowledge
    root, _kb_context_for_profile pulls KB hits, _build_llm_strategies
    passes them through to LLMPlanner.kb_context, and the profile is
    also threaded.
    """
    monkeypatch.setenv("APTW_TEST_KEY", "sk-xyz")

    class _DummyClient:
        def __init__(self, **kw):
            self.kwargs = kw
            self.closed = False

        def close(self):
            self.closed = True

    created: dict[str, object] = {}

    def stub_planner(**kwargs):
        created["planner_kwargs"] = kwargs
        from core.agent_loop import _NullPlanner
        return _NullPlanner()

    def stub_verifier(**kwargs):
        from core.agent_loop import _NullVerifier
        return _NullVerifier()

    def stub_selfc(**kwargs):
        from core.agent_loop import _NullSelfCorrector
        return _NullSelfCorrector()

    runner = CliRunner()
    logs = tmp_path / "logs"
    with patch("agent_extension.cli.preflight", return_value=_ok_report()), \
         patch("agent_extension.cli.AnthropicModelClient", side_effect=_DummyClient), \
         patch("agent_extension.cli.LLMPlanner", side_effect=stub_planner), \
         patch("agent_extension.cli.LLMVerifier", side_effect=stub_verifier), \
         patch("agent_extension.cli.LLMSelfCorrector", side_effect=stub_selfc), \
         patch(
             "agent_extension.cli._kb_context_for_profile",
             return_value="- kb-001 :: Sample :: body",
         ):
        result = runner.invoke(
            app,
            [
                "run",
                "--incident-id", "inc-kb",
                "--profile", "windows-host-triage",
                "--log-dir", str(logs),
                "--backend", "anthropic",
                "--api-key-env", "APTW_TEST_KEY",
                "--knowledge-root", str(tmp_path / "knowledge"),
            ],
        )

    assert result.exit_code == 0, result.stdout + "\n" + (result.stderr or "")
    kw = created["planner_kwargs"]
    assert kw["kb_context"] == "- kb-001 :: Sample :: body"
    # profile threaded through
    assert kw["profile"] is not None
    assert kw["profile"].name == "windows-host-triage"
    # Summary signals KB context present
    assert "KB context:  yes" in result.stdout


def test_run_backend_anthropic_reports_no_kb_when_knowledge_root_missing(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.setenv("APTW_TEST_KEY", "sk-xyz")

    class _DummyClient:
        def __init__(self, **kw): self.closed = False
        def close(self): self.closed = True

    captured: dict[str, object] = {}

    def stub_planner(**kwargs):
        captured["planner_kwargs"] = kwargs
        from core.agent_loop import _NullPlanner
        return _NullPlanner()

    runner = CliRunner()
    with patch("agent_extension.cli.preflight", return_value=_ok_report()), \
         patch("agent_extension.cli.AnthropicModelClient", side_effect=_DummyClient), \
         patch("agent_extension.cli.LLMPlanner", side_effect=stub_planner), \
         patch("agent_extension.cli.LLMVerifier") as _v, \
         patch("agent_extension.cli.LLMSelfCorrector") as _sc:
        # V/SC return null stand-ins
        from core.agent_loop import _NullSelfCorrector, _NullVerifier
        _v.side_effect = lambda **kwargs: _NullVerifier()
        _sc.side_effect = lambda **kwargs: _NullSelfCorrector()

        result = runner.invoke(
            app,
            [
                "run",
                "--incident-id", "inc-no-kb",
                "--profile", "windows-host-triage",
                "--log-dir", str(tmp_path / "logs"),
                "--backend", "anthropic",
                "--api-key-env", "APTW_TEST_KEY",
                "--knowledge-root", str(tmp_path / "missing"),
            ],
        )

    assert result.exit_code == 0, result.stdout + "\n" + (result.stderr or "")
    # kb_context resolves to None (empty string -> None via `or None`).
    assert captured["planner_kwargs"]["kb_context"] is None
    assert "KB context:  no" in result.stdout


# ---------------------------------------------------------------------------
# --dry-run (task #43)
# ---------------------------------------------------------------------------


def test_dry_run_prints_planner_inputs_and_exits_0(tmp_path: Path) -> None:
    """--dry-run should print incident_id/profile/backend/preflight summary
    and not create any audit log file."""
    runner = CliRunner()
    logs = tmp_path / "logs"
    with patch("agent_extension.cli.preflight", return_value=_ok_report()):
        result = runner.invoke(
            app,
            [
                "run",
                "--incident-id", "inc-dry",
                "--profile", "windows-host-triage",
                "--log-dir", str(logs),
                "--backend", "null",
                "--dry-run",
            ],
        )
    assert result.exit_code == 0, result.stdout + "\n" + (result.stderr or "")
    out = result.stdout
    assert "Dry run complete" in out
    assert "incident_id" in out
    assert "inc-dry" in out
    assert "profile" in out
    assert "windows-host-triage" in out
    assert "backend" in out
    # null backend -> api_key_env shown as "(unused)"
    assert "(unused)" in out
    # preflight summary line
    assert "preflight_ok" in out
    # No audit log written.
    assert not logs.exists() or not any(logs.rglob("audit.jsonl"))


def test_dry_run_anthropic_backend_shows_model_and_api_key_env(
    tmp_path: Path, monkeypatch,
) -> None:
    """--dry-run with --backend=anthropic should NOT attempt to read the
    API key or construct the client -- it just reports what would be used."""
    # Intentionally don't set the env var: dry-run must not require it.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    runner = CliRunner()
    with patch("agent_extension.cli.preflight", return_value=_ok_report()), \
         patch(
             "agent_extension.cli._kb_context_for_profile",
             return_value="- kb-001 :: sample :: body",
         ):
        result = runner.invoke(
            app,
            [
                "run",
                "--incident-id", "inc-dry-llm",
                "--profile", "windows-host-triage",
                "--log-dir", str(tmp_path / "logs"),
                "--backend", "anthropic",
                "--model", "claude-dry",
                "--dry-run",
            ],
        )
    assert result.exit_code == 0, result.stdout + "\n" + (result.stderr or "")
    out = result.stdout
    assert "claude-dry" in out
    assert "ANTHROPIC_API_KEY" in out
    # KB context printed
    assert "kb-001" in out


def test_dry_run_does_not_construct_anthropic_client(
    tmp_path: Path, monkeypatch,
) -> None:
    """Regression guard: --dry-run must never instantiate AnthropicModelClient."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    constructor_calls: list[object] = []

    def fake_client(**kw):
        constructor_calls.append(kw)
        raise AssertionError("AnthropicModelClient must NOT be constructed in dry-run")

    runner = CliRunner()
    with patch("agent_extension.cli.preflight", return_value=_ok_report()), \
         patch("agent_extension.cli.AnthropicModelClient", side_effect=fake_client):
        result = runner.invoke(
            app,
            [
                "run",
                "--incident-id", "inc-dry-guard",
                "--profile", "windows-host-triage",
                "--log-dir", str(tmp_path / "logs"),
                "--backend", "anthropic",
                "--dry-run",
            ],
        )
    assert result.exit_code == 0
    assert constructor_calls == []
