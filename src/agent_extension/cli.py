"""
CLI entry point (Mode A).

Wires the shared brain to a Typer app. Every command below is a thin
adapter over a `core` function -- no business logic lives here. The CLI
exists so an operator on a SIFT VM can run `aptwatcher preflight` without
standing up an MCP server.

Console scripts (see pyproject.toml):
- `aptwatcher` -> `app` (Typer app with subcommands)
- `aptwatcher-preflight` -> `preflight_command` (direct preflight shortcut)

References:
- docs/deployment/mode-a.md
- docs/reference/mcp-tools.md (what each command wraps)
"""

# NOTE: deliberately no `from __future__ import annotations` here. Typer
# inspects signatures with `inspect.signature(..., eval_str=True)`; under
# __future__ annotations every type becomes a string that Typer re-evals,
# and the re-eval mis-parses `Annotated[..., typer.Option(...)]`.

import argparse
import os
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from agent_extension.analyze import cmd_analyze
from agent_extension.audit_render import cmd_audit_render
from agent_extension.publish import ALLOWED_ADAPTERS, cmd_publish
from core import (
    ALL_PROFILES,
    AgentLoop,
    AnthropicAdapterError,
    AnthropicAuthError,
    AnthropicModelClient,
    APTWatcherConfig,
    AuditLogger,
    KBEntry,
    KnowledgeBase,
    LLMPlanner,
    LLMSelfCorrector,
    LLMVerifier,
    ProfileDefinition,
    __version__,
    default_config,
    get_profile,
    load_config,
    preflight,
)

app = typer.Typer(
    name="aptwatcher",
    help="Autonomous defensive IR agent on SANS SIFT.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_config_or_default(config_path):
    """Load config from path if given; otherwise use the Tier 0-only default."""
    if config_path is None:
        return default_config()
    if not config_path.exists():
        err_console.print(f"[red]Config file not found:[/red] {config_path}")
        raise typer.Exit(code=2)
    return load_config(config_path)


def _tier_flags(cfg: APTWatcherConfig):
    t = cfg.tiers
    return {
        "tier_0": t.tier_0,
        "tier_1": t.tier_1,
        "tier_2": t.tier_2,
        "tier_3": t.tier_3,
        "tier_4": t.tier_4,
    }


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@app.command("version")
def version_command():
    """Print the APTWatcher version and exit."""
    console.print(f"aptwatcher {__version__}")


@app.command("profiles")
def profiles_command(
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON instead of a table.")] = False,
):
    """List all registered use-case profiles."""
    if as_json:
        console.print_json(
            data={
                name: {
                    "description": p.description,
                    "required_tools": p.required_tools,
                    "optional_tools": p.optional_tools,
                    "required_artifact_categories": p.required_artifact_categories,
                }
                for name, p in ALL_PROFILES.items()
            },
        )
        return

    table = Table(title="Registered profiles", show_lines=False)
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Required tools", style="white")
    table.add_column("Description", style="dim")
    for name, prof in ALL_PROFILES.items():
        table.add_row(name, ", ".join(prof.required_tools), prof.description)
    console.print(table)


@app.command("preflight")
def preflight_command(
    profile: Annotated[str, typer.Option("--profile", "-p", help="Profile name.")] = "windows-host-triage",
    config_path: Annotated[Path | None, typer.Option("--config", "-c", help="Path to config.yaml.")] = None,
    evidence: Annotated[list[Path] | None, typer.Option("--evidence", "-e", help="Evidence file paths (repeatable).")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON output.")] = False,
):
    """Run preflight: probe SIFT tools, classify evidence, report gaps."""
    cfg = _load_config_or_default(config_path)
    report = preflight(
        profile_name=profile,
        evidence_paths=evidence,
        tier_config=_tier_flags(cfg),
    )

    if as_json:
        console.print_json(report.model_dump_json())
        raise typer.Exit(code=0 if report.ok else 1)

    status_style = "green" if report.ok else "red"
    status_text = "OK" if report.ok else "NOT OK"
    console.rule(f"[{status_style}]Preflight {status_text}[/{status_style}] -- profile: {report.profile}")

    if report.missing_required:
        console.print(f"[red]Missing required tools:[/red] {', '.join(report.missing_required)}")
    if report.missing_optional:
        console.print(f"[yellow]Missing optional tools:[/yellow] {', '.join(report.missing_optional)}")
    if report.warnings:
        for w in report.warnings:
            console.print(f"[yellow]![/yellow] {w}")

    if report.tool_inventory:
        tbl = Table(title="Tool inventory")
        tbl.add_column("Tool", style="cyan")
        tbl.add_column("Version")
        tbl.add_column("Path", style="dim")
        tbl.add_column("Meets min", justify="center")
        for tv in report.tool_inventory:
            tbl.add_row(
                tv.name,
                tv.version or "[dim](unparsed)[/dim]",
                tv.path,
                "[green]y[/green]" if tv.meets_minimum else "[red]n[/red]",
            )
        console.print(tbl)

    if report.evidence_manifest:
        etbl = Table(title="Evidence manifest")
        etbl.add_column("Path", style="cyan")
        etbl.add_column("Kind")
        etbl.add_column("Size (bytes)", justify="right")
        etbl.add_column("SHA-256", style="dim")
        for ev in report.evidence_manifest:
            etbl.add_row(ev.path, ev.kind, f"{ev.size_bytes:,}", ev.sha256)
        console.print(etbl)

    raise typer.Exit(code=0 if report.ok else 1)


def preflight_entry() -> None:
    """Console-script entry for `aptwatcher-preflight`.

    Wraps the Typer command in its own single-command app so option
    parsing and `typer.Exit` are handled properly when the script is
    invoked directly (pyproject `[project.scripts]`).
    """
    typer.run(preflight_command)


@app.command("knowledge-search")
def knowledge_search_command(
    query: Annotated[str, typer.Argument(help="Search phrase.")],
    knowledge_root: Annotated[Path, typer.Option("--knowledge-root", "-k", help="Path to the knowledge/ directory.")] = Path("knowledge"),
    top_k: Annotated[int, typer.Option("--top", help="How many entries to return.")] = 5,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON output.")] = False,
):
    """Keyword search across the knowledge base."""
    if not knowledge_root.exists():
        err_console.print(f"[yellow]Knowledge root not found:[/yellow] {knowledge_root}")
        err_console.print("[dim]No entries to search. Populate `knowledge/` first.[/dim]")
        raise typer.Exit(code=2)

    kb = KnowledgeBase(knowledge_root)
    if kb.load_errors:
        err_console.print(f"[yellow]KB load warnings: {len(kb.load_errors)} malformed entries[/yellow]")
        for e in kb.load_errors:
            err_console.print(f"  - {e}")

    hits = kb.search(query, top_k=top_k)

    if as_json:
        console.print_json(
            data=[
                {
                    "id": h.id,
                    "title": h.title,
                    "source_type": h.source_type,
                    "path": h.path,
                    "mitre_techniques": h.mitre_techniques,
                }
                for h in hits
            ],
        )
        return

    if not hits:
        console.print(f"[dim]No entries matched {query!r}[/dim]")
        return

    tbl = Table(title=f"Top {len(hits)} KB hits for {query!r}")
    tbl.add_column("ID", style="cyan")
    tbl.add_column("Title")
    tbl.add_column("Source", style="dim")
    tbl.add_column("MITRE")
    for h in hits:
        tbl.add_row(h.id, h.title, h.source_type, ", ".join(h.mitre_techniques) or "--")
    console.print(tbl)


_VALID_BACKENDS = ("null", "anthropic")

# Cap on how many KB entries we surface to the planner. Keep the prompt
# compact -- the planner can always issue follow-up queries later.
_KB_CONTEXT_TOP_K = 5


def _profile_search_query(profile: ProfileDefinition) -> str:
    """Build a KB search query from a profile's metadata."""
    parts: list[str] = [profile.name]
    if profile.description:
        parts.append(profile.description)
    parts.extend(profile.required_artifact_categories)
    parts.extend(profile.optional_artifact_categories)
    parts.extend(profile.required_tools)
    parts.extend(profile.optional_tools)
    return " ".join(parts)


def _format_kb_context(entries: list[KBEntry], *, body_chars: int = 300) -> str:
    """Render KB hits as a compact prompt block."""
    if not entries:
        return ""
    lines: list[str] = []
    for e in entries:
        mitre = ", ".join(e.mitre_techniques) if e.mitre_techniques else "—"
        body = (e.body or "").strip().replace("\n", " ")
        if len(body) > body_chars:
            body = body[: body_chars - 1].rstrip() + "…"
        lines.append(f"- {e.id} :: {e.title} (MITRE: {mitre}) :: {body}")
    return "\n".join(lines)


def _kb_context_for_profile(
    *,
    profile: ProfileDefinition,
    knowledge_root: Path,
) -> str:
    """Return a formatted KB excerpt for the given profile, or ''."""
    if not knowledge_root.exists() or not knowledge_root.is_dir():
        return ""
    kb = KnowledgeBase(knowledge_root)
    if kb.load_errors:
        for e in kb.load_errors:
            err_console.print(f"[yellow]KB load warning:[/yellow] {e}")
    query = _profile_search_query(profile)
    hits = kb.search(query, top_k=_KB_CONTEXT_TOP_K)
    return _format_kb_context(hits)


def _build_llm_strategies(
    *,
    backend: str,
    model: str | None,
    api_key_env: str,
    audit: AuditLogger,
    profile: ProfileDefinition | None = None,
    kb_context: str | None = None,
) -> tuple[LLMPlanner | None, LLMVerifier | None, LLMSelfCorrector | None, AnthropicModelClient | None]:
    """Instantiate LLM-backed strategies for the given backend."""
    if backend == "null":
        return None, None, None, None
    if backend == "anthropic":
        api_key = os.environ.get(api_key_env)
        if not api_key:
            err_console.print(
                f"[red]Backend 'anthropic' requires an API key.[/red] "
                f"Set {api_key_env} in the environment, or pass --api-key-env.",
            )
            raise typer.Exit(code=2)
        try:
            if model:
                client = AnthropicModelClient(api_key=api_key, model=model)
            else:
                client = AnthropicModelClient(api_key=api_key)
        except AnthropicAuthError as exc:
            err_console.print(f"[red]Anthropic client refused to start:[/red] {exc}")
            raise typer.Exit(code=2) from exc
        planner = LLMPlanner(
            client=client,
            audit=audit,
            profile=profile,
            kb_context=kb_context or None,
        )
        verifier = LLMVerifier(client=client, audit=audit)
        self_corrector = LLMSelfCorrector(client=client, audit=audit)
        return planner, verifier, self_corrector, client
    err_console.print(
        f"[red]Unknown backend:[/red] {backend!r}. "
        f"Choose from: {', '.join(_VALID_BACKENDS)}.",
    )
    raise typer.Exit(code=2)


def _preflight_summary_text(report) -> str:
    """One-line per tool: 'name version ok|missing'."""
    if not report.tool_inventory and not report.missing_required:
        return "(no tools probed)"
    lines: list[str] = []
    for tv in report.tool_inventory:
        tag = "ok" if tv.meets_minimum else "below-min"
        ver = tv.version or "?"
        lines.append(f"{tv.name} {ver} {tag}")
    for name in report.missing_required:
        lines.append(f"{name} MISSING_REQUIRED")
    for name in report.missing_optional:
        lines.append(f"{name} MISSING_OPTIONAL")
    return "; ".join(lines)


def _print_dry_run(
    *,
    incident_id: str,
    profile_def: ProfileDefinition | None,
    profile_name: str,
    report,
    backend: str,
    model: str | None,
    api_key_env: str,
    kb_context: str | None,
    knowledge_root: Path,
) -> None:
    """Print everything the planner would see. No side effects, no LLM calls."""
    console.rule(f"[cyan]aptwatcher run --dry-run[/cyan] -- incident {incident_id}")

    tbl = Table(title="Resolved run inputs", show_lines=False)
    tbl.add_column("Key", style="cyan", no_wrap=True)
    tbl.add_column("Value", style="white")
    tbl.add_row("incident_id", incident_id)
    tbl.add_row("profile", profile_name)
    tbl.add_row("backend", backend)
    tbl.add_row("model", model or "(adapter default)")
    tbl.add_row("api_key_env", api_key_env if backend == "anthropic" else "(unused)")
    tbl.add_row("knowledge_root", str(knowledge_root))
    tbl.add_row("preflight_ok", "yes" if report.ok else "no")
    console.print(tbl)

    if profile_def is not None:
        ptbl = Table(title="Profile metadata", show_lines=False)
        ptbl.add_column("Field", style="cyan")
        ptbl.add_column("Value")
        ptbl.add_row("name", profile_def.name)
        ptbl.add_row("description", profile_def.description or "")
        ptbl.add_row("required_tools", ", ".join(profile_def.required_tools) or "--")
        ptbl.add_row("optional_tools", ", ".join(profile_def.optional_tools) or "--")
        ptbl.add_row(
            "required_artifact_categories",
            ", ".join(profile_def.required_artifact_categories) or "--",
        )
        ptbl.add_row(
            "optional_artifact_categories",
            ", ".join(profile_def.optional_artifact_categories) or "--",
        )
        console.print(ptbl)
    else:
        err_console.print(f"[yellow]profile {profile_name!r} not registered[/yellow]")

    console.rule("[dim]Preflight summary (what the planner will see)[/dim]")
    console.print(_preflight_summary_text(report))

    console.rule("[dim]KB context (what the planner will see)[/dim]")
    if kb_context:
        console.print(kb_context)
    else:
        console.print("[dim](none -- backend is null, knowledge root missing, or no hits)[/dim]")

    console.rule("[green]Dry run complete -- no audit log written, no model calls made[/green]")


@app.command("run")
def run_command(
    incident_id: Annotated[str, typer.Option("--incident-id", "-i", help="Stable identifier for this triage run.")],
    profile: Annotated[str, typer.Option("--profile", "-p", help="Profile name.")] = "windows-host-triage",
    config_path: Annotated[Path | None, typer.Option("--config", "-c", help="Path to config.yaml.")] = None,
    evidence: Annotated[list[Path] | None, typer.Option("--evidence", "-e", help="Evidence file paths.")] = None,
    log_dir: Annotated[Path, typer.Option("--log-dir", help="Root directory for audit logs.")] = Path("logs"),
    allow_missing_tools: Annotated[bool, typer.Option("--allow-missing-tools", help="Override failed preflight.")] = False,
    backend: Annotated[str, typer.Option("--backend", help="Strategy backend: 'null' (default) or 'anthropic'.")] = "null",
    model: Annotated[str | None, typer.Option("--model", help="Model identifier.")] = None,
    api_key_env: Annotated[str, typer.Option("--api-key-env", help="Env var holding the API key.")] = "ANTHROPIC_API_KEY",
    knowledge_root: Annotated[Path, typer.Option("--knowledge-root", "-k", help="Path to knowledge/.")] = Path("knowledge"),
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Print resolved planner inputs and exit.")] = False,
):
    """End-to-end triage skeleton: preflight -> audit-logged agent loop -> report."""
    cfg = _load_config_or_default(config_path)

    report = preflight(
        profile_name=profile,
        evidence_paths=evidence,
        tier_config=_tier_flags(cfg),
    )
    if not report.ok and not allow_missing_tools:
        err_console.print(
            f"[red]Preflight failed for profile {profile!r}.[/red] "
            f"Missing required: {', '.join(report.missing_required)}",
        )
        err_console.print("[dim]Pass --allow-missing-tools to override (demo only).[/dim]")
        raise typer.Exit(code=1)

    profile_def: ProfileDefinition | None
    try:
        profile_def = get_profile(profile)
    except KeyError:
        profile_def = None

    kb_context: str | None = None
    if backend == "anthropic" and profile_def is not None:
        kb_context = _kb_context_for_profile(
            profile=profile_def,
            knowledge_root=knowledge_root,
        ) or None

    if dry_run:
        _print_dry_run(
            incident_id=incident_id,
            profile_def=profile_def,
            profile_name=profile,
            report=report,
            backend=backend,
            model=model,
            api_key_env=api_key_env,
            kb_context=kb_context,
            knowledge_root=knowledge_root,
        )
        raise typer.Exit(code=0)

    anthropic_client: AnthropicModelClient | None = None
    with AuditLogger(incident_id=incident_id, log_dir=log_dir) as audit:
        audit.append(event_type="preflight", payload=report.model_dump(mode="json"))
        planner, verifier, self_corrector, anthropic_client = _build_llm_strategies(
            backend=backend,
            model=model,
            api_key_env=api_key_env,
            audit=audit,
            profile=profile_def,
            kb_context=kb_context,
        )
        loop = AgentLoop(
            incident_id=incident_id,
            audit=audit,
            planner=planner,
            verifier=verifier,
            self_corrector=self_corrector,
        )
        try:
            findings = loop.run()
        except AnthropicAdapterError as exc:
            err_console.print(f"[red]LLM backend failure:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        finally:
            if anthropic_client is not None:
                anthropic_client.close()

    console.rule(f"[green]Run complete[/green] -- incident {incident_id}")
    console.print(f"Profile:     [cyan]{profile}[/cyan]")
    console.print(f"Backend:     [cyan]{backend}[/cyan]")
    if backend == "anthropic":
        kb_status = "yes" if kb_context else "no (empty or missing knowledge root)"
        console.print(f"KB context:  {kb_status}")
    console.print(f"Preflight:   {'[green]ok[/green]' if report.ok else '[red]not ok[/red]'}")
    console.print(f"Iterations:  {loop.state.iterations}")
    console.print(f"Findings:    {len(findings)}")
    console.print(f"Audit log:   {audit.log_path}")
    if not findings and backend == "null":
        console.print(
            "[dim]No findings emitted. The loop is running with the null planner.[/dim]",
        )


@app.command("analyze")
def analyze_command(
    input_path: Annotated[
        Path,
        typer.Option("--input", help="Path to a JSON file with {'findings': [...], 'iocs': [...]}."),
    ],
    output_dir: Annotated[
        Path,
        typer.Option("--output-dir", help="Directory into which the bundle tree is written."),
    ],
    campaign_tag: Annotated[str, typer.Option("--campaign-tag", help="Campaign tag.")] = "APTWATCHER",
    incident_id: Annotated[str | None, typer.Option("--incident-id", help="Stable incident id.")] = None,
    operator: Annotated[str | None, typer.Option("--operator", help="Signing operator name.")] = None,
    language: Annotated[str, typer.Option("--language", help="Report language: en|fr|both.")] = "both",
    sid_start: Annotated[int, typer.Option("--sid-start", help="Starting Suricata SID.")] = 3_000_000,
    skip_rules: Annotated[bool, typer.Option("--skip-rules", help="Skip rule generation.")] = False,
    skip_reports: Annotated[bool, typer.Option("--skip-reports", help="Skip report rendering.")] = False,
    skip_iocs: Annotated[bool, typer.Option("--skip-iocs", help="Skip IOC exports.")] = False,
    sign: Annotated[bool, typer.Option("--sign", help="Build a signed IncidentBundle.")] = False,
    private_key_path: Annotated[Path | None, typer.Option("--private-key-path", help="Ed25519 private-key file.")] = None,
    sift_workstation: Annotated[str, typer.Option("--sift-workstation", help="Hostname tag.")] = "offline-sift",
):
    """Fan verified findings + IOCs into the full analysis-output bundle."""
    if language not in ("en", "fr", "both"):
        err_console.print(f"[red]invalid --language:[/red] {language!r} (expected en|fr|both)")
        raise typer.Exit(code=1)
    ns = argparse.Namespace(
        input=input_path,
        output_dir=output_dir,
        campaign_tag=campaign_tag,
        incident_id=incident_id,
        operator=operator,
        language=language,
        sid_start=sid_start,
        skip_rules=skip_rules,
        skip_reports=skip_reports,
        skip_iocs=skip_iocs,
        sign=sign,
        private_key_path=private_key_path,
        sift_workstation=sift_workstation,
    )
    raise typer.Exit(code=cmd_analyze(ns))


@app.command("publish")
def publish_command(
    bundle_dir: Annotated[Path, typer.Option("--bundle-dir", help="Bundle directory.")],
    adapter: Annotated[list[str], typer.Option("--adapter", help=f"Allowed: {', '.join(ALLOWED_ADAPTERS)}.")],
    dry_run: Annotated[bool, typer.Option("--dry-run/--no-dry-run", help="Default dry-run.")] = True,
    netcraft_api_key_env: Annotated[str, typer.Option("--netcraft-api-key-env")] = "APTW_NETCRAFT_API_KEY",
    misp_api_key_env: Annotated[str, typer.Option("--misp-api-key-env")] = "APTW_MISP_API_KEY",
    misp_url: Annotated[str | None, typer.Option("--misp-url")] = None,
    glpi_ticket_id: Annotated[int | None, typer.Option("--glpi-ticket-id")] = None,
    taxii_server_url: Annotated[str | None, typer.Option("--taxii-server-url")] = None,
    taxii_collection_id: Annotated[str | None, typer.Option("--taxii-collection-id")] = None,
    taxii_api_key_env: Annotated[str, typer.Option("--taxii-api-key-env")] = "APTW_TAXII_API_KEY",
    taxii_username: Annotated[str | None, typer.Option("--taxii-username")] = None,
    taxii_password_env: Annotated[str | None, typer.Option("--taxii-password-env")] = None,
    incident_id: Annotated[str | None, typer.Option("--incident-id")] = None,
    campaign_tag: Annotated[str | None, typer.Option("--campaign-tag")] = None,
):
    """Push a generated analysis bundle through one or more publication adapters."""
    for name in adapter:
        if name not in ALLOWED_ADAPTERS:
            err_console.print(f"[red]unknown adapter:[/red] {name!r}")
            raise typer.Exit(code=1)
    ns = argparse.Namespace(
        bundle_dir=bundle_dir,
        adapters=list(adapter),
        dry_run=dry_run,
        netcraft_api_key_env=netcraft_api_key_env,
        misp_api_key_env=misp_api_key_env,
        misp_url=misp_url,
        glpi_ticket_id=glpi_ticket_id,
        taxii_server_url=taxii_server_url,
        taxii_collection_id=taxii_collection_id,
        taxii_api_key_env=taxii_api_key_env,
        taxii_username=taxii_username,
        taxii_password_env=taxii_password_env,
        incident_id=incident_id,
        campaign_tag=campaign_tag,
    )
    raise typer.Exit(code=cmd_publish(ns))


@app.command("eval")
def eval_command(
    fixtures_dir: Annotated[Path, typer.Option("--fixtures-dir")] = Path("tests/accuracy/fixtures"),
    output_dir: Annotated[Path, typer.Option("--output-dir")] = Path("accuracy-runs"),
    threshold: Annotated[float, typer.Option("--threshold")] = 0.60,
    fail_under_threshold: Annotated[bool, typer.Option("--fail-under-threshold/--no-fail-under-threshold")] = True,
):
    """Run the accuracy harness across scenario fixtures and emit a report."""
    if not fixtures_dir.exists() or not fixtures_dir.is_dir():
        err_console.print(f"[red]fixtures-dir not found:[/red] {fixtures_dir}")
        raise typer.Exit(code=2)
    tests_parent = Path(__file__).resolve().parents[2]
    if str(tests_parent) not in sys.path:
        sys.path.insert(0, str(tests_parent))
    try:
        from tests.accuracy.runner import run_batch
    except ModuleNotFoundError as exc:
        err_console.print(f"[red]accuracy runner unavailable:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    try:
        scorecards, summary, json_path, md_path = run_batch(
            fixtures_dir=fixtures_dir,
            output_dir=output_dir,
        )
    except FileNotFoundError as exc:
        err_console.print(f"[red]fixture missing:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    except Exception as exc:  # noqa: BLE001
        err_console.print(f"[red]eval failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    if not scorecards:
        err_console.print("[red]no scenarios discovered under --fixtures-dir[/red]")
        raise typer.Exit(code=2)

    mean_f1 = float(summary.get("mean_f1", 0.0))
    table = Table(title="Accuracy report", show_lines=False)
    table.add_column("scenario")
    table.add_column("f1_findings")
    table.add_column("f1_iocs")
    table.add_column("duration_ms")
    for sc in scorecards:
        table.add_row(
            sc.scenario_id,
            f"{sc.f1:.3f}",
            f"{sc.ioc_f1:.3f}",
            str(int(sc.duration_seconds * 1000)),
        )
    console.print(table)
    console.print(f"Mean F1: [cyan]{mean_f1:.3f}[/cyan] (threshold {threshold:.2f})")
    console.print(f"Report JSON: {json_path}")
    console.print(f"Report MD:   {md_path}")

    if fail_under_threshold and mean_f1 < threshold:
        err_console.print(
            f"[red]mean F1 {mean_f1:.3f} is below threshold {threshold:.2f}[/red]",
        )
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


@app.command("audit-render")
def audit_render_command(
    input_path: Annotated[
        Path,
        typer.Option("--input", help="Path to a JSONL audit log (logs/<incident>/audit.jsonl)."),
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", help="Write the rendered timeline to this path. Prints to stdout when omitted."),
    ] = None,
    fmt: Annotated[
        str,
        typer.Option("--format", help="Output format: 'md' (markdown table, default) or 'txt' (ASCII timeline)."),
    ] = "md",
):
    """Render a signed audit log as a judge-friendly execution timeline."""
    if fmt not in ("md", "txt"):
        err_console.print(f"[red]invalid --format:[/red] {fmt!r} (expected md|txt)")
        raise typer.Exit(code=2)
    ns = argparse.Namespace(
        input=input_path,
        output=output,
        format=fmt,
    )
    raise typer.Exit(code=cmd_audit_render(ns))
