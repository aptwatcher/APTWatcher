"""
APTWatcher MCP server (Mode B).

Exposes `core` functions as MCP tools. Tier-gated tools check the active
config before registration, so clients never see a tool they cannot call.

Run directly:

    aptwatcher-mcp              # stdio transport, default config
    python -m mcp_server.server

References:
- docs/reference/mcp-tools.md (full tool inventory)
- docs/deployment/mode-b.md
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from core import (
    ALL_PROFILES,
    BULK_EXTRACTOR_SCANNERS,
    CHAINSAW_OUTPUT_FORMATS,
    HAYABUSA_OUTPUT_FORMATS,
    PLASO_PARSER_PRESETS,
    REGRIPPER_PLUGINS,
    REGRIPPER_PROFILES,
    SIFT_UPDATE_PACKAGES,
    TIMESKETCH_QUERY_SUBCOMMANDS,
    VOLATILITY_PLUGINS,
    AuditEvent,
    BulkExtractorScannerError,
    BundleSignatureError,
    ChainsawOutputFormatError,
    ChainsawSearchError,
    Finding,
    HayabusaSubcommandError,
    IOCExportError,
    IOCQuery,
    IOCVerdict,
    KnowledgeBase,
    PlasoOutputFormatError,
    PlasoParserPresetError,
    RegRipperPluginError,
    RegRipperProfileError,
    ReportRenderError,
    RuleGenerationError,
    SiftUpdateConsentError,
    SiftUpdatePackageError,
    TimesketchHostError,
    TimesketchQueryError,
    TimesketchSubcommandError,
    TimesketchTimelineNameError,
    TimesketchUploadConsentError,
    VolatilityPluginError,
    YaraScanError,
    __version__,
    build_aggregator,
    default_config,
    export_bundle,
    export_community_yaml,
    export_per_type_txt,
    export_stix_bundle,
    generate_suricata_rules,
    generate_yara_rules,
    import_bundle,
    load_config,
    preflight,
    render_analyst_markdown,
    render_docx_report,
    render_generation_report,
    run_bulk_extractor,
    run_chainsaw_hunt,
    run_chainsaw_search,
    run_fls,
    run_fsstat,
    run_hayabusa_logon_summary,
    run_hayabusa_timeline,
    run_icat,
    run_log2timeline,
    run_mmls,
    run_psort,
    run_regripper_plugin,
    run_regripper_profile,
    run_sift_update,
    run_timesketch_query,
    run_timesketch_upload,
    run_volatility,
    run_yara_scan,
    search_threatfox,
    search_tweetfeed,
)
from core.bundle.schema import BundleIntegrityError
from core.sift.runner import ToolRunError

_DEFAULT_KB_ROOT = Path(os.environ.get("APTWATCHER_KB_ROOT", "knowledge"))
_DEFAULT_CONFIG = os.environ.get("APTWATCHER_CONFIG")


# ---------------------------------------------------------------------------
# Server factory
# ---------------------------------------------------------------------------


def build_server(
    *,
    config_path: Path | None = None,
    kb_root: Path | None = None,
) -> FastMCP:
    """
    Wire up a FastMCP instance with tools registered from `core`.

    Tool registration is deliberately explicit so we can gate each tool on
    the active tier config. For this scaffold only Tier 0 tools are
    registered; Tier 1+ tools are stubs the next commits will fill in.
    """
    cfg = load_config(config_path) if config_path else default_config()
    resolved_kb = kb_root or _DEFAULT_KB_ROOT

    mcp = FastMCP(
        name="aptwatcher",
        instructions=(
            "APTWatcher -- defensive IR triage on SANS SIFT. "
            "Tier 0 tools only in this build: preflight, profiles, "
            "knowledge search/get, volatility3, plaso, bulk_extractor, "
            "sleuthkit (fls/icat/mmls/fsstat), yara, hayabusa, "
            "sift_update (consent-gated)."
        ),
    )

    # ---- Tier 0: preflight --------------------------------------------------

    @mcp.tool(
        name="preflight",
        description=(
            "Probe the SIFT tool inventory for a named profile, classify and "
            "report which tools are present / missing / stale against the "
            "profile's declared need list. Returns a PreflightReport."
        ),
    )
    def preflight_tool(
        profile: str,
        evidence_manifest: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        report = preflight(profile=profile, evidence=evidence_manifest)
        return report.model_dump(mode="json")

    # ---- Tier 0: profiles ---------------------------------------------------

    @mcp.tool(
        name="list_profiles",
        description="Return the registered use-case profiles and their declared tool/artifact needs.",
    )
    def list_profiles_tool() -> dict[str, Any]:
        return {
            name: profile.model_dump(mode="json")
            for name, profile in ALL_PROFILES.items()
        }

    # ---- Tier 0: knowledge search / get ------------------------------------

    @mcp.tool(
        name="knowledge_search",
        description=(
            "Search the local knowledge base for entries matching a query "
            "string. Returns up to `top_k` entries with metadata."
        ),
    )
    def knowledge_search_tool(query: str, top_k: int = 5) -> list[dict[str, Any]]:
        kb = KnowledgeBase.load(resolved_kb)
        hits = kb.search(query, top_k=top_k)
        return [h.model_dump(mode="json") for h in hits]

    @mcp.tool(
        name="knowledge_get",
        description="Retrieve a single knowledge base entry by id.",
    )
    def knowledge_get_tool(entry_id: str) -> dict[str, Any] | None:
        kb = KnowledgeBase.load(resolved_kb)
        entry = kb.get(entry_id)
        return entry.model_dump(mode="json") if entry else None

    # ---- Tier 0: volatility3 ----------------------------------------------

    @mcp.tool(
        name="list_volatility_plugins",
        description="Return the Tier 0 allow-list of volatility3 plugins.",
    )
    def list_volatility_plugins_tool() -> dict[str, str]:
        return dict(VOLATILITY_PLUGINS)

    @mcp.tool(
        name="run_volatility",
        description=(
            "Run a volatility3 plugin against a memory image. Read-only on "
            "the source. Plugin must be in the Tier 0 allow-list."
        ),
    )
    def run_volatility_tool(
        image: str,
        plugin: str,
        extra_args: list[str] | None = None,
        timeout: float = 1800.0,
    ) -> dict[str, Any]:
        if not cfg.tiers.tier_0:
            return {"error": "Tier 0 is disabled in the active config."}
        try:
            result = run_volatility(
                image=Path(image),
                plugin=plugin,
                extra_args=extra_args,
                timeout=timeout,
            )
        except VolatilityPluginError as exc:
            return {"error": f"plugin_not_allowed: {exc}"}
        except ToolRunError as exc:
            return {"error": f"runner_error: {exc}"}
        return result.model_dump(mode="json")

    # ---- Tier 0: plaso (log2timeline + psort) -----------------------------

    @mcp.tool(
        name="list_plaso_parser_presets",
        description="Return the Tier 0 allow-list of plaso parser presets.",
    )
    def list_plaso_parser_presets_tool() -> dict[str, str]:
        return dict(PLASO_PARSER_PRESETS)

    @mcp.tool(
        name="run_log2timeline",
        description=(
            "Run log2timeline.py against a source, producing a .plaso "
            "storage file. Read-only on the source; output must be a "
            "fresh path."
        ),
    )
    def run_log2timeline_tool(
        source: str,
        storage_file: str,
        parser_preset: str,
        timeout: float = 7200.0,
    ) -> dict[str, Any]:
        if not cfg.tiers.tier_0:
            return {"error": "Tier 0 is disabled in the active config."}
        try:
            result = run_log2timeline(
                source=Path(source),
                storage_file=Path(storage_file),
                parser_preset=parser_preset,
                timeout=timeout,
            )
        except PlasoParserPresetError as exc:
            return {"error": f"parser_not_allowed: {exc}"}
        except ToolRunError as exc:
            return {"error": f"runner_error: {exc}"}
        return result.model_dump(mode="json")

    @mcp.tool(
        name="run_psort",
        description=(
            "Run psort.py against a .plaso storage file, producing an "
            "output in the requested format. Read-only on storage."
        ),
    )
    def run_psort_tool(
        storage_file: str,
        output_path: str,
        output_format: str = "l2tcsv",
        timeout: float = 7200.0,
    ) -> dict[str, Any]:
        if not cfg.tiers.tier_0:
            return {"error": "Tier 0 is disabled in the active config."}
        try:
            result = run_psort(
                storage_file=Path(storage_file),
                output_path=Path(output_path),
                output_format=output_format,
                timeout=timeout,
            )
        except PlasoOutputFormatError as exc:
            return {"error": f"format_not_allowed: {exc}"}
        except ToolRunError as exc:
            return {"error": f"runner_error: {exc}"}
        return result.model_dump(mode="json")

    # ---- Tier 0: bulk_extractor -------------------------------------------

    @mcp.tool(
        name="list_bulk_extractor_scanners",
        description=(
            "Return the Tier 0 allow-list of bulk_extractor scanners. "
            "Each entry is scanner_name -> short reason the scanner is "
            "considered defensive-IR-relevant and safe."
        ),
    )
    def list_bulk_extractor_scanners_tool() -> dict[str, str]:
        return dict(BULK_EXTRACTOR_SCANNERS)

    @mcp.tool(
        name="run_bulk_extractor",
        description=(
            "Run bulk_extractor against a source with an allow-listed "
            "scanner subset. Read-only on the source. Output directory "
            "must be absent or empty."
        ),
    )
    def run_bulk_extractor_tool(
        source: str,
        output_dir: str,
        scanners: list[str],
        timeout: float = 3600.0,
    ) -> dict[str, Any]:
        if not cfg.tiers.tier_0:
            return {"error": "Tier 0 is disabled in the active config."}
        try:
            result = run_bulk_extractor(
                source=Path(source),
                output_dir=Path(output_dir),
                scanners=scanners,
                timeout=timeout,
            )
        except BulkExtractorScannerError as exc:
            return {"error": f"scanner_not_allowed: {exc}"}
        except ToolRunError as exc:
            return {"error": f"runner_error: {exc}"}
        return result.model_dump(mode="json")

    # ---- Tier 0: sift_update (consent-gated) ------------------------------

    @mcp.tool(
        name="list_sift_update_packages",
        description=(
            "Return the allow-list of forensic packages sift_update may "
            "refresh on the SIFT VM."
        ),
    )
    def list_sift_update_packages_tool() -> dict[str, str]:
        return dict(SIFT_UPDATE_PACKAGES)

    @mcp.tool(
        name="sift_update",
        description=(
            "Refresh the SIFT forensic toolchain after explicit user "
            "consent. Requires a non-empty `consent_token`; emits a "
            "`sift_update_consent` audit event before running. Defaults "
            "to `dry_run=True`."
        ),
    )
    def run_sift_update_tool(
        consent_token: str,
        packages: list[str] | None = None,
        dry_run: bool = True,
        timeout: float = 1800.0,
    ) -> dict[str, Any]:
        if not cfg.tiers.tier_0:
            return {"error": "Tier 0 is disabled in the active config."}
        try:
            result = run_sift_update(
                consent_token=consent_token,
                packages=packages,
                dry_run=dry_run,
                timeout=timeout,
            )
        except SiftUpdateConsentError as exc:
            return {"error": f"consent_required: {exc}"}
        except SiftUpdatePackageError as exc:
            return {"error": f"package_not_allowed: {exc}"}
        except ToolRunError as exc:
            return {"error": f"runner_error: {exc}"}
        return result.model_dump(mode="json")

    # ---- Tier 0: sleuthkit (mmls / fsstat / fls / icat) -------------------

    @mcp.tool(
        name="run_mmls",
        description=(
            "List partitions in a disk image using sleuthkit's mmls. "
            "Read-only. Returns the partition table with block offsets."
        ),
    )
    def run_mmls_tool(
        image: str,
        timeout: float = 300.0,
    ) -> dict[str, Any]:
        if not cfg.tiers.tier_0:
            return {"error": "Tier 0 is disabled in the active config."}
        try:
            result = run_mmls(image=Path(image), timeout=timeout)
        except ToolRunError as exc:
            return {"error": f"runner_error: {exc}"}
        return result.model_dump(mode="json")

    @mcp.tool(
        name="run_fsstat",
        description=(
            "Report filesystem metadata (type, block size, fs creation "
            "time, mount info) using sleuthkit's fsstat. Read-only."
        ),
    )
    def run_fsstat_tool(
        image: str,
        offset: int | None = None,
        timeout: float = 300.0,
    ) -> dict[str, Any]:
        if not cfg.tiers.tier_0:
            return {"error": "Tier 0 is disabled in the active config."}
        try:
            result = run_fsstat(
                image=Path(image),
                offset=offset,
                timeout=timeout,
            )
        except ToolRunError as exc:
            return {"error": f"runner_error: {exc}"}
        return result.model_dump(mode="json")

    @mcp.tool(
        name="run_fls",
        description=(
            "List files from a filesystem image using sleuthkit's fls. "
            "Read-only. Supports optional partition offset, recursive "
            "walk, and a starting inode."
        ),
    )
    def run_fls_tool(
        image: str,
        offset: int | None = None,
        inode: str | None = None,
        recursive: bool = False,
        timeout: float = 600.0,
    ) -> dict[str, Any]:
        if not cfg.tiers.tier_0:
            return {"error": "Tier 0 is disabled in the active config."}
        try:
            result = run_fls(
                image=Path(image),
                offset=offset,
                inode=inode,
                recursive=recursive,
                timeout=timeout,
            )
        except ToolRunError as exc:
            return {"error": f"runner_error: {exc}"}
        return result.model_dump(mode="json")

    @mcp.tool(
        name="run_icat",
        description=(
            "Extract a file by inode from a filesystem image using "
            "sleuthkit's icat. Read-only on the image. Refuses to "
            "overwrite an existing output_path."
        ),
    )
    def run_icat_tool(
        image: str,
        inode: str,
        output_path: str,
        offset: int | None = None,
        timeout: float = 300.0,
    ) -> dict[str, Any]:
        if not cfg.tiers.tier_0:
            return {"error": "Tier 0 is disabled in the active config."}
        try:
            result = run_icat(
                image=Path(image),
                inode=inode,
                output_path=Path(output_path),
                offset=offset,
                timeout=timeout,
            )
        except ToolRunError as exc:
            return {"error": f"runner_error: {exc}"}
        return result.model_dump(mode="json")

    # ---- Tier 0: YARA scanner ---------------------------------------------

    @mcp.tool(
        name="run_yara_scan",
        description=(
            "Scan a file or directory against a YARA ruleset. Read-only "
            "on the target. `print_strings=False` by default to keep "
            "audit payloads small."
        ),
    )
    def run_yara_scan_tool(
        rules_path: str,
        target: str,
        recursive: bool = False,
        print_meta: bool = True,
        print_tags: bool = True,
        print_strings: bool = False,
        timeout_per_rule: int | None = None,
        fast_mode: bool = True,
        timeout: float = 1800.0,
    ) -> dict[str, Any]:
        if not cfg.tiers.tier_0:
            return {"error": "Tier 0 is disabled in the active config."}
        try:
            result = run_yara_scan(
                rules_path=Path(rules_path),
                target=Path(target),
                recursive=recursive,
                print_meta=print_meta,
                print_tags=print_tags,
                print_strings=print_strings,
                timeout_per_rule=timeout_per_rule,
                fast_mode=fast_mode,
                timeout=timeout,
            )
        except YaraScanError as exc:
            return {"error": f"yara_policy: {exc}"}
        except ToolRunError as exc:
            return {"error": f"runner_error: {exc}"}
        return result.model_dump(mode="json")

    # ---- Tier 0: Hayabusa (EVTX Sigma hunting) ----------------------------

    @mcp.tool(
        name="list_hayabusa_output_formats",
        description=(
            "Return the allow-list of Hayabusa timeline output formats "
            "(csv / json) and their subcommands."
        ),
    )
    def list_hayabusa_output_formats_tool() -> dict[str, str]:
        return dict(HAYABUSA_OUTPUT_FORMATS)

    @mcp.tool(
        name="run_hayabusa_timeline",
        description=(
            "Produce a Sigma-driven timeline of Windows EVTX events via "
            "Hayabusa. Read-only on the evtx source. `min_level` filters "
            "by severity (informational|low|medium|high|critical)."
        ),
    )
    def run_hayabusa_timeline_tool(
        evtx_source: str,
        output_path: str,
        output_format: str = "csv",
        min_level: str = "medium",
        profile: str | None = None,
        quiet: bool = True,
        timeout: float = 3600.0,
    ) -> dict[str, Any]:
        if not cfg.tiers.tier_0:
            return {"error": "Tier 0 is disabled in the active config."}
        try:
            result = run_hayabusa_timeline(
                evtx_source=Path(evtx_source),
                output_path=Path(output_path),
                output_format=output_format,
                min_level=min_level,
                profile=profile,
                quiet=quiet,
                timeout=timeout,
            )
        except HayabusaSubcommandError as exc:
            return {"error": f"hayabusa_policy: {exc}"}
        except ToolRunError as exc:
            return {"error": f"runner_error: {exc}"}
        return result.model_dump(mode="json")

    @mcp.tool(
        name="run_hayabusa_logon_summary",
        description=(
            "Summarise logon events from Windows EVTX using Hayabusa's "
            "logon-summary subcommand. Read-only on the evtx source."
        ),
    )
    def run_hayabusa_logon_summary_tool(
        evtx_source: str,
        output_path: str | None = None,
        timeout: float = 1800.0,
    ) -> dict[str, Any]:
        if not cfg.tiers.tier_0:
            return {"error": "Tier 0 is disabled in the active config."}
        try:
            result = run_hayabusa_logon_summary(
                evtx_source=Path(evtx_source),
                output_path=Path(output_path) if output_path else None,
                timeout=timeout,
            )
        except ToolRunError as exc:
            return {"error": f"runner_error: {exc}"}
        return result.model_dump(mode="json")

    # ---- Tier 0: RegRipper (Windows registry hive triage) -----------------

    @mcp.tool(
        name="list_regripper_plugins",
        description=(
            "Return the Tier 0 allow-list of RegRipper plugins. Each "
            "entry is plugin_name -> short reason the plugin is "
            "considered defensive-IR-relevant and safe."
        ),
    )
    def list_regripper_plugins_tool() -> dict[str, str]:
        return dict(REGRIPPER_PLUGINS)

    @mcp.tool(
        name="list_regripper_profiles",
        description=(
            "Return the Tier 0 allow-list of RegRipper hive profiles "
            "(software / system / ntuser / sam / security) and the short "
            "reason each profile is in scope."
        ),
    )
    def list_regripper_profiles_tool() -> dict[str, str]:
        return dict(REGRIPPER_PROFILES)

    @mcp.tool(
        name="run_regripper_plugin",
        description=(
            "Run a single allow-listed RegRipper plugin against an "
            "offline registry hive. Read-only on the hive; hive path "
            "must be an existing regular file."
        ),
    )
    def run_regripper_plugin_tool(
        hive: str,
        plugin: str,
        timeout: float = 300.0,
    ) -> dict[str, Any]:
        if not cfg.tiers.tier_0:
            return {"error": "Tier 0 is disabled in the active config."}
        try:
            result = run_regripper_plugin(
                hive=Path(hive),
                plugin=plugin,
                timeout=timeout,
            )
        except RegRipperPluginError as exc:
            return {"error": f"plugin_not_allowed: {exc}"}
        except ToolRunError as exc:
            return {"error": f"runner_error: {exc}"}
        return result.model_dump(mode="json")

    @mcp.tool(
        name="run_regripper_profile",
        description=(
            "Run an allow-listed RegRipper hive profile (software / "
            "system / ntuser / sam / security) against an offline "
            "registry hive. Read-only on the hive; hive path must be an "
            "existing regular file."
        ),
    )
    def run_regripper_profile_tool(
        hive: str,
        profile: str,
        timeout: float = 600.0,
    ) -> dict[str, Any]:
        if not cfg.tiers.tier_0:
            return {"error": "Tier 0 is disabled in the active config."}
        try:
            result = run_regripper_profile(
                hive=Path(hive),
                profile=profile,
                timeout=timeout,
            )
        except RegRipperProfileError as exc:
            return {"error": f"profile_not_allowed: {exc}"}
        except ToolRunError as exc:
            return {"error": f"runner_error: {exc}"}
        return result.model_dump(mode="json")

    # ---- Tier 0: Chainsaw (EVTX Sigma hunt + full-text search) -----------

    @mcp.tool(
        name="list_chainsaw_output_formats",
        description=(
            "Return the allow-list of Chainsaw output formats "
            "(json / csv) and short descriptions."
        ),
    )
    def list_chainsaw_output_formats_tool() -> dict[str, str]:
        return dict(CHAINSAW_OUTPUT_FORMATS)

    @mcp.tool(
        name="run_chainsaw_hunt",
        description=(
            "Run Chainsaw's `hunt` subcommand against an EVTX source with a "
            "Sigma rules directory and a mapping YAML. Read-only on the "
            "evtx source. Output format is `json` (default) or `csv`."
        ),
    )
    def run_chainsaw_hunt_tool(
        evtx_source: str,
        sigma_rules_dir: str,
        mapping: str,
        output_path: str,
        output_format: str = "json",
        timeout: float = 3600.0,
    ) -> dict[str, Any]:
        if not cfg.tiers.tier_0:
            return {"error": "Tier 0 is disabled in the active config."}
        try:
            result = run_chainsaw_hunt(
                evtx_source=Path(evtx_source),
                sigma_rules_dir=Path(sigma_rules_dir),
                mapping=Path(mapping),
                output_path=Path(output_path),
                output_format=output_format,
                timeout=timeout,
            )
        except ChainsawOutputFormatError as exc:
            return {"error": f"chainsaw_policy: {exc}"}
        except ToolRunError as exc:
            return {"error": f"runner_error: {exc}"}
        return result.model_dump(mode="json")

    @mcp.tool(
        name="run_chainsaw_search",
        description=(
            "Run Chainsaw's `search` subcommand for full-text search over "
            "EVTX records. Read-only on the evtx source. `search_term` is "
            "restricted to the safe set [A-Za-z0-9_\\-.\\s]."
        ),
    )
    def run_chainsaw_search_tool(
        evtx_source: str,
        search_term: str,
        output_path: str,
        output_format: str = "json",
        timeout: float = 1800.0,
    ) -> dict[str, Any]:
        if not cfg.tiers.tier_0:
            return {"error": "Tier 0 is disabled in the active config."}
        try:
            result = run_chainsaw_search(
                evtx_source=Path(evtx_source),
                search_term=search_term,
                output_path=Path(output_path),
                output_format=output_format,
                timeout=timeout,
            )
        except ChainsawSearchError as exc:
            return {"error": f"chainsaw_search: {exc}"}
        except ChainsawOutputFormatError as exc:
            return {"error": f"chainsaw_policy: {exc}"}
        except ToolRunError as exc:
            return {"error": f"runner_error: {exc}"}
        return result.model_dump(mode="json")

    # ---- Tier 0: Timesketch (timeline query + consent-gated upload) ------

    @mcp.tool(
        name="list_timesketch_query_subcommands",
        description=(
            "Return the allow-list of read-only Timesketch CLI query "
            "subcommands (list / describe / search) and short "
            "descriptions."
        ),
    )
    def list_timesketch_query_subcommands_tool() -> dict[str, str]:
        return dict(TIMESKETCH_QUERY_SUBCOMMANDS)

    @mcp.tool(
        name="run_timesketch_query",
        description=(
            "Run a read-only Timesketch CLI subcommand against a "
            "Timesketch server: list sketches, describe a sketch, or "
            "run a Lucene query. Host must be an http:// or https:// "
            "URL. Lucene queries are validated against a safe "
            "character set (no newlines, pipes, semicolons, backticks, "
            "or dollar signs)."
        ),
    )
    def run_timesketch_query_tool(
        subcommand: str,
        host: str,
        sketch_id: int | None = None,
        query: str | None = None,
        timeout: float = 300.0,
    ) -> dict[str, Any]:
        if not cfg.tiers.tier_0:
            return {"error": "Tier 0 is disabled in the active config."}
        try:
            result = run_timesketch_query(
                subcommand=subcommand,
                host=host,
                sketch_id=sketch_id,
                query=query,
                timeout=timeout,
            )
        except TimesketchSubcommandError as exc:
            return {"error": f"timesketch_policy: {exc}"}
        except TimesketchHostError as exc:
            return {"error": f"timesketch_host: {exc}"}
        except TimesketchQueryError as exc:
            return {"error": f"timesketch_query: {exc}"}
        except ToolRunError as exc:
            return {"error": f"runner_error: {exc}"}
        return result.model_dump(mode="json")

    @mcp.tool(
        name="run_timesketch_upload",
        description=(
            "Upload a local timeline (plaso storage or CSV) to a "
            "Timesketch server. State-changing-operational: writes to "
            "the remote Timesketch database even though the local "
            "evidence file is read-only. Requires consent_token="
            "'i-consent-timesketch-upload'. Emits a "
            "`timesketch_upload_consent` audit event before the "
            "subprocess."
        ),
    )
    def run_timesketch_upload_tool(
        timeline_source: str,
        sketch_id: int,
        timeline_name: str,
        consent_token: str,
        host: str | None = None,
        timeout: float = 3600.0,
    ) -> dict[str, Any]:
        if not cfg.tiers.tier_0:
            return {"error": "Tier 0 is disabled in the active config."}
        try:
            result = run_timesketch_upload(
                timeline_source=Path(timeline_source),
                sketch_id=sketch_id,
                timeline_name=timeline_name,
                consent_token=consent_token,
                host=host,
                timeout=timeout,
            )
        except TimesketchUploadConsentError as exc:
            return {"error": f"consent_required: {exc}"}
        except TimesketchTimelineNameError as exc:
            return {"error": f"timesketch_timeline_name: {exc}"}
        except TimesketchQueryError as exc:
            return {"error": f"timesketch_query: {exc}"}
        except TimesketchHostError as exc:
            return {"error": f"timesketch_host: {exc}"}
        except ToolRunError as exc:
            return {"error": f"runner_error: {exc}"}
        return result.model_dump(mode="json")

    # ---- Phase 3.7: Incident bundle export / import -----------------------

    @mcp.tool(
        name="export_bundle",
        description=(
            "Build a signed incident bundle directory from findings, IOCs, "
            "and audit events. Writes manifest/findings/iocs/audit plus an "
            "Ed25519 signature. Returns the in-memory IncidentBundle."
        ),
    )
    def export_bundle_tool(
        bundle_dir: str,
        incident_id: str,
        operator: str,
        sift_workstation: str,
        findings: list[dict[str, Any]],
        audit_events: list[dict[str, Any]],
        private_key_hex: str,
        iocs: list[dict[str, Any]] | None = None,
        profile: str | None = None,
        notes: str | None = None,
    ) -> dict[str, Any]:
        """Wrap `core.export_bundle`: write a signed IncidentBundle to disk."""
        try:
            findings_models = [Finding.model_validate(item) for item in findings]
            audit_models = [AuditEvent.model_validate(item) for item in audit_events]
            ioc_models = (
                [IOCVerdict.model_validate(item) for item in iocs]
                if iocs is not None
                else None
            )
        except Exception as exc:  # pragma: no cover - defensive
            return {"error": f"invalid_input: {exc}"}
        try:
            private_key_bytes = bytes.fromhex(private_key_hex)
        except ValueError as exc:
            return {"error": f"invalid_private_key: {exc}"}
        try:
            bundle = export_bundle(
                bundle_dir=Path(bundle_dir),
                incident_id=incident_id,
                operator=operator,
                sift_workstation=sift_workstation,
                findings=findings_models,
                audit_events=audit_models,
                private_key_bytes=private_key_bytes,
                iocs=ioc_models,
                profile=profile,
                notes=notes,
            )
        except BundleSignatureError as exc:
            return {"error": f"bundle_signature: {exc}"}
        except BundleIntegrityError as exc:
            return {"error": f"bundle_integrity: {exc}"}
        return bundle.model_dump(mode="json")

    @mcp.tool(
        name="import_bundle",
        description=(
            "Load an incident bundle directory from disk and verify its "
            "signature and per-file sha256 digests. Returns the "
            "IncidentBundle aggregate. Set `verify=False` only for "
            "offline inspection when the signer key is unavailable."
        ),
    )
    def import_bundle_tool(
        bundle_dir: str,
        expected_public_key_hex: str | None = None,
        verify: bool = True,
    ) -> dict[str, Any]:
        """Wrap `core.import_bundle`: read and verify a bundle directory."""
        try:
            bundle = import_bundle(
                bundle_dir=Path(bundle_dir),
                expected_public_key_hex=expected_public_key_hex,
                verify=verify,
            )
        except BundleSignatureError as exc:
            return {"error": f"bundle_signature: {exc}"}
        except BundleIntegrityError as exc:
            return {"error": f"bundle_integrity: {exc}"}
        return bundle.model_dump(mode="json")

    # ---- Phase 3.8: Rule generators ---------------------------------------

    @mcp.tool(
        name="generate_yara_rules",
        description=(
            "Synthesize YARA rules from findings and IOCs. Emits one "
            "hash-match rule per sha256 value and one string-match rule "
            "per filename appearing across multiple finding citations."
        ),
    )
    def generate_yara_rules_tool(
        findings: list[dict[str, Any]],
        iocs: list[dict[str, Any]],
        hashes: list[str] | None = None,
        campaign_tag: str = "APTWATCHER",
    ) -> dict[str, Any]:
        """Wrap `core.generate_yara_rules`: build hash/filename YARA rules."""
        try:
            findings_models = [Finding.model_validate(item) for item in findings]
            ioc_models = [IOCVerdict.model_validate(item) for item in iocs]
        except Exception as exc:  # pragma: no cover - defensive
            return {"error": f"invalid_input: {exc}"}
        try:
            rules = generate_yara_rules(
                findings=findings_models,
                iocs=ioc_models,
                hashes=hashes,
                campaign_tag=campaign_tag,
            )
        except RuleGenerationError as exc:
            return {"error": f"rule_generation: {exc}"}
        return {"rules": [r.model_dump(mode="json") for r in rules]}

    @mcp.tool(
        name="generate_suricata_rules",
        description=(
            "Synthesize Suricata rules from findings and network IOCs "
            "(domain/url/ipv4/ipv6). SIDs are assigned sequentially from "
            "`sid_start`; the caller keeps that value inside a "
            "private-use SID block."
        ),
    )
    def generate_suricata_rules_tool(
        findings: list[dict[str, Any]],
        iocs: list[dict[str, Any]],
        sid_start: int = 3_000_000,
        campaign_tag: str = "APTWATCHER",
    ) -> dict[str, Any]:
        """Wrap `core.generate_suricata_rules`: build network Suricata rules."""
        try:
            findings_models = [Finding.model_validate(item) for item in findings]
            ioc_models = [IOCVerdict.model_validate(item) for item in iocs]
        except Exception as exc:  # pragma: no cover - defensive
            return {"error": f"invalid_input: {exc}"}
        try:
            rules = generate_suricata_rules(
                findings=findings_models,
                iocs=ioc_models,
                sid_start=sid_start,
                campaign_tag=campaign_tag,
            )
        except RuleGenerationError as exc:
            return {"error": f"rule_generation: {exc}"}
        return {"rules": [r.model_dump(mode="json") for r in rules]}

    # ---- Phase 3.8: IOC exporters -----------------------------------------

    @mcp.tool(
        name="export_stix_bundle",
        description=(
            "Emit a STIX 2.1 bundle.json containing an identity SDO plus "
            "one indicator SDO per IOC. Object IDs are deterministic "
            "(uuid5 over the IOC tuple) so re-running on the same inputs "
            "yields byte-identical output."
        ),
    )
    def export_stix_bundle_tool(
        iocs: list[dict[str, Any]],
        output_path: str,
        incident_id: str,
        findings: list[dict[str, Any]] | None = None,
        created_by: str = "identity--aptwatcher",
    ) -> dict[str, Any]:
        """Wrap `core.export_stix_bundle`: write a STIX 2.1 indicator bundle."""
        try:
            ioc_models = [IOCVerdict.model_validate(item) for item in iocs]
            finding_models = (
                [Finding.model_validate(item) for item in findings]
                if findings is not None
                else None
            )
        except Exception as exc:  # pragma: no cover - defensive
            return {"error": f"invalid_input: {exc}"}
        try:
            bundle = export_stix_bundle(
                iocs=ioc_models,
                findings=finding_models,
                output_path=Path(output_path),
                incident_id=incident_id,
                created_by=created_by,
            )
        except IOCExportError as exc:
            return {"error": f"ioc_export: {exc}"}
        return bundle

    @mcp.tool(
        name="export_community_yaml",
        description=(
            "Emit a community-feed-style YAML submission template. "
            "Includes a DO NOT EDIT banner; human reviewers hand-tune the "
            "document before submitting it to a public feed."
        ),
    )
    def export_community_yaml_tool(
        iocs: list[dict[str, Any]],
        findings: list[dict[str, Any]],
        output_path: str,
        campaign_tag: str,
        submitter: str,
    ) -> dict[str, Any]:
        """Wrap `core.export_community_yaml`: write a community submission YAML."""
        try:
            ioc_models = [IOCVerdict.model_validate(item) for item in iocs]
            finding_models = [Finding.model_validate(item) for item in findings]
        except Exception as exc:  # pragma: no cover - defensive
            return {"error": f"invalid_input: {exc}"}
        try:
            document = export_community_yaml(
                iocs=ioc_models,
                findings=finding_models,
                output_path=Path(output_path),
                campaign_tag=campaign_tag,
                submitter=submitter,
            )
        except IOCExportError as exc:
            return {"error": f"ioc_export: {exc}"}
        return document

    @mcp.tool(
        name="export_per_type_txt",
        description=(
            "Emit one `<type>.txt` file per IOC type under `output_dir`, "
            "with values normalized, sorted, and deduplicated. Refuses "
            "to overwrite existing per-type files."
        ),
    )
    def export_per_type_txt_tool(
        iocs: list[dict[str, Any]],
        output_dir: str,
    ) -> dict[str, Any]:
        """Wrap `core.export_per_type_txt`: write per-IOC-type text dumps."""
        try:
            ioc_models = [IOCVerdict.model_validate(item) for item in iocs]
        except Exception as exc:  # pragma: no cover - defensive
            return {"error": f"invalid_input: {exc}"}
        try:
            written = export_per_type_txt(
                iocs=ioc_models,
                output_dir=Path(output_dir),
            )
        except IOCExportError as exc:
            return {"error": f"ioc_export: {exc}"}
        return {"written": {k: str(v) for k, v in written.items()}}

    # ---- Phase 3.8: Report renderers --------------------------------------

    @mcp.tool(
        name="render_docx_report",
        description=(
            "Render a professional bilingual (en/fr) campaign report as a "
            ".docx file. Refuses to overwrite an existing output_path. "
            "Severity bands are derived from Finding.confidence."
        ),
    )
    def render_docx_report_tool(
        findings: list[dict[str, Any]],
        iocs: list[dict[str, Any]],
        output_path: str,
        incident_id: str,
        campaign_tag: str,
        language: str = "en",
        operator: str | None = None,
    ) -> dict[str, Any]:
        """Wrap `core.render_docx_report`: emit a .docx incident report."""
        try:
            finding_models = [Finding.model_validate(item) for item in findings]
            ioc_models = [IOCVerdict.model_validate(item) for item in iocs]
        except Exception as exc:  # pragma: no cover - defensive
            return {"error": f"invalid_input: {exc}"}
        if language not in ("en", "fr"):
            return {"error": f"report_render: unsupported language: {language!r}"}
        try:
            written = render_docx_report(
                findings=finding_models,
                iocs=ioc_models,
                output_path=Path(output_path),
                incident_id=incident_id,
                campaign_tag=campaign_tag,
                language=language,  # type: ignore[arg-type]
                operator=operator,
            )
        except ReportRenderError as exc:
            return {"error": f"report_render: {exc}"}
        return {"output_path": str(written)}

    @mcp.tool(
        name="render_analyst_markdown",
        description=(
            "Render the English-only analyst narrative Markdown document "
            "(`ANALYSIS-<incident_id>.md`). Refuses to overwrite an "
            "existing output_path."
        ),
    )
    def render_analyst_markdown_tool(
        findings: list[dict[str, Any]],
        iocs: list[dict[str, Any]],
        output_path: str,
        incident_id: str,
        campaign_tag: str,
        operator: str | None = None,
    ) -> dict[str, Any]:
        """Wrap `core.render_analyst_markdown`: emit the analyst narrative."""
        try:
            finding_models = [Finding.model_validate(item) for item in findings]
            ioc_models = [IOCVerdict.model_validate(item) for item in iocs]
        except Exception as exc:  # pragma: no cover - defensive
            return {"error": f"invalid_input: {exc}"}
        try:
            written = render_analyst_markdown(
                findings=finding_models,
                iocs=ioc_models,
                output_path=Path(output_path),
                incident_id=incident_id,
                campaign_tag=campaign_tag,
                operator=operator,
            )
        except ReportRenderError as exc:
            return {"error": f"report_render: {exc}"}
        return {"output_path": str(written)}

    @mcp.tool(
        name="render_generation_report",
        description=(
            "Write `generation_report.json` -- the per-run stats manifest "
            "carrying counts, the Suricata SID range, and relative-path "
            "sha256 digests for every emitted artifact. Refuses to "
            "overwrite an existing output_path."
        ),
    )
    def render_generation_report_tool(
        output_path: str,
        incident_id: str,
        campaign_tag: str,
        counts: dict[str, int],
        file_digests: dict[str, str],
        sid_range: list[int] | None = None,
    ) -> dict[str, Any]:
        """Wrap `core.render_generation_report`: emit the stats manifest."""
        sid_tuple: tuple[int, int] | None
        if sid_range is None:
            sid_tuple = None
        elif len(sid_range) == 2:
            sid_tuple = (sid_range[0], sid_range[1])
        else:
            return {"error": "report_render: sid_range must be a [start, end] pair or null"}
        try:
            written = render_generation_report(
                output_path=Path(output_path),
                incident_id=incident_id,
                campaign_tag=campaign_tag,
                counts=counts,
                sid_range=sid_tuple,
                file_digests=file_digests,
            )
        except ReportRenderError as exc:
            return {"error": f"report_render: {exc}"}
        return {"output_path": str(written)}

    # ---- Server-level metadata --------------------------------------------

    @mcp.tool(
        name="aptwatcher_version",
        description="Return the running APTWatcher server version.",
    )
    def version_tool() -> dict[str, str]:
        return {"version": __version__}

    # ---- Tier 1: external threat intelligence ------------------------------

    @mcp.tool(
        name="intel_lookup",
        description=(
            "Tier 1: look up one IOC across the configured external "
            "threat-intel providers and return an aggregated IOCVerdict. "
            "Opt-in — returns a tier-disabled error when Tier 1 is off."
        ),
    )
    def intel_lookup_tool(value: str, ioc_type: str) -> dict[str, Any]:
        """Wrap the Tier 1 aggregator: one IOC -> one IOCVerdict."""
        if not cfg.tiers.tier_1:
            return {"error": "Tier 1 is disabled in the active config."}
        allowed = {"ipv4", "ipv6", "domain", "url", "sha256", "sha1", "md5", "email"}
        if ioc_type not in allowed:
            return {"error": f"invalid ioc_type: {ioc_type!r}; expected one of {sorted(allowed)}"}
        aggregator = build_aggregator(cfg)
        try:
            verdict = aggregator.lookup(IOCQuery(value=value, ioc_type=ioc_type))  # type: ignore[arg-type]
        finally:
            aggregator.close()
        return verdict.model_dump(mode="json")

    # ---- Tier 1: feed search verbs -----------------------------------------

    @mcp.tool(
        name="feed_threatfox",
        description="Tier 1: search abuse.ch ThreatFox for an IOC (IP/domain/URL/hash).",
    )
    def feed_threatfox_tool(query: str) -> dict[str, Any]:
        if not cfg.tiers.tier_1:
            return {"error": "Tier 1 is disabled in the active config."}
        key = os.environ.get(cfg.intel.threatfox.api_key_env or "ABUSECH_API_KEY")
        return search_threatfox(query, api_key=key)

    @mcp.tool(
        name="feed_tweetfeed",
        description="Tier 1: fetch today's TweetFeed indicators, optionally filtered by value/tag.",
    )
    def feed_tweetfeed_tool(value: str | None = None, tag: str | None = None) -> dict[str, Any]:
        if not cfg.tiers.tier_1:
            return {"error": "Tier 1 is disabled in the active config."}
        return search_tweetfeed(value=value, tag=tag)

    # ---- Tier 1: enrichment (aggregate across providers) -------------------

    def _enrich(value: str, ioc_type: str) -> dict[str, Any]:
        aggregator = build_aggregator(cfg)
        try:
            return aggregator.lookup(IOCQuery(value=value, ioc_type=ioc_type)).model_dump(mode="json")  # type: ignore[arg-type]
        finally:
            aggregator.close()

    @mcp.tool(
        name="enrich_ip",
        description="Tier 1: aggregate every configured provider's verdict for one IP address.",
    )
    def enrich_ip_tool(value: str) -> dict[str, Any]:
        if not cfg.tiers.tier_1:
            return {"error": "Tier 1 is disabled in the active config."}
        return _enrich(value, "ipv6" if ":" in value else "ipv4")

    @mcp.tool(
        name="enrich_domain",
        description="Tier 1: aggregate every configured provider's verdict for one domain.",
    )
    def enrich_domain_tool(value: str) -> dict[str, Any]:
        if not cfg.tiers.tier_1:
            return {"error": "Tier 1 is disabled in the active config."}
        return _enrich(value, "domain")

    @mcp.tool(
        name="enrich_hash",
        description="Tier 1: aggregate provider verdicts for one file hash (md5/sha1/sha256).",
    )
    def enrich_hash_tool(value: str) -> dict[str, Any]:
        if not cfg.tiers.tier_1:
            return {"error": "Tier 1 is disabled in the active config."}
        kind = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(value.strip()))
        if not kind:
            return {"error": "unrecognized hash length; expected md5/sha1/sha256"}
        return _enrich(value.strip().lower(), kind)

    # ---- Tier 1: MCP-side observability ------------------------------------

    @mcp.tool(name="admin_version", description="Return APTWatcher version and the Tier 1 provider roster.")
    def admin_version_tool() -> dict[str, Any]:
        return {
            "aptwatcher": __version__,
            "intel_providers": [
                "apt_watch", "dshield", "shodan_internetdb", "firehol", "ipsum",
                "stevenblack", "virustotal", "abuseipdb", "otx", "censys",
            ],
            "feeds": ["threatfox", "tweetfeed"],
        }

    @mcp.tool(name="admin_health", description="MCP-side readiness: Tier 1 flag and count of active providers.")
    def admin_health_tool() -> dict[str, Any]:
        agg = build_aggregator(cfg)
        try:
            active = len(agg.providers)
        finally:
            agg.close()
        return {"status": "ok" if cfg.tiers.tier_1 else "tier_1_disabled",
                "tier_1": cfg.tiers.tier_1, "active_providers": active}

    @mcp.tool(name="admin_providers_status", description="Per-provider enabled/keyed/key-present status.")
    def admin_providers_status_tool() -> dict[str, Any]:
        intel = cfg.intel
        keyed = {"virustotal": "VIRUSTOTAL_API_KEY", "abuseipdb": "ABUSEIPDB_API_KEY",
                 "otx": "OTX_API_KEY", "censys": "CENSYS_API_TOKEN"}
        status: dict[str, Any] = {}
        for name in ("apt_watch", "dshield", "shodan_internetdb", "firehol", "ipsum", "stevenblack"):
            status[name] = {"enabled": getattr(intel, name).enabled, "keyed": False}
        for name, env in keyed.items():
            sec = getattr(intel, name)
            present = bool(os.environ.get(sec.api_key_env or env))
            status[name] = {"enabled": sec.enabled, "keyed": True,
                            "key_present": present, "active": bool(sec.enabled and present)}
        return {"tier_1": cfg.tiers.tier_1, "providers": status}

    return mcp


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="aptwatcher-mcp",
        description="Run the APTWatcher MCP server over stdio.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path(_DEFAULT_CONFIG) if _DEFAULT_CONFIG else None,
        help="Path to config.yaml. Omit for Tier 0-only defaults.",
    )
    parser.add_argument(
        "--knowledge-root",
        type=Path,
        default=_DEFAULT_KB_ROOT,
        help="Directory containing the knowledge base (default: ./knowledge).",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio"],
        default="stdio",
        help="MCP transport (stdio is the only supported option at this stage).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    """Console-script entrypoint registered as `aptwatcher-mcp`."""
    args = _parse_args(argv)
    server = build_server(config_path=args.config, kb_root=args.knowledge_root)
    server.run(transport=args.transport)


if __name__ == "__main__":  # pragma: no cover
    main()
