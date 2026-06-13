"""
Use-case profile registry.

Seven profiles matching docs/use-cases/*. The registry is the authoritative
source -- preflight(), the tier gate, and the MCP tool-advertising logic all
read from here. Keeping the profiles in code (not YAML) means the tests
exercise the same definitions the running agent sees.

References:
- docs/use-cases/README.md
- docs/use-cases/windows-host-triage.md
- docs/use-cases/linux-host-triage.md
- docs/use-cases/memory-only.md
- docs/use-cases/timeline-only.md
- docs/use-cases/network-artifact.md
- docs/use-cases/osx-host-triage.md          (experimental)
- docs/use-cases/mobile-host-triage.md       (experimental, iOS/Android)
"""

from __future__ import annotations

from core.types import ProfileDefinition

WINDOWS_HOST_TRIAGE = ProfileDefinition(
    name="windows-host-triage",
    description="Full Windows triage: disk and/or memory plus triage bundle.",
    required_tools=[
        "volatility3",
        "log2timeline.py",
        "bulk_extractor",
        "RegRipper",
        "yara",
    ],
    optional_tools=["evtx_dump", "prefetch-parser", "shellbag_parser"],
    required_artifact_categories=[
        "memory_or_disk",
        "event_logs",
        "registry",
        "scheduled_tasks",
    ],
    optional_artifact_categories=[
        "prefetch",
        "browser_history",
        "shellbags",
        "srum",
    ],
    tier_prerequisites={
        "tier_1": "optional",
        "tier_2": "optional",
        "tier_3": "gated_by_flag",
    },
)

LINUX_HOST_TRIAGE = ProfileDefinition(
    name="linux-host-triage",
    description="Linux triage: disk plus memory, systemd/cron persistence sweep.",
    required_tools=[
        "volatility3",
        "log2timeline.py",
        "bulk_extractor",
        "yara",
        "chkrootkit",
    ],
    optional_tools=["rkhunter", "lynis", "auditd-parser"],
    required_artifact_categories=[
        "syslog_or_journalctl",
        "etc",
        "var_log",
        "bash_history",
        "process_tree",
    ],
    optional_artifact_categories=[
        "memory",
        "auditd_logs",
        "filesystem_mtime_delta",
    ],
    tier_prerequisites={
        "tier_1": "optional",
        "tier_2": "optional",
        "tier_3": "gated_by_flag",
    },
)

MEMORY_ONLY = ProfileDefinition(
    name="memory-only",
    description="Memory image only. Live-response triage without disk.",
    required_tools=["volatility3", "yara"],
    optional_tools=["bulk_extractor", "volshell"],
    required_artifact_categories=["memory_image"],
    optional_artifact_categories=["process_list_snapshot", "network_state_snapshot"],
    tier_prerequisites={
        "tier_1": "optional",
        "tier_2": "optional",
        "tier_3": "gated_by_flag",
    },
)

TIMELINE_ONLY = ProfileDefinition(
    name="timeline-only",
    description="Log bundles, evtx, prefetch. No image. Multi-host correlation friendly.",
    required_tools=["log2timeline.py", "psort.py", "evtx_dump", "jq"],
    optional_tools=["chainsaw", "hayabusa", "plaso-extras"],
    required_artifact_categories=["at_least_one_timeline_source"],
    optional_artifact_categories=[
        "firewall_logs",
        "proxy_logs",
        "dns_logs",
        "auth_server_logs",
    ],
    tier_prerequisites={
        "tier_1": "optional",
        "tier_2": "optional",
        "tier_3": "not_applicable",
    },
)

NETWORK_ARTIFACT = ProfileDefinition(
    name="network-artifact",
    description="PCAP + netflow + firewall/DNS logs. Network-only analysis.",
    required_tools=["yara", "bulk_extractor"],  # plus at least one of zeek/tshark/suricata
    optional_tools=["zeek", "tshark", "suricata", "rita", "chopshop", "maltrail"],
    required_artifact_categories=["at_least_one_network_source"],
    optional_artifact_categories=["proxy_logs", "tls_ja3_bundle", "suricata_alerts"],
    tier_prerequisites={
        "tier_1": "required",  # intel lookup carries most of the value
        "tier_2": "optional",
        "tier_3": "not_applicable",
    },
)

OSX_HOST_TRIAGE = ProfileDefinition(
    name="osx-host-triage",
    description=(
        "macOS triage: unified logs, launchd persistence, KnowledgeC.db, "
        "FSEvents. Experimental -- APFS tooling coverage on SIFT is partial."
    ),
    required_tools=[
        "log2timeline.py",
        "yara",
        "mac_apt",
    ],
    optional_tools=[
        "UnifiedLogReader",
        "plutil",
        "APOLLO",
        "spctl",
    ],
    required_artifact_categories=[
        "unified_logs",
        "launchd_plists",
        "fsevents",
        "bash_or_zsh_history",
    ],
    optional_artifact_categories=[
        "knowledgec_db",
        "quarantine_events_v2",
        "spotlight_store",
        "amfi_logs",
    ],
    tier_prerequisites={
        "tier_1": "optional",
        "tier_2": "optional",
        "tier_3": "gated_by_flag",
    },
)

MOBILE_HOST_TRIAGE = ProfileDefinition(
    name="mobile-host-triage",
    description=(
        "Mobile (iOS / Android) triage from logical or filesystem-level "
        "acquisitions. Experimental -- agent flags scope limitations "
        "and refuses physical-acquisition steps."
    ),
    required_tools=[
        "yara",
    ],
    optional_tools=[
        "ALEAPP",
        "iLEAPP",
        "sqlite3",
        "plutil",
        "adb",
    ],
    required_artifact_categories=[
        "mobile_acquisition_manifest",
        "app_databases",
    ],
    optional_artifact_categories=[
        "ios_biome",
        "android_logcat",
        "keychain_backup",
        "whatsapp_sqlite",
    ],
    tier_prerequisites={
        "tier_1": "optional",
        "tier_2": "optional",
        "tier_3": "not_applicable",
    },
)

ALL_PROFILES: dict[str, ProfileDefinition] = {
    p.name: p
    for p in (
        WINDOWS_HOST_TRIAGE,
        LINUX_HOST_TRIAGE,
        MEMORY_ONLY,
        TIMELINE_ONLY,
        NETWORK_ARTIFACT,
        OSX_HOST_TRIAGE,
        MOBILE_HOST_TRIAGE,
    )
}


def get_profile(name: str) -> ProfileDefinition:
    """Look up a profile by name. Raises KeyError for unknown names."""
    try:
        return ALL_PROFILES[name]
    except KeyError as exc:
        valid = ", ".join(sorted(ALL_PROFILES))
        raise KeyError(
            f"Unknown profile {name!r}. Known profiles: {valid}",
        ) from exc


__all__ = [
    "ALL_PROFILES",
    "LINUX_HOST_TRIAGE",
    "MEMORY_ONLY",
    "MOBILE_HOST_TRIAGE",
    "NETWORK_ARTIFACT",
    "OSX_HOST_TRIAGE",
    "TIMELINE_ONLY",
    "WINDOWS_HOST_TRIAGE",
    "get_profile",
]
