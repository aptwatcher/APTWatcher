"""
Tier 0 -- SIFT tool wrappers.

Thin, allow-listed subprocess wrappers around SIFT command-line
forensic tools. Every wrapper:

1. Accepts a typed argument set (no raw shell, no caller-supplied argv).
2. Writes a `tool_call` event to the audit log before and after the run,
   with correlation IDs so findings can cite the run.
3. Treats evidence files as read-only -- the wrapper never alters the
   path, never changes permissions, and never writes into an evidence
   directory.
4. Returns a `ToolRunResult` structured value, not a string blob.

Non-goals at this stage:

- Parsing vol3/plaso output into structured findings. That is the next
  layer up (`src/core/agent_loop.py`).
- Streaming. All wrappers are blocking with a caller-supplied timeout.

References:
- docs/architecture/tier-model.md (Tier 0 definition)
- docs/reference/sift-tools.md (tool inventory)
- docs/architecture/audit-logging.md (event shape)
"""

from __future__ import annotations

from core.sift.bulk_extractor import (
    BULK_EXTRACTOR_SCANNERS,
    BulkExtractorScannerError,
    run_bulk_extractor,
)
from core.sift.chainsaw import (
    CHAINSAW_OUTPUT_FORMATS,
    CHAINSAW_SUBCOMMANDS,
    ChainsawOutputFormatError,
    ChainsawSearchError,
    ChainsawSubcommandError,
    run_chainsaw_hunt,
    run_chainsaw_search,
)
from core.sift.hayabusa import (
    HAYABUSA_OUTPUT_FORMATS,
    HayabusaSubcommandError,
    run_hayabusa_logon_summary,
    run_hayabusa_timeline,
)
from core.sift.plaso import (
    PLASO_PARSER_PRESETS,
    PlasoOutputFormat,
    PlasoOutputFormatError,
    PlasoParserPresetError,
    run_log2timeline,
    run_psort,
)
from core.sift.regripper import (
    REGRIPPER_PLUGINS,
    REGRIPPER_PROFILES,
    RegRipperPluginError,
    RegRipperProfileError,
    run_regripper_plugin,
    run_regripper_profile,
)
from core.sift.runner import ToolRunError, ToolRunResult, run_tool
from core.sift.sleuthkit import (
    run_fls,
    run_fsstat,
    run_icat,
    run_mmls,
)
from core.sift.timesketch import (
    TIMESKETCH_QUERY_SUBCOMMANDS,
    TIMESKETCH_UPLOAD_CONSENT_TOKEN,
    TimesketchHostError,
    TimesketchQueryError,
    TimesketchSubcommandError,
    TimesketchTimelineNameError,
    TimesketchUploadConsentError,
    run_timesketch_query,
    run_timesketch_upload,
)
from core.sift.update import (
    SIFT_UPDATE_PACKAGES,
    SiftUpdateConsentError,
    SiftUpdatePackageError,
    run_sift_update,
)
from core.sift.volatility import (
    VOLATILITY_PLUGINS,
    VolatilityPluginError,
    run_volatility,
)
from core.sift.yara_scan import (
    YaraScanError,
    parse_yara_output,
    run_yara_scan,
)

__all__ = [
    "BULK_EXTRACTOR_SCANNERS",
    "BulkExtractorScannerError",
    "CHAINSAW_OUTPUT_FORMATS",
    "CHAINSAW_SUBCOMMANDS",
    "ChainsawOutputFormatError",
    "ChainsawSearchError",
    "ChainsawSubcommandError",
    "HAYABUSA_OUTPUT_FORMATS",
    "HayabusaSubcommandError",
    "PLASO_PARSER_PRESETS",
    "PlasoOutputFormat",
    "PlasoOutputFormatError",
    "PlasoParserPresetError",
    "REGRIPPER_PLUGINS",
    "REGRIPPER_PROFILES",
    "RegRipperPluginError",
    "RegRipperProfileError",
    "SIFT_UPDATE_PACKAGES",
    "SiftUpdateConsentError",
    "SiftUpdatePackageError",
    "TIMESKETCH_QUERY_SUBCOMMANDS",
    "TIMESKETCH_UPLOAD_CONSENT_TOKEN",
    "TimesketchHostError",
    "TimesketchQueryError",
    "TimesketchSubcommandError",
    "TimesketchTimelineNameError",
    "TimesketchUploadConsentError",
    "VOLATILITY_PLUGINS",
    "ToolRunError",
    "ToolRunResult",
    "VolatilityPluginError",
    "YaraScanError",
    "parse_yara_output",
    "run_bulk_extractor",
    "run_chainsaw_hunt",
    "run_chainsaw_search",
    "run_fls",
    "run_fsstat",
    "run_hayabusa_logon_summary",
    "run_hayabusa_timeline",
    "run_icat",
    "run_log2timeline",
    "run_mmls",
    "run_psort",
    "run_regripper_plugin",
    "run_regripper_profile",
    "run_sift_update",
    "run_timesketch_query",
    "run_timesketch_upload",
    "run_tool",
    "run_volatility",
    "run_yara_scan",
]
