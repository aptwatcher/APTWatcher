"""
Analysis output pipeline — rule generators.

Phase 3.8 task #62. Shared-brain synthesizers that turn a verified
`Finding` + `IOCVerdict` set into detection rules the defender
ecosystem already consumes (YARA, Suricata, Sigma).

Layering:

- `rules_yara.py`      YARA rule synthesis from hashes and repeated
                        filename strings.
- `rules_suricata.py`  Suricata rule synthesis from network IOCs with a
                        private-use SID block.
- `rules_sigma.py`     Phase 4 — stub only.

Every generator is pure in-memory: no subprocess, no network. Unit
tests do not require YARA or Suricata binaries. See the design doc at
`docs/design/analysis-output-pipeline.md` for the full contract.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class RuleGenerationError(ValueError):
    """Raised when the input finding/IOC set cannot produce a valid rule."""


class _RuleModel(BaseModel):
    """Base model for generated rule records. Forbids extra keys."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class YaraRule(_RuleModel):
    """A generated YARA rule."""

    name: str
    text: str
    source_iocs: list[str] = Field(default_factory=list)
    meta: dict[str, str] = Field(default_factory=dict)


class SuricataRule(_RuleModel):
    """A generated Suricata rule."""

    sid: int
    text: str
    source_iocs: list[str] = Field(default_factory=list)
    meta: dict[str, str] = Field(default_factory=dict)


class SigmaRule(_RuleModel):
    """Stub for Phase 4."""

    name: str
    text: str
    meta: dict[str, str] = Field(default_factory=dict)


# Phase 3.8 task #64 — IOC exporters.
from core.analysis.export_community import export_community_yaml
from core.analysis.export_iocs_txt import export_per_type_txt
from core.analysis.export_stix import IOCExportError, export_stix_bundle

# Phase 3.8 task #63 -- Report renderers.
from core.analysis.report_docx import ReportRenderError, render_docx_report
from core.analysis.report_markdown import (
    render_analyst_markdown,
    render_ttp_assessment,
)
from core.analysis.report_stats import render_generation_report
from core.analysis.rules_sigma import generate_sigma_rules
from core.analysis.rules_suricata import generate_suricata_rules
from core.analysis.rules_yara import generate_yara_rules

__all__ = [
    "IOCExportError",
    "ReportRenderError",
    "RuleGenerationError",
    "SigmaRule",
    "SuricataRule",
    "YaraRule",
    "export_community_yaml",
    "export_per_type_txt",
    "export_stix_bundle",
    "generate_sigma_rules",
    "generate_suricata_rules",
    "generate_yara_rules",
    "render_analyst_markdown",
    "render_docx_report",
    "render_generation_report",
    "render_ttp_assessment",
]

__all__ = [
    "IOCExportError",
    "ReportRenderError",
    "RuleGenerationError",
    "SigmaRule",
    "SuricataRule",
    "YaraRule",
    "export_community_yaml",
    "export_per_type_txt",
    "export_stix_bundle",
    "generate_sigma_rules",
    "generate_suricata_rules",
    "generate_yara_rules",
    "render_analyst_markdown",
    "render_docx_report",
    "render_generation_report",
    "render_ttp_assessment",
]
