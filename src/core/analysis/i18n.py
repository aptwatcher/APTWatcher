"""
Minimal translation dictionary for report renderers.

English is the source of truth. Only the strings used by the bilingual
``.docx`` report renderer and the Markdown narrative/TTP renderers live
here. The table is intentionally flat so it can be unit-tested as pure
data without any i18n framework.

Design rules:

- Keys are short snake_case identifiers, EN value is copied verbatim as
  the default, FR value is the localized form. Missing FR keys fall
  back to EN silently (a French render with an English string is still
  legible; the reverse would be misleading).
- Only headings, labels, and fixed boilerplate live here. Operator prose
  (finding summaries, IOC values) is **never** translated by this table
  — the design doc (``analysis-output-pipeline.md``) calls for an
  explicit ``[FR traduction manquante]`` marker in that case, handled
  by the renderer, not by this dict.

Reference:

- ``docs/design/analysis-output-pipeline.md`` -- "Report renderers"
  section.
"""

from __future__ import annotations

from typing import Literal

Language = Literal["en", "fr"]


# English is the source of truth. Every key used by a renderer MUST
# appear in ``_EN``. ``_FR`` may omit keys; missing keys fall back.
_EN: dict[str, str] = {
    # Document title / cover
    "title_campaign_report": "Campaign Report",
    "label_incident": "Incident",
    "label_campaign": "Campaign",
    "label_generated_at": "Generated",
    "label_operator": "Operator",
    "label_unknown_operator": "unknown",
    # Section headings
    "heading_executive_summary": "Executive Summary",
    "heading_findings": "Findings",
    "heading_iocs": "Indicators of Compromise",
    "heading_appendix_citations": "Appendix: Citation References",
    # Summary prose
    "summary_prefix": "This report covers",
    "summary_finding_count": "findings",
    "summary_ioc_count": "indicators of compromise",
    "summary_highest_severity": "Highest severity",
    "summary_no_findings": "No findings were recorded in this run.",
    # Findings table column headers
    "col_finding_id": "ID",
    "col_finding_title": "Title",
    "col_finding_severity": "Severity",
    "col_finding_mitre": "MITRE",
    "col_finding_citations": "Citations",
    # IOCs table column headers
    "col_ioc_type": "Type",
    "col_ioc_value": "Value",
    "col_ioc_confidence": "Confidence",
    "col_ioc_source": "Source",
    # Appendix labels
    "label_citation_source": "Source",
    "label_citation_locator": "Locator",
    "label_citation_tool_call": "Tool call",
    # Severity names (lower-cased values match the renderer's classifier)
    "severity_critical": "critical",
    "severity_high": "high",
    "severity_medium": "medium",
    "severity_low": "low",
    "severity_none": "none",
    # Placeholders
    "placeholder_none": "(none)",
    "placeholder_n_a": "N/A",
}


_FR: dict[str, str] = {
    "title_campaign_report": "Rapport de campagne",
    "label_incident": "Incident",
    "label_campaign": "Campagne",
    "label_generated_at": "Genere le",
    "label_operator": "Operateur",
    "label_unknown_operator": "inconnu",
    "heading_executive_summary": "Resume analytique",
    "heading_findings": "Constats",
    "heading_iocs": "Indicateurs de compromission",
    "heading_appendix_citations": "Annexe : references de citation",
    "summary_prefix": "Ce rapport couvre",
    "summary_finding_count": "constats",
    "summary_ioc_count": "indicateurs de compromission",
    "summary_highest_severity": "Gravite la plus elevee",
    "summary_no_findings": "Aucun constat n'a ete enregistre lors de cette execution.",
    "col_finding_id": "ID",
    "col_finding_title": "Titre",
    "col_finding_severity": "Gravite",
    "col_finding_mitre": "MITRE",
    "col_finding_citations": "Citations",
    "col_ioc_type": "Type",
    "col_ioc_value": "Valeur",
    "col_ioc_confidence": "Confiance",
    "col_ioc_source": "Source",
    "label_citation_source": "Source",
    "label_citation_locator": "Localisateur",
    "label_citation_tool_call": "Appel d'outil",
    "severity_critical": "critique",
    "severity_high": "elevee",
    "severity_medium": "moyenne",
    "severity_low": "faible",
    "severity_none": "aucune",
    "placeholder_none": "(aucun)",
    "placeholder_n_a": "N/D",
}


_TABLES: dict[Language, dict[str, str]] = {
    "en": _EN,
    "fr": _FR,
}


def translate(key: str, language: Language = "en") -> str:
    """
    Return the translated string for ``key`` in the requested language.

    English is the source of truth. If a key is missing in the requested
    language it falls back to the English value. If a key is missing in
    English as well, a ``KeyError`` is raised -- that is a bug in the
    caller, not a localization gap.
    """
    table = _TABLES.get(language, _EN)
    if key in table:
        return table[key]
    # Fall back to English.
    if key in _EN:
        return _EN[key]
    raise KeyError(f"unknown i18n key: {key!r}")


def available_languages() -> tuple[Language, ...]:
    """Return the tuple of language codes supported by this dictionary."""
    return ("en", "fr")


__all__ = ["Language", "available_languages", "translate"]
