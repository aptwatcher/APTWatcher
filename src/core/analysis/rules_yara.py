"""
YARA rule synthesizer.

Emits one rule per SHA-256 hash (observed in `IOCVerdict`s of type
`sha256` or in the explicit `hashes` argument) and one rule per
filename string that appears at least three times across
`Finding.evidence` citations.

The generator is pure in-memory: the emitted `rule { ... }` text is a
raw string with no dependency on a YARA runtime. Compilation against
`yara-python` happens at a later stage in the pipeline.

References:
- `docs/design/analysis-output-pipeline.md`
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import UTC, datetime

from core.analysis import RuleGenerationError, YaraRule
from core.types import Finding, IOCVerdict

# YARA identifiers: `[A-Za-z_][A-Za-z0-9_]*`. We enforce the stricter
# uppercase-only form so rule names are stable regardless of the
# operator-supplied campaign tag.
_YARA_IDENTIFIER_BODY = re.compile(r"[A-Z][A-Z0-9_]*$")

# Minimum occurrences of a filename string across findings before we
# promote it into a standalone YARA rule.
_FILENAME_OCCURRENCE_THRESHOLD = 3

# SHA-256 hex values: 64 lower/uppercase hex chars.
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")

# Filenames worth lifting from finding sources. We look for short,
# absolute-free, extension-bearing tokens that show up in the `source`
# or `locator` of a citation.
_FILENAME_RE = re.compile(
    r"(?<![\w./\\])([A-Za-z0-9._-]{3,64}\.[A-Za-z0-9]{1,8})(?![\w/\\])"
)


def _sanitize_identifier(raw: str, *, campaign_tag: str) -> str:
    """Return a YARA-legal, uppercase, campaign-prefixed identifier."""
    campaign = re.sub(r"[^A-Za-z0-9_]", "_", campaign_tag).upper().strip("_")
    if not campaign:
        campaign = "APTWATCHER"
    if not campaign[0].isalpha():
        campaign = "A" + campaign

    body = re.sub(r"[^A-Za-z0-9_]", "_", raw).upper().strip("_")
    if not body:
        body = "RULE"

    candidate = f"{campaign}_{body}"
    if not _YARA_IDENTIFIER_BODY.match(candidate):
        # Leading digit or similar pathology — guarantee the first char is a
        # letter by re-prefixing.
        candidate = f"A_{candidate}"
    return candidate


def _format_meta_block(meta: dict[str, str]) -> str:
    """Render the `meta:` section of a YARA rule, quoted and indented."""
    lines = ["    meta:"]
    for key, value in meta.items():
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'        {key} = "{escaped}"')
    return "\n".join(lines)


def _finding_ids_for(values: set[str], findings: list[Finding]) -> list[str]:
    """Return finding IDs that mention any of the given values."""
    touched: list[str] = []
    for f in findings:
        blob_parts: list[str] = [f.summary or ""]
        for c in f.evidence:
            blob_parts.append(c.source or "")
            if c.locator:
                blob_parts.append(c.locator)
        blob = " ".join(blob_parts).lower()
        for v in values:
            if v.lower() in blob:
                touched.append(f.finding_id)
                break
    return touched


def _collect_hashes(
    hashes: list[str] | None, iocs: list[IOCVerdict]
) -> list[str]:
    """Union of explicit hashes and sha256 IOC values, de-duplicated, lowered."""
    seen: dict[str, None] = {}
    for h in (hashes or []):
        if not isinstance(h, str):
            raise RuleGenerationError(f"hash entry is not a string: {h!r}")
        if not _SHA256_RE.match(h):
            raise RuleGenerationError(f"not a valid sha256 hex value: {h!r}")
        seen.setdefault(h.lower(), None)
    for ioc in iocs:
        if ioc.ioc_type != "sha256":
            continue
        if not _SHA256_RE.match(ioc.value):
            raise RuleGenerationError(
                f"IOC typed sha256 but value is not hex: {ioc.value!r}"
            )
        seen.setdefault(ioc.value.lower(), None)
    return list(seen.keys())


def _collect_repeated_filenames(findings: list[Finding]) -> list[str]:
    """Filenames appearing in >= threshold citations across findings."""
    counter: Counter[str] = Counter()
    for f in findings:
        local: set[str] = set()
        for citation in f.evidence:
            for field in (citation.source, citation.locator or ""):
                for match in _FILENAME_RE.finditer(field):
                    local.add(match.group(1))
        for name in local:
            counter[name] += 1
    return sorted(
        [name for name, count in counter.items()
         if count >= _FILENAME_OCCURRENCE_THRESHOLD]
    )


def _hash_rule(
    sha256: str,
    *,
    campaign_tag: str,
    today: str,
    finding_ids: list[str],
) -> YaraRule:
    name = _sanitize_identifier(f"FILE_{sha256[:12]}", campaign_tag=campaign_tag)
    meta: dict[str, str] = {
        "author": "APTWatcher",
        "campaign": campaign_tag,
        "created": today,
        "source_findings": ",".join(finding_ids),
        "hash": sha256,
    }
    text = (
        f"rule {name}\n"
        "{\n"
        f"{_format_meta_block(meta)}\n"
        "    condition:\n"
        f'        hash.sha256(0, filesize) == "{sha256}"\n'
        "}\n"
    )
    return YaraRule(name=name, text=text, source_iocs=[sha256], meta=meta)


def _filename_rule(
    filename: str,
    *,
    campaign_tag: str,
    today: str,
    finding_ids: list[str],
) -> YaraRule:
    body_hint = re.sub(r"[^A-Za-z0-9]", "_", filename).upper().strip("_")
    name = _sanitize_identifier(
        f"STRING_{body_hint}", campaign_tag=campaign_tag
    )
    meta: dict[str, str] = {
        "author": "APTWatcher",
        "campaign": campaign_tag,
        "created": today,
        "source_findings": ",".join(finding_ids),
        "filename": filename,
    }
    escaped = filename.replace("\\", "\\\\").replace('"', '\\"')
    text = (
        f"rule {name}\n"
        "{\n"
        f"{_format_meta_block(meta)}\n"
        "    strings:\n"
        f'        $s1 = "{escaped}" ascii wide\n'
        "    condition:\n"
        "        any of them\n"
        "}\n"
    )
    return YaraRule(name=name, text=text, source_iocs=[filename], meta=meta)


def generate_yara_rules(
    *,
    findings: list[Finding],
    iocs: list[IOCVerdict],
    hashes: list[str] | None = None,
    campaign_tag: str = "APTWATCHER",
) -> list[YaraRule]:
    """
    Synthesize a list of YARA rules from a verified finding/IOC set.

    For every SHA-256 hash (passed explicitly or carried on an IOC with
    `ioc_type == "sha256"`), emit a small hash-match rule. For every
    filename that appears across at least
    `_FILENAME_OCCURRENCE_THRESHOLD` citations, emit a string-match
    rule. Empty input yields an empty list.

    Rule names are normalized to `[A-Z][A-Z0-9_]*` and prefixed with a
    sanitized `campaign_tag`.
    """
    if not isinstance(campaign_tag, str) or not campaign_tag.strip():
        raise RuleGenerationError("campaign_tag must be a non-empty string")

    today = datetime.now(tz=UTC).strftime("%Y-%m-%d")
    rules: list[YaraRule] = []

    # --- Hash-based rules --------------------------------------------------
    hash_values = _collect_hashes(hashes, iocs)
    for h in hash_values:
        finding_ids = _finding_ids_for({h, h.upper()}, findings)
        rules.append(
            _hash_rule(
                h,
                campaign_tag=campaign_tag,
                today=today,
                finding_ids=finding_ids,
            )
        )

    # --- Filename-based rules ---------------------------------------------
    for filename in _collect_repeated_filenames(findings):
        finding_ids = _finding_ids_for({filename}, findings)
        rules.append(
            _filename_rule(
                filename,
                campaign_tag=campaign_tag,
                today=today,
                finding_ids=finding_ids,
            )
        )

    return rules


__all__ = ["generate_yara_rules"]
