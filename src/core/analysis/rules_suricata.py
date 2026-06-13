"""
Suricata rule synthesizer.

Emits one `alert` line per network IOC (`domain`, `url`, `ipv4`,
`ipv6`). SIDs are allocated sequentially starting from the caller's
`sid_start` — the caller is responsible for keeping that value inside a
private-use SID block (default is 3_000_000, matching the design doc's
reserved range).

The generator is pure in-memory: no subprocess, no file I/O. Dry-run
validation with a real Suricata binary happens at a later stage.

References:
- `docs/design/analysis-output-pipeline.md`
"""

from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import urlparse

from core.analysis import RuleGenerationError, SuricataRule
from core.types import Finding, IOCVerdict

# Characters that would break a Suricata `content:"..."` directive if
# they appeared un-escaped. We refuse to emit a rule rather than guess
# at escaping semantics.
_UNSAFE_CONTENT_CHARS = ("\n", "\r", '"', ";", "\\")

# IOC types this generator knows how to turn into network rules.
_SUPPORTED_IOC_TYPES: frozenset[str] = frozenset(
    {"domain", "url", "ipv4", "ipv6"}
)


def _assert_safe_for_content(value: str) -> None:
    """Refuse values that contain unescaped Suricata meta-characters."""
    for ch in _UNSAFE_CONTENT_CHARS:
        if ch in value:
            raise RuleGenerationError(
                f"IOC value contains character {ch!r} that would need "
                f"escaping inside a Suricata content: field — refusing to "
                f"emit ambiguous rule for {value!r}"
            )


def _url_path(url: str) -> str:
    """Extract the path+query component of a URL, defaulting to '/'."""
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return path


def _finding_ids_for_value(
    value: str, findings: list[Finding]
) -> list[str]:
    """Return finding IDs whose summary or evidence mentions the value."""
    touched: list[str] = []
    lowered = value.lower()
    for f in findings:
        blob_parts: list[str] = [f.summary or ""]
        for c in f.evidence:
            blob_parts.append(c.source or "")
            if c.locator:
                blob_parts.append(c.locator)
        if lowered in " ".join(blob_parts).lower():
            touched.append(f.finding_id)
    return touched


def _rule_for_domain(
    ioc: IOCVerdict,
    sid: int,
    *,
    campaign_tag: str,
    finding_ids: list[str],
    today: str,
) -> SuricataRule:
    _assert_safe_for_content(ioc.value)
    msg = f'{campaign_tag} - suspicious DNS lookup {ioc.value}'
    text = (
        f'alert dns any any -> any any '
        f'(msg:"{msg}"; dns.query; content:"{ioc.value}"; nocase; '
        f'sid:{sid}; rev:1;)'
    )
    meta = {
        "ioc_type": "domain",
        "ioc_value": ioc.value,
        "campaign": campaign_tag,
        "created": today,
        "source_findings": ",".join(finding_ids),
    }
    return SuricataRule(
        sid=sid, text=text, source_iocs=[ioc.value], meta=meta
    )


def _rule_for_url(
    ioc: IOCVerdict,
    sid: int,
    *,
    campaign_tag: str,
    finding_ids: list[str],
    today: str,
) -> SuricataRule:
    _assert_safe_for_content(ioc.value)
    path = _url_path(ioc.value)
    _assert_safe_for_content(path)
    msg = f'{campaign_tag} - http request to {ioc.value}'
    text = (
        f'alert http any any -> any any '
        f'(msg:"{msg}"; http.uri; content:"{path}"; '
        f'sid:{sid}; rev:1;)'
    )
    meta = {
        "ioc_type": "url",
        "ioc_value": ioc.value,
        "campaign": campaign_tag,
        "created": today,
        "source_findings": ",".join(finding_ids),
    }
    return SuricataRule(
        sid=sid, text=text, source_iocs=[ioc.value], meta=meta
    )


def _rule_for_ipv4(
    ioc: IOCVerdict,
    sid: int,
    *,
    campaign_tag: str,
    finding_ids: list[str],
    today: str,
) -> SuricataRule:
    _assert_safe_for_content(ioc.value)
    msg = f'{campaign_tag} - outbound to {ioc.value}'
    text = (
        f'alert ip any any -> {ioc.value} any '
        f'(msg:"{msg}"; sid:{sid}; rev:1;)'
    )
    meta = {
        "ioc_type": "ipv4",
        "ioc_value": ioc.value,
        "campaign": campaign_tag,
        "created": today,
        "source_findings": ",".join(finding_ids),
    }
    return SuricataRule(
        sid=sid, text=text, source_iocs=[ioc.value], meta=meta
    )


def _rule_for_ipv6(
    ioc: IOCVerdict,
    sid: int,
    *,
    campaign_tag: str,
    finding_ids: list[str],
    today: str,
) -> SuricataRule:
    _assert_safe_for_content(ioc.value)
    # Suricata expects the IPv6 address in its literal form (with colons).
    # We do not wrap in brackets — bracketing is the `host:port` URL
    # syntax, not Suricata's rule header syntax.
    msg = f'{campaign_tag} - outbound to {ioc.value}'
    text = (
        f'alert ip any any -> {ioc.value} any '
        f'(msg:"{msg}"; sid:{sid}; rev:1;)'
    )
    meta = {
        "ioc_type": "ipv6",
        "ioc_value": ioc.value,
        "campaign": campaign_tag,
        "created": today,
        "source_findings": ",".join(finding_ids),
    }
    return SuricataRule(
        sid=sid, text=text, source_iocs=[ioc.value], meta=meta
    )


def generate_suricata_rules(
    *,
    findings: list[Finding],
    iocs: list[IOCVerdict],
    sid_start: int = 3_000_000,
    campaign_tag: str = "APTWATCHER",
) -> list[SuricataRule]:
    """
    Synthesize a list of Suricata rules from a verified finding/IOC set.

    One rule is emitted per `IOCVerdict` whose type is in
    {`domain`, `url`, `ipv4`, `ipv6`}. Other types are skipped silently.
    SIDs are assigned sequentially starting at `sid_start`; the caller
    is expected to keep that value inside the deployment's private-use
    SID block.

    Any IOC value that contains a character which would need escaping
    inside a Suricata `content:` directive (newline, carriage return,
    `"`, `;`, `\\`) causes a `RuleGenerationError` — we refuse to emit
    ambiguous rules.
    """
    if not isinstance(campaign_tag, str) or not campaign_tag.strip():
        raise RuleGenerationError("campaign_tag must be a non-empty string")
    if not isinstance(sid_start, int) or sid_start < 0:
        raise RuleGenerationError(
            f"sid_start must be a non-negative int, got {sid_start!r}"
        )

    today = datetime.now(tz=UTC).strftime("%Y-%m-%d")

    rules: list[SuricataRule] = []
    next_sid = sid_start
    for ioc in iocs:
        if ioc.ioc_type not in _SUPPORTED_IOC_TYPES:
            continue
        finding_ids = _finding_ids_for_value(ioc.value, findings)
        if ioc.ioc_type == "domain":
            rules.append(
                _rule_for_domain(
                    ioc, next_sid,
                    campaign_tag=campaign_tag,
                    finding_ids=finding_ids,
                    today=today,
                )
            )
        elif ioc.ioc_type == "url":
            rules.append(
                _rule_for_url(
                    ioc, next_sid,
                    campaign_tag=campaign_tag,
                    finding_ids=finding_ids,
                    today=today,
                )
            )
        elif ioc.ioc_type == "ipv4":
            rules.append(
                _rule_for_ipv4(
                    ioc, next_sid,
                    campaign_tag=campaign_tag,
                    finding_ids=finding_ids,
                    today=today,
                )
            )
        elif ioc.ioc_type == "ipv6":
            rules.append(
                _rule_for_ipv6(
                    ioc, next_sid,
                    campaign_tag=campaign_tag,
                    finding_ids=finding_ids,
                    today=today,
                )
            )
        next_sid += 1

    return rules


__all__ = ["generate_suricata_rules"]
