"""
STIX 2.1 bundle exporter.

Emits a single-file ``bundle.stix.json`` containing an ``identity`` SDO for
APTWatcher plus one ``indicator`` SDO per input ``IOCVerdict``. The bundle
is built by hand (no ``stix2`` library dependency) so this module can run
inside the offline brain with no extra install footprint.

Design rules:

- UUIDs are deterministic (``uuid.uuid5`` in the URL namespace keyed on the
  tuple ``(ioc.ioc_type, ioc.value)``). Re-running the exporter on the same
  input therefore produces identical object IDs, which lets the audit log
  hash-compare bundles across runs.
- The bundle itself also carries a deterministic ID derived from the set
  of indicator IDs plus the ``incident_id``, so two runs with the same
  inputs produce byte-identical JSON.
- Empty or syntactically hostile IOC values (single-quote, control chars)
  raise :class:`IOCExportError` — the STIX pattern grammar is fragile and
  a broken pattern would silently break downstream consumers.
- ``findings`` is accepted for API symmetry with the other exporters but
  is not currently embedded in the bundle. A future pass will add
  ``sighting`` objects derived from each finding's citations.

References:

- docs/design/analysis-output-pipeline.md
- STIX 2.1 specification, section 4 (Indicator SDO)
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from core.types import Finding, IOCType, IOCVerdict, utcnow


class IOCExportError(ValueError):
    """Raised when input IOCs cannot produce a valid export."""


# Namespace used for deterministic UUIDv5 derivation. We piggy-back on
# NAMESPACE_URL because it is stable across Python versions and every
# consumer that reads STIX bundles already understands that IDs are
# opaque UUIDs; the derivation scheme is an APTWatcher implementation
# detail.
_UUID_NAMESPACE = uuid.NAMESPACE_URL


# STIX pattern templates per IOC type. Values are interpolated after
# validation; the templates themselves never change.
_PATTERN_TEMPLATES: dict[IOCType, str] = {
    "ipv4": "[ipv4-addr:value = '{value}']",
    "ipv6": "[ipv6-addr:value = '{value}']",
    "domain": "[domain-name:value = '{value}']",
    "url": "[url:value = '{value}']",
    "email": "[email-addr:value = '{value}']",
    "sha256": "[file:hashes.'SHA-256' = '{value}']",
    "sha1": "[file:hashes.'SHA-1' = '{value}']",
    "md5": "[file:hashes.'MD5' = '{value}']",
}


def _stix_timestamp(dt: datetime | None) -> str:
    """Format a datetime as a STIX 2.1 timestamp (RFC 3339, UTC, 'Z')."""
    if dt is None:
        dt = utcnow()
    dt = dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)
    # Drop microseconds below millisecond precision for stability.
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _deterministic_id(prefix: str, seed: str) -> str:
    """Build a STIX object ID with a UUIDv5-derived tail."""
    tail = uuid.uuid5(_UUID_NAMESPACE, seed)
    return f"{prefix}--{tail}"


def _validate_value(ioc: IOCVerdict) -> str:
    """Return a value that is safe to interpolate into a STIX pattern.

    Raises :class:`IOCExportError` if the value is empty or contains a
    character that would break the STIX pattern string literal.
    """
    value = (ioc.value or "").strip()
    if not value:
        raise IOCExportError("IOC value is empty")
    if "'" in value:
        raise IOCExportError(
            f"IOC value contains a single-quote which breaks STIX pattern "
            f"strings: {value!r}"
        )
    # Reject ASCII control characters; STIX patterns must be a single line.
    if any(ord(c) < 0x20 for c in value):
        raise IOCExportError(
            f"IOC value contains a control character: {value!r}"
        )
    return value


def _build_pattern(ioc: IOCVerdict) -> str:
    tmpl = _PATTERN_TEMPLATES.get(ioc.ioc_type)
    if tmpl is None:
        raise IOCExportError(f"unsupported IOC type for STIX export: {ioc.ioc_type}")
    value = _validate_value(ioc)
    return tmpl.format(value=value)


def _build_indicator(
    ioc: IOCVerdict,
    *,
    created_by: str,
    now_iso: str,
) -> dict[str, Any]:
    valid_from = _stix_timestamp(ioc.first_seen) if ioc.first_seen else now_iso
    indicator_id = _deterministic_id(
        "indicator",
        f"aptwatcher:{ioc.ioc_type}:{ioc.value}",
    )
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": indicator_id,
        "created": now_iso,
        "modified": now_iso,
        "created_by_ref": created_by,
        "name": f"{ioc.ioc_type}: {ioc.value}",
        "pattern": _build_pattern(ioc),
        "pattern_type": "stix",
        "valid_from": valid_from,
        "labels": ["malicious-activity"],
    }


def _build_identity(identity_id: str, *, now_iso: str) -> dict[str, Any]:
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now_iso,
        "modified": now_iso,
        "name": "APTWatcher",
        "identity_class": "organization",
    }


def export_stix_bundle(
    *,
    iocs: list[IOCVerdict],
    findings: list[Finding] | None = None,
    output_path: Path,
    incident_id: str,
    created_by: str = "identity--aptwatcher",
) -> dict[str, Any]:
    """Emit a STIX 2.1 bundle.json to ``output_path``.

    Returns the in-memory bundle dictionary, for callers that want to
    hash it or attach it to an ``IncidentBundle`` manifest without
    re-reading the file.
    """
    _ = findings  # accepted for API symmetry; see module docstring
    if not iocs:
        raise IOCExportError("cannot build a STIX bundle from an empty IOC list")
    if not incident_id:
        raise IOCExportError("incident_id is required")
    if not created_by.startswith("identity--"):
        raise IOCExportError(
            f"created_by must be a STIX identity id (got {created_by!r})"
        )

    now_iso = _stix_timestamp(utcnow())

    objects: list[dict[str, Any]] = [
        _build_identity(created_by, now_iso=now_iso),
    ]
    for ioc in iocs:
        objects.append(_build_indicator(ioc, created_by=created_by, now_iso=now_iso))

    # Deterministic bundle ID: derived from incident_id plus the ordered
    # indicator IDs, so the same input set always produces the same bundle.
    seed = "|".join([incident_id, *[obj["id"] for obj in objects if obj["type"] == "indicator"]])
    bundle_id = _deterministic_id("bundle", seed)

    bundle: dict[str, Any] = {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects,
    }

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(bundle, indent=2, sort_keys=False),
        encoding="utf-8",
    )
    return bundle


__all__ = [
    "IOCExportError",
    "export_stix_bundle",
]
