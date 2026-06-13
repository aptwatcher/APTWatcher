"""
Generation report writer -- the ``generation_report.json`` manifest.

Phase 3.8 task #63 companion to :mod:`core.analysis.report_docx` and
:mod:`core.analysis.report_markdown`.

The generation report is a single JSON file that travels inside the
``IncidentBundle`` alongside the rule, IOC, and report artifacts. It is
the canonical answer to "how many of each thing did the pipeline
produce and what are their hashes?"

JSON shape::

    {
      "schema_version": "1.0",
      "incident_id": "...",
      "campaign_tag": "...",
      "generated_at": "<iso-8601>",
      "counts": {...},
      "sid_range": {"start": N, "end": M} | null,
      "file_digests": {"<relative-path>": "sha256:<hex>", ...}
    }

Reference:

- ``docs/design/analysis-output-pipeline.md`` -- "Audit and
  provenance" section, ``generation_report.json`` example.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from core.analysis.report_docx import ReportRenderError
from core.types import utcnow

SCHEMA_VERSION = "1.0"


def _format_datetime(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    dt = dt.astimezone(UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def render_generation_report(
    *,
    output_path: Path,
    incident_id: str,
    campaign_tag: str,
    counts: dict[str, int],
    sid_range: tuple[int, int] | None,
    file_digests: dict[str, str],
    generated_at: datetime | None = None,
) -> Path:
    """
    Write ``generation_report.json`` -- the stats manifest.

    Parameters
    ----------
    output_path:
        Target file path. Must not exist -- the renderer refuses to
        overwrite.
    incident_id:
        Run identifier.
    campaign_tag:
        Human-readable campaign slug.
    counts:
        Mapping of artifact kind to integer count, e.g.
        ``{"findings": 12, "iocs": 47, "yara_rules": 3}``.
    sid_range:
        Inclusive ``(start, end)`` Suricata SID range for this run, or
        ``None`` if no Suricata rules were emitted.
    file_digests:
        Mapping of relative path to hash string (usual form
        ``"sha256:<hex>"``).
    generated_at:
        Optional timestamp override (for test determinism).

    Returns
    -------
    Path
        The same ``output_path`` value.
    """
    if not incident_id:
        raise ReportRenderError("incident_id must be a non-empty string")
    if not campaign_tag:
        raise ReportRenderError("campaign_tag must be a non-empty string")

    # Validate counts and file_digests shape up-front so a malformed
    # caller gets a clear error instead of a broken JSON file.
    for key, value in counts.items():
        if not isinstance(key, str):
            raise ReportRenderError(f"counts keys must be strings; got {type(key).__name__}")
        if not isinstance(value, int) or isinstance(value, bool):
            raise ReportRenderError(
                f"counts[{key!r}] must be int; got {type(value).__name__}",
            )
        if value < 0:
            raise ReportRenderError(f"counts[{key!r}] must be non-negative; got {value}")

    for key, digest in file_digests.items():
        if not isinstance(key, str):
            raise ReportRenderError(
                f"file_digests keys must be strings; got {type(key).__name__}",
            )
        if not isinstance(digest, str) or not digest:
            raise ReportRenderError(
                f"file_digests[{key!r}] must be a non-empty string",
            )

    if sid_range is not None:
        if not (isinstance(sid_range, tuple) and len(sid_range) == 2):
            raise ReportRenderError("sid_range must be a (start, end) tuple or None")
        start, end = sid_range
        if not (isinstance(start, int) and isinstance(end, int)):
            raise ReportRenderError("sid_range entries must be integers")
        if start > end:
            raise ReportRenderError(
                f"sid_range start ({start}) must be <= end ({end})",
            )

    output_path = Path(output_path)
    if output_path.exists():
        msg = f"refusing to overwrite existing manifest: {output_path}"
        raise ReportRenderError(msg)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    when = generated_at or utcnow()
    manifest: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "incident_id": incident_id,
        "campaign_tag": campaign_tag,
        "generated_at": _format_datetime(when),
        # Sort counts keys so the on-disk JSON is deterministic across runs.
        "counts": {k: counts[k] for k in sorted(counts)},
        "sid_range": (
            {"start": sid_range[0], "end": sid_range[1]}
            if sid_range is not None
            else None
        ),
        "file_digests": {k: file_digests[k] for k in sorted(file_digests)},
    }

    # indent=2 keeps the manifest human-readable; sort_keys is off
    # because we already built the dict in deterministic order.
    output_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return output_path


__all__ = [
    "SCHEMA_VERSION",
    "render_generation_report",
]
