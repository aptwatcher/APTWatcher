"""
Per-type IOC text dumps.

Mirrors the ``apt-intel/iocs/*.txt`` convention: one file per IOC type,
one value per line, sorted and deduplicated. These files feed SOC
consumers that want raw lists (block-lists, SIEM watchlists, quick
``grep`` targets) without parsing YAML or JSON.

Normalization rules:

- ``domain`` and ``email`` values are lowercased. DNS is case-insensitive
  and mailbox local-parts are treated as case-insensitive by every
  real-world consumer.
- ``sha256`` / ``sha1`` / ``md5`` are lowercased. Hex is canonically
  lowercase in every upstream feed we cross-reference.
- ``url`` values are kept verbatim — URL paths and query strings are
  case-sensitive per RFC 3986.
- ``ipv4`` / ``ipv6`` are kept verbatim. IPv6 normalization is out of
  scope here; the exporter trusts whatever upstream extractor produced
  the value.

Safety:

- The exporter refuses to overwrite an existing ``<type>.txt`` file in
  ``output_dir``. Callers must clean the directory or write to a fresh
  path. This matches the refuse-to-overwrite semantics in the
  evidence-integrity contract.
"""

from __future__ import annotations

from pathlib import Path

from core.analysis.export_stix import IOCExportError
from core.types import IOCType, IOCVerdict

# Types whose canonical form is lowercase. ``url`` is deliberately
# absent — paths and query strings are case-sensitive.
_LOWERCASE_TYPES: frozenset[IOCType] = frozenset(
    {"domain", "email", "sha256", "sha1", "md5"}
)


def _normalize(ioc: IOCVerdict) -> str:
    value = (ioc.value or "").strip()
    if not value:
        raise IOCExportError(
            f"IOC of type {ioc.ioc_type} has empty value"
        )
    if ioc.ioc_type in _LOWERCASE_TYPES:
        return value.lower()
    return value


def export_per_type_txt(
    *,
    iocs: list[IOCVerdict],
    output_dir: Path,
) -> dict[str, Path]:
    """Emit one ``<type>.txt`` file per IOC type.

    Returns a mapping from IOC type to the file path written. Types
    absent from ``iocs`` are also absent from the result.
    """
    if not iocs:
        raise IOCExportError("cannot export an empty IOC list")

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Group values by type, with normalization + deduplication.
    buckets: dict[str, set[str]] = {}
    for ioc in iocs:
        buckets.setdefault(ioc.ioc_type, set()).add(_normalize(ioc))

    # Refuse to overwrite any pre-existing <type>.txt file we would touch.
    conflicts: list[str] = []
    for ioc_type in buckets:
        candidate = output_dir / f"{ioc_type}.txt"
        if candidate.exists():
            conflicts.append(str(candidate))
    if conflicts:
        raise IOCExportError(
            "refusing to overwrite existing IOC files: " + ", ".join(sorted(conflicts))
        )

    written: dict[str, Path] = {}
    for ioc_type, values in buckets.items():
        path = output_dir / f"{ioc_type}.txt"
        ordered = sorted(values)
        # Trailing newline so tools like `wc -l` give a stable count.
        path.write_text("\n".join(ordered) + "\n", encoding="utf-8")
        written[ioc_type] = path

    return written


__all__ = [
    "export_per_type_txt",
]
