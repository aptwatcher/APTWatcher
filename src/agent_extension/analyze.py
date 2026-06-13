"""
`aptwatcher analyze` -- fan verified findings + IOCs into the full
analysis-output bundle (YARA / Suricata rules, STIX / community YAML /
per-type txt IOCs, EN/FR .docx reports, analyst + TTP Markdown, stats
manifest, optional signed IncidentBundle).

This module is the thin CLI wiring over the generators and renderers in
`core.analysis.*`. It owns argument parsing helpers, input loading, and
the fan-out orchestration. All business logic lives in the shared brain
modules; this file only routes.

Exit codes (per the design doc CLI contract):

- 0 success (or fully skipped).
- 1 user / input error (missing input file, bad JSON, missing operator
  for `--sign`, unknown language).
- 2 render / generator error (an exporter raised a typed error).

References:
- docs/design/analysis-output-pipeline.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from core.types import Finding, IOCVerdict

# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def build_analyze_parser(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    """Configure `--input` / `--output-dir` / ... on the given parser.

    The parser is returned so callers can chain. Split out so both the
    argparse integration path and the Typer bridge can share exactly the
    same flag surface.
    """
    parser.add_argument(
        "--input",
        dest="input",
        type=Path,
        required=True,
        help="Path to a JSON file containing {'findings': [...], 'iocs': [...]}.",
    )
    parser.add_argument(
        "--output-dir",
        dest="output_dir",
        type=Path,
        required=True,
        help="Directory (created if absent) into which the bundle tree is written.",
    )
    parser.add_argument(
        "--campaign-tag",
        dest="campaign_tag",
        default="APTWATCHER",
        help="Campaign tag used for rule names and report titles.",
    )
    parser.add_argument(
        "--incident-id",
        dest="incident_id",
        default=None,
        help="Stable incident id (auto-generated as INC-<YYYYMMDD>-<hex6> if absent).",
    )
    parser.add_argument(
        "--operator",
        dest="operator",
        default=None,
        help="Signing operator name. Required when --sign is set.",
    )
    parser.add_argument(
        "--language",
        dest="language",
        choices=["en", "fr", "both"],
        default="both",
        help="Report language(s) to render (.docx). Markdown outputs are always English.",
    )
    parser.add_argument(
        "--sid-start",
        dest="sid_start",
        type=int,
        default=3_000_000,
        help="Starting Suricata SID for auto-generated rules.",
    )
    parser.add_argument(
        "--skip-rules",
        dest="skip_rules",
        action="store_true",
        help="Skip YARA + Suricata rule generation.",
    )
    parser.add_argument(
        "--skip-reports",
        dest="skip_reports",
        action="store_true",
        help="Skip .docx and Markdown report rendering.",
    )
    parser.add_argument(
        "--skip-iocs",
        dest="skip_iocs",
        action="store_true",
        help="Skip STIX / community YAML / per-type txt IOC exports.",
    )
    parser.add_argument(
        "--sign",
        dest="sign",
        action="store_true",
        help="Build a signed IncidentBundle alongside the analysis outputs.",
    )
    parser.add_argument(
        "--private-key-path",
        dest="private_key_path",
        type=Path,
        default=None,
        help="Ed25519 private-key file. Required when --sign is set.",
    )
    parser.add_argument(
        "--sift-workstation",
        dest="sift_workstation",
        default="offline-sift",
        help="Hostname tag embedded in the bundle manifest.",
    )
    return parser


# ---------------------------------------------------------------------------
# Input loading
# ---------------------------------------------------------------------------


def _load_input_bundle(input_path: Path) -> tuple[list[Finding], list[IOCVerdict]]:
    """Load the `--input` JSON file into typed finding + IOC lists.

    The JSON shape is flexible but must contain two top-level lists:
    `findings` and `iocs`. Any schema mismatch raises ValueError.
    """
    if not input_path.exists():
        raise FileNotFoundError(f"input file not found: {input_path}")

    try:
        raw = json.loads(input_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"input file is not valid JSON: {exc}") from exc

    if not isinstance(raw, dict):
        raise ValueError(
            "input JSON must be an object with 'findings' and 'iocs' keys"
        )

    findings_raw = raw.get("findings", [])
    iocs_raw = raw.get("iocs", [])
    if not isinstance(findings_raw, list) or not isinstance(iocs_raw, list):
        raise ValueError("'findings' and 'iocs' must be JSON arrays")

    findings: list[Finding] = []
    for item in findings_raw:
        try:
            findings.append(Finding.model_validate(item))
        except ValidationError as exc:
            raise ValueError(f"invalid Finding payload: {exc}") from exc

    iocs: list[IOCVerdict] = []
    for item in iocs_raw:
        try:
            iocs.append(IOCVerdict.model_validate(item))
        except ValidationError as exc:
            raise ValueError(f"invalid IOCVerdict payload: {exc}") from exc

    return findings, iocs


def _auto_incident_id() -> str:
    """Generate a stable-ish fallback `INC-<YYYYMMDD>-<hex6>` id."""
    stamp = datetime.now(tz=UTC).strftime("%Y%m%d")
    suffix = uuid.uuid4().hex[:6].upper()
    return f"INC-{stamp}-{suffix}"


def _slugify_campaign(tag: str) -> str:
    """Lowercase alnum + dashes slug used in filenames."""
    cleaned = "".join(c if c.isalnum() else "-" for c in tag.strip().lower())
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    return cleaned.strip("-") or "aptwatcher"


# ---------------------------------------------------------------------------
# Fan-out
# ---------------------------------------------------------------------------


def _write_rules(
    *,
    output_dir: Path,
    findings: list[Finding],
    iocs: list[IOCVerdict],
    campaign_tag: str,
    sid_start: int,
) -> dict[str, Path]:
    """Write .yar + .suricata.rules + .sigma.yml. Returns written paths."""
    from core.analysis.rules_sigma import generate_sigma_rules
    from core.analysis.rules_suricata import generate_suricata_rules
    from core.analysis.rules_yara import generate_yara_rules

    rules_dir = output_dir / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    slug = _slugify_campaign(campaign_tag)
    written: dict[str, Path] = {}

    yara_rules = generate_yara_rules(
        findings=findings, iocs=iocs, campaign_tag=campaign_tag,
    )
    yara_path = rules_dir / f"{slug}.yar"
    yara_path.write_text(
        "\n\n".join(r.text for r in yara_rules) + ("\n" if yara_rules else ""),
        encoding="utf-8",
    )
    written["yara"] = yara_path

    suricata_rules = generate_suricata_rules(
        findings=findings,
        iocs=iocs,
        sid_start=sid_start,
        campaign_tag=campaign_tag,
    )
    suricata_path = rules_dir / f"{slug}.suricata.rules"
    suricata_path.write_text(
        "\n".join(r.text for r in suricata_rules) + ("\n" if suricata_rules else ""),
        encoding="utf-8",
    )
    written["suricata"] = suricata_path

    sigma_rules = generate_sigma_rules(
        findings=findings, iocs=iocs, campaign_tag=campaign_tag,
    )
    if sigma_rules:
        sigma_path = rules_dir / f"{slug}.sigma.yml"
        sigma_path.write_text(
            "\n---\n".join(r.text for r in sigma_rules) + "\n",
            encoding="utf-8",
        )
        written["sigma"] = sigma_path

    return written


def _write_iocs(
    *,
    output_dir: Path,
    findings: list[Finding],
    iocs: list[IOCVerdict],
    incident_id: str,
    campaign_tag: str,
) -> dict[str, Path]:
    """Write STIX bundle + community YAML + per-type txt. Returns paths."""
    from core.analysis.export_community import export_community_yaml
    from core.analysis.export_iocs_txt import export_per_type_txt
    from core.analysis.export_stix import export_stix_bundle

    iocs_dir = output_dir / "iocs"
    iocs_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}

    if iocs:
        txt_paths = export_per_type_txt(iocs=iocs, output_dir=iocs_dir)
        for ioc_type, path in txt_paths.items():
            written[f"txt:{ioc_type}"] = path

    stix_path = iocs_dir / "bundle.stix.json"
    export_stix_bundle(
        iocs=iocs,
        findings=findings,
        output_path=stix_path,
        incident_id=incident_id,
    )
    written["stix"] = stix_path

    community_path = iocs_dir / "community-submission.yml"
    export_community_yaml(
        iocs=iocs,
        findings=findings,
        output_path=community_path,
        campaign_tag=campaign_tag,
        submitter="aptwatcher-bot",
    )
    written["community"] = community_path

    return written


def _write_reports(
    *,
    output_dir: Path,
    findings: list[Finding],
    iocs: list[IOCVerdict],
    incident_id: str,
    campaign_tag: str,
    language: str,
) -> dict[str, Path]:
    """Write .docx + .md reports. Returns paths."""
    from core.analysis.report_docx import render_docx_report
    from core.analysis.report_markdown import (
        render_analyst_markdown,
        render_ttp_assessment,
    )

    reports_dir = output_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}

    if language in ("en", "both"):
        en_path = reports_dir / f"Campaign_Report_{incident_id}.docx"
        render_docx_report(
            findings=findings,
            iocs=iocs,
            output_path=en_path,
            incident_id=incident_id,
            campaign_tag=campaign_tag,
            language="en",
        )
        written["docx_en"] = en_path

    if language in ("fr", "both"):
        fr_path = reports_dir / f"Campaign_Report_{incident_id}_FR.docx"
        render_docx_report(
            findings=findings,
            iocs=iocs,
            output_path=fr_path,
            incident_id=incident_id,
            campaign_tag=campaign_tag,
            language="fr",
        )
        written["docx_fr"] = fr_path

    md_path = reports_dir / f"ANALYSIS-{incident_id}.md"
    render_analyst_markdown(
        findings=findings,
        iocs=iocs,
        output_path=md_path,
        incident_id=incident_id,
        campaign_tag=campaign_tag,
    )
    written["md_analysis"] = md_path

    ttp_path = reports_dir / f"TTP_{incident_id}.md"
    render_ttp_assessment(
        findings=findings,
        output_path=ttp_path,
        incident_id=incident_id,
        campaign_tag=campaign_tag,
    )
    written["md_ttp"] = ttp_path

    return written


def _write_generation_report(
    *,
    output_dir: Path,
    incident_id: str,
    campaign_tag: str,
    counts: dict[str, int],
    files: dict[str, Path],
) -> Path:
    """Write generation_report.json with file digests + counts."""
    try:
        from core.analysis.report_stats import render_generation_report
    except Exception:
        render_generation_report = None  # type: ignore[assignment]

    report_path = output_dir / "generation_report.json"

    if render_generation_report is not None:
        file_digests = {
            key: hashlib.sha256(path.read_bytes()).hexdigest()
            for key, path in files.items()
            if path.is_file()
        }
        render_generation_report(
            output_path=report_path,
            incident_id=incident_id,
            campaign_tag=campaign_tag,
            counts=counts,
            sid_range=None,
            file_digests=file_digests,
        )
        return report_path

    # Inline fallback so the manifest is always produced even if the
    # dedicated renderer is not yet wired in.
    manifest: dict[str, Any] = {
        "schema_version": "1.0",
        "incident_id": incident_id,
        "campaign_tag": campaign_tag,
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "counts": counts,
        "files": {},
    }
    for key, path in files.items():
        if path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            manifest["files"][key] = {
                "path": str(path),
                "sha256": digest,
                "bytes": path.stat().st_size,
            }
        elif path.is_dir():
            # e.g. the signed incident-bundle directory; its members are
            # digest-pinned by the bundle's own manifest.json.
            manifest["files"][key] = {"path": str(path), "directory": True}
        else:
            manifest["files"][key] = {"path": str(path), "missing": True}

    report_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report_path


def _write_signed_bundle(
    *,
    output_dir: Path,
    findings: list[Finding],
    iocs: list[IOCVerdict],
    incident_id: str,
    operator: str,
    private_key_path: Path,
    sift_workstation: str,
) -> Path:
    """Build a signed IncidentBundle under `<output-dir>/incident-bundle/`."""
    from core.bundle.exporter import export_bundle

    bundle_dir = output_dir / "incident-bundle"
    key_bytes = private_key_path.read_bytes()
    export_bundle(
        bundle_dir=bundle_dir,
        incident_id=incident_id,
        operator=operator,
        sift_workstation=sift_workstation,
        findings=findings,
        audit_events=[],
        private_key_bytes=key_bytes,
        iocs=iocs,
    )
    return bundle_dir


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def cmd_analyze(args: argparse.Namespace) -> int:
    """Fan out findings + IOCs into the full analysis output bundle.

    Returns an exit code; callers convert into `sys.exit(...)` or
    `typer.Exit(code=...)`.
    """
    input_path: Path = args.input
    output_dir: Path = args.output_dir
    campaign_tag: str = args.campaign_tag
    incident_id: str = args.incident_id or _auto_incident_id()
    operator: str | None = args.operator
    language: str = args.language
    sid_start: int = args.sid_start
    skip_rules: bool = args.skip_rules
    skip_reports: bool = args.skip_reports
    skip_iocs: bool = args.skip_iocs
    sign: bool = args.sign
    private_key_path: Path | None = args.private_key_path
    sift_workstation: str = args.sift_workstation

    # ---- validation ------------------------------------------------------
    if sign and not operator:
        print(
            "error: --sign requires --operator <name>",
            file=sys.stderr,
        )
        return 1
    if sign and private_key_path is None:
        print(
            "error: --sign requires --private-key-path <file>",
            file=sys.stderr,
        )
        return 1
    if sign and private_key_path is not None and not private_key_path.exists():
        print(
            f"error: private key file not found: {private_key_path}",
            file=sys.stderr,
        )
        return 1

    # ---- load input ------------------------------------------------------
    try:
        findings, iocs = _load_input_bundle(input_path)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    output_dir.mkdir(parents=True, exist_ok=True)

    # Persist the input arrays as sibling copies so `publish` can pick
    # them up without re-parsing the original `--input` file.
    try:
        (output_dir / "findings.json").write_text(
            json.dumps(
                [f.model_dump(mode="json") for f in findings], indent=2, sort_keys=True,
            ) + "\n",
            encoding="utf-8",
        )
        (output_dir / "iocs.json").write_text(
            json.dumps(
                [i.model_dump(mode="json") for i in iocs], indent=2, sort_keys=True,
            ) + "\n",
            encoding="utf-8",
        )
        (output_dir / "manifest.json").write_text(
            json.dumps(
                {"incident_id": incident_id, "campaign_tag": campaign_tag},
                indent=2,
                sort_keys=True,
            ) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        print(f"error: could not stage bundle files: {exc}", file=sys.stderr)
        return 2

    # ---- fan-out ---------------------------------------------------------
    all_files: dict[str, Path] = {}
    try:
        if not skip_rules:
            all_files.update(
                _write_rules(
                    output_dir=output_dir,
                    findings=findings,
                    iocs=iocs,
                    campaign_tag=campaign_tag,
                    sid_start=sid_start,
                ),
            )
        if not skip_iocs:
            all_files.update(
                _write_iocs(
                    output_dir=output_dir,
                    findings=findings,
                    iocs=iocs,
                    incident_id=incident_id,
                    campaign_tag=campaign_tag,
                ),
            )
        if not skip_reports:
            all_files.update(
                _write_reports(
                    output_dir=output_dir,
                    findings=findings,
                    iocs=iocs,
                    incident_id=incident_id,
                    campaign_tag=campaign_tag,
                    language=language,
                ),
            )
        if sign and operator is not None and private_key_path is not None:
            bundle_dir = _write_signed_bundle(
                output_dir=output_dir,
                findings=findings,
                iocs=iocs,
                incident_id=incident_id,
                operator=operator,
                private_key_path=private_key_path,
                sift_workstation=sift_workstation,
            )
            all_files["incident_bundle"] = bundle_dir
    except Exception as exc:  # generator/exporter typed errors bubble here
        print(f"error: analysis pipeline failed: {exc}", file=sys.stderr)
        return 2

    counts = {
        "findings": len(findings),
        "iocs": len(iocs),
    }
    try:
        report_path = _write_generation_report(
            output_dir=output_dir,
            incident_id=incident_id,
            campaign_tag=campaign_tag,
            counts=counts,
            files=all_files,
        )
    except Exception as exc:
        print(f"error: could not write generation_report.json: {exc}", file=sys.stderr)
        return 2

    print(f"analyze: incident_id={incident_id}")
    print(f"analyze: findings={len(findings)} iocs={len(iocs)}")
    print(f"analyze: outputs under {output_dir}")
    print(f"analyze: manifest={report_path}")
    return 0


__all__ = ["build_analyze_parser", "cmd_analyze"]
