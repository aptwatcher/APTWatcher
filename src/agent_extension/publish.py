"""
`aptwatcher publish` -- push a generated analysis bundle through one or
more publication adapters (Netcraft v3 Report API, MISP event push, GLPI
attachment upload, or the in-memory stub used in tests).

Mirrors the `analyze` module: all business logic is in `core.publish.*`;
this file handles argument parsing, bundle loading, adapter wiring, and
exit-code translation.

Exit codes:

- 0 every named adapter either submitted or ran in dry-run mode.
- 1 user / input error (missing bundle-dir, missing env var, unknown
  adapter).
- 3 any adapter raised `PublicationError` (network/auth failure).

References:
- docs/design/analysis-output-pipeline.md
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from core.types import Finding, IOCVerdict

ALLOWED_ADAPTERS = ("netcraft", "misp", "glpi", "stub", "taxii")


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def build_publish_parser(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    """Configure `--bundle-dir` / `--adapter` / ... on the given parser."""
    parser.add_argument(
        "--bundle-dir",
        dest="bundle_dir",
        type=Path,
        required=True,
        help="Bundle directory produced by `aptwatcher analyze`.",
    )
    parser.add_argument(
        "--adapter",
        dest="adapters",
        action="append",
        choices=list(ALLOWED_ADAPTERS),
        required=True,
        help=(
            "Adapter to invoke. Repeat the flag to run multiple adapters. "
            f"Allowed: {', '.join(ALLOWED_ADAPTERS)}."
        ),
    )
    # dry-run is default-TRUE. The operator must pass --no-dry-run to
    # actually fire requests. We implement this with a mutually-exclusive
    # --dry-run / --no-dry-run pair so the intent is never ambiguous.
    dry = parser.add_mutually_exclusive_group()
    dry.add_argument(
        "--dry-run",
        dest="dry_run",
        action="store_true",
        default=True,
        help="Default. Print what would be submitted; make no network calls.",
    )
    dry.add_argument(
        "--no-dry-run",
        dest="dry_run",
        action="store_false",
        help="Opt-out: actually submit the bundle through the adapter.",
    )
    parser.add_argument(
        "--netcraft-api-key-env",
        dest="netcraft_api_key_env",
        default="APTW_NETCRAFT_API_KEY",
        help="Environment variable holding the Netcraft Report v3 API key.",
    )
    parser.add_argument(
        "--misp-api-key-env",
        dest="misp_api_key_env",
        default="APTW_MISP_API_KEY",
        help="Environment variable holding the MISP API key.",
    )
    parser.add_argument(
        "--misp-url",
        dest="misp_url",
        default=None,
        help="MISP base URL (required when --adapter misp is used live).",
    )
    parser.add_argument(
        "--glpi-ticket-id",
        dest="glpi_ticket_id",
        type=int,
        default=None,
        help="GLPI ticket id (required when --adapter glpi is used).",
    )
    parser.add_argument(
        "--taxii-server-url",
        dest="taxii_server_url",
        default=None,
        help="TAXII 2.1 server base URL (required when --adapter taxii is used).",
    )
    parser.add_argument(
        "--taxii-collection-id",
        dest="taxii_collection_id",
        default=None,
        help="TAXII 2.1 collection id (required when --adapter taxii is used).",
    )
    parser.add_argument(
        "--taxii-api-key-env",
        dest="taxii_api_key_env",
        default="APTW_TAXII_API_KEY",
        help="Environment variable holding the TAXII 2.1 bearer token.",
    )
    parser.add_argument(
        "--taxii-username",
        dest="taxii_username",
        default=None,
        help="Optional HTTP basic-auth username for TAXII (mutually exclusive with bearer).",
    )
    parser.add_argument(
        "--taxii-password-env",
        dest="taxii_password_env",
        default=None,
        help="Env var holding the TAXII basic-auth password (paired with --taxii-username).",
    )
    return parser


# ---------------------------------------------------------------------------
# Bundle loading
# ---------------------------------------------------------------------------


def _load_bundle(
    bundle_dir: Path,
) -> tuple[list[Finding], list[IOCVerdict], dict[str, Any]]:
    """Load findings.json + iocs.json + manifest.json from `bundle_dir`."""
    if not bundle_dir.exists() or not bundle_dir.is_dir():
        raise FileNotFoundError(f"bundle directory not found: {bundle_dir}")

    findings_path = bundle_dir / "findings.json"
    iocs_path = bundle_dir / "iocs.json"
    manifest_path = bundle_dir / "manifest.json"

    if not findings_path.exists() or not iocs_path.exists():
        raise FileNotFoundError(
            f"bundle is missing findings.json or iocs.json: {bundle_dir}"
        )

    try:
        findings_raw = json.loads(findings_path.read_text(encoding="utf-8"))
        iocs_raw = json.loads(iocs_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"bundle JSON is malformed: {exc}") from exc

    findings: list[Finding] = []
    for item in findings_raw:
        # Support both the raw Finding shape and the BundleFinding wrapper
        # (`{"finding": {...}}`) produced by export_bundle.
        if isinstance(item, dict) and "finding" in item and "finding_id" not in item:
            item = item["finding"]  # noqa: PLW2901 — deliberate unwrap
        try:
            findings.append(Finding.model_validate(item))
        except ValidationError as exc:
            raise ValueError(f"invalid Finding in bundle: {exc}") from exc

    iocs: list[IOCVerdict] = []
    for item in iocs_raw:
        if isinstance(item, dict) and "ioc" in item and "ioc_type" not in item:
            item = item["ioc"]  # noqa: PLW2901 — deliberate unwrap
        try:
            iocs.append(IOCVerdict.model_validate(item))
        except ValidationError as exc:
            raise ValueError(f"invalid IOCVerdict in bundle: {exc}") from exc

    manifest: dict[str, Any] = {}
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            manifest = {}

    return findings, iocs, manifest


# ---------------------------------------------------------------------------
# Adapter factory
# ---------------------------------------------------------------------------


def _instantiate_adapter(
    *,
    name: str,
    args: argparse.Namespace,
    bundle_dir: Path,
):
    """Return a concrete PublicationAdapter instance for the given name.

    Imports are local so a missing `core.publish` module (e.g. in a
    partially landed branch) surfaces as a `PublicationError`-ish user
    error, not an ImportError at CLI startup.
    """
    if name == "netcraft":
        from core.publish.netcraft import NetcraftAdapter

        key_env = args.netcraft_api_key_env
        api_key = os.environ.get(key_env, "")
        if not api_key and not args.dry_run:
            raise ValueError(
                f"netcraft adapter needs env var {key_env!r} to be set",
            )
        return NetcraftAdapter(api_key=api_key)

    if name == "misp":
        from core.publish.misp import MispAdapter

        key_env = args.misp_api_key_env
        api_key = os.environ.get(key_env, "")
        if not args.misp_url:
            raise ValueError("misp adapter requires --misp-url")
        if not api_key and not args.dry_run:
            raise ValueError(
                f"misp adapter needs env var {key_env!r} to be set",
            )
        return MispAdapter(api_key=api_key, base_url=args.misp_url)

    if name == "glpi":
        from core.publish.glpi_attachment import GLPIAttachmentAdapter

        if args.glpi_ticket_id is None:
            raise ValueError("glpi adapter requires --glpi-ticket-id")
        return GLPIAttachmentAdapter(
            ticket_id=args.glpi_ticket_id,
            bundle_dir=bundle_dir,
        )

    if name == "stub":
        from core.publish.stub import StubPublicationAdapter

        return StubPublicationAdapter()

    if name == "taxii":
        from core.publish.taxii import TaxiiAdapter

        if not args.taxii_server_url:
            raise ValueError("taxii adapter requires --taxii-server-url")
        if not args.taxii_collection_id:
            raise ValueError("taxii adapter requires --taxii-collection-id")
        # Env-var presence is checked by the adapter itself at POST time
        # (and only in live mode — dry-run never touches env vars).
        return TaxiiAdapter(
            server_url=args.taxii_server_url,
            collection_id=args.taxii_collection_id,
            api_key_env=args.taxii_api_key_env,
            username=args.taxii_username,
            password_env=args.taxii_password_env,
        )

    raise ValueError(f"unknown adapter: {name!r}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def cmd_publish(args: argparse.Namespace) -> int:
    """Push `bundle_dir` through the named adapters. Returns exit code."""
    bundle_dir: Path = args.bundle_dir
    adapters: list[str] = list(args.adapters or [])
    dry_run: bool = args.dry_run

    if not adapters:
        print("error: at least one --adapter is required", file=sys.stderr)
        return 1

    # Validate adapter names up-front so a typo fails before we load a
    # potentially large bundle.
    for name in adapters:
        if name not in ALLOWED_ADAPTERS:
            print(f"error: unknown adapter {name!r}", file=sys.stderr)
            return 1

    try:
        findings, iocs, manifest = _load_bundle(bundle_dir)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    incident_id = str(manifest.get("incident_id", "") or "")
    campaign_tag = str(manifest.get("campaign_tag", "") or "APTWATCHER")

    # Deferred import: PublicationError lives in core.publish.
    try:
        from core.publish import PublicationError
    except Exception:
        class PublicationError(Exception):  # type: ignore[no-redef]
            """Fallback used only when core.publish is not yet wired in."""

    had_failure = False

    for name in adapters:
        try:
            adapter = _instantiate_adapter(
                name=name, args=args, bundle_dir=bundle_dir,
            )
        except ValueError as exc:
            print(f"publish[{name}]: user error: {exc}", file=sys.stderr)
            return 1
        except Exception as exc:
            print(
                f"publish[{name}]: failed to instantiate adapter: {exc}",
                file=sys.stderr,
            )
            return 1

        try:
            result = adapter.publish(
                findings=findings,
                iocs=iocs,
                incident_id=incident_id,
                campaign_tag=campaign_tag,
                dry_run=dry_run,
            )
            status = "dry-run" if dry_run else "submitted"
            summary = f"publish[{name}]: {status}"
            if isinstance(result, dict):
                count = result.get("count") or result.get("submitted")
                if count is not None:
                    summary += f" count={count}"
            print(summary)
        except PublicationError as exc:
            print(f"publish[{name}]: PublicationError: {exc}", file=sys.stderr)
            had_failure = True
        except Exception as exc:  # noqa: BLE001 -- last-resort trap
            print(f"publish[{name}]: unexpected error: {exc}", file=sys.stderr)
            had_failure = True

    return 3 if had_failure else 0


__all__ = ["ALLOWED_ADAPTERS", "build_publish_parser", "cmd_publish"]
