"""
Tier 0 -- Timesketch wrapper.

Timesketch is the collaborative timeline-analysis frontend that ships
with SIFT. It has two command-line surfaces that matter for a Tier 0
defensive IR agent:

* ``timesketch_importer`` -- upload a plaso storage file (``.plaso``)
  or a CSV timeline into a sketch on a Timesketch server.
* ``timesketch`` -- the general-purpose CLI for listing sketches,
  describing sketch metadata, and running Lucene queries over events
  already stored on the server.

Unlike every other Tier 0 wrapper, this module hosts TWO
entry points with different safety profiles:

1. ``run_timesketch_query`` -- read-only. It lists / describes / runs
   Lucene searches against a Timesketch server. Evidence on the SIFT
   VM is never touched; the server side is strictly read.
2. ``run_timesketch_upload`` -- state-changing-operational. It sends
   a local timeline to a Timesketch server, which mutates that
   server's database. Even though the local evidence file is still
   read-only, the overall action changes observable state on another
   system. This wrapper gates the invocation on a user-supplied
   consent token and emits a ``timesketch_upload_consent`` audit event
   before the subprocess is launched -- the same pattern used by
   ``core.sift.update.run_sift_update``.

Design:

- Query subcommands are allow-listed
  (``TIMESKETCH_QUERY_SUBCOMMANDS``). Timesketch exposes many
  sub-subcommands (``user``, ``config``, ``import``, ``timeline``,
  ``analysis``, ...); the Tier 0 wrapper only exposes the read-only
  sketch-facing trio:
    * ``list``     -- list sketches the authenticated user can see.
    * ``describe`` -- describe one sketch's metadata and timelines.
    * ``search``   -- run a Lucene query over one sketch's events.
- ``host`` is validated as an ``http://`` or ``https://`` URL with no
  shell metacharacters. Timesketch requires a host URL for every
  non-help subcommand.
- ``sketch_id`` must be a positive integer. Timesketch rejects
  negative or zero sketch IDs at the server, but we reject earlier
  so we never put a value like ``-rf`` on the argv.
- ``query`` is validated against a Lucene-friendly but shell-hostile
  character set. Newlines, semicolons, backticks, dollar signs, and
  pipes are rejected outright. See ``_QUERY_RE``.
- ``timeline_name`` is validated against a conservative character
  set ``[A-Za-z0-9_\\-. ]+`` so it can be safely embedded in argv
  without quoting gymnastics.
- Consent-token-gating on ``run_timesketch_upload`` mirrors
  ``run_sift_update``: the expected value is a fixed sentinel,
  ``i-consent-timesketch-upload``. Anything else -- empty, whitespace,
  or a different string -- raises ``TimesketchUploadConsentError``
  before any network call. The consent event records
  ``consent_token_present`` / ``consent_token_length`` (never the raw
  value) and is written to the audit log BEFORE the subprocess is
  spawned.

argv shapes:

    timesketch --host <host> sketch list
    timesketch --host <host> sketch describe <sketch_id>
    timesketch --host <host> sketch search --query <lucene> <sketch_id>

    timesketch_importer [--host <host>]
                        --sketch <sketch_id>
                        --timeline_name <name>
                        <timeline_source>

References:
- docs/reference/sift-tools.md
- docs/design/tier0-sift-lifecycle.md
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

from core.audit import AuditLogger
from core.sift.runner import ToolRunError, ToolRunResult, run_tool

# Allow-listed read-only Timesketch CLI subcommands. Key = subcommand
# string; value = short human-readable reason for documentation and
# audit payloads.
TIMESKETCH_QUERY_SUBCOMMANDS: dict[str, str] = {
    "list": "List sketches accessible to the authenticated user. Read-only.",
    "describe": "Describe a sketch's metadata and timelines. Read-only.",
    "search": "Run a Lucene query over a sketch's events. Read-only.",
}

# Fixed sentinel the caller must supply to unlock the upload path.
# Matching the ``SiftUpdateConsentError`` pattern: the wrapper does
# not trust an arbitrary truthy string, only this specific one.
TIMESKETCH_UPLOAD_CONSENT_TOKEN: str = "i-consent-timesketch-upload"

# Host URL validator. Require an explicit scheme (``http://`` or
# ``https://``) so a typo like ``example.com`` does not get silently
# accepted. After the scheme we allow URL-safe characters only --
# no spaces, no shell metacharacters, no control characters.
_HOST_RE = re.compile(r"^https?://[A-Za-z0-9_\-.:/]+\Z")

# Lucene-friendly safe character set. Permits Lucene operators
# (``:``, ``(``, ``)``, ``[``, ``]``, ``{``, ``}``, ``*``, ``\\``,
# ``"``, ``'``), whitespace, forward slashes (for paths embedded in
# queries), and the usual alphanumerics / hyphen / underscore / dot.
# Whitespace is restricted to the plain space character (``\s`` would
# also admit newline and tab, which must be rejected); ``\Z`` anchors
# the match so a trailing newline cannot slip past ``$``.
# Rejects shell metacharacters: ``;``, ``|``, ``&``, ``<``, ``>``,
# backtick, ``$``, and any newline / tab character -- those are what
# an attacker would reach for to break out of the argv boundary.
_QUERY_RE = re.compile(r'^[A-Za-z0-9_\-\. :/\(\)\"\'\\*\[\]\{\}]+\Z')

# Timeline name validator. Plaso and Timesketch accept liberal
# timeline names but we pin a conservative set so a caller cannot
# smuggle argv-breaking content (and so operators can eyeball the
# value in the audit log without worrying about escape sequences).
_TIMELINE_NAME_RE = re.compile(r"^[A-Za-z0-9_\-. ]+\Z")


class TimesketchSubcommandError(ValueError):
    """Raised when a requested query subcommand is not in the allow-list."""


class TimesketchHostError(ValueError):
    """Raised when a host URL fails the http/https + safe-character check."""


class TimesketchQueryError(ValueError):
    """Raised when a Lucene query is empty or contains unsafe characters."""


class TimesketchUploadConsentError(PermissionError):
    """
    Raised when ``run_timesketch_upload`` is invoked without the exact
    consent sentinel. Upload is a state-changing-operational action
    (data is written to an external Timesketch server), so an explicit
    opt-in is required.
    """


class TimesketchTimelineNameError(ValueError):
    """Raised when a timeline_name fails the safe-character check."""


def _resolve_binary(name: str) -> Path:
    """Find a Timesketch binary on PATH. Preflight should have caught this."""
    found = shutil.which(name)
    if found:
        return Path(found)
    raise ToolRunError(
        f"{name} not found on PATH. Preflight should have caught this.",
    )


def _validate_host(host: str) -> str:
    if not isinstance(host, str) or not host.strip():
        raise TimesketchHostError("host must be a non-empty string.")
    if not _HOST_RE.match(host):
        raise TimesketchHostError(
            f"Unsupported host URL: {host!r}. "
            "Must start with http:// or https:// and contain only "
            "URL-safe characters [A-Za-z0-9_-.:/].",
        )
    return host


def _validate_sketch_id(sketch_id: int) -> int:
    if not isinstance(sketch_id, int) or isinstance(sketch_id, bool):
        raise TimesketchQueryError(
            f"sketch_id must be an int, got {type(sketch_id).__name__}.",
        )
    if sketch_id <= 0:
        raise TimesketchQueryError(
            f"sketch_id must be a positive integer; got {sketch_id}.",
        )
    return sketch_id


def _validate_query(query: str) -> str:
    if not isinstance(query, str) or not query or not query.strip():
        raise TimesketchQueryError("query must be a non-empty string.")
    if not _QUERY_RE.match(query):
        raise TimesketchQueryError(
            "query contains characters outside the Lucene-safe set. "
            "Newlines, semicolons, pipes, backticks, and dollar signs "
            "are rejected by policy.",
        )
    return query


def _validate_timeline_name(name: str) -> str:
    if not isinstance(name, str) or not name or not name.strip():
        raise TimesketchTimelineNameError("timeline_name must be a non-empty string.")
    if not _TIMELINE_NAME_RE.match(name):
        raise TimesketchTimelineNameError(
            "timeline_name contains characters outside the safe set "
            f"[A-Za-z0-9_-. ]. Got: {name!r}",
        )
    return name


def run_timesketch_query(
    *,
    subcommand: str,
    host: str,
    sketch_id: int | None = None,
    query: str | None = None,
    audit: AuditLogger | None = None,
    timeout: float = 300.0,
    timesketch_binary: Path | None = None,
) -> ToolRunResult:
    """
    Run a read-only Timesketch CLI subcommand against a server.

    ``subcommand`` must be one of ``TIMESKETCH_QUERY_SUBCOMMANDS``:

    * ``"list"``     -- requires ``host`` only.
    * ``"describe"`` -- requires ``host`` + ``sketch_id``.
    * ``"search"``   -- requires ``host`` + ``sketch_id`` + ``query``.

    ``host`` must be an ``http://`` or ``https://`` URL with no shell
    metacharacters. ``sketch_id`` must be a positive integer.
    ``query`` must match the Lucene-safe character set
    (``[A-Za-z0-9_-\\.\\s:/()"'\\\\*[]{}]+``) -- newlines, pipes,
    semicolons, backticks, and dollar signs are rejected.

    The subprocess is read-only on the Timesketch server (list /
    describe / search are all idempotent reads). No local evidence is
    touched. The audit payload carries
    ``evidence_readonly_assumed=True`` for parity with the other
    Tier 0 wrappers.
    """
    if subcommand not in TIMESKETCH_QUERY_SUBCOMMANDS:
        raise TimesketchSubcommandError(
            f"Unsupported Timesketch query subcommand: {subcommand!r}. "
            f"Supported: {', '.join(sorted(TIMESKETCH_QUERY_SUBCOMMANDS))}",
        )
    validated_host = _validate_host(host)

    resolved_sketch_id: int | None = None
    if subcommand in ("describe", "search"):
        if sketch_id is None:
            raise TimesketchQueryError(
                f"subcommand={subcommand!r} requires sketch_id.",
            )
        resolved_sketch_id = _validate_sketch_id(sketch_id)

    resolved_query: str | None = None
    if subcommand == "search":
        if query is None:
            raise TimesketchQueryError(
                "subcommand='search' requires a non-empty query.",
            )
        resolved_query = _validate_query(query)

    binary = timesketch_binary or _resolve_binary("timesketch")
    argv: list[str] = [str(binary), "--host", validated_host, "sketch", subcommand]
    if subcommand == "describe":
        assert resolved_sketch_id is not None  # nosec: B101 -- guarded above
        argv.append(str(resolved_sketch_id))
    elif subcommand == "search":
        assert resolved_sketch_id is not None  # nosec: B101 -- guarded above
        assert resolved_query is not None  # nosec: B101 -- guarded above
        argv.extend(["--query", resolved_query, str(resolved_sketch_id)])

    return run_tool(
        argv,
        tool_name="timesketch",
        audit=audit,
        timeout=timeout,
        extra_audit_payload={
            "subcommand": subcommand,
            "host": validated_host,
            "sketch_id": resolved_sketch_id,
            "evidence_readonly_assumed": True,
        },
    )


def run_timesketch_upload(
    *,
    timeline_source: Path,
    sketch_id: int,
    timeline_name: str,
    consent_token: str,
    host: str | None = None,
    audit: AuditLogger | None = None,
    timeout: float = 3600.0,
    importer_binary: Path | None = None,
) -> ToolRunResult:
    """
    Upload a local timeline file to a Timesketch server, after consent.

    ``timeline_source`` is a local file (typically a plaso ``.plaso``
    storage file or a CSV timeline). It is treated as read-only --
    the importer only reads from it. The wrapper still flags the
    overall operation as ``state_changing: "operational"`` in the
    audit payload because the Timesketch server's database is
    mutated: even though the source evidence is untouched, the
    external system acquires new records. Reviewers reading the audit
    trail should be able to see the distinction at a glance.

    ``consent_token`` must equal the sentinel
    ``TIMESKETCH_UPLOAD_CONSENT_TOKEN``
    (``"i-consent-timesketch-upload"``). Anything else -- empty,
    whitespace, or a different string -- raises
    ``TimesketchUploadConsentError``. Before the subprocess is
    spawned, a ``timesketch_upload_consent`` audit event is written.
    The event records ``consent_token_present=True`` and
    ``consent_token_length`` but NEVER the raw token string.

    ``sketch_id`` must be a positive integer. ``timeline_name`` must
    match the safe set ``[A-Za-z0-9_-. ]+``. ``host`` is optional; if
    omitted, ``timesketch_importer`` reads its server URL from
    environment variables per its documented conventions. When
    supplied, the host must still be a valid http/https URL.
    """
    if consent_token != TIMESKETCH_UPLOAD_CONSENT_TOKEN:
        raise TimesketchUploadConsentError(
            "run_timesketch_upload requires consent_token="
            f"{TIMESKETCH_UPLOAD_CONSENT_TOKEN!r}. "
            "The caller must explicitly acknowledge that uploading "
            "a timeline mutates the Timesketch server's database.",
        )

    if not isinstance(timeline_source, Path):
        timeline_source = Path(timeline_source)
    if not timeline_source.exists():
        raise ToolRunError(f"Timeline source not found: {timeline_source}")
    if not timeline_source.is_file():
        raise ToolRunError(
            f"Timeline source is not a regular file: {timeline_source}",
        )

    validated_sketch_id = _validate_sketch_id(sketch_id)
    validated_name = _validate_timeline_name(timeline_name)
    validated_host: str | None = _validate_host(host) if host is not None else None

    if audit is not None:
        audit.append(
            event_type="timesketch_upload_consent",
            payload={
                "consent_token_present": True,
                "consent_token_length": len(consent_token),
                "sketch_id": validated_sketch_id,
                "timeline_name": validated_name,
                "host": validated_host,
                "source": str(timeline_source),
            },
        )

    binary = importer_binary or _resolve_binary("timesketch_importer")
    argv: list[str] = [str(binary)]
    if validated_host is not None:
        argv.extend(["--host", validated_host])
    argv.extend(
        [
            "--sketch",
            str(validated_sketch_id),
            "--timeline_name",
            validated_name,
            str(timeline_source),
        ]
    )

    return run_tool(
        argv,
        tool_name="timesketch_importer",
        audit=audit,
        timeout=timeout,
        extra_audit_payload={
            "source": str(timeline_source),
            "source_readonly_assumed": True,
            "sketch_id": validated_sketch_id,
            "timeline_name": validated_name,
            "host": validated_host,
            "state_changing": "operational",
            "consent": "granted",
        },
    )


__all__ = [
    "TIMESKETCH_QUERY_SUBCOMMANDS",
    "TIMESKETCH_UPLOAD_CONSENT_TOKEN",
    "TimesketchHostError",
    "TimesketchQueryError",
    "TimesketchSubcommandError",
    "TimesketchTimelineNameError",
    "TimesketchUploadConsentError",
    "run_timesketch_query",
    "run_timesketch_upload",
]
