"""
Accuracy-harness runner.

Loads a scenario manifest, drives `AgentLoop` with a `FakeModelClient`
replay of the recorded transcript, and scores the loop's final
findings + IOCs against a committed golden. Produces a `ScoreCard`
per scenario and a single aggregate report.

The trust boundary: this module imports `FakeModelClient` only. A
live `ModelClient` adapter must NEVER be instantiated from here --
the runtime assert in `_build_fake_client` is the enforcement point.

See `docs/design/accuracy-harness.md` for the full pipeline spec,
scoring rules, and report format.
"""

from __future__ import annotations

import json
import time
import traceback
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from core.agent_loop import AgentLoop
from core.audit import AuditLogger
from core.llm import FakeModelClient, ModelResponse
from core.strategies import LLMPlanner, LLMSelfCorrector, LLMVerifier
from core.types import Finding, FindingCitation
from tests.accuracy.scoring import (
    ScoredFinding,
    ScoredIOC,
    from_finding,
    from_golden_dict,
    ioc_from_dict,
    precision_recall_f1,
    score_findings,
    score_iocs,
)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class ScenarioManifest:
    """Parsed manifest.yaml for one scenario."""

    id: str
    description: str
    profile: str
    transcript_path: Path
    golden_path: Path
    kb_subset_globs: list[str] = field(default_factory=list)
    source_dir: Path = field(default=Path())
    # Optional scaffold shim: a path (relative to source_dir) to a
    # JSON file of pre-loaded findings injected via loop.add_finding()
    # before loop.run(). Phase 3 has no Executor that synthesizes
    # Finding records from LLM output, so until Phase 4 lands one,
    # this keeps the harness's scoring surface non-trivial. See the
    # design doc's "Future work -- native Executor-driven findings"
    # section.
    seed_findings_path: Path | None = None
    # Scaffold shim: IOC dicts dropped into the scenario audit log so
    # the IOC-scoring path has something to compare against. Same
    # rationale as seed_findings_path -- removed when the Executor
    # lands.
    seed_iocs_path: Path | None = None


@dataclass
class ScoreCard:
    """Per-scenario scoring snapshot.

    Aggregation produces an average of these; the harness never
    mutates a ScoreCard after it's been written.
    """

    scenario_id: str
    findings_tp: int = 0
    findings_fp: int = 0
    findings_fn: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    ioc_tp: int = 0
    ioc_fp: int = 0
    ioc_fn: int = 0
    ioc_precision: float = 0.0
    ioc_recall: float = 0.0
    ioc_f1: float = 0.0
    duration_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)
    # Per-tier breakdown of finding matches. Populated by the runner
    # for eventual aggregation. Each entry is (tp, fp, fn).
    by_tier: dict[str, tuple[int, int, int]] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------


def load_manifest(path: Path) -> ScenarioManifest:
    """Parse a manifest.yaml into a `ScenarioManifest`."""
    path = Path(path)
    with path.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"manifest at {path} must be a YAML mapping")
    source_dir = path.parent
    required = ("id", "description", "profile", "transcript_path", "golden_path")
    missing = [k for k in required if k not in raw]
    if missing:
        raise ValueError(
            f"manifest at {path} missing required keys: {missing}",
        )
    seed = raw.get("seed_findings_path")
    seed_iocs = raw.get("seed_iocs_path")
    return ScenarioManifest(
        id=str(raw["id"]),
        description=str(raw["description"]),
        profile=str(raw["profile"]),
        transcript_path=source_dir / str(raw["transcript_path"]),
        golden_path=source_dir / str(raw["golden_path"]),
        kb_subset_globs=list(raw.get("kb_subset_globs", []) or []),
        source_dir=source_dir,
        seed_findings_path=(source_dir / str(seed)) if seed else None,
        seed_iocs_path=(source_dir / str(seed_iocs)) if seed_iocs else None,
    )


def load_golden(path: Path) -> dict[str, list[dict[str, Any]]]:
    """Load the golden JSON and return {'findings': [...], 'iocs': [...]}."""
    path = Path(path)
    with path.open("r", encoding="utf-8") as fh:
        raw = json.load(fh)
    if not isinstance(raw, dict):
        raise ValueError(f"golden at {path} must be a JSON object")
    findings = raw.get("findings") or []
    iocs = raw.get("iocs") or []
    if not isinstance(findings, list) or not isinstance(iocs, list):
        raise ValueError(
            f"golden at {path} must have list-typed 'findings' and 'iocs'",
        )
    return {"findings": findings, "iocs": iocs}


def load_seed_findings(path: Path) -> list[Finding]:
    """Load a seed-findings JSON list into real `Finding` instances.

    Shape: list of dicts with `finding_id`, `summary`, `confidence`,
    `mitre`, and at least one `evidence` citation (otherwise the
    built-in verifier drops the finding during self-correction).
    """
    path = Path(path)
    with path.open("r", encoding="utf-8") as fh:
        raw = json.load(fh)
    if not isinstance(raw, list):
        raise ValueError(
            f"seed findings at {path} must be a JSON list of finding dicts",
        )
    out: list[Finding] = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"seed finding #{i} in {path} must be a JSON object")
        citations = [
            FindingCitation(**c) if isinstance(c, dict) else FindingCitation(source=str(c))
            for c in (item.get("evidence") or [])
        ]
        out.append(
            Finding(
                finding_id=str(item.get("finding_id") or f"seed-{i}"),
                summary=str(item.get("summary") or ""),
                mitre=list(item.get("mitre") or []),
                confidence=float(item.get("confidence", 0.5)),
                evidence=citations,
                reasoning=item.get("reasoning"),
            ),
        )
    return out


def load_transcript(path: Path) -> list[ModelResponse]:
    """Load a transcript.json as an ordered list of ModelResponse."""
    path = Path(path)
    with path.open("r", encoding="utf-8") as fh:
        raw = json.load(fh)
    if not isinstance(raw, list):
        raise ValueError(
            f"transcript at {path} must be a JSON list of ModelResponse dicts",
        )
    out: list[ModelResponse] = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict) or "content" not in item:
            raise ValueError(
                f"transcript entry #{i} in {path} missing 'content' field",
            )
        out.append(
            ModelResponse(
                content=str(item["content"]),
                stop_reason=item.get("stop_reason", "fake"),
                model=item.get("model", "fake-model"),
                usage=item.get("usage"),
                raw=item.get("raw"),
            ),
        )
    return out


# ---------------------------------------------------------------------------
# Runner core
# ---------------------------------------------------------------------------


def _build_fake_client(transcript: list[ModelResponse]) -> FakeModelClient:
    """Construct a FakeModelClient and assert the trust boundary.

    The runtime `isinstance` assertion is belt-and-braces paranoia:
    the caller only ever passes a FakeModelClient here, but the
    check is cheap and makes it impossible to silently wire a live
    adapter in by mistake.
    """
    client = FakeModelClient(responses=list(transcript))
    assert isinstance(client, FakeModelClient), (
        "accuracy harness refused: client is not a FakeModelClient"
    )
    return client


def _collect_iocs_from_audit(audit_path: Path) -> list[dict[str, Any]]:
    """Pull IOC-shaped payloads out of the throwaway audit log.

    Phase 3 does not surface IOCs on `AgentState` yet. As a forward-
    compatible shim, the runner reads the scenario's audit log and
    picks up any `ioc` / `tool_call` events whose payload carries an
    IOC-shaped record. Scenarios whose transcripts do not emit such
    events simply score zero actual IOCs, which is fine.
    """
    iocs: list[dict[str, Any]] = []
    if not audit_path.exists():
        return iocs
    for line in audit_path.read_text(encoding="utf-8").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        payload = row.get("payload") or {}
        # Direct ioc event (future extension point).
        if row.get("event_type") == "ioc":
            if "value" in payload and ("type" in payload or "ioc_type" in payload):
                iocs.append(payload)
            continue
        # Tool-call payload that carries an IOC list (e.g., intel lookup).
        for record in payload.get("iocs", []) or []:
            if isinstance(record, dict) and "value" in record:
                iocs.append(record)
    return iocs


def run_scenario(
    manifest: ScenarioManifest,
    *,
    output_dir: Path,
) -> ScoreCard:
    """Run one scenario and return its ScoreCard.

    Never raises: any error is captured in the scorecard's `errors`
    list so the batch runner can continue to the next scenario.
    """
    card = ScoreCard(scenario_id=manifest.id)
    t0 = time.perf_counter()
    log_dir: Path | None = None
    try:
        golden = load_golden(manifest.golden_path)
        transcript = load_transcript(manifest.transcript_path)
        client = _build_fake_client(transcript)

        log_dir = Path(output_dir) / "audit" / manifest.id
        log_dir.mkdir(parents=True, exist_ok=True)
        audit = AuditLogger(incident_id=manifest.id, log_dir=log_dir)

        planner = LLMPlanner(client=client, audit=audit)
        verifier = LLMVerifier(client=client, audit=audit)
        self_corrector = LLMSelfCorrector(client=client, audit=audit)

        loop = AgentLoop(
            incident_id=manifest.id,
            audit=audit,
            planner=planner,
            verifier=verifier,
            self_corrector=self_corrector,
        )
        # Scaffold-shim: pre-populate findings from the manifest if the
        # scenario supplied a seed file. See design doc "Future work".
        if manifest.seed_findings_path is not None:
            for finding in load_seed_findings(manifest.seed_findings_path):
                loop.add_finding(finding)
        # Scaffold-shim: drop seed IOCs into the audit log as a single
        # synthetic `tool_call` event so the IOC-scoring path has input.
        if manifest.seed_iocs_path is not None:
            with manifest.seed_iocs_path.open("r", encoding="utf-8") as fh:
                seed_iocs_raw = json.load(fh)
            if not isinstance(seed_iocs_raw, list):
                raise ValueError(
                    f"seed iocs at {manifest.seed_iocs_path} must be a list",
                )
            audit.append(
                event_type="tool_call",
                payload={
                    "phase": "end",
                    "tool": "harness.seed_iocs",
                    "iocs": seed_iocs_raw,
                },
            )
        findings = loop.run()

        # Score findings.
        actual_findings: list[ScoredFinding] = [from_finding(f) for f in findings]
        expected_findings: list[ScoredFinding] = [
            from_golden_dict(d) for d in golden["findings"]
        ]
        tp, fp, fn = score_findings(actual_findings, expected_findings)
        p, r, f1 = precision_recall_f1(tp, fp, fn)
        card.findings_tp, card.findings_fp, card.findings_fn = tp, fp, fn
        card.precision, card.recall, card.f1 = p, r, f1

        # Per-tier breakdown.
        tier_bins: dict[str, tuple[list[ScoredFinding], list[ScoredFinding]]] = {
            "high": ([], []),
            "medium": ([], []),
            "low": ([], []),
        }
        for f_ in actual_findings:
            if f_.tier in tier_bins:
                tier_bins[f_.tier][0].append(f_)
        for f_ in expected_findings:
            if f_.tier in tier_bins:
                tier_bins[f_.tier][1].append(f_)
        for tier_name, (a_bin, e_bin) in tier_bins.items():
            card.by_tier[tier_name] = score_findings(a_bin, e_bin)

        # Score IOCs.
        audit_path = audit.log_path
        actual_iocs_raw = _collect_iocs_from_audit(audit_path)
        actual_iocs: list[ScoredIOC] = [ioc_from_dict(d) for d in actual_iocs_raw]
        expected_iocs: list[ScoredIOC] = [
            ioc_from_dict(d) for d in golden["iocs"]
        ]
        itp, ifp, ifn = score_iocs(actual_iocs, expected_iocs)
        ip, ir, if1 = precision_recall_f1(itp, ifp, ifn)
        card.ioc_tp, card.ioc_fp, card.ioc_fn = itp, ifp, ifn
        card.ioc_precision, card.ioc_recall, card.ioc_f1 = ip, ir, if1

    except Exception as exc:  # noqa: BLE001 -- we want every failure captured
        card.errors.append(f"{type(exc).__name__}: {exc}")
        card.errors.append(traceback.format_exc())
    finally:
        card.duration_seconds = round(time.perf_counter() - t0, 4)
    return card


# ---------------------------------------------------------------------------
# Discovery and aggregation
# ---------------------------------------------------------------------------


def discover_manifests(fixtures_dir: Path) -> list[ScenarioManifest]:
    """Return every `manifest.yaml` found one level under fixtures_dir."""
    fixtures_dir = Path(fixtures_dir)
    if not fixtures_dir.exists():
        raise FileNotFoundError(f"fixtures_dir does not exist: {fixtures_dir}")
    manifests: list[ScenarioManifest] = []
    for child in sorted(fixtures_dir.iterdir()):
        if not child.is_dir():
            continue
        candidate = child / "manifest.yaml"
        if candidate.is_file():
            manifests.append(load_manifest(candidate))
    return manifests


def aggregate(scorecards: list[ScoreCard]) -> dict[str, Any]:
    """Compute mean P/R/F1 and per-tier rollup across scorecards."""
    n = len(scorecards)
    if n == 0:
        return {
            "scenario_count": 0,
            "mean_precision": 0.0,
            "mean_recall": 0.0,
            "mean_f1": 0.0,
            "by_tier": {},
        }
    mean_p = sum(c.precision for c in scorecards) / n
    mean_r = sum(c.recall for c in scorecards) / n
    mean_f1 = sum(c.f1 for c in scorecards) / n

    tier_totals: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    for c in scorecards:
        for tier_name, (tp, fp, fn) in c.by_tier.items():
            tier_totals[tier_name][0] += tp
            tier_totals[tier_name][1] += fp
            tier_totals[tier_name][2] += fn
    by_tier: dict[str, dict[str, float]] = {}
    for tier_name, (tp, fp, fn) in tier_totals.items():
        p, r, f1 = precision_recall_f1(tp, fp, fn)
        by_tier[tier_name] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": round(p, 4),
            "recall": round(r, 4),
            "f1": round(f1, 4),
        }

    return {
        "scenario_count": n,
        "mean_precision": round(mean_p, 4),
        "mean_recall": round(mean_r, 4),
        "mean_f1": round(mean_f1, 4),
        "by_tier": by_tier,
    }


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def _scorecard_to_json(card: ScoreCard) -> dict[str, Any]:
    return {
        "scenario_id": card.scenario_id,
        "findings_tp": card.findings_tp,
        "findings_fp": card.findings_fp,
        "findings_fn": card.findings_fn,
        "precision": round(card.precision, 4),
        "recall": round(card.recall, 4),
        "f1": round(card.f1, 4),
        "ioc_tp": card.ioc_tp,
        "ioc_fp": card.ioc_fp,
        "ioc_fn": card.ioc_fn,
        "ioc_precision": round(card.ioc_precision, 4),
        "ioc_recall": round(card.ioc_recall, 4),
        "ioc_f1": round(card.ioc_f1, 4),
        "duration_seconds": card.duration_seconds,
        "errors": list(card.errors),
        "by_tier": {
            tier_name: {"tp": tp, "fp": fp, "fn": fn}
            for tier_name, (tp, fp, fn) in card.by_tier.items()
        },
    }


def write_report(
    scorecards: list[ScoreCard],
    output_dir: Path,
) -> tuple[Path, Path]:
    """Write accuracy_report_<ts>.json and .md; return both paths."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    json_path = output_dir / f"accuracy_report_{ts}.json"
    md_path = output_dir / f"accuracy_report_{ts}.md"

    agg = aggregate(scorecards)
    report = {
        "schema_version": "1.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "scenarios": [_scorecard_to_json(c) for c in scorecards],
        "aggregate": agg,
    }
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    # Markdown rendering: compact, easy to paste into a PR comment.
    lines: list[str] = []
    lines.append(f"# Accuracy report -- {ts}")
    lines.append("")
    lines.append(f"- Scenarios: {agg['scenario_count']}")
    lines.append(f"- Mean precision: {agg['mean_precision']:.3f}")
    lines.append(f"- Mean recall:    {agg['mean_recall']:.3f}")
    lines.append(f"- Mean F1:        {agg['mean_f1']:.3f}")
    lines.append("")
    lines.append("## Per-scenario")
    lines.append("")
    lines.append("| Scenario | TP | FP | FN | P | R | F1 | IOC F1 | Errors |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    for c in scorecards:
        lines.append(
            f"| {c.scenario_id} | {c.findings_tp} | {c.findings_fp} | {c.findings_fn} | {c.precision:.3f} | {c.recall:.3f} | {c.f1:.3f} |"
            f" {c.ioc_f1:.3f} | {len(c.errors)} |",
        )
    lines.append("")
    lines.append("## Per-tier aggregate")
    lines.append("")
    lines.append("| Tier | TP | FP | FN | F1 |")
    lines.append("|---|---:|---:|---:|---:|")
    for tier_name in ("high", "medium", "low"):
        row = agg["by_tier"].get(tier_name)
        if not row:
            continue
        lines.append(
            "| {t} | {tp} | {fp} | {fn} | {f1:.3f} |".format(
                t=tier_name,
                tp=row["tp"],
                fp=row["fp"],
                fn=row["fn"],
                f1=row["f1"],
            ),
        )
    lines.append("")
    md_path.write_text("\n".join(lines), encoding="utf-8")

    return json_path, md_path


# ---------------------------------------------------------------------------
# Batch entry point -- used by the CLI
# ---------------------------------------------------------------------------


def run_batch(
    fixtures_dir: Path,
    output_dir: Path,
) -> tuple[list[ScoreCard], dict[str, Any], Path, Path]:
    """Discover manifests under fixtures_dir, run each, write the report.

    Returns (scorecards, aggregate_dict, json_path, md_path). The
    CLI uses the aggregate's mean F1 to decide the exit code.
    """
    manifests = discover_manifests(fixtures_dir)
    scorecards: list[ScoreCard] = []
    for m in manifests:
        scorecards.append(run_scenario(m, output_dir=output_dir))
    json_path, md_path = write_report(scorecards, output_dir)
    return scorecards, aggregate(scorecards), json_path, md_path


__all__ = [
    "ScenarioManifest",
    "ScoreCard",
    "aggregate",
    "discover_manifests",
    "load_golden",
    "load_manifest",
    "load_transcript",
    "run_batch",
    "run_scenario",
    "write_report",
]
