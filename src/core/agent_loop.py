"""
Agent reasoning loop — skeleton.

The APTWatcher agent walks a disciplined four-phase cycle:

    plan → execute → verify → self_correct

and repeats until the planner decides to finalize. A `report_emit` event
is only permitted after a `self_correction` event has been written for
the *current* finding set; the `finalize()` method enforces this
architecturally rather than relying on prompt discipline.

This file is the structural skeleton. Real planning / verification /
self-correction logic is LLM-driven and lives behind the
`Planner`/`Verifier`/`SelfCorrector` strategy interfaces. Each strategy
has a no-op stub implementation so the loop is testable without a live
model.

References:
- docs/architecture/self-correction.md
- docs/architecture/audit-logging.md
- docs/prompts/system.md
- docs/design/analysis-output-pipeline.md (Phase 3.8 fan-out)
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from core.audit import AuditLogger
from core.types import Finding, IOCVerdict

if TYPE_CHECKING:
    from core.config import APTWatcherConfig


# ---------------------------------------------------------------------------
# Phase payloads
# ---------------------------------------------------------------------------


@dataclass
class PlanStep:
    """One step the planner intends to take in the next execute phase."""

    step_id: str
    intent: str  # human-readable description of what this step tries to answer
    tool: str | None = None  # MCP tool name the executor should call, if any
    tool_args: dict[str, object] = field(default_factory=dict)


@dataclass
class ExecutionRecord:
    """One tool call the executor actually performed, with its correlation id."""

    step_id: str
    correlation_id: str
    summary: str  # short, structured summary of what came back
    raw_ref: str | None = None  # audit-log pointer, typically correlation_id


@dataclass
class VerificationIssue:
    """One issue the verifier noticed in the current finding set."""

    severity: str  # "block", "warn", "info"
    rule: str  # e.g. "rule1_evidence_required", "rule2_hallucination_check"
    finding_id: str | None
    detail: str


@dataclass
class SelfCorrectionDecision:
    """Output of one self-correction pass."""

    iteration: int
    issues: list[VerificationIssue]
    resolved: list[str]  # finding_ids that were fixed
    dropped: list[str]  # finding_ids that were removed
    replan: bool  # True if the loop should go back to plan → execute
    notes: str | None = None


# ---------------------------------------------------------------------------
# Strategy interfaces
# ---------------------------------------------------------------------------


class Planner(Protocol):
    def next_plan(self, state: AgentState) -> list[PlanStep]:
        """Return the next batch of plan steps, or [] to signal finalize."""


class Executor(Protocol):
    def execute(self, step: PlanStep, *, audit: AuditLogger) -> ExecutionRecord:
        """Run one plan step and return its record."""


class Verifier(Protocol):
    def verify(self, findings: list[Finding]) -> list[VerificationIssue]:
        """Produce a flat list of issues against the current finding set."""


class SelfCorrector(Protocol):
    def correct(
        self,
        *,
        findings: list[Finding],
        issues: list[VerificationIssue],
        iteration: int,
    ) -> SelfCorrectionDecision:
        """Decide how to act on verification issues. Never mutates input."""


# ---------------------------------------------------------------------------
# Null strategies — no-op implementations used by tests and by the
# initial scaffold until the real planner / verifier land.
# ---------------------------------------------------------------------------


class _NullPlanner:
    def next_plan(self, state: AgentState) -> list[PlanStep]:
        return []  # immediately finalize


class _NullExecutor:
    def execute(self, step: PlanStep, *, audit: AuditLogger) -> ExecutionRecord:
        correlation_id = uuid.uuid4().hex
        return ExecutionRecord(
            step_id=step.step_id,
            correlation_id=correlation_id,
            summary="null-executor: no-op",
        )


class _NullVerifier:
    def verify(self, findings: list[Finding]) -> list[VerificationIssue]:
        # Baseline architectural check: every finding must cite at least one source.
        issues: list[VerificationIssue] = []
        for f in findings:
            if not f.evidence:
                issues.append(
                    VerificationIssue(
                        severity="block",
                        rule="rule1_evidence_required",
                        finding_id=f.finding_id,
                        detail="Finding has zero citations; report emitter will refuse.",
                    ),
                )
        return issues


class _NullSelfCorrector:
    def correct(
        self,
        *,
        findings: list[Finding],
        issues: list[VerificationIssue],
        iteration: int,
    ) -> SelfCorrectionDecision:
        drop = [i.finding_id for i in issues if i.severity == "block" and i.finding_id]
        return SelfCorrectionDecision(
            iteration=iteration,
            issues=issues,
            resolved=[],
            dropped=[fid for fid in drop if fid is not None],
            replan=False,
            notes="null-self-corrector: drop blocking findings, do not replan.",
        )


# ---------------------------------------------------------------------------
# Loop state
# ---------------------------------------------------------------------------


@dataclass
class AgentState:
    incident_id: str
    findings: list[Finding] = field(default_factory=list)
    iocs: list[IOCVerdict] = field(default_factory=list)
    execution_log: list[ExecutionRecord] = field(default_factory=list)
    iterations: int = 0
    self_correction_done_for_current_findings: bool = False
    report_emitted: bool = False


class ReportEmitError(RuntimeError):
    """Raised when the loop is asked to emit a report before self-correction."""


# ---------------------------------------------------------------------------
# The loop
# ---------------------------------------------------------------------------


class AgentLoop:
    """
    Orchestrates plan → execute → verify → self_correct cycles.

    The loop's job is only sequencing and auditing. Every decision is
    delegated to a strategy object; swap the null strategies for real
    LLM-backed ones to bring the loop to life.

    Usage:

        loop = AgentLoop(
            incident_id="inc-001",
            audit=logger,
            planner=MyPlanner(),
            executor=MyExecutor(),
            verifier=MyVerifier(),
            self_corrector=MySelfCorrector(),
        )
        report = loop.run()
    """

    MAX_ITERATIONS = 12  # hard ceiling; self-corrector should terminate earlier

    def __init__(
        self,
        *,
        incident_id: str,
        audit: AuditLogger,
        planner: Planner | None = None,
        executor: Executor | None = None,
        verifier: Verifier | None = None,
        self_corrector: SelfCorrector | None = None,
        config: APTWatcherConfig | None = None,
    ) -> None:
        self.state = AgentState(incident_id=incident_id)
        self.audit = audit
        self.planner: Planner = planner or _NullPlanner()
        self.executor: Executor = executor or _NullExecutor()
        self.verifier: Verifier = verifier or _NullVerifier()
        self.self_corrector: SelfCorrector = self_corrector or _NullSelfCorrector()
        self.config = config

    # ---- public API -------------------------------------------------------

    def run(self) -> list[Finding]:
        """Run the loop to exhaustion and return the accepted finding set."""
        while self.state.iterations < self.MAX_ITERATIONS:
            steps = self._plan()
            if not steps:
                break
            self._execute(steps)
            self._verify_and_correct()
            self.state.iterations += 1
        # Ensure we've at least run one verify+correct even if the planner
        # returned [] immediately. That makes the self-correction gate
        # real for zero-finding runs too.
        if not self.state.self_correction_done_for_current_findings:
            self._verify_and_correct()
        return self.finalize()

    def finalize(self) -> list[Finding]:
        """Gate the report emission. Refuses without self-correction."""
        if not self.state.self_correction_done_for_current_findings:
            raise ReportEmitError(
                "Cannot emit report: no self_correction event for current findings.",
            )
        if self.state.report_emitted:
            return self.state.findings
        self.audit.append(
            event_type="report_emit",
            payload={
                "incident_id": self.state.incident_id,
                "finding_count": len(self.state.findings),
                "iterations": self.state.iterations,
            },
        )
        self.state.report_emitted = True
        # Phase 3.8 -- optional analysis pipeline fan-out. The verdict is
        # already emitted above; any failure below must not propagate.
        if self.config is not None and getattr(
            self.config, "emit_analysis_pipeline", False,
        ):
            try:
                self.emit_analysis_outputs()
            except Exception as exc:  # hard safety net; emit already logs
                self._audit_analysis_error("finalize_dispatch", exc)
        return list(self.state.findings)

    def add_finding(self, finding: Finding) -> None:
        """Executors / external callers add findings here. Invalidates the gate."""
        self.state.findings.append(finding)
        self.state.self_correction_done_for_current_findings = False
        self.audit.append(
            event_type="finding",
            payload={
                "finding_id": finding.finding_id,
                "summary": finding.summary,
                "confidence": finding.confidence,
                "mitre": list(finding.mitre),
                "citation_count": len(finding.evidence),
            },
        )

    def add_ioc(self, ioc: IOCVerdict) -> None:
        """Track a verdict-grade IOC on state so the analysis pipeline can fan out."""
        self.state.iocs.append(ioc)

    # ---- phase helpers ----------------------------------------------------

    def _plan(self) -> list[PlanStep]:
        steps = self.planner.next_plan(self.state)
        self.audit.append(
            event_type="tool_call",  # plan is a logical tool_call with tool="planner"
            payload={
                "phase": "plan",
                "tool": "planner",
                "iteration": self.state.iterations,
                "step_count": len(steps),
                "step_ids": [s.step_id for s in steps],
            },
        )
        return steps

    def _execute(self, steps: list[PlanStep]) -> None:
        for step in steps:
            record = self.executor.execute(step, audit=self.audit)
            self.state.execution_log.append(record)

    def _verify_and_correct(self) -> None:
        issues = self.verifier.verify(self.state.findings)
        self.audit.append(
            event_type="claim_verification",
            payload={
                "iteration": self.state.iterations,
                "finding_count": len(self.state.findings),
                "issue_count": len(issues),
                "issues": [
                    {
                        "severity": i.severity,
                        "rule": i.rule,
                        "finding_id": i.finding_id,
                        "detail": i.detail,
                    }
                    for i in issues
                ],
            },
        )
        decision = self.self_corrector.correct(
            findings=self.state.findings,
            issues=issues,
            iteration=self.state.iterations,
        )
        if decision.dropped:
            self.state.findings = [
                f for f in self.state.findings if f.finding_id not in decision.dropped
            ]
        self.audit.append(
            event_type="self_correction",
            payload={
                "iteration": decision.iteration,
                "issues": [
                    {
                        "severity": i.severity,
                        "rule": i.rule,
                        "finding_id": i.finding_id,
                        "detail": i.detail,
                    }
                    for i in decision.issues
                ],
                "resolved": decision.resolved,
                "dropped": decision.dropped,
                "replan": decision.replan,
                "notes": decision.notes,
            },
        )
        self.state.self_correction_done_for_current_findings = True

    # ---- Phase 3.8 analysis fan-out --------------------------------------

    def _audit_analysis_emit(self, step: str, payload: dict[str, object]) -> None:
        """Log one successful analysis-pipeline step."""
        self.audit.append(
            event_type="analysis_emit",
            payload={"step": step, **payload},
        )

    def _audit_analysis_error(self, step: str, exc: BaseException) -> None:
        """Log one failed analysis-pipeline step. Never re-raises."""
        self.audit.append(
            event_type="analysis_error",
            payload={
                "step": step,
                "error_type": type(exc).__name__,
                "error": str(exc),
            },
        )

    @staticmethod
    def _file_digest(path: Path) -> str:
        """Return `sha256:<hex>` of a file on disk; empty string if missing."""
        if not path.exists() or not path.is_file():
            return ""
        return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

    def emit_analysis_outputs(self) -> dict[str, Path]:
        """
        Fan verified findings + IOCs into the Phase 3.8 analysis pipeline.

        Mirrors the CLI ``aptwatcher analyze`` flow but runs inside the
        loop's finalize() step. Every step is wrapped in a try/except so
        an exporter raising does not abort the others -- the verdict is
        already the authoritative output at this point, so the pipeline
        runs in best-effort mode and logs ``analysis_error`` events on
        failure.

        Returns a mapping from step name to produced artifact path, for
        callers that want to inspect what landed on disk. The mapping
        only contains successful steps.
        """
        produced: dict[str, Path] = {}
        if self.config is None:
            return produced
        if not getattr(self.config, "emit_analysis_pipeline", False):
            return produced

        output_dir_cfg = getattr(self.config, "analysis_output_dir", None)
        if output_dir_cfg is None:
            self._audit_analysis_error(
                "preflight",
                RuntimeError("analysis_output_dir is not configured"),
            )
            return produced
        output_dir = Path(output_dir_cfg)
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self._audit_analysis_error("preflight", exc)
            return produced

        campaign_tag: str = (
            getattr(self.config, "analysis_campaign_tag", None)
            or "APTWATCHER"
        )
        languages: list[str] = list(
            getattr(self.config, "analysis_languages", None) or ["en"],
        )
        sign_key_hex: str | None = getattr(
            self.config, "analysis_sign_key_hex", None,
        )

        findings = list(self.state.findings)
        iocs = list(self.state.iocs)
        incident_id = self.state.incident_id

        # Defer heavy imports so the loop stays importable on hosts where
        # python-docx or pyyaml are not installed.
        try:
            from core.analysis.export_community import export_community_yaml
            from core.analysis.export_iocs_txt import export_per_type_txt
            from core.analysis.export_stix import export_stix_bundle
            from core.analysis.report_docx import render_docx_report
            from core.analysis.report_markdown import (
                render_analyst_markdown,
                render_ttp_assessment,
            )
            from core.analysis.report_stats import render_generation_report
            from core.analysis.rules_suricata import generate_suricata_rules
            from core.analysis.rules_yara import generate_yara_rules
        except Exception as exc:
            self._audit_analysis_error("import_analysis", exc)
            return produced

        # ---- 1. Rule generators ------------------------------------------
        rules_dir = output_dir / "rules"
        try:
            rules_dir.mkdir(parents=True, exist_ok=True)
            yara_rules = generate_yara_rules(
                findings=findings, iocs=iocs, campaign_tag=campaign_tag,
            )
            yara_path = rules_dir / "aptwatcher.yar"
            yara_text = "\n\n".join(r.text for r in yara_rules)
            if yara_rules:
                yara_text += "\n"
            yara_path.write_text(yara_text, encoding="utf-8")
            produced["yara"] = yara_path
            self._audit_analysis_emit(
                "generate_yara_rules",
                {
                    "path": str(yara_path),
                    "rule_count": len(yara_rules),
                    "sha256": self._file_digest(yara_path),
                },
            )
        except Exception as exc:
            self._audit_analysis_error("generate_yara_rules", exc)

        try:
            rules_dir.mkdir(parents=True, exist_ok=True)
            suricata_rules = generate_suricata_rules(
                findings=findings, iocs=iocs, campaign_tag=campaign_tag,
            )
            suricata_path = rules_dir / "aptwatcher.rules"
            suricata_text = "\n".join(r.text for r in suricata_rules)
            if suricata_rules:
                suricata_text += "\n"
            suricata_path.write_text(suricata_text, encoding="utf-8")
            produced["suricata"] = suricata_path
            self._audit_analysis_emit(
                "generate_suricata_rules",
                {
                    "path": str(suricata_path),
                    "rule_count": len(suricata_rules),
                    "sha256": self._file_digest(suricata_path),
                },
            )
        except Exception as exc:
            self._audit_analysis_error("generate_suricata_rules", exc)

        # ---- 2. IOC exporters --------------------------------------------
        iocs_dir = output_dir / "iocs"
        try:
            iocs_dir.mkdir(parents=True, exist_ok=True)
            stix_path = iocs_dir / "stix.json"
            if iocs and not stix_path.exists():
                export_stix_bundle(
                    iocs=iocs,
                    findings=findings,
                    output_path=stix_path,
                    incident_id=incident_id,
                )
                produced["stix"] = stix_path
                self._audit_analysis_emit(
                    "export_stix_bundle",
                    {
                        "path": str(stix_path),
                        "ioc_count": len(iocs),
                        "sha256": self._file_digest(stix_path),
                    },
                )
        except Exception as exc:
            self._audit_analysis_error("export_stix_bundle", exc)

        try:
            iocs_dir.mkdir(parents=True, exist_ok=True)
            community_path = iocs_dir / "community.yaml"
            if not community_path.exists():
                export_community_yaml(
                    iocs=iocs,
                    findings=findings,
                    output_path=community_path,
                    campaign_tag=campaign_tag,
                    submitter="aptwatcher-bot",
                )
                produced["community"] = community_path
                self._audit_analysis_emit(
                    "export_community_yaml",
                    {
                        "path": str(community_path),
                        "sha256": self._file_digest(community_path),
                    },
                )
        except Exception as exc:
            self._audit_analysis_error("export_community_yaml", exc)

        try:
            per_type_dir = iocs_dir / "per_type"
            per_type_dir.mkdir(parents=True, exist_ok=True)
            if iocs:
                per_type_paths = export_per_type_txt(
                    iocs=iocs, output_dir=per_type_dir,
                )
                for ioc_type, path in per_type_paths.items():
                    produced[f"ioc_txt:{ioc_type}"] = path
                self._audit_analysis_emit(
                    "export_per_type_txt",
                    {
                        "output_dir": str(per_type_dir),
                        "file_count": len(per_type_paths),
                    },
                )
        except Exception as exc:
            self._audit_analysis_error("export_per_type_txt", exc)

        # ---- 3. Report renderers -----------------------------------------
        reports_dir = output_dir / "reports"
        try:
            reports_dir.mkdir(parents=True, exist_ok=True)
            analyst_path = reports_dir / "analyst.md"
            if not analyst_path.exists():
                render_analyst_markdown(
                    findings=findings,
                    iocs=iocs,
                    output_path=analyst_path,
                    incident_id=incident_id,
                    campaign_tag=campaign_tag,
                )
                produced["analyst_md"] = analyst_path
                self._audit_analysis_emit(
                    "render_analyst_markdown",
                    {
                        "path": str(analyst_path),
                        "sha256": self._file_digest(analyst_path),
                    },
                )
        except Exception as exc:
            self._audit_analysis_error("render_analyst_markdown", exc)

        for language in languages:
            lang = str(language).lower()
            if lang not in ("en", "fr"):
                self._audit_analysis_error(
                    "render_docx_report",
                    ValueError(f"unsupported language: {language!r}"),
                )
                continue
            try:
                reports_dir.mkdir(parents=True, exist_ok=True)
                docx_path = reports_dir / f"report_{lang}.docx"
                if not docx_path.exists():
                    render_docx_report(
                        findings=findings,
                        iocs=iocs,
                        output_path=docx_path,
                        incident_id=incident_id,
                        campaign_tag=campaign_tag,
                        language=lang,  # type: ignore[arg-type]
                    )
                    produced[f"docx_{lang}"] = docx_path
                    self._audit_analysis_emit(
                        "render_docx_report",
                        {
                            "language": lang,
                            "path": str(docx_path),
                            "sha256": self._file_digest(docx_path),
                        },
                    )
            except Exception as exc:
                self._audit_analysis_error(
                    f"render_docx_report:{lang}", exc,
                )

            try:
                reports_dir.mkdir(parents=True, exist_ok=True)
                ttp_path = reports_dir / f"ttp_{lang}.md"
                if not ttp_path.exists():
                    render_ttp_assessment(
                        findings=findings,
                        output_path=ttp_path,
                        incident_id=incident_id,
                        campaign_tag=campaign_tag,
                    )
                    produced[f"ttp_{lang}"] = ttp_path
                    self._audit_analysis_emit(
                        "render_ttp_assessment",
                        {
                            "language": lang,
                            "path": str(ttp_path),
                            "sha256": self._file_digest(ttp_path),
                        },
                    )
            except Exception as exc:
                self._audit_analysis_error(
                    f"render_ttp_assessment:{lang}", exc,
                )

        # ---- 4. Generation report ----------------------------------------
        try:
            gen_report_path = output_dir / "generation_report.json"
            if not gen_report_path.exists():
                file_digests: dict[str, str] = {}
                for key, path in produced.items():
                    digest = self._file_digest(path)
                    if digest:
                        # Key the digest map by relative path if possible --
                        # readable, and stable across absolute-path drift.
                        try:
                            rel = path.relative_to(output_dir)
                            file_digests[str(rel)] = digest
                        except ValueError:
                            file_digests[key] = digest
                counts = {
                    "findings": len(findings),
                    "iocs": len(iocs),
                }
                render_generation_report(
                    output_path=gen_report_path,
                    incident_id=incident_id,
                    campaign_tag=campaign_tag,
                    counts=counts,
                    sid_range=None,
                    file_digests=file_digests,
                )
                produced["generation_report"] = gen_report_path
                self._audit_analysis_emit(
                    "render_generation_report",
                    {
                        "path": str(gen_report_path),
                        "file_count": len(file_digests),
                        "sha256": self._file_digest(gen_report_path),
                    },
                )
        except Exception as exc:
            self._audit_analysis_error("render_generation_report", exc)

        # ---- 5. Signed IncidentBundle (optional) -------------------------
        if sign_key_hex:
            try:
                from core.bundle.exporter import export_bundle

                key_bytes = bytes.fromhex(sign_key_hex.strip())
                bundle_dir = output_dir / "incident-bundle"
                # Re-read audit events so the bundle carries the live log.
                try:
                    audit_events = self.audit.read_all()
                except Exception:
                    audit_events = []
                export_bundle(
                    bundle_dir=bundle_dir,
                    incident_id=incident_id,
                    operator="aptwatcher-agent",
                    sift_workstation="aptwatcher-loop",
                    findings=findings,
                    audit_events=audit_events,
                    private_key_bytes=key_bytes,
                    iocs=iocs,
                )
                produced["incident_bundle"] = bundle_dir
                bundle_json = bundle_dir / "findings.json"
                self._audit_analysis_emit(
                    "export_bundle",
                    {
                        "bundle_dir": str(bundle_dir),
                        "findings_sha256": self._file_digest(bundle_json),
                    },
                )
            except Exception as exc:
                self._audit_analysis_error("export_bundle", exc)

        return produced


__all__ = [
    "AgentLoop",
    "AgentState",
    "ExecutionRecord",
    "Executor",
    "PlanStep",
    "Planner",
    "ReportEmitError",
    "SelfCorrectionDecision",
    "SelfCorrector",
    "VerificationIssue",
    "Verifier",
]
