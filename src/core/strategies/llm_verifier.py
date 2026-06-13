"""
LLM-backed Verifier strategy.

`LLMVerifier` implements `core.agent_loop.Verifier` by:

1. Loading the verifier system prompt from `prompts/verifier.md` once
   at construction time (via `core.llm.load_prompt`).
2. On each `verify(findings)` call, rendering the current finding
   set as a terse user message and asking the `ModelClient` for a
   JSON list of `VerificationIssue` candidates.
3. Merging the model's output with a **baseline** architectural
   check: every finding must have at least one citation. The
   baseline runs unconditionally and is never skipped, even when
   the model output is malformed.

Defensive posture
-----------------

The verifier NEVER crashes the agent loop. If the model returns
invalid JSON, the wrong shape, or an unknown severity, the
`PlannerResponseError`-analogue `VerifierResponseError` is caught
internally, an `llm_call` audit event is emitted with
`parse_error`, and the wrapper falls back to the baseline-only
issue list.

This preserves the architectural invariant (no finding without
evidence ever ships) regardless of model reliability.

References:
- prompts/verifier.md
- docs/architecture/self-correction.md
- src/core/agent_loop.py (_NullVerifier implements the same baseline)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.agent_loop import VerificationIssue
from core.audit import AuditLogger
from core.llm import ModelClient, ModelMessage, ModelRequest, load_prompt
from core.types import Finding

ALLOWED_SEVERITIES: frozenset[str] = frozenset({"block", "warn", "info"})


class VerifierResponseError(ValueError):
    """Raised internally when the model output cannot be parsed.

    Caught by `LLMVerifier.verify`, which logs the failure via the
    audit logger (when supplied) and returns the baseline issues
    only.
    """


class LLMVerifier:
    """Verifier strategy driven by a `core.llm.ModelClient`.

    Parameters
    ----------
    client
        Any object conforming to the `ModelClient` Protocol.
    prompts_root
        Override for `load_prompt`'s search root. Defaults to the
        repo-level `prompts/` directory.
    audit
        Optional `AuditLogger`. When supplied, each verify call
        emits a `llm_call` event with the issue count and any
        parsing failures.
    """

    def __init__(
        self,
        *,
        client: ModelClient,
        prompts_root: Path | None = None,
        audit: AuditLogger | None = None,
    ) -> None:
        self._client = client
        self._audit = audit
        self._system_prompt = load_prompt("verifier", prompts_root=prompts_root)

    # ---- Verifier Protocol ------------------------------------------------

    def verify(self, findings: list[Finding]) -> list[VerificationIssue]:
        baseline = _baseline_issues(findings)

        if not findings:
            # Nothing to ask the model about. Baseline is trivially empty.
            self._emit_audit(
                issue_count=0,
                reasoning=None,
                error=None,
                baseline_count=0,
                model_count=0,
            )
            return list(baseline)

        request = self._build_request(findings)
        response = self._client.complete(request)

        try:
            model_issues, reasoning = self._parse_response(
                response.content,
                known_finding_ids={f.finding_id for f in findings},
            )
        except VerifierResponseError as exc:
            self._emit_audit(
                issue_count=len(baseline),
                reasoning=None,
                error=str(exc),
                baseline_count=len(baseline),
                model_count=0,
            )
            return list(baseline)

        merged = _merge_issues(baseline, model_issues)
        self._emit_audit(
            issue_count=len(merged),
            reasoning=reasoning,
            error=None,
            baseline_count=len(baseline),
            model_count=len(model_issues),
        )
        return merged

    # ---- helpers ----------------------------------------------------------

    def _build_request(self, findings: list[Finding]) -> ModelRequest:
        user_text = self._render_user_message(findings)
        return ModelRequest(
            system=self._system_prompt,
            messages=[ModelMessage(role="user", content=user_text)],
            max_tokens=2048,
            temperature=0.0,
        )

    def _render_user_message(self, findings: list[Finding]) -> str:
        lines: list[str] = []
        lines.append(f"finding_count: {len(findings)}")
        lines.append("findings:")
        for f in findings:
            lines.append(f"  - id: {f.finding_id}")
            lines.append(f"    summary: {f.summary}")
            lines.append(f"    confidence: {f.confidence}")
            if f.mitre:
                lines.append(f"    mitre: {', '.join(f.mitre)}")
            if f.reasoning:
                lines.append(f"    reasoning: {f.reasoning}")
            if f.evidence:
                lines.append("    evidence:")
                for cite in f.evidence:
                    locator = f" locator={cite.locator}" if cite.locator else ""
                    tc = (
                        f" tool_call_id={cite.tool_call_id}"
                        if cite.tool_call_id
                        else ""
                    )
                    lines.append(
                        f"      - source={cite.source}{locator}{tc}",
                    )
            else:
                lines.append("    evidence: []")
        lines.append("")
        lines.append("Review per the rules in the system prompt and return JSON.")
        return "\n".join(lines)

    def _parse_response(
        self,
        content: str,
        *,
        known_finding_ids: set[str],
    ) -> tuple[list[VerificationIssue], str]:
        text = content.strip()
        if not text:
            raise VerifierResponseError("Model returned empty content.")
        if text.startswith("```"):
            text = text.strip("`")
            first_newline = text.find("\n")
            if first_newline != -1:
                first_line = text[:first_newline].strip().lower()
                if first_line in ("json", ""):
                    text = text[first_newline + 1 :]
            text = text.strip()

        try:
            obj: Any = json.loads(text)
        except json.JSONDecodeError as exc:
            raise VerifierResponseError(
                f"Model output is not valid JSON: {exc}",
            ) from exc

        if not isinstance(obj, dict):
            raise VerifierResponseError(
                f"Top-level JSON must be an object, got {type(obj).__name__}.",
            )

        reasoning_raw = obj.get("reasoning", "")
        reasoning = reasoning_raw if isinstance(reasoning_raw, str) else ""

        raw_issues = obj.get("issues", [])
        if not isinstance(raw_issues, list):
            raise VerifierResponseError(
                f"'issues' must be a list, got {type(raw_issues).__name__}.",
            )

        issues: list[VerificationIssue] = []
        for idx, raw in enumerate(raw_issues):
            if not isinstance(raw, dict):
                raise VerifierResponseError(
                    f"Issue #{idx} must be an object, got "
                    f"{type(raw).__name__}.",
                )
            severity = raw.get("severity")
            rule = raw.get("rule")
            finding_id = raw.get("finding_id", None)
            detail = raw.get("detail")

            if not isinstance(severity, str) or severity not in ALLOWED_SEVERITIES:
                raise VerifierResponseError(
                    f"Issue #{idx} has invalid severity {severity!r}. "
                    f"Allowed: {sorted(ALLOWED_SEVERITIES)}.",
                )
            if not isinstance(rule, str) or not rule.strip():
                raise VerifierResponseError(
                    f"Issue #{idx} is missing a non-empty string 'rule'.",
                )
            if finding_id is not None and not isinstance(finding_id, str):
                raise VerifierResponseError(
                    f"Issue #{idx} has non-string 'finding_id'.",
                )
            if finding_id is not None and finding_id not in known_finding_ids:
                # The model invented a finding_id. Drop silently — the
                # prompt forbids this. We do not raise because the rest
                # of the batch may still be useful.
                continue
            if not isinstance(detail, str) or not detail.strip():
                raise VerifierResponseError(
                    f"Issue #{idx} is missing a non-empty string 'detail'.",
                )
            issues.append(
                VerificationIssue(
                    severity=severity,
                    rule=rule,
                    finding_id=finding_id,
                    detail=detail,
                ),
            )

        return issues, reasoning

    def _emit_audit(
        self,
        *,
        issue_count: int,
        reasoning: str | None,
        error: str | None,
        baseline_count: int,
        model_count: int,
    ) -> None:
        if self._audit is None:
            return
        payload: dict[str, Any] = {
            "tool": "llm_verifier",
            "issue_count": issue_count,
            "baseline_count": baseline_count,
            "model_count": model_count,
        }
        if reasoning:
            payload["reasoning"] = reasoning[:2000]
        if error is not None:
            payload["parse_error"] = error
        self._audit.append(event_type="llm_call", payload=payload)


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _baseline_issues(findings: list[Finding]) -> list[VerificationIssue]:
    """Architectural floor: every finding must cite at least one source.

    Mirrors the check in `_NullVerifier`. Runs unconditionally so
    that a broken or offline model cannot let an un-evidenced
    finding through.
    """
    out: list[VerificationIssue] = []
    for f in findings:
        if not f.evidence:
            out.append(
                VerificationIssue(
                    severity="block",
                    rule="rule1_evidence_required",
                    finding_id=f.finding_id,
                    detail=(
                        "Finding has zero citations; report emitter "
                        "will refuse."
                    ),
                ),
            )
    return out


def _merge_issues(
    baseline: list[VerificationIssue],
    extra: list[VerificationIssue],
) -> list[VerificationIssue]:
    """Concatenate baseline + model issues, deduped by (rule, finding_id).

    Baseline wins on conflict — the architectural check's wording is
    canonical.
    """
    seen: set[tuple[str, str | None]] = set()
    out: list[VerificationIssue] = []
    for issue in list(baseline) + list(extra):
        key = (issue.rule, issue.finding_id)
        if key in seen:
            continue
        seen.add(key)
        out.append(issue)
    return out


__all__ = [
    "ALLOWED_SEVERITIES",
    "LLMVerifier",
    "VerifierResponseError",
]
