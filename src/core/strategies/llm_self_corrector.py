"""
LLM-backed SelfCorrector strategy.

`LLMSelfCorrector` implements `core.agent_loop.SelfCorrector` by:

1. Loading the self-corrector system prompt from
   `prompts/self_corrector.md` once at construction time.
2. On each `correct(findings=..., issues=..., iteration=...)`
   call, rendering the finding set + issue list as a terse user
   message and asking the `ModelClient` for a decision JSON.
3. Parsing the JSON envelope `{"notes", "resolved", "dropped",
   "replan"}` into a `SelfCorrectionDecision`, validating that
   every `resolved` / `dropped` ID exists in the input finding
   set.

Defensive posture
-----------------

`SelfCorrectionDecision` is the LAST line of defence before
`AgentLoop.finalize` gates the report emission. If the model
output is malformed, `LLMSelfCorrector` NEVER returns a decision
that would let a blocking-severity issue through.

Safe-default policy on parse failure:

    - Drop every finding that currently has a `severity: block`
      issue against it (matching the `_NullSelfCorrector`
      behaviour in `core.agent_loop`).
    - Resolve nothing.
    - Do NOT replan (that would loop forever if the model keeps
      returning garbage).
    - `notes` = short parse-error summary; actual error is in the
      audit log payload.

Mirrors the defensive contract in `core.strategies.llm_planner`
and `core.strategies.llm_verifier`.

References:
- prompts/self_corrector.md
- docs/architecture/self-correction.md
- src/core/agent_loop.py (_NullSelfCorrector implements the same safe default)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.agent_loop import SelfCorrectionDecision, VerificationIssue
from core.audit import AuditLogger
from core.llm import ModelClient, ModelMessage, ModelRequest, load_prompt
from core.types import Finding


class SelfCorrectorResponseError(ValueError):
    """Raised internally when the model output cannot be parsed.

    Caught by `LLMSelfCorrector.correct`, which logs the failure
    via the audit logger (when supplied) and falls back to the
    safe-default decision.
    """


class LLMSelfCorrector:
    """SelfCorrector strategy driven by a `core.llm.ModelClient`.

    Parameters
    ----------
    client
        Any object conforming to the `ModelClient` Protocol.
    prompts_root
        Override for `load_prompt`'s search root. Defaults to the
        repo-level `prompts/` directory.
    audit
        Optional `AuditLogger`. When supplied, each correct call
        emits a `llm_call` event summarising the decision and any
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
        self._system_prompt = load_prompt(
            "self_corrector",
            prompts_root=prompts_root,
        )

    # ---- SelfCorrector Protocol ------------------------------------------

    def correct(
        self,
        *,
        findings: list[Finding],
        issues: list[VerificationIssue],
        iteration: int,
    ) -> SelfCorrectionDecision:
        known_ids = {f.finding_id for f in findings}

        if not issues:
            # No issues → nothing to correct. Don't waste a model call.
            self._emit_audit(
                iteration=iteration,
                resolved=[],
                dropped=[],
                replan=False,
                notes=None,
                error=None,
                used_fallback=False,
            )
            return SelfCorrectionDecision(
                iteration=iteration,
                issues=[],
                resolved=[],
                dropped=[],
                replan=False,
                notes="no issues; nothing to correct.",
            )

        request = self._build_request(
            findings=findings,
            issues=issues,
            iteration=iteration,
        )
        response = self._client.complete(request)

        try:
            decision_body = self._parse_response(
                response.content,
                known_finding_ids=known_ids,
            )
        except SelfCorrectorResponseError as exc:
            fallback = _safe_default_decision(
                issues=issues,
                iteration=iteration,
                known_ids=known_ids,
                parse_error=str(exc),
            )
            self._emit_audit(
                iteration=iteration,
                resolved=fallback.resolved,
                dropped=fallback.dropped,
                replan=fallback.replan,
                notes=None,
                error=str(exc),
                used_fallback=True,
            )
            return fallback

        notes, resolved, dropped, replan = decision_body
        self._emit_audit(
            iteration=iteration,
            resolved=resolved,
            dropped=dropped,
            replan=replan,
            notes=notes,
            error=None,
            used_fallback=False,
        )
        return SelfCorrectionDecision(
            iteration=iteration,
            issues=list(issues),
            resolved=resolved,
            dropped=dropped,
            replan=replan,
            notes=notes or None,
        )

    # ---- helpers ---------------------------------------------------------

    def _build_request(
        self,
        *,
        findings: list[Finding],
        issues: list[VerificationIssue],
        iteration: int,
    ) -> ModelRequest:
        user_text = self._render_user_message(
            findings=findings,
            issues=issues,
            iteration=iteration,
        )
        return ModelRequest(
            system=self._system_prompt,
            messages=[ModelMessage(role="user", content=user_text)],
            max_tokens=2048,
            temperature=0.0,
        )

    def _render_user_message(
        self,
        *,
        findings: list[Finding],
        issues: list[VerificationIssue],
        iteration: int,
    ) -> str:
        lines: list[str] = []
        lines.append(f"iteration: {iteration}")
        lines.append(f"finding_count: {len(findings)}")
        lines.append(f"issue_count: {len(issues)}")
        lines.append("findings:")
        for f in findings:
            evidence_n = len(f.evidence)
            lines.append(
                f"  - id: {f.finding_id}  summary: {f.summary}  "
                f"confidence: {f.confidence}  evidence: {evidence_n}",
            )
        lines.append("issues:")
        for issue in issues:
            lines.append(
                f"  - severity: {issue.severity}  rule: {issue.rule}  "
                f"finding_id: {issue.finding_id}  detail: {issue.detail}",
            )
        lines.append("")
        lines.append("Decide per the system prompt and return JSON.")
        return "\n".join(lines)

    def _parse_response(
        self,
        content: str,
        *,
        known_finding_ids: set[str],
    ) -> tuple[str, list[str], list[str], bool]:
        text = content.strip()
        if not text:
            raise SelfCorrectorResponseError("Model returned empty content.")
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
            raise SelfCorrectorResponseError(
                f"Model output is not valid JSON: {exc}",
            ) from exc

        if not isinstance(obj, dict):
            raise SelfCorrectorResponseError(
                f"Top-level JSON must be an object, got {type(obj).__name__}.",
            )

        notes_raw = obj.get("notes", "")
        notes = notes_raw if isinstance(notes_raw, str) else ""

        replan_raw = obj.get("replan", False)
        if not isinstance(replan_raw, bool):
            raise SelfCorrectorResponseError(
                f"'replan' must be a boolean, got {type(replan_raw).__name__}.",
            )
        replan = replan_raw

        resolved = _validate_id_list(
            obj.get("resolved", []),
            field="resolved",
            known=known_finding_ids,
        )
        dropped = _validate_id_list(
            obj.get("dropped", []),
            field="dropped",
            known=known_finding_ids,
        )

        # A finding cannot be both resolved and dropped in the same pass.
        # If the model claims both, dropping wins (it's the safer action).
        overlap = set(resolved) & set(dropped)
        if overlap:
            resolved = [fid for fid in resolved if fid not in overlap]

        return notes, resolved, dropped, replan

    def _emit_audit(
        self,
        *,
        iteration: int,
        resolved: list[str],
        dropped: list[str],
        replan: bool,
        notes: str | None,
        error: str | None,
        used_fallback: bool,
    ) -> None:
        if self._audit is None:
            return
        payload: dict[str, Any] = {
            "tool": "llm_self_corrector",
            "iteration": iteration,
            "resolved": resolved,
            "dropped": dropped,
            "replan": replan,
            "used_fallback": used_fallback,
        }
        if notes:
            payload["notes"] = notes[:2000]
        if error is not None:
            payload["parse_error"] = error
        self._audit.append(event_type="llm_call", payload=payload)


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _validate_id_list(
    value: Any,
    *,
    field: str,
    known: set[str],
) -> list[str]:
    """Return a clean list[str] of known finding IDs.

    Raises on wrong shape or non-string entries. Silently drops IDs
    not present in `known` — a model that invented a finding ID is a
    known failure mode we tolerate per-entry rather than per-batch.
    """
    if not isinstance(value, list):
        raise SelfCorrectorResponseError(
            f"'{field}' must be a list, got {type(value).__name__}.",
        )
    out: list[str] = []
    seen: set[str] = set()
    for idx, item in enumerate(value):
        if not isinstance(item, str):
            raise SelfCorrectorResponseError(
                f"'{field}[{idx}]' must be a string, got "
                f"{type(item).__name__}.",
            )
        if item not in known:
            continue  # invented ID — drop silently
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _safe_default_decision(
    *,
    issues: list[VerificationIssue],
    iteration: int,
    known_ids: set[str],
    parse_error: str,
) -> SelfCorrectionDecision:
    """Fallback when the model output is malformed.

    Mirrors `_NullSelfCorrector.correct`: drop every finding that
    currently has a `severity: block` issue against it. Resolve
    nothing. Don't replan. Surface the parse-error summary in
    `notes` so the audit reader knows why the fallback fired.
    """
    dropped_ids: list[str] = []
    seen: set[str] = set()
    for issue in issues:
        if issue.severity != "block":
            continue
        fid = issue.finding_id
        if fid is None or fid not in known_ids or fid in seen:
            continue
        seen.add(fid)
        dropped_ids.append(fid)
    return SelfCorrectionDecision(
        iteration=iteration,
        issues=list(issues),
        resolved=[],
        dropped=dropped_ids,
        replan=False,
        notes=f"fallback: {parse_error[:300]}",
    )


__all__ = [
    "LLMSelfCorrector",
    "SelfCorrectorResponseError",
]
