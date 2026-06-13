"""
LLM-backed Planner strategy.

`LLMPlanner` implements `core.agent_loop.Planner` by:

1. Loading the planner system prompt from `prompts/planner.md` once at
   construction time (via `core.llm.load_prompt`).
2. On each `next_plan(state)` call, building a `ModelRequest` whose
   user message summarizes the current agent state (iteration index,
   accepted findings, recent execution records, optional profile /
   preflight / KB context).
3. Asking the `ModelClient` for a completion.
4. Parsing the JSON envelope described in `prompts/planner.md` into a
   `list[PlanStep]`, or returning `[]` when the model signals
   `finalize=true`.

Defensive posture: the planner NEVER crashes the agent loop on
malformed model output. If JSON parsing fails, if required keys are
missing, or if the response shape is otherwise wrong, the planner
logs the failure through the audit log (when one is supplied) and
returns `[]` — effectively signalling "finalize". The loop will then
still run verify + self_correct before emitting the report. That
keeps bad model output from producing an infinite or junk plan.

References:
- prompts/planner.md (output schema)
- docs/architecture/self-correction.md
- docs/architecture/shared-brain.md
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.agent_loop import AgentState, PlanStep
from core.audit import AuditLogger
from core.llm import ModelClient, ModelMessage, ModelRequest, load_prompt
from core.types import ProfileDefinition


class PlannerResponseError(ValueError):
    """Raised internally when the model output cannot be parsed.

    The LLMPlanner catches this and returns [] so the agent loop
    finalizes cleanly. Tests can still assert on this class when
    calling `_parse_response` directly.
    """


# Hard ceiling on plan-step batch size, matching prompts/planner.md
# (the prompt asks for <= 6; we enforce it here so a buggy model
# cannot flood the executor).
MAX_STEPS_PER_BATCH = 6


class LLMPlanner:
    """Planner strategy driven by a `core.llm.ModelClient`.

    Parameters
    ----------
    client
        Any object conforming to the `ModelClient` Protocol. Unit
        tests pass `FakeModelClient`; production wires in a real
        provider adapter.
    profile
        Optional profile metadata; when provided its name and tier
        are included in the user-message context so the model knows
        what ruleset it is planning under.
    preflight_summary
        Optional short string summarising which SIFT tools preflight
        reported as ready. The model uses this to avoid scheduling
        steps against missing tools.
    kb_context
        Optional pre-fetched KB excerpt (e.g. from
        `KnowledgeBase.search(...)`) that the model can condition on.
    prompts_root
        Override for `load_prompt`'s search root. Defaults to the
        repo-level `prompts/` directory.
    audit
        Optional `AuditLogger`. When supplied, each plan call emits
        a `llm_call` event with the request/response summary and any
        parsing failures.
    max_steps
        Upper bound on steps returned per iteration. Defaults to
        MAX_STEPS_PER_BATCH.
    """

    def __init__(
        self,
        *,
        client: ModelClient,
        profile: ProfileDefinition | None = None,
        preflight_summary: str | None = None,
        kb_context: str | None = None,
        prompts_root: Path | None = None,
        audit: AuditLogger | None = None,
        max_steps: int = MAX_STEPS_PER_BATCH,
    ) -> None:
        self._client = client
        self._profile = profile
        self._preflight_summary = preflight_summary
        self._kb_context = kb_context
        self._audit = audit
        self._max_steps = max(1, min(max_steps, MAX_STEPS_PER_BATCH))
        self._system_prompt = load_prompt("planner", prompts_root=prompts_root)

    # ---- Planner Protocol -------------------------------------------------

    def next_plan(self, state: AgentState) -> list[PlanStep]:
        request = self._build_request(state)
        response = self._client.complete(request)

        try:
            steps, reasoning, finalize = self._parse_response(response.content)
        except PlannerResponseError as exc:
            self._emit_audit(
                state=state,
                reasoning=None,
                finalize=True,
                step_ids=[],
                error=str(exc),
            )
            return []

        self._emit_audit(
            state=state,
            reasoning=reasoning,
            finalize=finalize,
            step_ids=[s.step_id for s in steps],
            error=None,
        )

        if finalize:
            return []
        return steps

    # ---- helpers ----------------------------------------------------------

    def _build_request(self, state: AgentState) -> ModelRequest:
        user_text = self._render_user_message(state)
        return ModelRequest(
            system=self._system_prompt,
            messages=[ModelMessage(role="user", content=user_text)],
            max_tokens=2048,
            temperature=0.1,
        )

    def _render_user_message(self, state: AgentState) -> str:
        lines: list[str] = []
        lines.append(f"incident_id: {state.incident_id}")
        lines.append(f"iteration: {state.iterations}")
        lines.append(f"findings_accepted: {len(state.findings)}")
        lines.append(f"executions_so_far: {len(state.execution_log)}")
        if self._profile is not None:
            lines.append(f"profile: {self._profile.name}")
            if self._profile.description:
                lines.append(f"profile_description: {self._profile.description}")
        if self._preflight_summary:
            lines.append("preflight_summary:")
            lines.append(self._preflight_summary)
        if self._kb_context:
            lines.append("kb_context:")
            lines.append(self._kb_context)
        # Execution tail (last 3) — keeps context tight for the model.
        if state.execution_log:
            lines.append("recent_executions:")
            for rec in state.execution_log[-3:]:
                lines.append(
                    f"  - {rec.step_id} :: {rec.summary} "
                    f"(corr={rec.correlation_id})",
                )
        # Findings tail (last 5 IDs + titles).
        if state.findings:
            lines.append("recent_findings:")
            for f in state.findings[-5:]:
                lines.append(f"  - {f.finding_id}: {f.summary}")
        lines.append("")
        lines.append("Produce the next plan batch as JSON per the system prompt.")
        return "\n".join(lines)

    def _parse_response(
        self,
        content: str,
    ) -> tuple[list[PlanStep], str, bool]:
        text = content.strip()
        if not text:
            raise PlannerResponseError("Model returned empty content.")
        # Some models wrap JSON in a code fence despite being told not to.
        # Strip an outer ```json ... ``` or ``` ... ``` if present.
        if text.startswith("```"):
            text = text.strip("`")
            # After stripping backticks, the first line may be "json".
            first_newline = text.find("\n")
            if first_newline != -1:
                first_line = text[:first_newline].strip().lower()
                if first_line in ("json", ""):
                    text = text[first_newline + 1 :]
            text = text.strip()

        try:
            obj: Any = json.loads(text)
        except json.JSONDecodeError as exc:
            raise PlannerResponseError(f"Model output is not valid JSON: {exc}") from exc

        if not isinstance(obj, dict):
            raise PlannerResponseError(
                f"Top-level JSON must be an object, got {type(obj).__name__}.",
            )

        reasoning_raw = obj.get("reasoning", "")
        reasoning = reasoning_raw if isinstance(reasoning_raw, str) else ""
        finalize = bool(obj.get("finalize", False))
        raw_steps = obj.get("steps", [])
        if not isinstance(raw_steps, list):
            raise PlannerResponseError(
                f"'steps' must be a list, got {type(raw_steps).__name__}.",
            )

        if finalize:
            # Contract: finalize=true implies empty steps. Tolerate the
            # model getting that wrong — finalize wins.
            return [], reasoning, True

        steps: list[PlanStep] = []
        seen_ids: set[str] = set()
        for idx, raw in enumerate(raw_steps):
            if len(steps) >= self._max_steps:
                break
            if not isinstance(raw, dict):
                raise PlannerResponseError(
                    f"Step #{idx} must be an object, got "
                    f"{type(raw).__name__}.",
                )
            step_id = raw.get("step_id")
            intent = raw.get("intent")
            if not isinstance(step_id, str) or not step_id.strip():
                raise PlannerResponseError(
                    f"Step #{idx} is missing a non-empty string 'step_id'.",
                )
            if step_id in seen_ids:
                raise PlannerResponseError(
                    f"Duplicate step_id '{step_id}' within the same batch.",
                )
            if not isinstance(intent, str) or not intent.strip():
                raise PlannerResponseError(
                    f"Step '{step_id}' is missing a non-empty string 'intent'.",
                )
            tool = raw.get("tool", None)
            if tool is not None and not isinstance(tool, str):
                raise PlannerResponseError(
                    f"Step '{step_id}' has non-string 'tool'.",
                )
            tool_args = raw.get("tool_args", {})
            if not isinstance(tool_args, dict):
                raise PlannerResponseError(
                    f"Step '{step_id}' has non-object 'tool_args'.",
                )
            seen_ids.add(step_id)
            steps.append(
                PlanStep(
                    step_id=step_id,
                    intent=intent,
                    tool=tool,
                    tool_args=dict(tool_args),
                ),
            )

        if not steps:
            # No parseable steps AND finalize was false: defensive
            # finalize so the loop terminates cleanly.
            return [], reasoning, True

        return steps, reasoning, False

    def _emit_audit(
        self,
        *,
        state: AgentState,
        reasoning: str | None,
        finalize: bool,
        step_ids: list[str],
        error: str | None,
    ) -> None:
        if self._audit is None:
            return
        payload: dict[str, Any] = {
            "tool": "llm_planner",
            "iteration": state.iterations,
            "finalize": finalize,
            "step_count": len(step_ids),
            "step_ids": step_ids,
        }
        if reasoning:
            # Truncate extremely long reasoning to keep the audit log
            # readable. 2_000 chars is generous.
            payload["reasoning"] = reasoning[:2000]
        if error is not None:
            payload["parse_error"] = error
        self._audit.append(event_type="llm_call", payload=payload)


__all__ = [
    "LLMPlanner",
    "MAX_STEPS_PER_BATCH",
    "PlannerResponseError",
]
