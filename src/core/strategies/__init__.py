"""
Concrete strategy implementations for the APTWatcher agent loop.

The loop in `core.agent_loop` delegates every decision to a strategy
object that implements one of four Protocols:

- Planner -> next_plan(state) -> list[PlanStep]
- Executor -> execute(step, *, audit) -> ExecutionRecord
- Verifier -> verify(findings) -> list[VerificationIssue]
- SelfCorrector -> correct(...) -> SelfCorrectionDecision

This package holds the LLM-backed implementations. Each strategy
module builds on `core.llm.ModelClient` so tests can drop in a
`FakeModelClient` without reaching out to a real provider.

References:
- docs/architecture/self-correction.md
- docs/architecture/shared-brain.md
- prompts/planner.md
- prompts/verifier.md
- prompts/self_corrector.md
"""

from __future__ import annotations

from core.strategies.llm_planner import (
    LLMPlanner,
    PlannerResponseError,
)
from core.strategies.llm_self_corrector import (
    LLMSelfCorrector,
    SelfCorrectorResponseError,
)
from core.strategies.llm_verifier import (
    ALLOWED_SEVERITIES,
    LLMVerifier,
    VerifierResponseError,
)

__all__ = [
    "ALLOWED_SEVERITIES",
    "LLMPlanner",
    "LLMSelfCorrector",
    "LLMVerifier",
    "PlannerResponseError",
    "SelfCorrectorResponseError",
    "VerifierResponseError",
]
