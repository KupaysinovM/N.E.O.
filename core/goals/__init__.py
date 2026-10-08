"""
Goals — NEO's first bounded, multi-step pursuit of an outcome.

    User goal
        ↓
    Planner            data → validated, ordered, bounded
        ↓
    Plan / Step
        ↓
    TaskManager        one real Phase 2 task per attempt
        ↓
    ExecutionLayer     the only path from a request to a capability
        ↓
    Action registry
        ↓
    Real Windows
        ↓
    Phase 4 verify
        ↓
    Step result → next step / stop / bounded recovery
        ↓
    GoalResult

THE ONE SENTENCE
    NEO pursues a goal through *verified* steps and reports what it can prove,
    not "all the calls came back without raising".

THE THREE THINGS PHASE 5 DOES NOT DO
    It does not let a plan name anything that is not already a registered
    capability. It does not loop until the goal is done — every loop here has a
    written ceiling (see limits.py). And it does not let a success that could
    not be verified count as a success.

THE RELATIONSHIP TO THE EARLIER PHASES
    A Goal owns Steps. A Step is not a Task; each *attempt* at a step creates a
    real Task through the existing TaskManager, so persistence, events,
    cancellation and confirmation are Phase 2's, unchanged. Verification is
    Phase 4's: the executor asks the same verifier the execution layer asks,
    and accepts the same answers.
"""
from __future__ import annotations

from core.goals.executor import GoalExecutor
from core.goals.limits import Limits
from core.goals.models import (
    Attempt,
    Goal,
    GoalContext,
    GoalResult,
    GoalStatus,
    Plan,
    Step,
    StepStatus,
    TERMINAL_GOAL_STATUSES,
    TERMINAL_STEP_STATUSES,
    new_goal_id,
)
from core.goals.planner import EXPECTATION_KINDS, TEMPLATES, PlanRejected, Planner
from core.goals.recovery import (
    NO_RETRIES,
    PERMANENT_ERROR_KINDS,
    TRANSIENT_ERROR_KINDS,
    RetryPolicy,
    classify,
    is_recoverable,
    is_transient,
)
from core.goals.store import GoalHistory, GoalLoadReport, GoalStore, default_goals_path

__all__ = [
    "Goal", "Plan", "Step", "Attempt", "GoalContext", "GoalResult",
    "GoalStatus", "StepStatus", "TERMINAL_GOAL_STATUSES", "TERMINAL_STEP_STATUSES",
    "new_goal_id",
    "Planner", "PlanRejected", "TEMPLATES", "EXPECTATION_KINDS",
    "Limits", "RetryPolicy", "NO_RETRIES",
    "TRANSIENT_ERROR_KINDS", "PERMANENT_ERROR_KINDS",
    "classify", "is_transient", "is_recoverable",
    "GoalExecutor",
    "GoalStore", "GoalHistory", "GoalLoadReport", "default_goals_path",
]