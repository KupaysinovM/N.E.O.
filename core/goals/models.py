"""
The shape of a goal, a plan and a step — and the states they may legally be in.

THE RELATIONSHIP, STATED ONCE
    Goal
      └── Plan
           └── Step
                └── Task        (a real Phase 2 task, one per attempt)
                     └── ExecutionRequest → ExecutionLayer → registry → Windows

A Step does not replace a Task and is not a Task. Every attempt at a step
creates a genuine task through the existing TaskManager, so Phase 2's
persistence, events, cancellation and confirmation apply to goal work with no
second implementation of any of them. The goal layer adds ordering, dependency
and verification requirements; it owns no capability of its own.

WHAT A GOAL IS NOT
    Not memory, not a planner that invents capabilities, not an agent loop. A
    goal is a record with a bounded plan attached, and a status that can only
    be reached by the steps actually having reached their own outcomes.

STATUS VOCABULARY
    The names deliberately reuse the values already in use elsewhere:
      PENDING / RUNNING / PAUSED / COMPLETED / FAILED / CANCELLED  — TaskStatus
      NOT_SUPPORTED / CANCELLED                                    — ExecStatus
      VERIFIED / NOT_VERIFIED / AMBIGUOUS / STALE / NOT_AVAILABLE   — verifier.Status
    A step status of "NOT_VERIFIED" therefore *is* an ExecStatus, and a goal
    that is "NOT_VERIFIED" is reporting the same thing the execution layer
    reports for a call whose effect could not be seen. No parallel enums.
"""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from core.goals.limits import Limits
from core.goals.recovery import NO_RETRIES, RetryPolicy
from core.task_models import ErrorKind, TaskError
from core.verification.expectations import Expectation

#: Metadata and context keys whose values are dropped before a goal is written
#: to disk. Credentials live in core/secret_store.py and config/secure/, and a
#: goal record has no business holding one; this is the belt to that braces.
_SECRET_KEYS = ("api_key", "apikey", "token", "secret", "password", "passwd",
                "authorization", "credential", "cookie", "session_key")


def scrub_sensitive(value: Any, depth: int = 0) -> Any:
    """Drop credential-shaped entries from a structure bound for the disk.

    Applied on the way *out*, not on the way in, so a value that happens to look
    secret still reaches a running goal; it simply is not written to a file that
    outlives the process. The shape of the value is not guessed from prose —
    only from the key it is stored under, or from a key-looking string.
    """
    if depth > 6:
        return None
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            if str(key).lower() in _SECRET_KEYS:
                continue
            cleaned[key] = scrub_sensitive(item, depth + 1)
        return cleaned
    if isinstance(value, (list, tuple)):
        return [scrub_sensitive(item, depth + 1) for item in value]
    if isinstance(value, str) and value.startswith("AIza") and len(value) > 20:
        return "[withheld: credential-shaped value]"
    return value


# ── statuses ────────────────────────────────────────────────────────────────

class StepStatus(str, Enum):
    """Where one step is. Values match the other layers' vocabulary exactly."""

    PENDING   = "PENDING"                 # same as TaskStatus.PENDING
    READY     = "READY"                   # dependencies are satisfied
    RUNNING   = "RUNNING"                 # same as TaskStatus.RUNNING
    VERIFIED  = "VERIFIED"                # same as verifier.Status.VERIFIED
    COMPLETED = "COMPLETED"               # ran with nothing to verify
    NOT_VERIFIED = "NOT_VERIFIED"         # same as ExecStatus.NOT_VERIFIED
    FAILED    = "FAILED"                  # same as TaskStatus.FAILED
    BLOCKED   = "BLOCKED"                 # a dependency or the goal stopped it
    AWAITING_CONFIRMATION = "AWAITING_CONFIRMATION"   # same as ExecStatus
    CANCELLED = "CANCELLED"               # same as TaskStatus.CANCELLED
    SKIPPED   = "SKIPPED"                 # optional step the goal went without
    #: Phase 6. This step ran, did not reach its outcome, and a bounded replan
    #: replaced it. It is deliberately *not* a success and deliberately *not* a
    #: failure of the goal: the failure is still on the record (history, notes,
    #: its task), and whether the goal achieved anything is decided by the steps
    #: that replaced it. Reporting this as COMPLETED would erase a real failure;
    #: reporting the goal FAILED would ignore a recovery that worked.
    SUPERSEDED = "SUPERSEDED"


TERMINAL_STEP_STATUSES = frozenset({
    StepStatus.VERIFIED, StepStatus.COMPLETED, StepStatus.NOT_VERIFIED,
    StepStatus.FAILED, StepStatus.BLOCKED, StepStatus.CANCELLED,
    StepStatus.SKIPPED, StepStatus.SUPERSEDED,
})

#: A required step must be one of these for the goal to be allowed to succeed.
SUCCESSFUL_STEP_STATUSES = frozenset({StepStatus.VERIFIED, StepStatus.COMPLETED})


class GoalStatus(str, Enum):
    """Where the whole goal is."""

    PENDING      = "PENDING"
    PLANNING     = "PLANNING"
    READY        = "READY"
    RUNNING      = "RUNNING"
    PAUSED       = "PAUSED"
    AWAITING_CONFIRMATION = "AWAITING_CONFIRMATION"
    COMPLETED    = "COMPLETED"
    FAILED       = "FAILED"
    NOT_VERIFIED = "NOT_VERIFIED"
    BLOCKED      = "BLOCKED"
    CANCELLED    = "CANCELLED"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    PLANNING_FAILED = "PLANNING_FAILED"


TERMINAL_GOAL_STATUSES = frozenset({
    GoalStatus.COMPLETED, GoalStatus.FAILED, GoalStatus.NOT_VERIFIED,
    GoalStatus.BLOCKED, GoalStatus.CANCELLED, GoalStatus.NOT_SUPPORTED,
    GoalStatus.PLANNING_FAILED,
})


def new_goal_id() -> str:
    return uuid.uuid4().hex


# ── one attempt at one step ─────────────────────────────────────────────────

@dataclass
class Attempt:
    """One execution of one step. A step keeps every attempt, bounded."""

    number: int = 1
    task_id: str = ""
    status: str = ""                    # ExecStatus the execution reported
    final_status: str = ""              # what to branch on (may be NOT_VERIFIED)
    verification_status: str = ""
    verified: bool = False
    recovery: bool = False              # True when this attempt followed a recovery
    message: str = ""
    error: Optional[TaskError] = None
    started_at: float = 0.0
    finished_at: float = 0.0
    data: dict = field(default_factory=dict)

    @property
    def duration(self) -> float:
        return max(0.0, (self.finished_at or 0.0) - (self.started_at or 0.0))

    def to_dict(self) -> dict:
        return {
            "number": self.number, "task_id": self.task_id,
            "status": self.status, "final_status": self.final_status,
            "verification_status": self.verification_status,
            "verified": self.verified, "recovery": self.recovery,
            "message": self.message,
            "error": self.error.to_dict() if self.error else None,
            "started_at": self.started_at, "finished_at": self.finished_at,
            "data": dict(self.data),
        }

    @classmethod
    def from_dict(cls, raw: dict) -> "Attempt":
        error_raw = raw.get("error")
        return cls(
            number=int(raw.get("number", 1) or 1),
            task_id=str(raw.get("task_id", "")),
            status=str(raw.get("status", "")),
            final_status=str(raw.get("final_status", "")),
            verification_status=str(raw.get("verification_status", "")),
            verified=bool(raw.get("verified", False)),
            recovery=bool(raw.get("recovery", False)),
            message=str(raw.get("message", "")),
            error=(TaskError.from_dict(error_raw) if isinstance(error_raw, dict) else None),
            started_at=float(raw.get("started_at") or 0.0),
            finished_at=float(raw.get("finished_at") or 0.0),
            data=dict(raw.get("data") or {}) if isinstance(raw.get("data"), dict) else {},
        )


# ── the step ────────────────────────────────────────────────────────────────

@dataclass
class Step:
    """One bounded operation, with what has to be true afterwards."""

    step_id: str
    description: str = ""
    action: str = ""
    arguments: dict = field(default_factory=dict)
    expected: Optional[Expectation] = None      # only used if the action has none
    depends_on: list = field(default_factory=list)
    retry: RetryPolicy = field(default_factory=lambda: NO_RETRIES)
    #: Opt-in re-acquisition of a window the OS moved. A stale HWND is not a
    #: strategy failure — the window is usually still there under a new handle —
    #: so a step may ask for one bounded re-location before it is repeated. It
    #: never invents a different operation and never guesses between two
    #: candidates.
    re_resolve: bool = False
    required: bool = True
    status: StepStatus = StepStatus.PENDING
    attempts: int = 0
    recovery_attempts: int = 0
    task_id: str = ""
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    expected_by: str = "none"                   # none | plan | action
    resolved_arguments: dict = field(default_factory=dict)
    result: Optional[Attempt] = None
    history: list = field(default_factory=list)  # every Attempt
    notes: list = field(default_factory=list)   # bounded human-readable reasons
    verification: Optional[dict] = None

    # -- state ---------------------------------------------------------------

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_STEP_STATUSES

    @property
    def succeeded(self) -> bool:
        """Did this step reach the outcome its contract asked for?"""
        return self.status in SUCCESSFUL_STEP_STATUSES

    @property
    def verified(self) -> bool:
        """True only when something was observed to be true."""
        return self.status is StepStatus.VERIFIED

    @property
    def error_kind(self) -> Optional[ErrorKind]:
        last = self.result.error if self.result else None
        return last.kind if last else None

    def note(self, text: str, limit: int = 6) -> None:
        """Keep the newest `limit` reasons. Old ones are dropped, not filed."""
        self.notes.append(str(text)[:200])
        if len(self.notes) > limit:
            del self.notes[: len(self.notes) - limit]

    def to_dict(self) -> dict:
        return {
            "step_id": self.step_id,
            "description": self.description,
            "action": self.action,
            "arguments": dict(self.arguments),
            "resolved_arguments": dict(self.resolved_arguments),
            "expected": self.expected.to_dict() if self.expected else None,
            "expected_by": self.expected_by,
            "depends_on": list(self.depends_on),
            "retry": self.retry.to_dict(),
            "re_resolve": self.re_resolve,
            "required": self.required,
            "status": self.status.value,
            "attempts": self.attempts,
            "recovery_attempts": self.recovery_attempts,
            "task_id": self.task_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "result": self.result.to_dict() if self.result else None,
            "verification": dict(self.verification) if self.verification else None,
            "notes": list(self.notes),
        }

    @classmethod
    def from_dict(cls, raw: dict) -> "Step":
        if not isinstance(raw, dict):
            raise ValueError("step record must be an object")
        step_id = str(raw.get("step_id", "")).strip()
        if not step_id:
            raise ValueError("step_id is required")
        status_raw = str(raw.get("status", StepStatus.PENDING.value)).upper()
        try:
            status = StepStatus(status_raw)
        except ValueError as e:
            raise ValueError(f"unknown step status {status_raw!r}") from e
        expected_raw = raw.get("expected")
        history_raw = raw.get("history")
        return cls(
            step_id=step_id,
            description=str(raw.get("description", "")),
            action=str(raw.get("action", "")),
            arguments=dict(raw.get("arguments") or {}),
            expected=(Expectation.from_dict(expected_raw)
                      if isinstance(expected_raw, dict) and expected_raw.get("kind") else None),
            expected_by=str(raw.get("expected_by", "none")),
            depends_on=[str(d) for d in (raw.get("depends_on") or [])],
            retry=RetryPolicy.from_dict(raw.get("retry")),
            re_resolve=bool(raw.get("re_resolve", False)),
            required=bool(raw.get("required", True)),
            status=status,
            attempts=int(raw.get("attempts", 0) or 0),
            recovery_attempts=int(raw.get("recovery_attempts", 0) or 0),
            task_id=str(raw.get("task_id", "")),
            started_at=raw.get("started_at"),
            finished_at=raw.get("finished_at"),
            resolved_arguments=(dict(raw.get("resolved_arguments") or {})
                                if isinstance(raw.get("resolved_arguments"), dict) else {}),
            result=(Attempt.from_dict(raw["result"])
                    if isinstance(raw.get("result"), dict) else None),
            verification=(dict(raw["verification"])
                          if isinstance(raw.get("verification"), dict) else None),
            history=[Attempt.from_dict(a) for a in history_raw
                     if isinstance(a, dict)] if isinstance(history_raw, list) else [],
            notes=[str(n) for n in (raw.get("notes") or [])],
        )


# ── the plan ────────────────────────────────────────────────────────────────

@dataclass
class Plan:
    """An ordered, bounded, validated list of steps. Never executable code."""

    goal_id: str
    steps: list = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    source: str = "explicit"          # explicit | template:<name> | proposal
    version: int = 1

    def __len__(self) -> int:
        return len(self.steps)

    def __iter__(self):
        return iter(self.steps)

    def step(self, step_id: str) -> Optional[Step]:
        for step in self.steps:
            if step.step_id == step_id:
                return step
        return None

    @property
    def required_steps(self) -> list:
        return [s for s in self.steps if s.required]

    def to_dict(self) -> dict:
        return {"goal_id": self.goal_id, "created_at": self.created_at,
                "source": self.source, "version": self.version,
                "steps": [s.to_dict() for s in self.steps]}

    @classmethod
    def from_dict(cls, raw: dict) -> "Plan":
        if not isinstance(raw, dict):
            raise ValueError("plan record must be an object")
        steps_raw = raw.get("steps")
        if not isinstance(steps_raw, list):
            raise ValueError("plan has no step list")
        return cls(goal_id=str(raw.get("goal_id", "")),
                   steps=[Step.from_dict(s) for s in steps_raw],
                   created_at=float(raw.get("created_at") or 0.0),
                   source=str(raw.get("source", "explicit")),
                   version=int(raw.get("version", 1) or 1))


# ── bounded execution context ───────────────────────────────────────────────

@dataclass
class GoalContext:
    """What the goal is doing, in as few words as can be true.

    This is a working context for the duration of one goal, not memory. It is
    bounded on every axis (items, characters, step summaries) and it never
    holds a screen capture, a credential, or a raw control tree: the things it
    carries are the goal's own text, step outcomes, and the handful of observed
    values a later step asked for by name.
    """

    goal_id: str = ""
    description: str = ""
    current_step: str = ""
    entries: dict = field(default_factory=dict)      # observed world values
    step_summaries: list = field(default_factory=list)
    recovery_attempts: int = 0
    task_ids: list = field(default_factory=list)
    max_items: int = 12
    max_chars: int = 600
    #: Keys a step that has not finished yet still names with `{"$from": ...}`.
    #: A reference is a dependency, not an observation: dropping one would fail
    #: a step whose earlier work already succeeded, so eviction skips these.
    #: The executor recomputes the set from the live plan before every step.
    pinned: set = field(default_factory=set)

    def remember(self, key: str, value: Any) -> None:
        """Record one observed value under an explicit key.

        Keys are how a later step asks for a value by name
        (`{"$from": "step:s1.handle"}`). Nothing is invented here: the executor
        only calls this with values Windows actually reported.
        """
        self.entries[str(key)] = value
        while len(self.entries) > self.max_items:
            # Drop the oldest inserted key, not the least useful one — the
            # newest observations are the ones a next step can still rely on —
            # except that a key a later step still names is kept until that
            # step has resolved it.
            stale = next((k for k in self.entries if k not in self.pinned), None)
            if stale is None:
                # Everything left is still named by a step that has not run.
                # The bound is still a bound, so the oldest pinned key goes.
                stale = next(iter(self.entries), None)
            if stale is None:
                break
            self.entries.pop(stale, None)

    def recall(self, key: str, default: Any = None) -> Any:
        return self.entries.get(str(key), default)

    def knows(self, key: str) -> bool:
        return str(key) in self.entries

    def add_task(self, task_id: str) -> None:
        if task_id and task_id not in self.task_ids:
            self.task_ids.append(task_id)
            if len(self.task_ids) > self.max_items:
                del self.task_ids[: len(self.task_ids) - self.max_items]

    def add_step_summary(self, step_id: str, status: str, detail: str = "") -> None:
        self.step_summaries.append({
            "step_id": step_id, "status": status,
            "detail": str(detail)[: self.max_chars],
        })
        if len(self.step_summaries) > self.max_items:
            del self.step_summaries[: len(self.step_summaries) - self.max_items]

    def to_dict(self) -> dict:
        return {"goal_id": self.goal_id,
                "description": str(self.description)[: self.max_chars],
                "current_step": self.current_step,
                "entries": {k: v for k, v in list(self.entries.items())[: self.max_items]},
                "step_summaries": list(self.step_summaries),
                "recovery_attempts": self.recovery_attempts,
                "task_ids": list(self.task_ids)}

    def describe(self) -> str:
        lines = [f"Goal: {self.description or self.goal_id}"]
        if self.current_step:
            lines.append(f"At step: {self.current_step}")
        for summary in self.step_summaries:
            lines.append(f"  {summary['step_id']}: {summary['status']} "
                         f"{summary['detail']}".rstrip())
        return "\n".join(lines)


# ── the result ──────────────────────────────────────────────────────────────

@dataclass
class GoalResult:
    """What the goal actually achieved. `ok` is never a guess."""

    goal_id: str
    status: GoalStatus
    message: str = ""
    step_count: int = 0
    verified: int = 0
    completed: int = 0
    not_verified: int = 0
    failed: int = 0
    blocked: int = 0
    cancelled: int = 0
    skipped: int = 0
    awaiting_confirmation: int = 0
    recovery_attempts: int = 0
    #: Phase 6. Steps a bounded replan replaced, and how many replans ran. Both
    #: are on the result so "the goal succeeded" can always be read next to
    #: "after one step was abandoned and replaced".
    superseded: int = 0
    replans: int = 0
    duration_seconds: float = 0.0
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    steps: list = field(default_factory=list)          # ordered summaries
    error: Optional[TaskError] = None
    world_summary: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        """True only for a goal whose required steps reached their outcomes."""
        return self.status is GoalStatus.COMPLETED

    def to_dict(self) -> dict:
        return {
            "goal_id": self.goal_id, "status": self.status.value,
            "ok": self.ok, "message": self.message,
            "counts": {"steps": self.step_count, "verified": self.verified,
                       "completed": self.completed,
                       "not_verified": self.not_verified, "failed": self.failed,
                       "blocked": self.blocked, "cancelled": self.cancelled,
                       "skipped": self.skipped,
                       "awaiting_confirmation": self.awaiting_confirmation,
                       "superseded": self.superseded},
            "recovery_attempts": self.recovery_attempts,
            "replans": self.replans,
            "duration_seconds": round(self.duration_seconds, 3),
            "started_at": self.started_at, "finished_at": self.finished_at,
            "steps": list(self.steps),
            "error": self.error.to_dict() if self.error else None,
            "world_summary": dict(self.world_summary),
        }

    def report(self) -> str:
        """A truthful paragraph. No adjective that the steps did not earn."""
        lines = [f"Goal {self.goal_id[:8]}: {self.status.value} — {self.message}"]
        for step in self.steps:
            mark = "x" if step["status"] in ("VERIFIED", "COMPLETED") else "-"
            lines.append(f"  [{mark}] {step['step_id']}: {step['description']} "
                         f"→ {step['status']}{(' — ' + step['detail']) if step.get('detail') else ''}")
        counts = (f"{self.verified} verified, {self.completed} completed, "
                  f"{self.not_verified} not verified, {self.failed} failed, "
                  f"{self.blocked} blocked, {self.cancelled} cancelled")
        lines.append(f"  {counts} (of {self.step_count} steps)")
        if self.superseded or self.replans:
            lines.append(f"  {self.superseded} step(s) superseded by "
                         f"{self.replans} bounded replan(s)")
        return "\n".join(lines)


def _result_from_dict(goal_id: str, status: GoalStatus, raw: dict) -> GoalResult:
    """Read a persisted result back. Counts are nested under "counts"."""
    counts = raw.get("counts")
    counts = counts if isinstance(counts, dict) else raw
    number = lambda key: int(counts.get(key, 0) or 0)          # noqa: E731
    return GoalResult(
        goal_id=goal_id, status=status,
        message=str(raw.get("message", "")),
        steps=[s for s in (raw.get("steps") or []) if isinstance(s, dict)],
        step_count=number("steps"), verified=number("verified"),
        completed=number("completed"), not_verified=number("not_verified"),
        failed=number("failed"), blocked=number("blocked"),
        cancelled=number("cancelled"), skipped=number("skipped"),
        awaiting_confirmation=number("awaiting_confirmation"),
        superseded=number("superseded"),
        recovery_attempts=int(raw.get("recovery_attempts", 0) or 0),
        replans=int(raw.get("replans", 0) or 0),
        duration_seconds=float(raw.get("duration_seconds", 0.0) or 0.0),
        started_at=raw.get("started_at"), finished_at=raw.get("finished_at"),
        error=(TaskError.from_dict(raw["error"])
               if isinstance(raw.get("error"), dict) else None),
        world_summary=(dict(raw["world_summary"])
                       if isinstance(raw.get("world_summary"), dict) else {}))


# ── the goal ────────────────────────────────────────────────────────────────

@dataclass
class Goal:
    """A bounded user goal, the plan for it, and what happened."""

    goal_id: str = field(default_factory=new_goal_id)
    description: str = ""
    status: GoalStatus = GoalStatus.PENDING
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    plan: Optional[Plan] = None
    current_step: str = ""
    context: GoalContext = field(default_factory=GoalContext)
    result: Optional[GoalResult] = None
    error: Optional[TaskError] = None
    limits: Limits = field(default_factory=Limits)
    metadata: dict = field(default_factory=dict)
    #: Set by cancel(). Never replaced, so a late check sees a cancel that
    #: already happened — the same rule the Phase 2 task context follows.
    cancel_event: threading.Event = field(default_factory=threading.Event, repr=False)
    pause_requested: bool = False
    planning_attempts: int = 0
    #: Phase 6. How many times execution has been re-planned, and the bounded
    #: record of why. `replans` is what `Limits.max_replans` is compared against,
    #: so the ceiling survives a save/load cycle instead of resetting.
    replans: int = 0
    replan_history: list = field(default_factory=list)

    def short_id(self) -> str:
        return self.goal_id[:8]

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_GOAL_STATUSES

    @property
    def cancelled(self) -> bool:
        return self.cancel_event.is_set()

    def steps(self) -> list:
        return list(self.plan.steps) if self.plan else []

    def step(self, step_id: str) -> Optional[Step]:
        return self.plan.step(step_id) if self.plan else None

    def step_report(self) -> list:
        """One honest line per step, in plan order."""
        out = []
        for step in self.steps():
            detail = ""
            if step.result and step.result.error:
                detail = step.result.error.message
            elif step.result and step.result.message:
                detail = step.result.message
            elif step.notes:
                detail = step.notes[-1]
            out.append({"step_id": step.step_id, "description": step.description,
                        "action": step.action, "status": step.status.value,
                        "required": step.required, "verified": step.verified,
                        "attempts": step.attempts,
                        "recovery_attempts": step.recovery_attempts,
                        "task_id": step.task_id, "detail": detail[:300]})
        return out

    def to_dict(self) -> dict:
        """The persisted record. No screenshots, no credentials, no trees."""
        return {
            "goal_id": self.goal_id,
            "description": str(self.description)[:600],
            "status": self.status.value,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "current_step": self.current_step,
            "plan": self.plan.to_dict() if self.plan else None,
            "context": self.context.to_dict(),
            "result": self.result.to_dict() if self.result else None,
            "error": self.error.to_dict() if self.error else None,
            "limits": self.limits.to_dict(),
            "planning_attempts": self.planning_attempts,
            "replans": self.replans,
            "replan_history": list(self.replan_history),
            "metadata": scrub_sensitive(dict(self.metadata)),
        }

    @classmethod
    def from_dict(cls, raw: dict) -> "Goal":
        """Strict on purpose, like Task.from_dict.

        A goal record that cannot be read is not repaired into a plausible
        goal. A goal that was mid-flight when NEO stopped comes back as
        INTERRUPTED/FAILED, because Phase 5 has no resumable execution.
        """
        if not isinstance(raw, dict):
            raise ValueError("goal record must be an object")
        goal_id = str(raw.get("goal_id", "")).strip()
        if not goal_id:
            raise ValueError("goal_id is required")
        status_raw = str(raw.get("status", GoalStatus.PENDING.value)).upper()
        try:
            status = GoalStatus(status_raw)
        except ValueError as e:
            raise ValueError(f"unknown goal status {status_raw!r}") from e
        context_raw = raw.get("context")
        context = GoalContext()
        if isinstance(context_raw, dict):
            context = GoalContext(
                goal_id=str(context_raw.get("goal_id", goal_id)),
                description=str(context_raw.get("description", "")),
                current_step=str(context_raw.get("current_step", "")),
                entries=(dict(context_raw["entries"])
                         if isinstance(context_raw.get("entries"), dict) else {}),
                step_summaries=[s for s in (context_raw.get("step_summaries") or [])
                                if isinstance(s, dict)],
                recovery_attempts=int(context_raw.get("recovery_attempts", 0) or 0),
                task_ids=[str(t) for t in (context_raw.get("task_ids") or [])],
            )
        result_raw = raw.get("result")
        error_raw = raw.get("error")
        return cls(
            goal_id=goal_id,
            description=str(raw.get("description", "")),
            status=status,
            created_at=float(raw.get("created_at") or 0.0),
            started_at=raw.get("started_at"),
            completed_at=raw.get("completed_at"),
            plan=(Plan.from_dict(raw["plan"])
                  if isinstance(raw.get("plan"), dict) else None),
            current_step=str(raw.get("current_step", "")),
            context=context,
            result=(_result_from_dict(goal_id, status, result_raw)
                    if isinstance(result_raw, dict) else None),
            error=(TaskError.from_dict(error_raw) if isinstance(error_raw, dict) else None),
            limits=Limits(),
            planning_attempts=int(raw.get("planning_attempts", 0) or 0),
            replans=int(raw.get("replans", 0) or 0),
            replan_history=[dict(r) for r in (raw.get("replan_history") or [])
                            if isinstance(r, dict)][-8:],
            metadata=(dict(raw["metadata"])
                      if isinstance(raw.get("metadata"), dict) else {}),
        )
