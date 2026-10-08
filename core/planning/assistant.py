"""
The assistant pipeline — one call from a sentence to a truthful answer.

WHY THIS EXISTS
    Everything Phase 6 added is reachable, but nothing yet ties it together for
    the one caller that matters: a conversation. "Open Notepad and write my
    notes" arrives as text, from the HUD or the keyboard, and something has to
    turn it into a goal, plan it, run it, and say what actually happened.

    `AssistantGoals.submit()` is that something, and it is deliberately a plain
    function with three dependencies. It knows nothing about Qt, nothing about
    Gemini Live, and nothing about threads. That is what makes it callable from
    the voice pipeline, the text pipeline, a test, or a script — and it is why
    Part 11's requirement ("make the new planner callable from the same
    assistant pipeline") is satisfied without touching the voice code at all.

WHAT IT DOES NOT DO
    It does not decide whether a request should run. It does not speak. It does
    not retry. It does not swallow a refusal. When planning is refused, the
    refusal is the answer, in the shared error taxonomy, with the model's own
    last complaint attached.

VOICE
    The voice pipeline is documented as NOT VERIFIED end-to-end: NEO listens and
    transcribes, and its text responses are generated, but the automatic
    handoff from a generated response to TTS playback has not been proven. This
    class is callable from that pipeline once it is repaired, and nothing in it
    assumes anything about how the text arrived.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from core.capabilities import PIPELINE_ACTION
from core.events import Event, EventBus, EventType
from core.goals.limits import Limits
from core.goals.models import Goal, GoalResult, GoalStatus
from core.planning import model_planner as _model_planner
from core.planning import memory_context as _memory
from core.planning import workflows as _workflows
from core.task_models import ErrorKind, TaskError


@dataclass
class Reply:
    """What to say, and what actually happened. The two are not the same."""

    goal: Optional[Goal] = None
    result: Optional[GoalResult] = None
    intent: Optional[dict] = None
    planned: bool = False
    ran: bool = False
    text: str = ""
    status: str = ""
    verified: bool = False
    refused: str = ""
    replans: int = 0

    @property
    def succeeded(self) -> bool:
        return bool(self.result and self.result.ok)

    def to_dict(self) -> dict:
        return {"goal_id": self.goal.goal_id if self.goal else "",
                "planned": self.planned, "ran": self.ran, "status": self.status,
                "verified": self.verified, "refused": self.refused,
                "replans": self.replans, "text": self.text,
                "result": self.result.to_dict() if self.result else None}

    def summary(self) -> str:
        """One paragraph a person can act on, using only earned words."""
        if self.refused:
            return f"NEO could not plan that: {self.refused}"
        if not self.result:
            return self.text or "Nothing was run."
        counts = (f"{self.result.verified} verified, "
                  f"{self.result.completed} completed, "
                  f"{self.result.not_verified} not verified, "
                  f"{self.result.failed} failed")
        return f"{self.text or self.result.message} ({self.result.status.value}; {counts})"


class AssistantGoals:
    """Sentence → bounded goal → validated plan → execution → honest answer.

    Thread-safe at the level that matters: it creates one goal per request and
    does not hold mutable per-request state, so two submissions cannot see each
    other's context. `submit` may be called from any thread; the bounded
    proposer call inside it is off-thread already, and the executor owns its
    own goal lock.
    """

    def __init__(self, executor: Any, planner: Any = None,
                 actions: Any = None, plugins: Any = None,
                 proposer: Optional[Callable[..., Any]] = None,
                 memory: Any = None, limits: Optional[Limits] = None,
                 bus: Optional[EventBus] = None,
                 logger: Optional[Callable[[str], None]] = None,
                 notify: Optional[Callable[[str], None]] = None):
        self.executor = executor
        self.actions = actions
        self.plugins = plugins
        self.bus = bus if bus is not None else getattr(executor, "bus", None) or EventBus()
        self._logger = logger or (lambda _msg: None)
        self._notify = notify or (lambda _msg: None)
        self.limits = (limits or getattr(executor, "limits", None) or Limits()).clamped()
        self.memory = memory if memory is not None else _memory.from_memory_manager()
        self.planner = planner or getattr(executor, "planner", None)
        if self.planner is not None:
            self.planner._actions = self.planner._actions or actions
            self.planner._plugins = self.planner._plugins or plugins
        self.model_planner = _model_planner.ModelPlanner(
            planner=self.planner, actions=actions, plugins=plugins,
            proposer=proposer, limits=self.limits, memory=self.memory,
            bus=self.bus, logger=logger)
        #: One replanner for every goal this object creates, so the executor
        #: and the model planner cannot disagree about what a bounded replan is.
        self.replanner = self._replan
        self._lock = threading.Lock()

    # -- the one call -------------------------------------------------------

    def submit(self, sentence: str, run: bool = True,
               workflow: str = "", params: Optional[dict] = None) -> Reply:
        """Turn a sentence into a goal and, by default, run it.

        `workflow` and `params` bypass natural-language planning for a caller
        that already knows which recipe it wants — the voice pipeline's "run
        workflow B" path, a test, a script. Everything still goes through
        `Planner.build()`, so the fast route has no privilege the slow one does
        not.
        """
        text = str(sentence or "").strip()
        if not text and not workflow:
            return Reply(status="NOT_PLANNED", refused="there was nothing to plan",
                         text="NEO needs a request before it can do anything.")
        if not text:
            # A caller that named a workflow has already said what it wants;
            # the parameters are the sentence as far as the goal record goes.
            text = f"workflow: {workflow} {sorted((params or {}).keys())}"

        goal = self.executor.create_goal(text,
                                         metadata={"requested_by": "assistant",
                                                   "capability": PIPELINE_ACTION})

        if workflow:
            outcome = self._plan_by_workflow(goal, workflow, dict(params or {}))
        else:
            outcome = self.model_planner.plan(goal)

        reply = Reply(goal=goal, planned=outcome.ok,
                      intent=(outcome.intent.to_dict() if outcome.intent else None),
                      refused=outcome.refused,
                      status=(GoalStatus.READY.value if outcome.ok
                              else GoalStatus.PLANNING_FAILED.value))

        if not outcome.ok:
            goal.status = GoalStatus.PLANNING_FAILED
            goal.completed_at = self.executor._clock()
            goal.error = _model_planner.refusal_to_error(outcome) or TaskError(
                message=outcome.refused, kind=ErrorKind.INVALID_REQUEST)
            goal.result = self.executor._result(
                goal, message=f"no supported plan: {outcome.refused}")
            reply.text = reply.summary()
            self.bus.emit(Event(type=EventType.GOAL_FAILED, goal_id=goal.goal_id,
                                status=goal.status.value,
                                data={"refused": outcome.refused}))
            self._notify(f"Could not plan: {outcome.refused}")
            return reply

        # The executor owns planning state; tell it the plan is validated and
        # attach the bounded replanner this object owns.
        self.executor.replanner = self.replanner
        self.executor.limits = self.limits
        reply.text = (f"Planned {len(outcome.plan)} step(s) for "
                      f"'{goal.description[:80]}'"
                      + (" using the planner model." if outcome.used_model
                         else " from what the request plainly contained."))
        if not run:
            self._notify(reply.text)
            return reply

        result = self.executor.run(goal)
        reply.result = result
        reply.ran = True
        reply.verified = result.verified > 0 or result.status is GoalStatus.COMPLETED
        reply.status = result.status.value
        reply.replans = goal.replans
        reply.text = reply.summary()
        self._notify(reply.text)
        return reply

    # -- the two planning routes -------------------------------------------

    def _plan_by_workflow(self, goal: Goal, workflow: str,
                          params: dict) -> _model_planner.PlanningOutcome:
        """Plan from a named recipe. Same gates as every other route."""
        builder = _workflows.WORKFLOWS.get(str(workflow))
        if builder is None:
            return _model_planner.PlanningOutcome(
                goal=goal, source=f"workflow:{workflow}",
                refused=(f"'{workflow}' is not a workflow NEO knows. Available: "
                         f"{', '.join(_workflows.names())}."),
                reason_kind=ErrorKind.ACTION_NOT_SUPPORTED.value)
        outcome = _model_planner.PlanningOutcome(goal=goal,
                                                 source=f"workflow:{workflow}")
        try:
            steps = builder(params)
            self.executor.plan_goal(
                goal, raw_steps=steps, source=f"workflow:{workflow}")
            if goal.plan is None:
                outcome.refused = (goal.error.message if goal.error
                                   else "the workflow plan was rejected")
                outcome.reason_kind = (
                    goal.error.kind.value if goal.error else
                    ErrorKind.INVALID_REQUEST.value)
            else:
                outcome.plan = goal.plan
                outcome.candidates = 1
        except Exception as e:
            outcome.refused = str(e)
            outcome.reason_kind = getattr(getattr(e, "kind", None), "value", "")
        return outcome

    def _replan(self, goal: Goal, step, view: dict) -> Optional[list]:
        """The executor's bounded replan seam, backed by the model planner.

        Returns candidate steps or `None`. `None` means "nothing safe is left",
        which the executor reports as the exact reason the goal stopped.
        """
        if goal.cancel_event.is_set():
            return None
        return self.model_planner.replan(goal, view)

    # -- describing what it can do -----------------------------------------

    def capabilities(self) -> dict:
        """What this pipeline can currently do, read from the live registries."""
        from core.capabilities import build_catalogue

        return {"workflows": _workflows.names(),
                "capabilities": build_catalogue(self.actions, self.plugins).to_dict(),
                "limits": self.limits.to_dict(),
                "memory_available": self.memory.reader is not None}