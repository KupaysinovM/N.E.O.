"""
The goal executor — the loop that runs a plan and reports what really happened.

WHAT HAPPENS, IN ORDER, FOR EVERY STEP
    resolve arguments → check dependencies → confirm if asked → execute through
    the Phase 2 layer → observe → verify → record → continue / recover / stop

There is no ordering shortcut. A step whose dependencies are not in a
successful state does not run, and a step whose execution reported SUCCESS but
whose effect could not be observed is NOT_VERIFIED — never complete, and never
followed by the steps that depend on it.

WHAT THE EXECUTOR IS NOT ALLOWED TO DO
    It does not call an action. It builds an `ExecutionRequest` and hands it to
    the existing `ExecutionLayer`, which is the only path from a request to a
    registry to a real capability. It does not bypass the confirmation gate, it
    does not decide what a step's effect should be verified against (that comes
    from the action's Phase 4 contract), and it does not invent a new operation
    when something fails. Recovery re-observes and repeats the *same* step, a
    bounded number of times, and never rewrites the plan.

WHAT CANNOT BE INTERRUPTED
    Neither can Phase 2 stop a Windows call that is already inside the OS, and
    Phase 5 does not pretend otherwise. Cancelling a goal sets the goal's cancel
    event, cancels the task in flight through the Phase 2 boundary, and refuses
    to start anything new. Pausing refuses to start anything new and says so;
    a step already running finishes first. Both are cooperative, and the goal
    report says which happened.

THE LOOP IS FINITE
    Steps run at most `limits.max_steps` times, each at most
    `limits.max_step_attempts` times, recoveries at most per step and per goal,
    verification at its own bounded timeout, and the whole run at
    `limits.max_goal_seconds`. There is no `while not complete` here.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Callable, Optional

from core.events import Event, EventBus, EventType
from core.execution import (
    ExecStatus,
    ExecutionLayer,
    ExecutionRequest,
    ExecutionResult,
)
from core.goals.limits import Limits
from core.goals.models import (
    Attempt,
    Goal,
    GoalResult,
    GoalStatus,
    Plan,
    Step,
    StepStatus,
    TERMINAL_GOAL_STATUSES,
    new_goal_id,
    scrub_sensitive,
)
from core.goals.planner import Planner, PlanRejected
from core.goals.recovery import classify, is_transient
from core.task_models import ErrorKind, TaskError, TaskStatus
from core.verification import verifier as _verifier
from core.verification import world as _world


#: How many `{"$from": ...}` references one argument tree may contain. Mirrors
#: `core.goals.limits.DEFAULT_MAX_REFERENCES`, and exists here only so the walk
#: in `_referenced_keys` is bounded even on a tree a plan did not have validated.
_MAX_REFERENCE_WALK = 64


def _referenced_keys(value: Any, found: Optional[set] = None, budget: int = _MAX_REFERENCE_WALK) -> set:
    """Every `{"$from": key}` a step's raw arguments name, at any depth.

    This walks the *unresolved* arguments on purpose: once a step has resolved
    them the reference is gone and there is nothing left to keep alive.
    """
    found = set() if found is None else found
    if budget <= 0:
        return found
    if isinstance(value, dict):
        if "$from" in value:
            found.add(str(value["$from"]))
            return found
        for item in value.values():
            _referenced_keys(item, found, budget - 1)
    elif isinstance(value, list):
        for item in value:
            _referenced_keys(item, found, budget - 1)
    return found


class GoalExecutor:
    """Runs goals. One instance per NEO process; goals are keyed by id."""

    def __init__(self, manager: Any, layer: ExecutionLayer,
                 planner: Optional[Planner] = None,
                 bus: Optional[EventBus] = None,
                 history: Any = None,
                 limits: Optional[Limits] = None,
                 logger: Optional[Callable[[str], None]] = None,
                 notify: Optional[Callable[[str], None]] = None,
                 world_capture: Optional[Callable[..., Any]] = None,
                 replanner: Optional[Callable[..., Any]] = None,
                 clock: Callable[[], float] = time.time):
        self.manager = manager
        self.layer = layer
        self.limits = (limits or Limits()).clamped()
        self.planner = planner or Planner(manager=None, limits=self.limits, logger=logger)
        self.bus = bus if bus is not None else getattr(manager, "bus", None) or EventBus()
        self.history = history
        self._logger = logger or (lambda _msg: None)
        self._notify = notify or (lambda _msg: None)
        self._clock = clock
        # Injectable so a unit test never reads the real desktop, and so the
        # capture stays one bounded read rather than a polling loop.
        self._world_capture = world_capture or _world.capture
        #: Phase 6. Optional bounded re-planner: `replanner(goal, step, view)`
        #: returns candidate raw steps for what to try next, or None. It is the
        #: same shape of seam `Planner.propose` has always had — an outside
        #: reasoner whose output must survive `Planner.build()` — and `None` is
        #: a perfectly good answer, meaning "there is nothing safe left to try".
        self.replanner = replanner
        self._lock = threading.RLock()
        self._goals: dict = {}
        self._active_task: dict = {}      # goal_id → task id currently executing
        self.persistence_error: str = ""

    # ── goals ───────────────────────────────────────────────────────────────

    def create_goal(self, description: str, metadata: Optional[dict] = None) -> Goal:
        goal = Goal(goal_id=new_goal_id(), description=str(description or ""),
                    limits=self.limits, created_at=self._clock(),
                    metadata=dict(metadata or {}))
        goal.context.goal_id = goal.goal_id
        goal.context.description = goal.description
        goal.context.max_items = self.limits.max_context_items
        goal.context.max_chars = self.limits.max_result_chars
        with self._lock:
            self._goals[goal.goal_id] = goal
        self._emit(EventType.GOAL_CREATED, goal, data={"description": goal.description[:200]})
        self._persist()
        return goal

    def get_goal(self, goal_id: str) -> Optional[Goal]:
        with self._lock:
            return self._goals.get(goal_id)

    def list_goals(self) -> list:
        with self._lock:
            return list(self._goals.values())

    def plan_goal(self, goal: Goal, raw_steps: Optional[list] = None,
                  template: Optional[str] = None,
                  template_params: Optional[dict] = None,
                  proposer: Optional[Callable[[int], Any]] = None,
                  source: str = "explicit") -> Goal:
        """Attach a validated plan, or leave the goal failed and say why."""
        goal.status = GoalStatus.PLANNING
        goal.planning_attempts += 1
        self._emit(EventType.GOAL_PLANNING, goal)
        try:
            if raw_steps is not None:
                plan = self.planner.build(goal.goal_id, raw_steps, source=source)
            elif template is not None:
                plan = self.planner.template(template, goal.goal_id, template_params)
            elif proposer is not None:
                plan = self.planner.propose(goal.goal_id, proposer)
            else:
                raise PlanRejected(
                    "no plan was supplied: pass explicit steps, a recipe name, "
                    "or a proposer", kind=ErrorKind.INVALID_REQUEST)
        except PlanRejected as e:
            goal.plan = None
            goal.error = e.to_error()
            goal.status = (GoalStatus.NOT_SUPPORTED
                           if e.kind is ErrorKind.ACTION_NOT_SUPPORTED
                           else GoalStatus.PLANNING_FAILED)
            goal.completed_at = self._clock()
            goal.result = self._result(goal, message=str(e))
            self._emit(EventType.GOAL_FAILED, goal, status=goal.status.value,
                       data={"error": str(e), "kind": e.kind.value})
            self._persist()
            return goal

        goal.plan = plan
        goal.status = GoalStatus.READY
        goal.error = None
        self._emit(EventType.GOAL_PLANNED, goal,
                   data={"steps": len(plan), "source": plan.source})
        self._persist()
        return goal

    # ── lifecycle ───────────────────────────────────────────────────────────

    def pause(self, goal: Goal) -> Goal:
        """Stop after the current step. Nothing new starts.

        This is the Phase 2 pause contract: a step already inside Windows is not
        interrupted, because nothing here can interrupt it honestly.
        """
        goal.pause_requested = True
        if goal.status is GoalStatus.RUNNING:
            goal.status = GoalStatus.PAUSED
            self._emit(EventType.GOAL_PAUSED, goal,
                       data={"note": "no new step will start; a step already "
                                    "running is finishing"})
        self._persist()
        return goal

    def resume(self, goal: Goal) -> Goal:
        """Allow the goal to continue, or refuse and say why."""
        if goal.status is GoalStatus.CANCELLED or goal.cancel_event.is_set():
            return goal
        goal.pause_requested = False
        if goal.status is GoalStatus.PAUSED:
            goal.status = GoalStatus.READY
            self._emit(EventType.GOAL_RESUMED, goal)
        self._resolve_awaiting_confirmation(goal)
        self._persist()
        return goal

    def cancel(self, goal: Goal, reason: str = "") -> Goal:
        """Cancel the goal and everything still open under it."""
        already = goal.cancel_event.is_set()
        goal.cancel_event.set()
        goal.pause_requested = False
        with self._lock:
            task_id = self._active_task.get(goal.goal_id, "")
        in_flight = bool(task_id)
        if in_flight and self.manager is not None:
            # The Phase 2 boundary, used as-is: the flag is set and the running
            # action is told, not killed.
            try:
                if (self.manager.get_task(task_id) is not None
                        and not self.manager.get_task(task_id).is_terminal):
                    self.manager.cancel_task(task_id)
            except Exception as e:
                self._logger(f"[Goals] cancel could not reach task {task_id[:8]}: {e}")
        for step in goal.steps():
            if not step.is_terminal:
                step.status = StepStatus.CANCELLED
                step.finished_at = step.finished_at or self._clock()
                step.note(reason or "the goal was cancelled")
        goal.status = GoalStatus.CANCELLED
        goal.completed_at = self._clock()
        goal.error = TaskError(message=reason or "Goal was cancelled.",
                               kind=ErrorKind.TASK_CANCELLED)
        goal.result = self._result(goal, message=reason or "Goal was cancelled.")
        if not already:
            self._emit(EventType.GOAL_CANCELLED, goal,
                       data={"reason": reason or "cancelled",
                             "execution_in_flight": in_flight,
                             "note": ("a running action cannot be interrupted by NEO; "
                                      "it was asked to stop and told")})
            self._notify(f"Goal {goal.short_id()} cancelled.")
        self._persist()
        return goal

    # ── the run ─────────────────────────────────────────────────────────────

    def run(self, goal: Goal) -> GoalResult:
        """Run the plan from wherever it got to. Always returns a result.

        `run()` is resumable in the narrow, honest sense: calling it again
        continues a goal that paused or is waiting on a confirmation. It is not
        crash-resume — a goal whose process died is marked INTERRUPTED on load
        (see core/goals/store.py) and is never continued from a file.
        """
        if goal.plan is None:
            if not goal.is_terminal:
                # Planning already refused this goal and said why; overwriting
                # that with a vaguer failure would lose the actual reason.
                goal.status = GoalStatus.PLANNING_FAILED
                goal.completed_at = self._clock()
                goal.error = goal.error or TaskError(
                    message="This goal has no plan, so nothing can be executed.",
                    kind=ErrorKind.INVALID_REQUEST)
                self._emit(EventType.GOAL_FAILED, goal, data={"error": "no plan"})
            return self._finish(goal, message=goal.error.message
                                if goal.error else "the goal was never planned")

        if goal.cancelled:
            return goal.result or self._result(goal, message="the goal was cancelled")

        self._resolve_awaiting_confirmation(goal)
        if goal.status is GoalStatus.CANCELLED or goal.is_terminal:
            return goal.result or self._result(goal, message=goal.status.value)
        if any(s.status is StepStatus.AWAITING_CONFIRMATION for s in goal.steps()):
            # Still genuinely on screen: the gate owns the next word. The goal
            # says so rather than guessing, and rather than parking invisibly.
            goal.status = GoalStatus.AWAITING_CONFIRMATION
            return self._finish(goal, message="waiting for the user's confirmation")

        goal.status = GoalStatus.RUNNING
        if goal.started_at is None:
            goal.started_at = self._clock()
        deadline = max(self._clock(), goal.started_at) + self.limits.max_goal_seconds
        self._emit(EventType.GOAL_STARTED, goal,
                   data={"steps": len(goal.plan), "deadline_seconds":
                         self.limits.max_goal_seconds})

        stopped_because = ""
        # Phase 6: an index loop, not `for step in goal.plan.steps`. A bounded
        # replan appends to the plan, and a plan a run loop cannot see grow is
        # a plan that silently stops mid-goal. Everything else about the loop is
        # Phase 5's.
        position = 0
        while position < len(goal.plan.steps):
            step = goal.plan.steps[position]
            position += 1
            if step.is_terminal:
                continue

            if goal.cancel_event.is_set():
                stopped_because = "the goal was cancelled"
                self._block_remaining(goal, step, StepStatus.CANCELLED, stopped_because)
                goal.status = GoalStatus.CANCELLED
                break

            if goal.pause_requested:
                stopped_because = "the goal was paused"
                goal.status = GoalStatus.PAUSED
                break

            if self._clock() > deadline:
                stopped_because = (f"the goal ran for longer than its limit of "
                                   f"{self.limits.max_goal_seconds:.0f}s")
                self._block_remaining(goal, step, StepStatus.BLOCKED, stopped_because)
                goal.status = GoalStatus.BLOCKED
                goal.error = TaskError(message=stopped_because, kind=ErrorKind.TIMEOUT)
                break

            blocker = self._unsatisfied_dependency(goal, step)
            if blocker is not None:
                step.status = StepStatus.BLOCKED
                step.finished_at = self._clock()
                step.note(f"blocked by {blocker}")
                self._emit(EventType.STEP_BLOCKED, goal, step=step,
                           data={"blocked_by": blocker})
                self._block_remaining(goal, step, StepStatus.BLOCKED,
                                      f"the goal stopped at {step.step_id}")
                goal.status = GoalStatus.BLOCKED
                stopped_because = f"{blocker} did not succeed"
                break

            step.status = StepStatus.READY
            self._emit(EventType.STEP_STARTED, goal, step=step,
                       data={"action": step.action, "depends_on": list(step.depends_on)})
            self._run_step(goal, step, deadline)

            if step.status is StepStatus.AWAITING_CONFIRMATION:
                # The gate owns the next word, not the goal loop. The goal waits
                # in a state that says so, instead of pretending to be finished
                # or parking invisibly.
                self._block_remaining(goal, step, StepStatus.BLOCKED,
                                      f"{step.step_id} is waiting for the user")
                goal.status = GoalStatus.AWAITING_CONFIRMATION
                stopped_because = f"{step.step_id} needs the user's confirmation"
                self._persist()
                return self._finish(goal, message=stopped_because)

            if step.status is StepStatus.CANCELLED:
                self._block_remaining(goal, step, StepStatus.CANCELLED,
                                      "the goal was cancelled")
                goal.status = GoalStatus.CANCELLED
                stopped_because = "the goal was cancelled"
                break

            if not step.succeeded:
                if not step.required:
                    # An optional step is allowed to fail. Its own dependents,
                    # if it has any, are still blocked by the dependency check.
                    continue
                # Phase 6: before giving up, one bounded look at whether there
                # is a *supported* way forward from what is actually on screen.
                # A refusal here is not a delay — it means the goal stops with
                # the exact reason the replanner could not produce a safe plan.
                if self._try_replan(goal, step, deadline):
                    continue
                self._block_remaining(
                    goal, step, StepStatus.BLOCKED,
                    f"the goal stopped at {step.step_id} ({step.status.value})")
                goal.status = self._goal_status_for(step)
                stopped_because = self._stop_message(step)
                goal.error = self._error_for(step)
                break

            self._persist()

        if goal.status is GoalStatus.RUNNING:
            goal.status = self._overall_status(goal)
            if goal.status is GoalStatus.COMPLETED:
                stopped_because = ""
                goal.completed_at = self._clock()
                self._emit(EventType.GOAL_COMPLETED, goal)
                self._notify(f"Goal {goal.short_id()} completed.")
            else:
                stopped_because = stopped_because or self._stop_message_for_goal(goal)
        elif goal.status in (GoalStatus.CANCELLED, GoalStatus.PAUSED):
            if goal.status is GoalStatus.CANCELLED:
                goal.completed_at = goal.completed_at or self._clock()

        return self._finish(goal, message=stopped_because)

    # ── one step ────────────────────────────────────────────────────────────

    def _run_step(self, goal: Goal, step: Step, deadline: float) -> Attempt:
        """Execute one step, with its bounded retries. Always returns an attempt."""
        step.status = StepStatus.RUNNING
        step.started_at = step.started_at or self._clock()
        goal.current_step = step.step_id
        goal.context.current_step = step.step_id
        step.task_id = ""
        step.result = None
        self._pin_live_references(goal)

        try:
            arguments = self._resolve_arguments(goal, step)
        except PlanRejected as e:
            step.status = StepStatus.FAILED
            step.finished_at = self._clock()
            step.result = Attempt(number=1, status=ExecStatus.FAILED.value,
                                  final_status=ExecStatus.FAILED.value,
                                  message=str(e), error=e.to_error(),
                                  started_at=step.started_at, finished_at=step.started_at)
            step.history.append(step.result)
            step.note(str(e))
            self._emit(EventType.STEP_FAILED, goal, step=step,
                       data={"error": str(e), "kind": e.kind.value})
            return step.result
        step.resolved_arguments = dict(arguments)

        max_attempts = min(step.retry.attempts, self.limits.max_step_attempts)
        attempt_number = 0
        recovering = False

        while attempt_number < max_attempts:
            if goal.cancel_event.is_set() or self._clock() > deadline:
                break
            attempt_number += 1
            step.attempts = attempt_number
            recovering = attempt_number > 1

            if recovering:
                step.recovery_attempts += 1
                goal.context.recovery_attempts += 1
                self._emit(EventType.STEP_RECOVERY_STARTED, goal, step=step,
                           data={"attempt": attempt_number,
                                 "recovery_attempts": step.recovery_attempts})
                self._reobserve(goal)
                if step.re_resolve:
                    self._re_resolve_window(goal, step)

            attempt = self._attempt(goal, step, attempt_number, recovering)
            step.result = attempt
            step.history.append(attempt)
            self._record_in_context(goal, step, attempt)

            if step.status in (StepStatus.VERIFIED, StepStatus.COMPLETED,
                               StepStatus.AWAITING_CONFIRMATION):
                break

            allowed, why = step.retry.allows(self._error_kind_for(step), attempt_number)
            room = (step.recovery_attempts < self.limits.max_recovery_attempts
                    and goal.context.recovery_attempts <= self.limits.max_recovery_total)
            repeatable = step.status in (StepStatus.NOT_VERIFIED, StepStatus.FAILED)
            if not (allowed and room and repeatable):
                if allowed and not room:
                    why = "this goal has used its bounded recovery attempts"
                step.note(f"not retried: {why}")
                break
            if step.retry.delay:
                time.sleep(min(step.retry.delay, 1.0))

        step.finished_at = step.finished_at or self._clock()
        if step.status is StepStatus.PENDING:
            step.status = StepStatus.BLOCKED
            step.note("the step never ran")
        self._emit(self._step_event(step.status), goal, step=step,
                   data={"status": step.status.value, "attempts": step.attempts})
        if step.recovery_attempts:
            self._emit(EventType.STEP_RECOVERY_COMPLETED, goal, step=step,
                       data={"recovery_attempts": step.recovery_attempts})
        self._persist()
        return step.result or Attempt()

    def _attempt(self, goal: Goal, step: Step, number: int, recovering: bool) -> Attempt:
        """One execution through the Phase 2 layer, plus its verification."""
        task = self.manager.create_task(
            user_request=step.description or step.action,
            metadata={"goal_id": goal.goal_id, "step_id": step.step_id,
                      "plan_source": goal.plan.source if goal.plan else "",
                      "attempt": number, "recovery": recovering})
        task_id = task.task_id
        step.task_id = task_id
        goal.context.add_task(task_id)

        request = ExecutionRequest(
            action=step.action, arguments=dict(step.resolved_arguments or step.arguments),
            task_id=task_id, step=step.description or step.action, requested_by="goal")
        self.manager.set_action(task_id, step.action, step.description)

        with self._lock:
            self._active_task[goal.goal_id] = task_id
        started = self._clock()
        try:
            result = self.layer.execute(request, self.manager.context_for(task_id))
        finally:
            with self._lock:
                self._active_task.pop(goal.goal_id, None)

        attempt = self._classify(goal, step, result, number, recovering, started)
        self._maybe_plan_verification(goal, step, result, attempt)
        self._apply_outcome(goal, step, result, attempt)
        return attempt

    def _classify(self, goal: Goal, step: Step, result: ExecutionResult, number: int,
                  recovering: bool, started: float) -> Attempt:
        """Turn one ExecutionResult into an attempt and a step status.

        The branch that matters is the one Phase 4 exists for: a call that
        reported SUCCESS whose effect could not be observed is NOT_VERIFIED, and
        NOT_VERIFIED is not a successful status here either.
        """
        status = result.outcome                      # final_status, not raw status
        verified = result.verified
        verification_status = result.verification_status or ""
        error = result.error

        if status is ExecStatus.NOT_VERIFIED:
            # The call ran and reported success; the effect could not be seen.
            # This is the whole point of Phase 4 arriving at Phase 5: it is not
            # a failure, and it is emphatically not a success.
            step.status = StepStatus.NOT_VERIFIED
            step.note(result.message.splitlines()[-1][:200] if result.message
                      else "the expected state was not observed")
        elif status is ExecStatus.SUCCESS and verified:
            step.status = StepStatus.VERIFIED
        elif status is ExecStatus.SUCCESS:
            if verification_status == "NOT_AVAILABLE":
                step.status = StepStatus.COMPLETED
                step.note("ran with nothing observable to verify")
            else:
                step.status = StepStatus.NOT_VERIFIED
                step.note("the expected state was not observed")
        elif status is ExecStatus.CANCELLED:
            step.status = StepStatus.CANCELLED
        elif status is ExecStatus.REQUIRES_CONFIRMATION:
            step.status = StepStatus.AWAITING_CONFIRMATION
            step.note("parked behind the confirmation gate; nothing has been done yet")
        else:
            step.status = StepStatus.FAILED

        step.verification = result.verification
        return Attempt(
            number=number, task_id=result.task_id or step.task_id,
            status=result.status.value, final_status=status.value,
            verification_status=verification_status, verified=verified,
            recovery=recovering, message=result.message[: self.limits.max_result_chars],
            error=error, started_at=started, finished_at=self._clock(),
            data={"invoked": bool(result.data.get("invoked", False)),
                  "recovery": recovering})

    def _maybe_plan_verification(self, goal: Goal, step: Step, result: ExecutionResult,
                                 attempt: Attempt) -> None:
        """Verify a plan-declared expectation the execution layer did not check.

        Only reachable when the action declares no contract of its own: the
        execution layer already verified everything the action asked for, and
        this adds the goal layer's own check on top rather than replacing one.
        """
        expectation = step.expected
        if expectation is None or step.expected_by != "plan":
            return
        if result.status is not ExecStatus.SUCCESS:
            return

        self._emit(EventType.VERIFICATION_STARTED, self._goal_task(goal, step),
                   step.action, data={"expectation": expectation.to_dict(),
                                      "declared_by": "plan"})
        outcome = _verifier.verify(expectation, cancel_event=goal.cancel_event)
        payload = outcome.to_dict()
        attempt.verification_status = outcome.status.value
        step.verification = payload
        self._remember_observations(goal, step, outcome)

        if outcome.status is _verifier.Status.VERIFIED:
            attempt.verified = True
            step.status = StepStatus.VERIFIED
            step.note(outcome.reason[:200])
            self._emit(EventType.VERIFICATION_COMPLETED, self._goal_task(goal, step),
                       step.action, status=outcome.status.value, data=payload)
        elif outcome.status is _verifier.Status.CANCELLED:
            step.status = StepStatus.CANCELLED
            step.note("the wait was cancelled before anything was observed")
            self._emit(EventType.VERIFICATION_FAILED, self._goal_task(goal, step),
                       step.action, status=outcome.status.value, data=payload)
        elif outcome.status is _verifier.Status.NOT_AVAILABLE:
            # The check had nothing to look at. The execution's own SUCCESS
            # stands, and the step is recorded as unverified rather than passed.
            if step.status is StepStatus.NOT_VERIFIED:
                step.status = StepStatus.COMPLETED
                step.note("nothing observable to verify")
            self._emit(EventType.VERIFICATION_COMPLETED, self._goal_task(goal, step),
                       step.action, status=outcome.status.value, data=payload)
        else:
            step.status = StepStatus.NOT_VERIFIED
            step.note(outcome.describe()[:200])
            self._emit(EventType.VERIFICATION_FAILED, self._goal_task(goal, step),
                       step.action, status=outcome.status.value, data=payload)

    def _apply_outcome(self, goal: Goal, step: Step, result: ExecutionResult,
                       attempt: Attempt) -> None:
        """Tie the attempt to the step by recording what it actually reported."""
        if result.status is ExecStatus.SUCCESS and result.data.get("handle"):
            attempt.data["handle"] = result.data["handle"]
        self._remember_execution(goal, step, result)

    # ── arguments, world state, observations ─────────────────────────────────

    def _pin_live_references(self, goal: Goal) -> None:
        """Keep every value a step that has not finished still names.

        The context is bounded and evicts the oldest entry first, which is the
        right order for *observations*. A `{"$from": key}` reference is not an
        observation, though — it is a dependency. Evicting one turns a step
        whose earlier work succeeded into a failure about arguments, so the
        keys any unfinished step still names are pinned and the bound is
        enforced against everything else.
        """
        needed: set = set()
        for other in goal.steps():
            if other.status in (StepStatus.PENDING, StepStatus.READY,
                                StepStatus.RUNNING):
                needed |= _referenced_keys(other.arguments)
        goal.context.pinned = needed

    def _resolve_arguments(self, goal: Goal, step: Step) -> dict:
        """Substitute `{"$from": "key"}` from what the goal observed.

        This is how a later step uses the state an earlier one produced: the
        handle that `launch_app` reported is handed to `focus_window` by name.
        A reference that was never observed is a failure, never a silent empty
        value — an unfilled argument is exactly how a step ends up doing nothing.
        """
        return self._substitute(dict(step.arguments), goal.context, f"step {step.step_id}")

    def _substitute(self, value: Any, context, path: str, depth: int = 0) -> Any:
        if depth > self.limits.max_argument_depth:
            raise PlanRejected(f"{path} nests too deeply to resolve")
        if isinstance(value, dict):
            if "$from" in value:
                key = str(value["$from"])
                if not context.knows(key):
                    raise PlanRejected(
                        f"{path} refers to '{key}', which this goal has not observed",
                        kind=ErrorKind.INVALID_ARGUMENTS)
                observed = context.recall(key)
                if observed is None:
                    raise PlanRejected(
                        f"{path} refers to '{key}', which was observed as 'not there'",
                        kind=ErrorKind.INVALID_ARGUMENTS)
                return observed
            return {k: self._substitute(v, context, f"{path}.{k}", depth + 1)
                    for k, v in value.items()}
        if isinstance(value, list):
            return [self._substitute(v, context, f"{path}[{i}]", depth + 1)
                    for i, v in enumerate(value)]
        return value

    def _remember_execution(self, goal: Goal, step: Step, result: ExecutionResult) -> None:
        """Record what a step actually reported, under explicit keys.

        Only fields Windows returned are recorded. A step that launched an app
        publishes its handle; a step that read a value publishes that value.
        """
        data = result.data or {}
        window = data.get("window") or data.get("already_open") or {}
        if isinstance(window, dict) and window.get("handle"):
            handle = int(window["handle"])
            goal.context.remember(f"step:{step.step_id}.handle", handle)
            # Remember what that handle belonged to, so a later bounded
            # re-location can ask for the same window rather than guessing.
            for key in ("process_name", "title", "process_id"):
                if window.get(key):
                    goal.context.remember(f"handle:{handle}.{key}", window[key])
            if data.get("target"):
                goal.context.remember(f"step:{step.step_id}.title", str(data["target"]))
        operation = str((step.resolved_arguments or step.arguments).get("operation", ""))
        app = str((step.resolved_arguments or step.arguments).get("app_name", ""))
        if operation == "launch_app" and app:
            goal.context.remember(f"app:{app}.launched", True)
        if step.status is StepStatus.VERIFIED:
            goal.context.remember(f"step:{step.step_id}.verified", True)

    def _remember_observations(self, goal: Goal, step: Step,
                               outcome: _verifier.Outcome) -> None:
        """Fold a verification outcome's observations into the goal's context."""
        last = outcome.observations[-1] if outcome.observations else None
        if last is None:
            return
        goal.context.remember(f"step:{step.step_id}.observed", last.to_dict())
        if isinstance(last.value, (int, float, bool, str)):
            goal.context.remember(f"step:{step.step_id}.value", last.value)
        if isinstance(last.value, dict) and last.value.get("handle"):
            goal.context.remember(f"step:{step.step_id}.handle", int(last.value["handle"]))

    def _record_in_context(self, goal: Goal, step: Step, attempt: Attempt) -> None:
        detail = (attempt.error.message if attempt.error
                  else (attempt.message.splitlines()[-1] if attempt.message else ""))
        goal.context.add_step_summary(step.step_id, step.status.value,
                                      detail[: self.limits.max_result_chars])
        if step.verification:
            observations = (step.verification.get("observations") or [])
            if observations:
                goal.context.remember(f"step:{step.step_id}.observed", observations[-1])

    def _reobserve(self, goal: Goal) -> None:
        """Bounded recovery step one: look again before repeating anything.

        One capture, with the cancellation flag attached. It never changes the
        plan and never invents an operation. It deliberately does *not* discard
        what earlier steps reported: a handle `launch_app` returned is a fact
        about that launch, not a claim about now, and deleting it would strand
        every later step that names it. What goes stale is handled where it
        matters — the Phase 4 verifier re-resolves every target from scratch on
        every poll, so a step retried after this is checked against the live
        machine, not against a memory.
        """
        try:
            # 30 rather than a handful: a re-location has to *see* the window
            # that moved, and the sample is bounded by the world capture, not by
            # the cost — enumerating top-level windows is one pass either way.
            state = self._world_capture(max_windows=30, include_controls=False,
                                        cancel_event=goal.cancel_event)
        except Exception as e:
            self._logger(f"[Goals] re-observation failed: {e}")
            return
        reader = getattr(state, "get", None)
        active = reader("active_window") if callable(reader) else None
        if isinstance(active, dict) and active.get("handle"):
            goal.context.remember("desktop:active_window", dict(active))
        visible = reader("visible_windows") if callable(reader) else None
        if isinstance(visible, list):
            goal.context.remember("desktop:windows", [dict(w) for w in visible
                                                       if isinstance(w, dict)])
        goal.context.remember("desktop:reobserved_at", self._clock())

    def _re_resolve_window(self, goal: Goal, step: Step) -> bool:
        """Re-acquire a window Windows moved, once, before repeating the step.

        A handle that has gone stale is not a strategy failure — the window is
        usually still there under a new one, which is exactly what a
        single-instance application does when it finishes handing off. So a step
        that opted in gets one re-location, and it is deliberately conservative:

        * it only ever looks for a window owned by the *same process* the stale
          handle belonged to, recorded when that handle was first seen;
        * it acts only when there is **exactly one** candidate — two windows of
          the same application is not something to guess between;
        * it never adds or removes a parameter, never changes the operation, and
          never re-plans.

        Returns True when the step's arguments were replaced, so the caller (and
        the event) can say what happened.
        """
        arguments = dict(step.resolved_arguments or step.arguments)
        handle = arguments.get("window_handle")
        if not isinstance(handle, int):
            return False
        remembered = goal.context.recall(f"handle:{handle}.process_name", "")
        if not remembered:
            return False
        live = [w for w in (goal.context.recall("desktop:windows") or [])
                if isinstance(w, dict)
                and (w.get("process_name") or "").lower() == str(remembered).lower()]
        if len(live) != 1 or not live[0].get("handle"):
            return False
        moved = int(live[0]["handle"])
        if moved == handle:
            return False
        arguments["window_handle"] = moved
        step.resolved_arguments = arguments
        step.note(f"the window moved from handle {handle} to {moved}; the same "
                  f"{remembered} window was re-located before retrying",
                  self.limits.max_step_notes)
        self._logger(f"[Goals] step {step.step_id}: window handle {handle} → {moved}")
        return True

    # ── Phase 6: bounded adaptive replanning ─────────────────────────────────

    def _try_replan(self, goal: Goal, step: Step, deadline: float) -> bool:
        """Ask whether there is a *supported* way forward, once, and boundedly.

        The contract this implements is deliberately narrow, because the
        failure mode of adaptive replanning is an assistant that talks itself
        into trying the same thing forever:

        * no replanner installed, or the step did not fail in a way a new
          approach could answer → no replan;
        * the goal has used `Limits.max_replans`, or this step has used
          `Limits.max_replans_per_step` → no replan;
        * the goal is out of time, or the plan is already at
          `Limits.max_total_steps` → no replan;
        * exactly one bounded world capture, then one bounded call;
        * every candidate goes through `Planner.build()` — the same validation
          every other plan goes through, so an unknown operation, an unknown
          capability, a cycle or a too-long plan is refused, not repaired;
        * `None` from the replanner is a complete and legitimate answer meaning
          "nothing safe is left to try", and the goal stops with that as the
          reason.

        Returns True when the plan was extended. The step that failed becomes
        `SUPERSEDED` rather than being rewritten: the failure stays on the
        record, and the steps that replaced it are what the goal's completion
        now depends on.
        """
        if self.replanner is None:
            return False
        if step.status not in (StepStatus.NOT_VERIFIED, StepStatus.FAILED):
            return False
        if goal.replans >= self.limits.max_replans:
            return self._refuse_replan(
                goal, step, f"the goal has used all {self.limits.max_replans} of "
                            f"its bounded replans")
        if self._replans_for(goal, step) >= self.limits.max_replans_per_step:
            return self._refuse_replan(
                goal, step, f"this step has used all "
                            f"{self.limits.max_replans_per_step} of its bounded replans")
        if goal.cancel_event.is_set() or self._clock() > deadline:
            return self._refuse_replan(goal, step, "the goal ran out of time")

        # One capture, before the question is asked. A replanner reasoning about
        # a desktop it has not looked at is inventing, and this is the same
        # bounded read `_reobserve` has always used.
        self._reobserve(goal)

        view = self._replan_view(goal, step)
        self._emit(EventType.GOAL_REPLANNING, goal, step=step,
                   data={"reason": view["failure"], "replans": goal.replans})
        self._logger(f"[Goals] step {step.step_id} did not reach its outcome; "
                     f"asking for a bounded replan "
                     f"({goal.replans + 1}/{self.limits.max_replans})")

        candidate = self._call_replanner(goal, step, view)
        if candidate is None:
            return self._refuse_replan(
                goal, step, "no supported recovery was proposed for this step")

        rewritten = self._rewrite_ids(goal, candidate, goal.replans + 1)
        if len(goal.plan.steps) + len(rewritten) > self.limits.max_total_steps:
            return self._refuse_replan(
                goal, step, f"the plan is already at its ceiling of "
                            f"{self.limits.max_total_steps} steps across replans")

        try:
            replacement = self.planner.build(goal.goal_id, rewritten,
                                             source=f"replan:{goal.replans + 1}")
        except PlanRejected as e:
            return self._refuse_replan(goal, step, f"the proposed recovery was "
                                                   f"refused: {e}")

        goal.replans += 1
        goal.plan.steps.extend(replacement.steps)
        step.status = StepStatus.SUPERSEDED
        step.note(f"a bounded replan ({goal.replans}/{self.limits.max_replans}) "
                  f"replaced this step with: "
                  f"{', '.join(s.step_id for s in replacement.steps)}",
                  self.limits.max_step_notes)
        self._adopt_successor(goal, step, replacement.steps)
        self._record_replan(goal, step, "accepted",
                            f"replaced by {len(replacement.steps)} step(s)")
        self._emit(EventType.STEP_SUPERSEDED, goal, step=step,
                   data={"replans": goal.replans,
                         "replacement": [s.step_id for s in replacement.steps]})
        self._emit(EventType.GOAL_REPLANNED, goal,
                   data={"replans": goal.replans,
                         "steps": [s.step_id for s in replacement.steps],
                         "source": replacement.source})
        self._persist()
        return True

    def _refuse_replan(self, goal: Goal, step: Step, reason: str) -> bool:
        """Say plainly that nothing was re-planned, and stop trying."""
        self._record_replan(goal, step, "refused", reason)
        self._emit(EventType.GOAL_REPLAN_REFUSED, goal, step=step,
                   data={"reason": reason, "replans": goal.replans})
        self._logger(f"[Goals] no replan for {step.step_id}: {reason}")
        return False

    def _replans_for(self, goal: Goal, step: Step) -> int:
        return sum(1 for r in goal.replan_history
                   if isinstance(r, dict) and r.get("step_id") == step.step_id)

    def _record_replan(self, goal: Goal, step: Step, outcome: str, reason: str) -> None:
        goal.replan_history.append({
            "step_id": step.step_id, "outcome": outcome,
            "reason": str(reason)[:300], "at": self._clock(),
            "replans": goal.replans + (1 if outcome == "accepted" else 0),
        })
        # Bounded like every other record in the goal: the last few replans are
        # the ones that explain the current shape of the plan.
        del goal.replan_history[: max(0, len(goal.replan_history) - 8)]

    def _replan_view(self, goal: Goal, step: Step) -> dict:
        """What a replanner is allowed to see. Bounded, and factual.

        Only three things are in here: what the goal was, what actually just
        happened, and what is still registered. It is not a transcript, it is
        not the world, and it contains no credentials — `GoalContext` never
        holds any, and the values in it are the ones Windows reported.
        """
        detail = (step.result.error.message if step.result and step.result.error
                  else (step.result.message.splitlines()[-1] if step.result
                        and step.result.message else ""))
        remaining = [s.step_id for s in goal.plan.steps if not s.is_terminal]
        return {
            "goal_id": goal.goal_id,
            "objective": goal.description[:400],
            "failure": {
                "step_id": step.step_id,
                "action": step.action,
                "status": step.status.value,
                "arguments": scrub_sensitive(dict(step.resolved_arguments
                                                  or step.arguments)),
                "detail": str(detail)[:300],
                "attempts": step.attempts,
            },
            "remaining_steps": remaining[: self.limits.max_steps],
            "completed_steps": [{"step_id": s.step_id, "action": s.action,
                                 "status": s.status.value}
                                for s in goal.plan.steps if s.succeeded][:8],
            "context": goal.context.describe()[: self.limits.max_replan_context_chars],
            "available_actions": sorted(self.planner.supported_actions())[:32],
            "limits": self.limits.to_dict(),
            "rules": [
                "name only registered actions",
                "arguments are plain data, never code or a shell command",
                "verification is decided by the action, not by you",
                "return no steps if nothing supported would help",
            ],
        }

    def _call_replanner(self, goal: Goal, step: Step, view: dict) -> Optional[list]:
        """Run the replanner off-thread with a timeout. Never waits forever.

        The same rule as `Planner._call_proposer`: a reasoner that hangs is a
        logged failure, not a frozen goal.
        """
        box: dict = {}

        def _worker() -> None:
            try:
                box["value"] = self.replanner(goal, step, view)
            except Exception as e:                 # a replanner may not crash us
                box["error"] = e

        thread = threading.Thread(target=_worker, daemon=True, name="goal-replanner")
        thread.start()
        thread.join(self.limits.replanner_seconds)
        if thread.is_alive():
            self._logger(f"[Goals] replanner for {step.step_id} overran "
                         f"{self.limits.replanner_seconds:.0f}s and was abandoned")
            return None
        if "error" in box:
            self._logger(f"[Goals] replanner for {step.step_id} failed: "
                         f"{box['error']}")
            return None
        value = box.get("value")
        return value if isinstance(value, list) and value else None

    @staticmethod
    def _rewrite_ids(goal: Goal, candidate: list, attempt: int) -> list:
        """Make a replan's step ids unique to the goal, dependencies intact.

        A replan reuses ids freely — `open`, `focus` are natural names — but two
        steps in one goal must never share an id, and a renamed step must drag
        its dependents' references along with it or the plan stops describing
        itself.
        """
        taken = {s.step_id for s in goal.plan.steps}
        renamed: dict = {}
        out: list = []
        for index, raw in enumerate(candidate):
            if not isinstance(raw, dict):
                out.append(raw)
                continue
            step = dict(raw)
            original = str(step.get("id") or step.get("step_id") or f"s{index + 1}")
            chosen = original
            if chosen in taken:
                chosen = f"{original}_r{attempt}"
                suffix = 1
                while chosen in taken:
                    suffix += 1
                    chosen = f"{original}_r{attempt}_{suffix}"
            renamed[original] = chosen
            taken.add(chosen)
            step["id"] = chosen
            step.pop("step_id", None)
            depends = step.get("depends_on")
            if isinstance(depends, str):
                depends = [depends]
            if isinstance(depends, list):
                step["depends_on"] = [renamed.get(str(d), str(d)) for d in depends]
            out.append(step)
        return out

    @staticmethod
    def _adopt_successor(goal: Goal, superseded: Step, replacement: list) -> None:
        """Re-point later steps from the replaced step at what replaced it.

        A step that depended on the old step still depends on *the work it was
        waiting for*. Silently dropping the dependency would let it run against
        a machine where that work never happened, and leaving it pointed at a
        superseded step would block it forever. So it now waits for the last
        step of the replacement — and, as everywhere else, that step has to
        succeed first.
        """
        if not replacement:
            return
        successor = replacement[-1].step_id
        for step in goal.plan.steps:
            if step.is_terminal or superseded.step_id not in step.depends_on:
                continue
            step.depends_on = [successor if d == superseded.step_id else d
                               for d in step.depends_on]

    # ── confirmation ─────────────────────────────────────────────────────────

    def _resolve_awaiting_confirmation(self, goal: Goal) -> None:
        """Pick a goal back up once the user has answered the gate.

        Three honest endings, and no fourth: the user approved and the task
        completed, the user declined or the gate could not ask and the task was
        cancelled, or the question is still on screen. The third leaves the goal
        waiting — it does not guess an answer.
        """
        waiting = [s for s in goal.steps() if s.status is StepStatus.AWAITING_CONFIRMATION]
        if not waiting:
            return
        for step in waiting:
            task = (self.manager.get_task(step.task_id)
                    if step.task_id and self.manager else None)
            if task is None or task.status is TaskStatus.RUNNING:
                continue                       # still genuinely waiting
            if task.status is TaskStatus.COMPLETED:
                recorded = (task.metadata or {}).get("execution") or {}
                outcome = str(recorded.get("final_status")
                              or recorded.get("status") or "")
                attempt = step.result
                if attempt is not None:
                    if recorded.get("status"):
                        attempt.status = str(recorded["status"])
                    attempt.final_status = outcome or attempt.final_status
                    attempt.verified = bool(recorded.get("verified"))
                    attempt.verification_status = str(
                        recorded.get("verification_status") or "NOT_AVAILABLE")
                    if isinstance(recorded.get("verification"), dict):
                        step.verification = recorded["verification"]
                if outcome == ExecStatus.NOT_VERIFIED.value:
                    # The user authorized the attempt and it ran — but the
                    # machine did not do what the step's contract claimed.
                    # This is the case Phase 5 exists to report honestly: a
                    # confirmation authorizes the action, not its outcome.
                    step.status = StepStatus.NOT_VERIFIED
                    step.note("the user authorized it and it ran, but the "
                              "expected state was not observed afterwards")
                elif bool(recorded.get("verified")):
                    step.status = StepStatus.VERIFIED
                    step.note("the user authorized it and the expected state "
                              "was observed afterwards")
                else:
                    step.status = StepStatus.COMPLETED
                    step.note("the user authorized it and Windows reported it ran")
                self._emit(self._step_event(step.status), goal, step=step,
                           data={"note": step.notes[-1] if step.notes else ""})
            elif task.status is TaskStatus.CANCELLED:
                step.status = StepStatus.BLOCKED
                detail = (task.error.message if task.error
                          else "the user did not authorize it")
                step.note(detail)
                step.result = (step.result or Attempt())
                self._emit(EventType.STEP_BLOCKED, goal, step=step,
                           data={"blocked_by": detail})
                goal.status = GoalStatus.BLOCKED
                goal.error = task.error or TaskError(
                    message=detail, kind=ErrorKind.AUTHORIZATION_DENIED)
                # The earlier "waiting" result described a question that has now
                # been answered. It must not outlive the answer.
                goal.result = None
            elif task.status is TaskStatus.FAILED:
                step.status = StepStatus.FAILED
                detail = task.error.message if task.error else "the authorized action failed"
                step.note(detail)
                self._emit(EventType.STEP_FAILED, goal, step=step, data={"error": detail})
        if all(s.status is not StepStatus.AWAITING_CONFIRMATION for s in waiting) \
                and goal.status is GoalStatus.AWAITING_CONFIRMATION:
            goal.status = GoalStatus.READY

    # ── status decisions ─────────────────────────────────────────────────────

    @staticmethod
    def _goal_status_for(step: Step) -> GoalStatus:
        if step.status is StepStatus.NOT_VERIFIED:
            return GoalStatus.NOT_VERIFIED
        if step.status is StepStatus.FAILED:
            return GoalStatus.FAILED
        if step.status is StepStatus.CANCELLED:
            return GoalStatus.CANCELLED
        return GoalStatus.BLOCKED

    def _overall_status(self, goal: Goal) -> GoalStatus:
        """What the whole goal achieved, given every step's real outcome.

        A required step that is NOT_VERIFIED makes the goal NOT_VERIFIED. There
        is no path through this function that returns COMPLETED while a required
        step failed, was not verified, was blocked or was cancelled.
        """
        for step in goal.steps():
            if not step.required or step.status is StepStatus.SKIPPED:
                continue
            if step.status is StepStatus.SUPERSEDED:
                # Phase 6. This step failed and a bounded replan replaced it. It
                # is not counted against the goal — the steps that replaced it
                # are, and they carry the same `required` weight. What it must
                # never do is quietly promote a failed attempt into a success.
                continue
            if step.status is StepStatus.NOT_VERIFIED:
                return GoalStatus.NOT_VERIFIED
            if step.status is StepStatus.FAILED:
                return GoalStatus.FAILED
            if step.status is StepStatus.BLOCKED:
                return GoalStatus.BLOCKED
            if step.status is StepStatus.CANCELLED:
                return GoalStatus.CANCELLED
            if step.status is StepStatus.AWAITING_CONFIRMATION:
                return GoalStatus.AWAITING_CONFIRMATION
            if not step.succeeded:
                return GoalStatus.FAILED
        if any(s.status is StepStatus.CANCELLED for s in goal.steps()):
            return GoalStatus.CANCELLED
        return GoalStatus.COMPLETED

    @staticmethod
    def _stop_message(step: Step) -> str:
        if step.status is StepStatus.NOT_VERIFIED:
            return (f"stopped at '{step.step_id}': the step ran but its result could "
                    f"not be verified, so NEO is not reporting it as done")
        if step.status is StepStatus.FAILED:
            return f"stopped at '{step.step_id}': the action failed"
        if step.status is StepStatus.CANCELLED:
            return f"stopped at '{step.step_id}': it was cancelled"
        return f"stopped at '{step.step_id}'"

    @staticmethod
    def _stop_message_for_goal(goal: Goal) -> str:
        bad = [s for s in goal.steps()
               if s.required and not s.succeeded]
        if bad:
            return GoalExecutor._stop_message(bad[0])
        return "the goal did not complete"

    @staticmethod
    def _error_for(step: Step) -> Optional[TaskError]:
        if step.result and step.result.error:
            return step.result.error
        if step.status is StepStatus.NOT_VERIFIED:
            return TaskError(message=step.notes[-1] if step.notes else
                             "the expected state was not observed",
                             kind=ErrorKind.NOT_VERIFIED)
        if step.status is StepStatus.BLOCKED:
            return TaskError(message=step.notes[-1] if step.notes else
                             "the step was blocked",
                             kind=ErrorKind.INVALID_REQUEST)
        return None

    @staticmethod
    def _error_kind_for(step: Step) -> Optional[ErrorKind]:
        if step.result and step.result.error:
            return step.result.error.kind
        if step.status is StepStatus.NOT_VERIFIED:
            return ErrorKind.NOT_VERIFIED
        return None

    def _unsatisfied_dependency(self, goal: Goal, step: Step) -> Optional[str]:
        """The first dependency that has not reached a successful state."""
        for dependency in step.depends_on:
            parent = goal.step(dependency)
            if parent is None:
                return dependency
            if not parent.succeeded:
                return dependency
        return None

    def _block_remaining(self, goal: Goal, stopped_at: Step, status: StepStatus,
                         reason: str) -> None:
        """Say plainly that the steps after the stop point did not run."""
        seen_stop = False
        for step in goal.plan.steps:
            if step is stopped_at:
                seen_stop = True
                continue
            if not seen_stop or step.is_terminal:
                continue
            step.status = status
            step.finished_at = step.finished_at or self._clock()
            step.note(reason, self.limits.max_step_notes)
            self._emit(EventType.STEP_BLOCKED, goal, step=step,
                       data={"reason": reason, "stopped_at": stopped_at.step_id})

    @staticmethod
    def _step_event(status: StepStatus) -> EventType:
        if status is StepStatus.VERIFIED:
            return EventType.STEP_VERIFIED
        if status is StepStatus.NOT_VERIFIED:
            return EventType.STEP_NOT_VERIFIED
        if status is StepStatus.SUPERSEDED:
            return EventType.STEP_SUPERSEDED
        if status is StepStatus.BLOCKED:
            return EventType.STEP_BLOCKED
        if status is StepStatus.AWAITING_CONFIRMATION:
            return EventType.STEP_AWAITING_CONFIRMATION
        if status is StepStatus.CANCELLED:
            return EventType.STEP_CANCELLED
        return EventType.STEP_FINISHED

    # ── results, events, persistence ────────────────────────────────────────

    def _finish(self, goal: Goal, message: str = "") -> GoalResult:
        result = self._result(goal, message)
        goal.result = result
        if goal.status in TERMINAL_GOAL_STATUSES:
            goal.completed_at = goal.completed_at or self._clock()
            if goal.status is GoalStatus.FAILED:
                self._emit(EventType.GOAL_FAILED, goal, status=goal.status.value,
                           data={"message": result.message})
            elif goal.status is GoalStatus.NOT_VERIFIED:
                self._emit(EventType.GOAL_NOT_VERIFIED, goal, status=goal.status.value,
                           data={"message": result.message})
        self._persist()
        return result

    def _result(self, goal: Goal, message: str = "") -> GoalResult:
        counts = {"VERIFIED": 0, "COMPLETED": 0, "NOT_VERIFIED": 0, "FAILED": 0,
                  "BLOCKED": 0, "CANCELLED": 0, "SKIPPED": 0, "SUPERSEDED": 0,
                  "AWAITING_CONFIRMATION": 0, "PENDING": 0, "READY": 0, "RUNNING": 0}
        for step in goal.steps():
            counts[step.status.value] = counts.get(step.status.value, 0) + 1
        steps = goal.step_report()
        started = goal.started_at or goal.created_at
        finished = goal.completed_at or self._clock()
        return GoalResult(
            goal_id=goal.goal_id, status=goal.status, message=message or
            ("every required step reached its outcome" if goal.status is GoalStatus.COMPLETED
             else goal.status.value),
            step_count=len(steps),
            verified=counts["VERIFIED"], completed=counts["COMPLETED"],
            not_verified=counts["NOT_VERIFIED"], failed=counts["FAILED"],
            blocked=counts["BLOCKED"], cancelled=counts["CANCELLED"],
            skipped=counts["SKIPPED"],
            awaiting_confirmation=counts["AWAITING_CONFIRMATION"],
            superseded=counts["SUPERSEDED"],
            recovery_attempts=goal.context.recovery_attempts,
            replans=goal.replans,
            duration_seconds=max(0.0, finished - started),
            started_at=started, finished_at=finished, steps=steps,
            error=goal.error,
            world_summary={"observed_values": len(goal.context.entries),
                           "known_steps": len(goal.context.step_summaries)})

    def _goal_task(self, goal: Goal, step: Step):
        """The step's Phase 2 task, so an event carries a real task id."""
        if not step.task_id or self.manager is None:
            return None
        return self.manager.get_task(step.task_id)

    def _emit(self, kind: EventType, goal: Goal, step: Optional[Step] = None,
              action: str = "", status: str = "", data: Optional[dict] = None) -> None:
        task_id = step.task_id if step else ""
        payload = {"goal_id": goal.goal_id, "goal_status": goal.status.value}
        if step is not None:
            payload.update({"step_id": step.step_id, "step_status": step.status.value})
        payload.update(data or {})
        self.bus.emit(Event(type=kind, task_id=task_id, goal_id=goal.goal_id,
                            step_id=step.step_id if step else "", action=action,
                            status=status or (step.status.value if step else ""),
                            data=payload))

    def _persist(self) -> None:
        if self.history is None:
            return
        try:
            error = self.history.save(self.list_goals())
        except Exception as e:
            self._logger(f"[Goals] goal history could not be saved: {e}")
            return
        if error != self.persistence_error:
            self.persistence_error = error
            if error:
                self._notify(f"Goal history could not be saved — {error}")
            else:
                self._logger("[Goals] goal history saved")