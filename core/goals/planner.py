"""
Bounded planning — turning a request into a validated list of registered steps.

THE ORDER OF OPERATIONS, WHICH IS THE POINT
    propose → validate → order → execute

A plan is data before it is anything else. Every operation it names is checked
against the real ActionRegistry / PluginRegistry; an operation that is not
registered is NOT_SUPPORTED and the plan is rejected. A plan that is too long,
has duplicate ids, depends on itself, contains a cycle, or carries an argument
that is not plain data is rejected with a reason. Nothing here executes, and
nothing here can invent a capability: there is no path from a plan to a
function that does not already exist in a registry.

WHAT THE MODEL IS ALLOWED TO CONTRIBUTE
    It may propose which registered operations to use, in what order, with what
    data, and what a step is for. It may not choose how a step is verified when
    the action declares a verification contract — `declared_expectation()` wins
    and a plan expectation is only consulted for an action that declares none,
    which can add rigor but can never remove it. That asymmetry is deliberate:
    the one thing Phase 4 built must not become negotiable by a planner.

WHAT IS NOT HERE
    No free-form natural-language planner. `TEMPLATES` is a small set of
    whitelisted, deterministic recipes a caller selects by name, and
    `propose()` is the seam a future model-backed planner plugs into — bounded
    by `max_proposals`, with the proposer itself run off-thread and abandoned
    if it hangs. Neither route can produce a plan that has not been validated
    against the registries.
"""
from __future__ import annotations

import sys
import threading
import time
from typing import Any, Callable, Optional

from core.execution import resolve_capability
from core.goals.limits import Limits
from core.goals.models import Plan, Step
from core.goals.recovery import NO_RETRIES, RetryPolicy
from core.task_models import ErrorKind, TaskError
from core.verification.expectations import Expectation, ExpectationKind

#: Every expectation kind the Phase 4 vocabulary defines. A plan may only name
#: one of these; there is no "run this expression" kind.
EXPECTATION_KINDS = frozenset({
    ExpectationKind.WINDOW_EXISTS,
    ExpectationKind.WINDOW_CLOSED,
    ExpectationKind.WINDOW_ACTIVE,
    ExpectationKind.CONTROL_EXISTS,
    ExpectationKind.CONTROL_VALUE,
    ExpectationKind.CONTROL_STATE,
    ExpectationKind.APP_RUNNING,
    ExpectationKind.CONTROL_CHANGED,
})

#: Argument value types a plan may contain. Anything else — a callable, a
#: module, a file object, a custom object — is data that could only be here so
#: something later would run it.
_ALLOWED_SCALARS = (str, int, float, bool, type(None))

class PlanRejected(Exception):
    """A plan NEO refused to execute, with the reason in the taxonomy.

    `kind` is one of the Phase 2 ErrorKinds so a caller can branch on it the
    same way it branches on any other failure, and so the reason survives into
    the goal record instead of becoming a sentence somebody has to interpret.
    """

    def __init__(self, message: str, kind: ErrorKind = ErrorKind.INVALID_REQUEST,
                 step_id: str = ""):
        super().__init__(message)
        self.kind = kind
        self.step_id = step_id

    def to_error(self) -> TaskError:
        return TaskError(message=str(self), kind=self.kind)


def _check_value(value: Any, limits: Limits, depth: int = 0, refs: Optional[list] = None,
                 path: str = "arguments") -> None:
    """Refuse anything in a plan's arguments that is not inert data."""
    refs = refs if refs is not None else []
    if depth > limits.max_argument_depth:
        raise PlanRejected(f"{path} nests deeper than {limits.max_argument_depth} levels")
    if isinstance(value, _ALLOWED_SCALARS):
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise PlanRejected(f"{path} has a non-string key ({type(key).__name__})")
            if key == "$from":
                if not isinstance(item, str) or not item.strip():
                    raise PlanRejected(f"{path}.$from must name an observed value")
                refs.append(item)
                if len(refs) > limits.max_references:
                    raise PlanRejected(
                        f"arguments use more than {limits.max_references} references")
                continue
            _check_value(item, limits, depth + 1, refs, f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _check_value(item, limits, depth + 1, refs, f"{path}[{index}]")
        return
    raise PlanRejected(
        f"{path} contains a {type(value).__name__}, which is not inert data. "
        f"A plan carries values, never code.")


def _check_expectation(raw: Any, limits: Limits) -> Optional[Expectation]:
    """A plan expectation must be a real Phase 4 expectation, or absent."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise PlanRejected("an expectation must be an object")
    kind = str(raw.get("kind", "")).strip()
    if kind not in EXPECTATION_KINDS:
        raise PlanRejected(
            f"'{kind}' is not a verification NEO knows how to perform. "
            f"Known kinds: {', '.join(sorted(EXPECTATION_KINDS))}.")
    expectation = Expectation.from_dict(raw)
    # A plan may shorten the wait. It may not lengthen it past the ceiling, or
    # set it to something that means "check forever".
    if expectation.timeout <= 0:
        raise PlanRejected("an expectation timeout must be greater than zero")
    expectation = Expectation(kind=expectation.kind, target=dict(expectation.target),
                              expected=expectation.expected, property=expectation.property,
                              compare=expectation.compare,
                              timeout=min(expectation.timeout,
                                          limits.max_expectation_timeout),
                              interval=expectation.interval,
                              note=expectation.note or "declared by the plan")
    _check_value(expectation.target, limits, 0, None, "expectation.target")
    return expectation


class Planner:
    """Turns a request into a `Plan`, or refuses with a reason."""

    def __init__(self, actions: Any = None, plugins: Any = None,
                 limits: Optional[Limits] = None,
                 logger: Optional[Callable[[str], None]] = None):
        self._actions = actions
        self._plugins = plugins
        self.limits = (limits or Limits()).clamped()
        self._logger = logger or (lambda _msg: None)

    # -- capability lookup ---------------------------------------------------

    def supported_actions(self) -> set:
        """Every operation a plan may name, from the real registries.

        Read through each registry's public contract rather than its storage:
        `names()` where it exists (ActionRegistry), and `get_tool_declarations()`
        where it does not (PluginRegistry). Using the same public surface the app
        uses to build the model's tool list is what keeps "the planner checked
        the registry" and "the model was told about this" in agreement.
        """
        names: set = set()
        for registry in (self._actions, self._plugins):
            if registry is None:
                continue
            lister = getattr(registry, "names", None)
            if callable(lister):
                try:
                    names |= {str(n) for n in lister()}
                    continue
                except Exception:
                    pass
            declarations = getattr(registry, "get_tool_declarations", None)
            if callable(declarations):
                try:
                    names |= {str(d.get("name")) for d in declarations()
                              if isinstance(d, dict) and d.get("name")}
                except Exception:
                    continue
        return names

    def supports(self, action: str) -> bool:
        _registry, kind, _handler = resolve_capability(action, self._actions, self._plugins)
        return kind != ""

    def declared_expectation(self, action: str, arguments: dict) -> Optional[Expectation]:
        """The verification contract the *action* declares, if it has one.

        This is the Phase 4 seam (`expectation_for` at module level), asked the
        same way the execution layer asks it. The planner never decides what a
        step has to prove when the action itself has already said.
        """
        _registry, kind, handler = resolve_capability(action, self._actions, self._plugins)
        if kind != "actions" or handler is None:
            return None
        module_name = getattr(handler, "__module__", None)
        module = sys.modules.get(module_name) if module_name else None
        provider = getattr(module, "expectation_for", None)
        if not callable(provider):
            return None
        try:
            _pre, expectation = provider(dict(arguments or {}), {})
        except Exception as e:
            self._logger(f"[Goals] '{action}' could not state its expectation: {e}")
            return None
        return expectation

    def requires_confirmation(self, action: str, arguments: dict) -> bool:
        """Whether this action parks behind the Phase 2 gate for these arguments.

        Advisory only, and it is deliberately not a decision: the gate inside
        the action is what actually enforces it, and the executor handles
        REQUIRES_CONFIRMATION wherever it comes from. This exists so a plan can
        *say* that a step will need the user, not so it can skip the ask.
        """
        try:
            from core.windows import control as _control
        except Exception:
            return False
        operation = str((arguments or {}).get("operation", "")).strip().lower()
        return bool(operation) and operation in getattr(
            _control, "CONFIRMATION_REQUIRED", frozenset())

    # -- building a plan -----------------------------------------------------

    def build(self, goal_id: str, raw_steps: list, source: str = "explicit") -> Plan:
        """Validate and order a proposed list of steps. Raises PlanRejected."""
        if not isinstance(raw_steps, list) or not raw_steps:
            raise PlanRejected("a plan needs at least one step")

        limit = self.limits
        if len(raw_steps) > limit.max_steps:
            raise PlanRejected(
                f"this plan has {len(raw_steps)} steps and the limit is "
                f"{limit.max_steps}; a longer plan is refused rather than "
                f"silently shortened",
                kind=ErrorKind.INVALID_REQUEST)

        prepared: list = []
        seen: set = set()
        for index, raw in enumerate(raw_steps):
            step = self._prepare(goal_id, raw, index)
            if step.step_id in seen:
                raise PlanRejected(f"two steps share the id '{step.step_id}'",
                                   step_id=step.step_id)
            seen.add(step.step_id)
            prepared.append(step)

        for step in prepared:
            for dependency in step.depends_on:
                if dependency not in seen:
                    raise PlanRejected(
                        f"step '{step.step_id}' depends on '{dependency}', which "
                        f"is not in this plan", step_id=step.step_id)
                if dependency == step.step_id:
                    raise PlanRejected(f"step '{step.step_id}' depends on itself",
                                       step_id=step.step_id)

        ordered = self._order(prepared)
        return Plan(goal_id=goal_id, steps=ordered, source=source, created_at=time.time())

    def _prepare(self, goal_id: str, raw: Any, index: int) -> Step:
        if not isinstance(raw, dict):
            raise PlanRejected(f"step {index} is not an object")

        action = str(raw.get("action", "")).strip()
        if not action:
            raise PlanRejected(f"step {index} names no action")
        if not self.supports(action):
            supported = ", ".join(sorted(self.supported_actions())[:12]) or "none"
            raise PlanRejected(
                f"'{action}' is not a registered action, so it cannot be planned. "
                f"Available: {supported}.",
                kind=ErrorKind.ACTION_NOT_SUPPORTED)

        arguments = raw.get("arguments", {})
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            raise PlanRejected(f"step {index} arguments must be an object",
                               kind=ErrorKind.INVALID_ARGUMENTS)
        _check_value(arguments, self.limits)

        step_id = str(raw.get("id") or raw.get("step_id") or f"s{index + 1}").strip()
        if not step_id:
            raise PlanRejected(f"step {index} has no id")

        depends_raw = raw.get("depends_on", [])
        if isinstance(depends_raw, str):
            depends_raw = [depends_raw]
        if not isinstance(depends_raw, list):
            raise PlanRejected(f"step '{step_id}' has an unreadable depends_on")
        depends_on = [str(d).strip() for d in depends_raw if str(d).strip()]

        declared = self.declared_expectation(action, arguments)
        supplied = _check_expectation(raw.get("expected"), self.limits)
        expected = declared if declared is not None else supplied
        expected_by = ("action" if declared is not None
                       else ("plan" if supplied is not None else "none"))

        retry = RetryPolicy.from_dict(raw.get("retry"))
        if retry.attempts > self.limits.max_step_attempts:
            # A plan may ask for fewer attempts than the ceiling, never more.
            retry = retry.with_attempts(self.limits.max_step_attempts)

        return Step(
            step_id=step_id,
            description=str(raw.get("description")
                            or f"{action} ({expected.describe() if expected else 'no check'})")[:200],
            action=action,
            arguments=dict(arguments),
            expected=expected,
            expected_by=expected_by,
            depends_on=depends_on,
            retry=retry if retry.attempts > 1 else NO_RETRIES,
            re_resolve=bool(raw.get("re_resolve", False)),
            required=bool(raw.get("required", True)),
        )

    @staticmethod
    def _order(steps: list) -> list:
        """Topological order, ties broken by declared order.

        Dependencies decide what must come first; they never shuffle what does
        not depend on anything, so a plan reads the way it was written. A cycle
        is refused rather than broken, because breaking one would be deciding
        which of two impossible orders to pretend was intended.
        """
        ordered: list = []
        placed: set = set()
        remaining = list(steps)
        while remaining:
            progressed = False
            still: list = []
            for step in remaining:
                if all(d in placed for d in step.depends_on):
                    ordered.append(step)
                    placed.add(step.step_id)
                    progressed = True
                else:
                    still.append(step)
            if not progressed:
                stuck = ", ".join(sorted(s.step_id for s in still))
                raise PlanRejected(f"these steps depend on each other in a loop: {stuck}",
                                   kind=ErrorKind.INVALID_REQUEST)
            remaining = still
        return ordered

    # -- templates -----------------------------------------------------------

    def template(self, name: str, goal_id: str, params: Optional[dict] = None) -> Plan:
        """Build one of the whitelisted, deterministic recipes."""
        builder = TEMPLATES.get(str(name))
        if builder is None:
            raise PlanRejected(
                f"'{name}' is not a goal recipe NEO knows. Available: "
                f"{', '.join(sorted(TEMPLATES))}.",
                kind=ErrorKind.ACTION_NOT_SUPPORTED)
        params = dict(params or {})
        _check_value(params, self.limits)
        steps = builder(params)
        return self.build(goal_id, steps, source=f"template:{name}")

    # -- bounded proposal ----------------------------------------------------

    def propose(self, goal_id: str, proposer: Callable[[int], Any],
                attempts: Optional[int] = None) -> Plan:
        """Ask a proposer for a plan, a bounded number of times, then stop.

        The proposer is the seam a future model-backed planner fills. It runs
        off-thread and is abandoned if it overruns, so a planner that hangs is a
        logged failure rather than a frozen process. Each candidate goes through
        the same `build()` as everything else, and the loop ends on the first
        candidate that validates — there is no "keep trying until one sticks
        forever", and no code path here re-plans after execution begins.
        """
        limit = attempts if attempts is not None else min(
            self.limits.max_planning_attempts, self.limits.max_proposals)
        limit = max(1, min(int(limit), self.limits.max_proposals))
        reasons: list = []

        for index in range(limit):
            candidate = self._call_proposer(proposer, index, reasons)
            if isinstance(candidate, Plan):
                return candidate
            try:
                return self.build(goal_id, candidate, source=f"proposal:{index + 1}")
            except PlanRejected as e:
                reasons.append(f"attempt {index + 1}: {e}")
                self._logger(f"[Goals] plan attempt {index + 1} refused: {e}")

        detail = " | ".join(reasons[-3:]) if reasons else "the proposer returned nothing usable"
        raise PlanRejected(
            f"no usable plan after {limit} attempt(s). {detail}",
            kind=ErrorKind.INVALID_REQUEST)

    def _call_proposer(self, proposer: Callable[[int], Any], index: int,
                       reasons: list) -> Any:
        """Run the proposer off-thread with a timeout. Never waits forever."""
        box: dict = {}

        def _worker() -> None:
            try:
                box["value"] = proposer(index)
            except Exception as e:                     # a planner may not crash us
                box["error"] = e

        thread = threading.Thread(target=_worker, daemon=True, name="goal-proposer")
        thread.start()
        thread.join(self.limits.proposer_seconds)
        if thread.is_alive():
            reasons.append(f"attempt {index + 1}: the planner took longer than "
                           f"{self.limits.proposer_seconds:.0f}s and was abandoned")
            return None
        if "error" in box:
            reasons.append(f"attempt {index + 1}: the planner failed: {box['error']}")
            return None
        return box.get("value")


# ── whitelisted recipes ─────────────────────────────────────────────────────
# Each returns raw step dicts, which go through exactly the same validation as
# anything else. `windows_control` is the Phase 3 action; its verification
# contract is declared by the action, so these recipes say nothing about what
# gets checked.

def _open_app(params: dict) -> list:
    app = str(params.get("app_name", "")).strip()
    if not app:
        raise PlanRejected("which application should NEO open?", kind=ErrorKind.INVALID_REQUEST)
    return [{"id": "open", "description": f"Open {app}", "action": "windows_control",
             "arguments": {"operation": "launch_app", "app_name": app}}]


def _open_and_type(params: dict) -> list:
    app = str(params.get("app_name", "")).strip()
    if not app:
        raise PlanRejected("which application should NEO open?", kind=ErrorKind.INVALID_REQUEST)
    return [
        {"id": "open", "description": f"Open {app}", "action": "windows_control",
         "arguments": {"operation": "launch_app", "app_name": app}},
        {"id": "type", "description": f"Put {params.get('text', '')!r} into it",
         "action": "windows_control", "depends_on": ["open"],
         "arguments": {"operation": "set_value",
                       "window_handle": {"$from": "step:open.handle"},
                       "control_type": str(params.get("control_type", "Document")),
                       "text": str(params.get("text", ""))},
         # Windows sometimes replaces a window's handle between the moment a
         # launch reports it and the moment a later step uses it — Notepad's
         # single-instance hand-off does exactly this. One re-location is the
         # supported recovery; without it the goal would fail on a race that
         # has nothing to do with whether the text can be written.
         "re_resolve": True,
         "retry": {"attempts": 2, "delay": 0.25,
                   "reason": "the text area may not be ready the instant it opens"}},
    ]


def _open_and_focus(params: dict) -> list:
    app = str(params.get("app_name", "")).strip()
    if not app:
        raise PlanRejected("which application should NEO open?", kind=ErrorKind.INVALID_REQUEST)
    return [
        {"id": "open", "description": f"Open {app}", "action": "windows_control",
         "arguments": {"operation": "launch_app", "app_name": app}},
        {"id": "focus", "description": f"Bring {app} to the front",
         "action": "windows_control", "depends_on": ["open"],
         "arguments": {"operation": "focus_window",
                       "window_handle": {"$from": "step:open.handle"}},
         "re_resolve": True,
         "retry": {"attempts": 2, "delay": 0.25,
                   "reason": "Windows refuses activation while the user is working"}},
    ]


def _close_window(params: dict) -> list:
    target = {k: params[k] for k in ("window_handle", "title", "app_name")
              if params.get(k)}
    if not target:
        raise PlanRejected("which window should NEO close?", kind=ErrorKind.INVALID_REQUEST)
    return [{"id": "close", "description": "Close the window", "action": "windows_control",
             "arguments": {"operation": "close_window", **target}}]


#: The whole recipe list. Each is deterministic, whitelisted, and produces
#: nothing that `build()` would refuse.
TEMPLATES = {
    "open_app": _open_app,
    "open_and_type": _open_and_type,
    "open_and_focus": _open_and_focus,
    "close_window": _close_window,
}