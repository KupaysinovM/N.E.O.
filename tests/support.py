"""
Shared fixtures for the Phase 2 and Phase 5 tests.

Everything here is test-only. Nothing in tests/ is imported by the application,
and no fixture is a stand-in for a real capability: the classes under test are
the production ones (ActionRegistry, PluginRegistry, TaskManager,
ExecutionLayer, Planner, GoalExecutor, GoalStore) and the small handlers below
only exist to give them inputs.

A fixture action is never presented as a production tool, and results in these
tests are checked against what the fixture actually did — the point of the
suite is to verify the boundary, not to make the boundary look good.

THE ONE SUBSTITUTION IN HERE, AND WHY IT IS HONEST
    The OS read. `core.verification.verifier._observe` is replaced with
    `DemoWorld`, an object that answers the Phase 4 questions from state a test
    sets directly. Everything above that stays real: the bounded polling loop,
    the comparison rules, the timeout, the NOT_AVAILABLE/AMBIGUOUS/STALE
    classification, the events, the whole execution layer, and the whole goal
    layer. Replacing the read is what `verify(observer=...)` exists for; doing
    it through the same seam keeps the substituted part identical to a real
    observation rather than a different object shaped like one.
"""
from __future__ import annotations

import contextlib
import pathlib
import tempfile
import time
from typing import Optional

from core import confirm
from core import capabilities
from config import policy as policy_config
from core.action_loader import ActionRecord, ActionRegistry
from core.execution import ExecutionLayer, ExecStatus, ExecutionResult
from core.goals.executor import GoalExecutor
from core.goals.limits import Limits
from core.goals.planner import Planner
from core.goals.store import GoalHistory, GoalStore
from core.plugin_loader import PluginRecord, PluginRegistry
from core.security import AuthorizationPolicy, RiskClass
from core.task_manager import TaskManager
from core.task_models import ErrorKind, TaskError
from core.task_store import TaskStore
from core.verification.expectations import (
    ExpectationKind,
    control_value,
    window_active,
    window_closed,
    window_exists,
)
from core.verification.observation import Kind, Observation, Source

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
PARAMS = {"type": "OBJECT", "properties": {}}

#: The handle the demo capabilities pretend to open. Nothing is 4242 on a real
#: desktop, and the value never leaves tests/.
DEMO_HANDLE = 4242


class Sink:
    """Collects log lines so a test can assert that something was reported."""

    def __init__(self) -> None:
        self.lines: list[str] = []

    def __call__(self, message) -> None:
        self.lines.append(str(message))

    def text(self) -> str:
        return "\n".join(self.lines)


def tmp_dir(prefix: str = "neo-phase2-") -> pathlib.Path:
    return pathlib.Path(tempfile.mkdtemp(prefix=prefix))


def make_action_registry(*pairs: tuple[str, object]) -> ActionRegistry:
    """A real ActionRegistry holding fixture handlers (name, handler).

    Fixture capabilities stand in for production actions, and every
    production action carries a category mapping in `config/policy.py` —
    without one the authorization policy would (correctly) resolve the fixture
    as `unknown` and refuse it. Declaring the fixture here mirrors what
    `make_layer` already does for the risk classifier: the test says "this
    name is a declared capability of this category", the same way production
    declares its own. A test that wants an *undeclared* name builds its
    registry without this helper (or removes the mapping), which is exactly
    how the policy's unknown-not-registered path is exercised.
    """
    records = {
        name: ActionRecord(name=name, description="test fixture", parameters=dict(PARAMS),
                           handler=handler, file="fixture.py", valid=True)
        for name, handler in pairs
    }
    declare_fixture_categories(*records)
    return ActionRegistry(records, logger=lambda _msg: None)


def declare_fixture_categories(*names: str) -> None:
    """Map fixture names into an enabled policy category (test-only).

    `setdefault` never touches a name that already has a real mapping —
    `file_controller` stays `filesystem`, `send_message` stays `communication`.
    Only true fixtures get the stand-in category, and only because a category
    must exist for the policy to have anything to say about them.
    """
    for name in names:
        policy_config.CATEGORY_BY_ACTION.setdefault(str(name), "process")


def make_plugin_registry(*pairs: tuple[str, object]) -> PluginRegistry:
    """A real PluginRegistry holding fixture plugins (name, run).

    Fixture plugins are declared to the policy category map like fixture
    actions are — production plugins are refused earlier (no trusted security
    classification), and tests that exercise *that* path build their layer
    with the default `AuthorizationPolicy`, whose DENY short-circuits before
    the category map is ever consulted.
    """
    records = {
        name: PluginRecord(name=name, description="test fixture", parameters=dict(PARAMS),
                           run=run, file="fixture.py", valid=True)
        for name, run in pairs
    }
    declare_fixture_categories(*records)
    return PluginRegistry(records, logger=lambda _msg: None)


def make_manager(tmp: pathlib.Path, name: str = "tasks.json",
                 max_tasks: int = 500, **kwargs) -> TaskManager:
    """A TaskManager whose history goes to a temp file — never the real one."""
    store = TaskStore(path=tmp / name, max_tasks=max_tasks, logger=kwargs.get("logger"))
    return TaskManager(store=store, **kwargs)


def make_layer(manager: TaskManager, actions=None, plugins=None, **kwargs) -> ExecutionLayer:
    overrides = {}
    action_names = getattr(actions, "names", None)
    if callable(action_names):
        overrides.update({str(name): RiskClass.LOW_RISK_REVERSIBLE
                          for name in action_names()
                          if capabilities.get(str(name)) is None})
    plugin_records = getattr(plugins, "_plugins", {})
    if isinstance(plugin_records, dict):
        overrides.update({str(name): RiskClass.LOW_RISK_REVERSIBLE
                          for name in plugin_records})
    kwargs.setdefault("security_policy", AuthorizationPolicy(overrides=overrides))
    return ExecutionLayer(actions=actions, plugins=plugins, manager=manager, **kwargs)


def resolve_confirmation(accepted: bool) -> None:
    """Answer only the currently displayed confirmation challenge in tests."""
    confirm.resolve(accepted, token=confirm.pending_token())


@contextlib.contextmanager
def unbound_gate():
    """No interface at all — the headless case the gate refuses to guess about."""
    previous_timeout = confirm.TIMEOUT_SECONDS
    confirm.bind(None, None, None)
    try:
        yield
    finally:
        confirm.bind(None, None, None)
        confirm.bind_resolution(None)
        confirm.TIMEOUT_SECONDS = previous_timeout
        with confirm._lock:
            confirm._pending = None


class _FastClock:
    """A clock that jumps a long way on every reading.

    Used to reach a bounded limit in a test without waiting for it: the code
    under test is unchanged, it just gets its own sense of time.
    """

    def __init__(self, step: float = 1000.0) -> None:
        self.value = 0.0
        self.step = step

    def __call__(self) -> float:
        self.value += self.step
        return self.value

    def advance(self, seconds: float) -> float:
        self.value += seconds
        return self.value


@contextlib.contextmanager
def prompts_enabled() -> None:
    """Put the legacy confirmation gate on the execution path (test seam only).

    NEO ships `config/permissions.json` with `authorizationMode: silent_policy`,
    so the production path never asks: it executes or refuses. Configuration
    can no longer turn the gate on either — every prompt switch is
    `const: false` in the schemas, and a missing, invalid, partial, or
    contradictory document blocks execution via `config_failure()` instead of
    resurrecting a prompt. This context manager is the *only* way the legacy
    gate is reached, which is exactly how its contract keeps being tested:
    one pending token, single use, forged and replayed tokens refused, scope
    escalation still refused.

    Tests for the *default* silent path must not use this; see
    `tests.test_policy_config`.
    """
    from unittest.mock import patch
    with patch("core.execution.policy.prompts_enabled", return_value=True):
        yield


def with_prompts(test_method):
    """Decorator: run this one test with the confirmation gate on the path.

    Kept separate from `prompts_enabled()` so a test's body does not have to be
    re-indented inside a `with` — the gate tests are long and their shape is
    the point.
    """
    import functools

    @functools.wraps(test_method)
    def wrapper(*args, **kwargs):
        with prompts_enabled():
            return test_method(*args, **kwargs)
    return wrapper


@contextlib.contextmanager
def bound_gate(show=None, hide=None, log=None):
    """Bind the real confirmation gate to stub callbacks, then restore it.

    The gate keeps all of its behaviour (one pending token, one shot, expiry);
    only the HUD callbacks are replaced so a test never needs a Qt window.
    Module globals are put back afterwards so tests cannot leak into each other
    or into anything that runs later in the same process.
    """
    previous_timeout = confirm.TIMEOUT_SECONDS
    confirm.bind(show=show or (lambda _t, _d: None),
                 hide=hide or (lambda: None),
                 log=log or (lambda _m: None))
    try:
        yield
    finally:
        confirm.bind(None, None, None)
        confirm.bind_resolution(None)
        confirm.TIMEOUT_SECONDS = previous_timeout
        # Clear any token left pending, so the next test starts from a clean gate.
        with confirm._lock:
            confirm._pending = None


def wait_for(predicate, timeout: float = 2.0, interval: float = 0.01) -> bool:
    """Wait for a worker thread (the gate runs confirmed work off the Qt thread)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


# ── Phase 5: the world double ───────────────────────────────────────────────

class DemoWorld:
    """A controllable stand-in for the machine, at the observation seam only.

    It holds exactly the facts the Phase 4 vocabulary asks about — which
    windows exist, which is in front, what a control reads, which processes are
    alive — and hands back real `Observation` objects with real provenance. It
    never decides a verdict: comparison, polling and status classification all
    happen in the real verifier.
    """

    def __init__(self) -> None:
        self.windows: set = {DEMO_HANDLE}
        self.active: int = 0
        self.values: dict = {}
        self.running: set = set()
        #: What each capability actually did, in order. Tests assert against
        #: this list, so "did NEO really do that" has one answer.
        self.calls: list = []
        #: operation → how many more times it should report a transient failure.
        self.fail_times: dict = {}
        #: operation → an ErrorKind to fail with, permanently.
        self.fail_permanently: dict = {}
        #: When False, a capability reports success but changes nothing — the
        #: exact situation Phase 4 exists to catch.
        self.apply_effects: bool = True
        #: Which read number a control value becomes readable on. 1 means always;
        #: a higher value models a control that is not ready for the first
        #: polls, which is a real race on Windows and the honest reason for a
        #: bounded retry.
        self.control_value_visible_from: int = 1
        #: Which `set_value` attempt actually writes. 1 means the first one
        #: lands; 2 models "the first attempt reported success and the value was
        #: not there" — the situation Phase 4 exists to catch and the only
        #: honest justification for trying again.
        self.set_value_effects_after: int = 1
        self.control_reads: int = 0
        self.captures: int = 0
        self.remembered: dict = {}

    # -- the Phase 4 seam ---------------------------------------------------

    def observe(self, expectation):
        kind = expectation.kind
        target = expectation.target or {}

        def _answer(observed_kind, value, about, source=Source.WIN32):
            return Observation(kind=observed_kind, source=source, target=about,
                               value=value)

        if kind == ExpectationKind.WINDOW_EXISTS:
            handle = target.get("window_handle")
            exists = True if handle is None else int(handle) in self.windows
            return _answer(Kind.WINDOW_EXISTS, exists, f"window handle {handle}")
        if kind == ExpectationKind.WINDOW_CLOSED:
            handle = int(target.get("window_handle") or 0)
            return _answer(Kind.WINDOW_EXISTS, handle not in self.windows,
                           f"window handle {handle}")
        if kind == ExpectationKind.WINDOW_ACTIVE:
            handle = int(target.get("window_handle") or 0)
            return _answer(Kind.WINDOW_ACTIVE, self.active == handle,
                           f"window handle {handle}")
        if kind == ExpectationKind.CONTROL_EXISTS:
            return _answer(Kind.CONTROL_EXISTS, True, str(target.get("control_type")),
                           source=Source.UIA)
        if kind == ExpectationKind.CONTROL_VALUE:
            key = (int(target.get("window_handle") or 0),
                   str(target.get("control_type")))
            self.control_reads += 1
            # `type_into` (Phase 6) is the targeted form of `set_value` and
            # lands on the same key, so both count towards "has a write
            # actually happened yet".
            landed = (self.calls.count("set_value")
                      + self.calls.count("type_into")) >= self.set_value_effects_after
            value = self.values.get(key) if landed else None
            return _answer(Kind.CONTROL_VALUE, value, str(key), source=Source.UIA)
        if kind == ExpectationKind.CONTROL_STATE:
            return _answer(Kind.CONTROL_STATE, self.values.get(str(target.get("property"))),
                           str(target.get("property")), source=Source.UIA)
        if kind == ExpectationKind.APP_RUNNING:
            name = str(target.get("app_name") or "")
            return _answer(Kind.APP_RUNNING, name in self.running, name,
                           source=Source.APPS)
        return None

    # -- what the capabilities report ---------------------------------------

    def _failing(self, operation: str) -> Optional[TaskError]:
        remaining = self.fail_times.get(operation, 0)
        if remaining > 0:
            self.fail_times[operation] = remaining - 1
            return TaskError(message=f"{operation} timed out (test fixture)",
                             kind=ErrorKind.TIMEOUT)
        kind = self.fail_permanently.get(operation)
        if kind is not None:
            return TaskError(message=f"{operation} is not permitted (test fixture)",
                             kind=kind)
        return None


@contextlib.contextmanager
def observed_by(world: DemoWorld):
    """Answer Phase 4's questions from `world` for the duration of a test."""
    from core.verification import verifier as _verifier

    original = _verifier._observe

    def _look(expectation, cancel_event=None):
        return world.observe(expectation)

    _verifier._observe = _look
    try:
        yield world
    finally:
        _verifier._observe = original


# ── Phase 5: demo capabilities ──────────────────────────────────────────────
# These return the *structured* contract (ExecutionResult), because a goal step
# needs the data a real structured action reports — which window it opened, what
# it set — not just a sentence.

WORLD: DemoWorld = DemoWorld()


def _ok(operation: str, data: dict) -> ExecutionResult:
    return ExecutionResult(status=ExecStatus.SUCCESS, action="demo_control",
                           message=f"{operation} reported success",
                           data={"windows_operation": operation, **data})


def demo_launch(parameters=None, cancel_event=None):
    params = dict(parameters or {})
    WORLD.calls.append("launch")
    error = WORLD._failing("launch")
    if error is not None:
        return ExecutionResult(status=ExecStatus.FAILED, action="demo_control",
                               message=error.message, error=error,
                               data={"invoked": False})
    if WORLD.apply_effects:
        WORLD.windows.add(DEMO_HANDLE)
    return _ok("launch", {"window": {"handle": DEMO_HANDLE, "title": "Fixture window"}})


def demo_focus(parameters=None, cancel_event=None):
    params = dict(parameters or {})
    handle = int(_handle_of(params))
    WORLD.calls.append("focus")
    error = WORLD._failing("focus")
    if error is not None:
        return ExecutionResult(status=ExecStatus.FAILED, action="demo_control",
                               message=error.message, error=error,
                               data={"invoked": False})
    if WORLD.apply_effects:
        WORLD.active = handle
    return _ok("focus", {"window_handle": handle})


def demo_close(parameters=None, cancel_event=None):
    params = dict(parameters or {})
    handle = int(_handle_of(params))
    WORLD.calls.append("close")
    error = WORLD._failing("close")
    if error is not None:
        return ExecutionResult(status=ExecStatus.FAILED, action="demo_control",
                               message=error.message, error=error,
                               data={"invoked": False})
    if WORLD.apply_effects:
        WORLD.windows.discard(handle)
    return _ok("close", {"window_handle": handle})


def demo_set_value(parameters=None, cancel_event=None):
    params = dict(parameters or {})
    handle = int(_handle_of(params))
    control_type = str(params.get("control_type", "Document"))
    text = str(params.get("text", ""))
    WORLD.calls.append("set_value")
    error = WORLD._failing("set_value")
    if error is not None:
        return ExecutionResult(status=ExecStatus.FAILED, action="demo_control",
                               message=error.message, error=error,
                               data={"invoked": False})
    if WORLD.apply_effects:
        WORLD.values[(handle, control_type)] = text
    return _ok("set_value", {"window_handle": handle, "value": text})


def demo_type_into(parameters=None, cancel_event=None):
    """Phase 6's targeted text entry: write, then report what a read-back saw.

    Mirrors the real `type_into` closely enough to be useful: it records the
    method it used, and it can be told to *report* success without changing the
    control — which is exactly the situation Phase 4 exists to catch, and
    `DemoWorld.set_value_effects_after` already models it for `set_value`.
    """
    params = dict(parameters or {})
    handle = int(_handle_of(params))
    control_type = str(params.get("control_type", "Document"))
    text = str(params.get("text", ""))
    method = str(params.get("method", ""))
    WORLD.calls.append("type_into")
    error = WORLD._failing("type_into")
    if error is not None:
        return ExecutionResult(status=ExecStatus.FAILED, action="demo_control",
                               message=error.message, error=error,
                               data={"invoked": False})
    if WORLD.apply_effects:
        WORLD.values[(handle, control_type)] = text
    return _ok("type_into", {"window_handle": handle, "written": True,
                             "method": method or "value_pattern",
                             "characters": len(text),
                             "read_back_matches": True})


def demo_list(parameters=None, cancel_event=None):
    WORLD.calls.append("list")
    return _ok("list", {"windows": [{"handle": h} for h in sorted(WORLD.windows)]})


def demo_unsupported(parameters=None, cancel_event=None):
    return "NOT_SUPPORTED: this fixture refuses to do anything."


def demo_boom(parameters=None, cancel_event=None):
    raise RuntimeError("the fixture capability crashed")


def demo_needs_approval(parameters=None, cancel_event=None):
    """Park behind the real Phase 2 gate, exactly as windows_control does."""
    params = dict(parameters or {})
    WORLD.calls.append("needs_approval")
    if not params.get("approved"):
        parked = confirm.request(
            key="demo:irreversible", title="Do the irreversible thing?",
            detail="A test is asking for permission.",
            run=lambda: demo_control({**params, "approved": True}))
        if parked.startswith("[CONFIRMATION_PENDING]"):
            return parked
        return ExecutionResult(
            status=ExecStatus.FAILED, action="demo_control", message=parked,
            error=TaskError(message="Confirmation was required but unavailable.",
                            kind=ErrorKind.AUTHORIZATION_UNAVAILABLE),
            data={"invoked": False, "awaiting_confirmation": False})
    WORLD.calls.append("approved")
    return _ok("needs_approval", {"approved": True})


def demo_control(parameters=None, cancel_event=None):
    """One capability with several operations, like the real windows_control."""
    params = dict(parameters or {})
    operation = str(params.get("operation", ""))
    table = {"launch": demo_launch, "focus": demo_focus, "close": demo_close,
             "set_value": demo_set_value, "list": demo_list,
             "type_into": demo_type_into,
             "unsupported": demo_unsupported, "boom": demo_boom,
             "needs_approval": demo_needs_approval}
    # The operation names the real windows_control uses, so a goal recipe can
    # be exercised without renaming anything it plans.
    table.update({"launch_app": demo_launch, "focus_window": demo_focus,
                  "close_window": demo_close, "app_running": demo_list})
    handler = table.get(operation)
    if handler is None:
        return ("NOT_SUPPORTED: this fixture has no operation "
                f"'{operation}'.")
    return handler(params, cancel_event)


def _handle_of(params: dict) -> int:
    value = params.get("window_handle")
    if isinstance(value, dict):            # an unresolved {"$from": ...} ref
        value = value.get("$from")
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


#: The Phase 4 contract for the demo capability, declared where the execution
#: layer and the planner both look for it. Nothing here is model-writable: the
#: planner can only choose *which* operation runs, never what gets checked.
def expectation_for(params: dict, result_data: dict):
    operation = str((params or {}).get("operation", "")).replace("_app", "").replace(
        "_window", "").replace("_control", "")
    data = dict(result_data or {})

    class _Result:
        pass

    _Result.data = data

    if operation == "launch":
        window = data.get("window") or data.get("already_open") or {}
        handle = window.get("handle") or DEMO_HANDLE
        return (None, window_exists({"window_handle": handle}, timeout=0.6))
    if operation == "focus":
        return (None, window_active(params, timeout=0.6))
    if operation == "close":
        return (None, window_closed(params, timeout=0.6))
    if operation == "set_value":
        return (None, control_value(params, str(params.get("text", "")), timeout=0.6))
    if operation == "type_into":
        return (None, control_value(params, str(params.get("text", "")), timeout=0.6))
    return (None, None)


#: The registry a goal is planned against in the tests. `demo_control` is the
#: one capability, and `demo_singleton` is a second one so ordering and
#: dependency tests have two distinct things to depend on.
DEMO_ACTIONS = (
    ("demo_control", demo_control),
    ("demo_singleton", demo_list),
)


def demo_plan(*operations):
    """Raw step dicts for a plan, one step per (operation, extra) pair."""
    steps = []
    previous = None
    for index, entry in enumerate(operations):
        operation, extra = (entry if isinstance(entry, tuple) else (entry, {}))
        step = {"id": f"s{index + 1}", "operation": operation, **dict(extra)}
        if previous:
            step["depends_on"] = [previous]
        previous = step["id"]
        steps.append(step)
    return steps


def make_goal_stack(tmp: pathlib.Path, world: Optional[DemoWorld] = None,
                    limits: Optional[Limits] = None, **kwargs):
    """A complete, real Phase 5 stack over the demo capabilities.

    Returns `(manager, layer, planner, executor, world)`. Every component is the
    production class; only the capabilities and the observation are fixtures.
    """
    manager = make_manager(tmp)
    registry = kwargs.pop("actions", None) or make_action_registry(*DEMO_ACTIONS)
    layer = make_layer(manager, actions=registry, logger=Sink())
    layer.bind_confirmation_gate()
    global WORLD
    if world is not None:
        # The fixture capabilities read this module global at call time, so a
        # test that supplies its own world is really running against it.
        WORLD = world
    chosen = world if world is not None else WORLD
    planner = Planner(actions=registry, logger=Sink())
    executor = GoalExecutor(
        manager=manager, layer=layer, planner=planner, limits=limits or Limits(),
        logger=Sink(), notify=Sink(),
        world_capture=capturing(chosen),
        **kwargs)
    return manager, layer, planner, executor, chosen


class _CountingWorld:
    """A world capture that counts reads and returns the demo world's facts."""

    def __init__(self, world: DemoWorld) -> None:
        self.world = world

    def capture(self, **_kwargs):
        self.world.captures += 1
        return self

    def get(self, key: str, default=None):
        return self.world.remembered.get(key, default)

    def remember(self, key: str, value):
        self.world.remembered[key] = value


def capturing(world: DemoWorld):
    """The world-capture callable the executor is given during a test."""
    return _CountingWorld(world).capture


def make_goal_history(tmp: pathlib.Path, name: str = "goals.json",
                      max_goals: int = 100, **kwargs) -> GoalHistory:
    """A GoalHistory whose file lives in a temp directory — never the real one."""
    return GoalHistory(store=GoalStore(path=tmp / name, max_goals=max_goals,
                                       logger=kwargs.get("logger")))


@contextlib.contextmanager
def reset_demo_world():
    """Give each test a clean demo world, so no test can pass on another's state."""
    global WORLD
    previous = WORLD
    WORLD = DemoWorld()
    try:
        yield WORLD
    finally:
        WORLD = previous


@contextlib.contextmanager
def audited(*names: str):
    """Temporarily declare test fixtures plannable.

    Phase 6 refuses a capability that is registered but absent from
    `core.capabilities.AUDIT` — an unaudited capability is not an automatically
    permitted one, and that asymmetry is deliberate. Test fixtures have to be
    audited the same way a real capability would be, which is what this does,
    through the same table, for the duration of the test.
    """
    from core import capabilities

    previous = {name: capabilities.ALL_CAPABILITIES.get(name) for name in names}
    for name in names:
        capabilities.ALL_CAPABILITIES[name] = capabilities.Capability(
            action=name, module="tests/support.py",
            verdict=capabilities.EXISTING_WORKING, risk=capabilities.LOW,
            summary="test fixture", verifiable=True,
            note="registered by the test suite, audited here for its run only")
    try:
        yield
    finally:
        for name, before in previous.items():
            if before is None:
                capabilities.ALL_CAPABILITIES.pop(name, None)
            else:
                capabilities.ALL_CAPABILITIES[name] = before


@contextlib.contextmanager
def marked_unsafe(*names: str):
    """Temporarily mark test fixtures UNSAFE, whatever the audit says.

    The other half of `audited`, and the one that proves the gate has teeth:
    a capability that is *registered and audited* can still be refused, because
    the verdict is what the planner reads.
    """
    from core import capabilities

    previous = {name: capabilities.ALL_CAPABILITIES.get(name) for name in names}
    for name in names:
        capabilities.ALL_CAPABILITIES[name] = capabilities.Capability(
            action=name, module="tests/support.py", verdict=capabilities.UNSAFE,
            risk=capabilities.HIGH, summary="test fixture marked unsafe",
            note="marked unsafe by the test suite for the duration of the test")
    try:
        yield
    finally:
        for name, before in previous.items():
            if before is None:
                capabilities.ALL_CAPABILITIES.pop(name, None)
            else:
                capabilities.ALL_CAPABILITIES[name] = before


def demo_answer(parameters=None, cancel_event=None):
    """A read-only fixture capability, for recipes that need a second name."""
    return {"answer": "fixture"}


#: The registry Phase 6's tests plan against. The recipes name the *real*
#: action names — `windows_control`, `web_search`, `open_app` — so the tests
#: exercise the same steps production would, with the same handlers standing in
#: for the real implementations. The Phase 5 tuple above is left untouched so
#: no Phase 5 test changes meaning.
PLANNING_ACTIONS = DEMO_ACTIONS + (
    ("windows_control", demo_control),
    ("web_search", demo_answer),
    ("open_app", demo_answer),
    ("reminder", demo_answer),
)