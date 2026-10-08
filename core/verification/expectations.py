"""
Expected state — what "it worked" has to mean before anything runs.

A verification step is only meaningful if someone said what it was checking.
This module is that someone, and it is deliberately *not* the model.

WHY THE MODEL DOES NOT WRITE EXPECTATIONS
    The tempting design is to let Gemini write "check that the window is open",
    which arrives as code or as a shell command, and both are the Phase 1
    disaster all over again. Here an expectation is a small structured record
    chosen from a fixed vocabulary by ordinary Python, based on which operation
    ran and which parameters were passed. A model picks `focus_window`; it never
    picks how focus gets verified, and it cannot invent a new check.

WHAT AN EXPECTATION IS NOT
    It is not a promise that the action will succeed, and it is not a post-hoc
    rationalisation. `preconditions()` are captured *before* the action runs, so
    "the toggle changed state" compares against what was really there first —
    not against what the action claimed.

THE HONEST DEFAULT
    An operation with no deterministic observable consequence — invoking an
    arbitrary button, clicking a coordinate — gets `None`. No expectation means
    no verification, which is reported as NOT_AVAILABLE rather than dressed up
    as a pass.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

#: Bounded polling defaults. An expectation is never waited on forever, and the
#: whole verification stage is cancellable between polls.
DEFAULT_TIMEOUT = 6.0
DEFAULT_INTERVAL = 0.4


class ExpectationKind(str):
    WINDOW_EXISTS     = "window_exists"
    WINDOW_CLOSED     = "window_closed"
    WINDOW_ACTIVE     = "window_active"
    CONTROL_EXISTS    = "control_exists"
    CONTROL_VALUE     = "control_value"
    CONTROL_STATE     = "control_state"
    APP_RUNNING       = "app_running"
    CONTROL_CHANGED   = "control_state_changed"


@dataclass(frozen=True)
class Expectation:
    """One check: an observable fact, and what it should be."""

    kind: str
    target: dict = field(default_factory=dict)
    expected: Any = None
    property: str = ""                 # which state, for CONTROL_STATE
    compare: str = "equals"            # equals | not_equals | changed | is_true | exists
    timeout: float = DEFAULT_TIMEOUT
    interval: float = DEFAULT_INTERVAL
    note: str = ""

    def to_dict(self) -> dict:
        return {"kind": self.kind, "target": dict(self.target),
                "expected": self.expected, "property": self.property,
                "compare": self.compare, "timeout": self.timeout,
                "interval": self.interval, "note": self.note}

    @staticmethod
    def from_dict(data: dict) -> "Expectation":
        return Expectation(kind=str(data.get("kind", "")),
                           target=dict(data.get("target") or {}),
                           expected=data.get("expected"),
                           property=str(data.get("property") or ""),
                           compare=str(data.get("compare") or "equals"),
                           timeout=float(data.get("timeout") or DEFAULT_TIMEOUT),
                           interval=float(data.get("interval") or DEFAULT_INTERVAL),
                           note=str(data.get("note") or ""))

    def describe(self) -> str:
        """Plain English a log or a task record can carry."""
        what = self.target.get("window_handle") or self.target.get("title") \
            or self.target.get("element_name") or self.target.get("app_name") \
            or self.target.get("automation_id") or "the target"
        if self.kind in (ExpectationKind.WINDOW_EXISTS, ExpectationKind.CONTROL_EXISTS,
                         ExpectationKind.APP_RUNNING):
            return f"{what} exists"
        if self.kind == ExpectationKind.WINDOW_CLOSED:
            return f"{what} no longer exists"
        if self.kind == ExpectationKind.WINDOW_ACTIVE:
            return f"{what} is the foreground window"
        if self.kind == ExpectationKind.CONTROL_VALUE:
            return f"{what} reads {self.expected!r}"
        if self.kind == ExpectationKind.CONTROL_CHANGED:
            return f"{what} changed {self.property}"
        return f"{what}: {self.property} is {self.expected!r}"


# ── constructors ────────────────────────────────────────────────────────────

def _window_selector(params: dict) -> dict:
    return {k: params[k] for k in ("window_handle", "title", "process_id")
            if params.get(k)}


def window_exists(params: dict, timeout: float = DEFAULT_TIMEOUT) -> Expectation:
    return Expectation(kind=ExpectationKind.WINDOW_EXISTS, target=_window_selector(params),
                       expected=True, compare="equals", timeout=timeout,
                       note="the window exists and Windows can address it")


def window_closed(params: dict, timeout: float = DEFAULT_TIMEOUT) -> Expectation:
    # The observation for this is already a boolean meaning "it is gone", so the
    # expectation is "that boolean is True". Comparing it against False — or
    # checking "is_true" against a False expectation — inverts the whole check
    # and verifies a window that is still open, which is the exact opposite of
    # what this phase exists to prevent.
    return Expectation(kind=ExpectationKind.WINDOW_CLOSED, target=_window_selector(params),
                       expected=True, compare="equals", timeout=timeout,
                       note="the window that was closed is gone, not merely hidden")


def window_active(params: dict, timeout: float = DEFAULT_TIMEOUT) -> Expectation:
    return Expectation(kind=ExpectationKind.WINDOW_ACTIVE, target=_window_selector(params),
                       expected=True, compare="equals", timeout=timeout,
                       note="Windows reports this window as the foreground one")


def control_exists(params: dict, timeout: float = DEFAULT_TIMEOUT) -> Expectation:
    return Expectation(kind=ExpectationKind.CONTROL_EXISTS, target=dict(params),
                       expected=True, compare="equals", timeout=timeout)


def control_value(params: dict, text: str,
                  timeout: float = DEFAULT_TIMEOUT) -> Expectation:
    return Expectation(kind=ExpectationKind.CONTROL_VALUE, target=dict(params),
                       expected=text, compare="equals", timeout=timeout,
                       note="the value read back from the control")


def control_state(params: dict, property_name: str, expected: Any,
                  timeout: float = DEFAULT_TIMEOUT) -> Expectation:
    return Expectation(kind=ExpectationKind.CONTROL_STATE, target=dict(params),
                       property=property_name, expected=expected, compare="equals",
                       timeout=timeout)


def app_running(app_name: str, timeout: float = DEFAULT_TIMEOUT) -> Expectation:
    return Expectation(kind=ExpectationKind.APP_RUNNING, target={"app_name": app_name},
                       expected=True, compare="equals", timeout=timeout)


# ── mapping operations to expectations ──────────────────────────────────────

#: Windows operations whose effect `expected_after` can always check.
#: `invoke` is absent on purpose: a button can mean anything, and a rule that
#: claims to know would be an invention rather than a verification.
VERIFIABLE_OPERATIONS = (
    "launch_app", "app_running", "focus_window", "close_window", "set_value",
    # Phase 6. `type_into` reads the value back, so it carries the same
    # guarantee `set_value` always did; `resolve_window` and `dismiss_dialog`
    # are decided by facts about a window, which are exactly what Phase 4 was
    # built to observe.
    "type_into", "resolve_window", "dismiss_dialog",
)

#: Phase 6. Operations that change the machine and have no reliable observable
#: consequence. Listed explicitly rather than left as a gap, because "we did
#: not check this" is a decision somebody should be able to see. Every one of
#: these returns `None` and is reported as NOT_AVAILABLE — which is the honest
#: answer, not a pass and not a failure.
UNVERIFIED_BY_DESIGN = (
    # Reading operations: they cannot change what they measure, so verifying
    # them would mean verifying the reader.
    "list_windows", "active_window", "locate_window", "list_controls",
    "find_control", "find_controls", "describe_controls", "get_value",
    "list_processes", "process_info", "desktop_snapshot", "cursor_position",
    "classify_dialog",
    # Actions with no determinate consequence: "Invoke() returned" is not
    # "the application responded", and "a click was sent" is not "it clicked".
    "invoke", "press_keys", "type_text","click", "move_mouse", "scroll", "drag",
    # `window_state` and `focus_control` do have observable consequences, but
    # the Phase 4 observation vocabulary has no way to read "is this window
    # minimized" or "does this control have keyboard focus" — so they are
    # reported as NOT_AVAILABLE until it does, rather than approximated.
    "window_state", "focus_control",
    # `dismiss_dialog` is *not* here: it is checkable, but only against the
    # window the action actually dismissed, which is a result rather than a
    # parameter. See the `dismiss_dialog` branch in `expected_after`.
)

#: Operations that are verifiable only when the action itself observed the state
#: it changed — a toggle that reported no state, or an element that publishes no
#: pattern, yields `None` and is reported as NOT_AVAILABLE. Listing them here
#: means "checkable in principle", never "always checked".
CONDITIONALLY_VERIFIABLE_OPERATIONS = ("toggle", "select", "expand", "collapse")


def expected_after(operation: str, params: dict, result: Any = None,
                   timeout: float = DEFAULT_TIMEOUT) -> Optional[Expectation]:
    """What should be observably true once `operation` has run.

    `result` is the façade result, used only where the operation discovered the
    target itself (a launch reports which window it opened). Nothing here reads
    the model's own verdict about whether it worked — that verdict is exactly
    what Phase 4 exists to stop trusting.
    """
    params = params or {}
    data = getattr(result, "data", {}) or {}

    if operation == "launch_app":
        name = params.get("app_name", "")
        window = data.get("window") or data.get("already_open") or {}
        if window.get("handle"):
            return window_exists({"window_handle": window["handle"]}, timeout=timeout)
        # Phase 6: a launch that produced a process and no window is not a
        # failure — a tray utility or a slow launcher looks exactly like this.
        # `data["detection"]` already says which of those happened; the check
        # itself stays the narrowest true one, which is that the process the
        # launch started is alive.
        return app_running(name, timeout=timeout)

    if operation == "focus_window":
        return window_active(params, timeout=timeout)

    if operation == "close_window":
        return window_closed(params, timeout=timeout)

    if operation == "set_value":
        text = params.get("text")
        if text is None:
            return None
        return control_value(params, str(text), timeout=timeout)

    if operation == "type_into":
        # Phase 6. The same contract as `set_value`, because `type_into` ends
        # with the same read-back: the text is either in the control or it is
        # not, and "the keys were sent" is not the same claim.
        text = params.get("text")
        if text is None:
            return None
        if data.get("written") is False:
            return None              # nothing was written; nothing to check
        return control_value(params, str(text), timeout=timeout)

    if operation == "resolve_window":
        window = data.get("window") or {}
        if window.get("handle"):
            return window_exists({"window_handle": window["handle"]},
                                 timeout=timeout)
        # Without a reported window the only thing that can still be true is
        # the one the request itself named, and that is a real check rather
        # than a formality — it is what "resolve" promised.
        selector = _window_selector(params)
        return window_exists(selector, timeout=timeout) if selector else None

    if operation == "dismiss_dialog":
        dialog = data.get("dialog") or {}
        window = dialog.get("window") or {}
        handle = window.get("handle")
        if handle and data.get("dismissed"):
            return window_closed({"window_handle": handle}, timeout=timeout)
        # The caller named the window; dismissing it means it is gone.
        selector = _window_selector(params)
        return window_closed(selector, timeout=timeout) if selector else None

    if operation == "toggle":
        state = data.get("state_after")
        if state is None:
            # The control published no toggle state, so there is nothing to
            # compare against. Saying so beats asserting the action worked.
            return None
        return control_state(params, "toggle_state", state, timeout=timeout)

    if operation in ("select", "expand", "collapse"):
        prop = {"select": "is_selected", "expand": "is_expanded",
                "collapse": "is_expanded"}[operation]
        expected = data.get("selected") if prop == "is_selected" else data.get("expanded")
        if expected is None:
            return None
        return control_state(params, prop, bool(expected), timeout=timeout)

    if operation == "app_running":
        return app_running(params.get("app_name", ""), timeout=timeout)

    # `invoke` is deliberately absent. A button can mean anything; claiming a
    # universal rule for "the click did what its label promised" is the exact
    # invention this phase is built to prevent.
    return None


def preconditions(operation: str, params: dict) -> Optional[Expectation]:
    """State worth capturing *before* the action runs.

    Only a toggle has a meaningful "did it actually change?" check, and that
    needs the previous state read before anything is pressed.
    """
    if operation == "toggle":
        return control_state(params or {}, "toggle_state", None, timeout=1.5)
    return None