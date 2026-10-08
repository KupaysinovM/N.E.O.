"""
Observation — reading what is actually true right now.

Phase 3 gave NEO hands. Phase 4 starts by giving it eyes, and the first rule of
an eye is that it has to say where what it saw came from.

WHAT AN OBSERVATION IS
    A single fact read from the machine, with enough metadata to answer "how do
    you know?" without trusting the reader: which subsystem produced it, when,
    what it was about, whether it is still fresh, and whether the value was
    withheld because it was sensitive.

WHAT AN OBSERVATION IS NOT
    It is not an inference. If Windows would not tell us something, the
    observation carries an error kind and no value — never a plausible guess,
    never a default that reads like an answer.

WHY THIS REUSES THE PHASE 3 ADAPTER
    Everything here goes through `core.windows.control`, the same façade the
    actions use. There is exactly one Windows implementation in this project;
    adding a second one for verification is how the two would start disagreeing
    about what the desktop looks like.

SENSITIVITY IS ENFORCED HERE, NOT ASKED FOR NICELY
    Reading a password field through UI Automation is technically possible and
    is exactly what must not happen. `control_value` refuses before it reads,
    and the observation that comes back says "withheld" rather than carrying a
    secret into task history, events or the world state.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from core.windows import control
from core.windows.errors import WindowsError, WindowsErrorKind


class Source(str):
    """Which subsystem produced a value. Provenance, not a confidence score."""

    WIN32 = "windows_win32"
    UIA = "windows_uia"
    APPS = "windows_apps"
    UNAVAILABLE = "unavailable"


class Kind(str):
    WINDOW = "window"
    ACTIVE_WINDOW = "active_window"
    WINDOW_EXISTS = "window_exists"
    WINDOW_ACTIVE = "window_active"
    CONTROL = "control"
    CONTROL_EXISTS = "control_exists"
    CONTROL_VALUE = "control_value"
    CONTROL_STATE = "control_state"
    APP_RUNNING = "app_running"


class Freshness(str):
    """How much this observation is still worth trusting."""

    CURRENT = "current"          # read just now, in this call
    STALE = "stale"              # read earlier; the world may have moved on
    UNKNOWN = "unknown"          # could not be read, so freshness is moot


class Sensitivity(str):
    SAFE = "safe"
    WITHHELD = "sensitive_withheld"


@dataclass(frozen=True)
class Observation:
    """One observed fact, with everything needed to weigh it."""

    kind: str
    source: str
    target: str = ""
    value: Any = None
    observed_at: float = field(default_factory=time.time)
    freshness: str = Freshness.CURRENT
    sensitivity: str = Sensitivity.SAFE
    error_kind: str = ""                 # a WindowsErrorKind, when it failed
    note: str = ""
    observation_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    # -- truth -------------------------------------------------------------

    @property
    def ok(self) -> bool:
        """True only when a real value was read. An error is never a success."""
        return not self.error_kind and self.value is not None

    @property
    def ambiguous(self) -> bool:
        return self.error_kind == WindowsErrorKind.ELEMENT_AMBIGUOUS

    @property
    def stale(self) -> bool:
        return self.error_kind == WindowsErrorKind.ELEMENT_STALE

    @property
    def cancelled(self) -> bool:
        return self.error_kind == WindowsErrorKind.CANCELLED

    # -- shape -------------------------------------------------------------

    def to_dict(self) -> dict:
        return {"observation_id": self.observation_id, "kind": self.kind,
                "source": self.source, "target": self.target, "value": self.value,
                "observed_at": self.observed_at, "freshness": self.freshness,
                "sensitivity": self.sensitivity, "error_kind": self.error_kind,
                "note": self.note}

    def describe(self) -> str:
        """One line a log or a task record can carry without lying."""
        when = time.strftime("%H:%M:%S", time.localtime(self.observed_at))
        if not self.ok:
            return f"{self.kind} of {self.target or 'the target'}: not observed " \
                   f"({self.error_kind or 'no value'}) via {self.source} at {when}"
        if self.sensitivity == Sensitivity.WITHHELD:
            return f"{self.kind} of {self.target}: value withheld (sensitive) " \
                   f"via {self.source} at {when}"
        return f"{self.kind} of {self.target or 'the target'}: {self.value!r} " \
               f"via {self.source} at {when}"


# ── failure helper ──────────────────────────────────────────────────────────

def _failure(kind: str, source: str, target: str, error: Exception,
             note: str = "") -> Observation:
    error_kind = (error.kind if isinstance(error, WindowsError)
                  else WindowsErrorKind.OS_ERROR)
    message = getattr(error, "message", "") or str(error)
    return Observation(kind=kind, source=source, target=target, value=None,
                       freshness=Freshness.UNKNOWN,
                       error_kind=str(error_kind),
                       note=note or message)


def _cancelled(kind: str, source: str, target: str) -> Observation:
    return Observation(kind=kind, source=source, target=target, value=None,
                       freshness=Freshness.UNKNOWN,
                       error_kind=WindowsErrorKind.CANCELLED,
                       note="Cancelled before the state was read.")


def _cancelled_check(cancel_event) -> bool:
    return cancel_event is not None and cancel_event.is_set()


def _describe_target(title: str = "", process_id: Optional[int] = None,
                     window_handle: Optional[int] = None) -> str:
    if window_handle:
        return f"window handle {window_handle}"
    if title:
        return f"window titled '{title}'" + (f" (pid {process_id})" if process_id else "")
    return f"window owned by process {process_id}" if process_id else "the active window"


# ── window observations ─────────────────────────────────────────────────────

def window_exists(title: str = "", process_id: Optional[int] = None,
                  window_handle: Optional[int] = None,
                  cancel_event=None) -> Observation:
    """Does a window matching this description exist right now?

    Existence is answered by asking Windows, never by remembering: a handle
    from an earlier observation is re-checked, because windows close.

    "Not there" is an *observation*, not a failed observation: the value is
    False and no error is recorded, because Windows did answer the question.
    Only a lookup that could not be answered at all — ambiguous, refused, OS
    error — carries an error kind, and those must never be mistaken for
    absence. Conflating the two is how "the window closed" gets verified by a
    lookup that never happened.
    """
    target = _describe_target(title, process_id, window_handle)
    if _cancelled_check(cancel_event):
        return _cancelled(Kind.WINDOW_EXISTS, Source.WIN32, target)
    result = control.locate_window(title=title, process_id=process_id,
                                   window_handle=window_handle, cancel_event=cancel_event)
    if result.status != "SUCCESS":
        kind = str(result.error.kind) if result.error else WindowsErrorKind.WINDOW_NOT_FOUND
        if kind == WindowsErrorKind.WINDOW_NOT_FOUND:
            return Observation(kind=Kind.WINDOW_EXISTS, source=Source.WIN32,
                               target=target, value=False,
                               freshness=Freshness.CURRENT,
                               note="No window matches this description.")
        return Observation(kind=Kind.WINDOW_EXISTS, source=Source.WIN32, target=target,
                           value=None, freshness=Freshness.UNKNOWN,
                           error_kind=kind, note=result.message)
    window = result.data["window"]
    return Observation(kind=Kind.WINDOW_EXISTS, source=Source.WIN32, target=target,
                       value=True,
                       note=f"'{window['title']}' (pid {window['process_id']}, "
                            f"{window['process_name'] or 'unknown process'})")


def window_snapshot(title: str = "", process_id: Optional[int] = None,
                    window_handle: Optional[int] = None,
                    cancel_event=None) -> Observation:
    """One window's current, real description — or the reason there is none."""
    target = _describe_target(title, process_id, window_handle)
    if _cancelled_check(cancel_event):
        return _cancelled(Kind.WINDOW, Source.WIN32, target)
    result = control.locate_window(title=title, process_id=process_id,
                                   window_handle=window_handle, cancel_event=cancel_event)
    if result.status != "SUCCESS":
        return _failure(Kind.WINDOW, Source.WIN32, target,
                        result.error or WindowsError(result.message))
    return Observation(kind=Kind.WINDOW, source=Source.WIN32, target=target,
                       value=result.data["window"])


def active_window(cancel_event=None) -> Observation:
    """Which window Windows says has the foreground right now."""
    if _cancelled_check(cancel_event):
        return _cancelled(Kind.ACTIVE_WINDOW, Source.WIN32, "the foreground window")
    result = control.active_window(cancel_event=cancel_event)
    if result.status != "SUCCESS":
        return _failure(Kind.ACTIVE_WINDOW, Source.WIN32, "the foreground window",
                        result.error or WindowsError(result.message))
    window = result.data["window"]
    return Observation(kind=Kind.ACTIVE_WINDOW, source=Source.WIN32,
                       target=f"foreground window handle {window['handle']}",
                       value=window)


def window_is_active(window_handle: int, cancel_event=None) -> Observation:
    """Is this exact window the foreground one?

    The handle is compared against the live foreground handle every time. A
    handle remembered from earlier is never trusted on its own.
    """
    target = f"window handle {window_handle}"
    if _cancelled_check(cancel_event):
        return _cancelled(Kind.WINDOW_ACTIVE, Source.WIN32, target)
    current = active_window(cancel_event=cancel_event)
    if not current.ok:
        return Observation(kind=Kind.WINDOW_ACTIVE, source=Source.WIN32, target=target,
                           value=None, freshness=Freshness.UNKNOWN,
                           error_kind=current.error_kind,
                           note=current.note)
    return Observation(kind=Kind.WINDOW_ACTIVE, source=Source.WIN32, target=target,
                       value=int(current.value.get("handle", 0)) == int(window_handle),
                       note=f"foreground is {current.value.get('title')!r}")


def app_running(name: str, cancel_event=None) -> Observation:
    """Is a process with this name alive? Read-only, and it never launches."""
    if _cancelled_check(cancel_event):
        return _cancelled(Kind.APP_RUNNING, Source.APPS, name)
    result = control.app_running(name, cancel_event=cancel_event)
    if result.status != "SUCCESS":
        return _failure(Kind.APP_RUNNING, Source.APPS, name,
                        result.error or WindowsError(result.message))
    return Observation(kind=Kind.APP_RUNNING, source=Source.APPS, target=name,
                       value=bool(result.data.get("running")),
                       note=f"{len(result.data.get('processes', []))} matching process(es)")


# ── control observations ────────────────────────────────────────────────────

def _control_target(params: dict) -> str:
    bits = []
    if params.get("window_handle"):
        bits.append(f"handle {params['window_handle']}")
    if params.get("title"):
        bits.append(f"'{params['title']}'")
    if params.get("automation_id"):
        bits.append(f"automation_id={params['automation_id']}")
    if params.get("element_name"):
        bits.append(f"name='{params['element_name']}'")
    if params.get("control_type"):
        bits.append(params["control_type"])
    return "control " + ", ".join(bits) if bits else "control"


def control_exists(params: dict, cancel_event=None) -> Observation:
    """Does exactly one control match this description? Two is not one."""
    target = _control_target(params)
    if _cancelled_check(cancel_event):
        return _cancelled(Kind.CONTROL_EXISTS, Source.UIA, target)
    result = control.find_control(params, title=params.get("title", ""),
                                  process_id=params.get("process_id"),
                                  window_handle=params.get("window_handle"),
                                  cancel_event=cancel_event)
    if result.status == "SUCCESS":
        element = result.data["control"]
        return Observation(kind=Kind.CONTROL_EXISTS, source=Source.UIA, target=target,
                           value=True, note=element.get("describe") or "")
    return Observation(kind=Kind.CONTROL_EXISTS, source=Source.UIA, target=target,
                       value=False, freshness=Freshness.CURRENT,
                       error_kind=str(result.error.kind if result.error
                                      else WindowsErrorKind.ELEMENT_NOT_FOUND),
                       note=result.message)


def control_value(params: dict, cancel_event=None) -> Observation:
    """Read a control's current value — or refuse, if it holds a credential.

    A sensitive field never produces a value here. The refusal is part of the
    observation, because "this field exists and NEO will not read it" is the
    honest fact about it.
    """
    target = _control_target(params)
    if _cancelled_check(cancel_event):
        return _cancelled(Kind.CONTROL_VALUE, Source.UIA, target)
    result = control.get_control_value(params, cancel_event=cancel_event)
    if result.status == "SUCCESS":
        return Observation(kind=Kind.CONTROL_VALUE, source=Source.UIA, target=target,
                           value=result.data.get("value"))
    sensitive = (result.error is not None
                 and result.error.kind == WindowsErrorKind.ACCESS_DENIED)
    return Observation(kind=Kind.CONTROL_VALUE, source=Source.UIA, target=target,
                       value=None, freshness=Freshness.UNKNOWN,
                       sensitivity=(Sensitivity.WITHHELD if sensitive
                                    else Sensitivity.SAFE),
                       error_kind=str(result.error.kind if result.error else ""),
                       note=result.message)


def control_state(params: dict, property_name: str, cancel_event=None) -> Observation:
    """Read toggle/selected/expanded/enabled state without touching the control."""
    target = _control_target(params)
    if _cancelled_check(cancel_event):
        return _cancelled(Kind.CONTROL_STATE, Source.UIA, target)
    result = control.read_control_state({**params, "property": property_name},
                                        cancel_event=cancel_event)
    if result.status == "SUCCESS":
        return Observation(kind=Kind.CONTROL_STATE, source=Source.UIA, target=target,
                           value=result.data.get("value"),
                           note=f"{property_name} via {result.data.get('pattern')}")
    return _failure(Kind.CONTROL_STATE, Source.UIA, target,
                    result.error or WindowsError(result.message))