"""
The façade every other part of NEO uses to reach Windows.

This is the contract. `core/windows/win32.py` and `core/windows/uia.py` are one
implementation of it on Windows; a future macOS or Linux adapter would implement
the same functions and nothing above this line would change. That is the whole
point of keeping the boundary: the action layer, the task manager and the
execution layer never learn which OS they are on.

Every function returns a `WindowsResult`. It carries what was attempted, what
was actually reported, how long it took, and — when it failed — which named
failure it was. Nothing here returns a bare string and nothing here claims more
than the Windows API told it.

PHASE 6 ADDITIONS
    Four capabilities were added here rather than beside this façade, because
    there is exactly one path to Windows in this project and a second one would
    be how the two started disagreeing:

      * `resolve_window` — scored window targeting that refuses to guess between
        two equally good matches (core/windows/targeting.py);
      * `find_controls` / `describe_controls` — bounded *structured* discovery,
        so the answer to "what can I press here" is a summary rather than a
        4,000-element tree (core/windows/discovery.py);
      * `type_into` — text entry that identifies the target, verifies focus,
        writes, and reads the value back, instead of typing into whatever
        happens to be foreground (core/windows/typing.py);
      * `classify_dialog` / `dismiss_dialog` — knowing what kind of window is
        blocking, and never automating an authentication or permission dialog
        (core/windows/dialogs.py).

    `launch_app` now reports a `detection` as well as a process, because
    "a process started" and "there is a window NEO can drive" are different
    facts and only one of them is usually what was meant.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import core.windows as _boundary
from core.windows.errors import (
    WindowsError,
    WindowsErrorKind,
    cancelled as cancelled_error,
    invalid_argument,
)
from core.windows.identifiers import ElementQuery
from core.windows.models import ProcessInfo, UIElement, WindowInfo

# Default ceilings. The model reads these results; a 4,000-control dump is not
# information, it is a way to spend a context window.
DEFAULT_WINDOW_LIMIT = 25
DEFAULT_CONTROL_LIMIT = 60
MAX_CONTROL_LIMIT = 300
MAX_DEPTH = 12


@dataclass
class WindowsResult:
    """The outcome of one Windows operation."""

    operation: str
    status: str = "SUCCESS"
    target: str = ""
    message: str = ""
    data: dict = field(default_factory=dict)
    error: Optional[WindowsError] = None
    started_at: float = 0.0
    completed_at: float = 0.0

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def duration(self) -> float:
        return round(max(0.0, (self.completed_at or 0.0) - (self.started_at or 0.0)), 4)

    def to_dict(self) -> dict:
        return {"operation": self.operation, "status": self.status,
                "target": self.target, "message": self.message,
                "data": dict(self.data), "duration_seconds": self.duration,
                "error": self.error.to_dict() if self.error else None}


def _require_supported():
    if not _boundary.is_supported():
        raise WindowsError(WindowsErrorKind.OS_ERROR, _boundary.unavailable_reason())


def _check_cancel(cancel_event) -> None:
    """Phase 2's boundary: a cancelled task stops before it touches Windows."""
    if cancel_event is not None and cancel_event.is_set():
        raise cancelled_error()


def _run(operation: str, target: str, fn: Callable, cancel_event=None) -> WindowsResult:
    """Execute one Windows call, recording what happened either way.

    The status mapping is deliberate: an unavailable platform or a
    not-implemented control is NOT_AVAILABLE/NOT_SUPPORTED rather than FAILED,
    so the model can tell "this machine cannot" from "this went wrong".
    """
    started = time.time()
    try:
        _require_supported()
        _check_cancel(cancel_event)
    except WindowsError as e:
        completed = time.time()
        if e.kind == WindowsErrorKind.CANCELLED:
            status = "CANCELLED"
        elif e.kind == WindowsErrorKind.OS_ERROR and _boundary.unavailable_reason():
            status = "NOT_AVAILABLE"       # the platform, not the operation
        else:
            status = "FAILED"
        return WindowsResult(operation=operation, status=status, target=target,
                             message=e.message, error=e,
                             started_at=started, completed_at=completed)
    try:
        data = fn() or {}
        completed = time.time()
        return WindowsResult(operation=operation, status="SUCCESS", target=target,
                             message=data.get("message", "") or f"{operation} completed.",
                             data={k: v for k, v in data.items() if k != "message"},
                             started_at=started, completed_at=completed)
    except WindowsError as e:
        completed = time.time()
        status = _status_for(e.kind)
        return WindowsResult(operation=operation, status=status, target=target,
                             message=e.message, error=e,
                             started_at=started, completed_at=completed)
    except Exception as e:                       # a Windows call failed oddly
        from core.windows.errors import os_error
        completed = time.time()
        wrapped = os_error(f"{operation} failed on this PC.", str(e))
        return WindowsResult(operation=operation, status="FAILED", target=target,
                             message=wrapped.message, error=wrapped,
                             started_at=started, completed_at=completed)


_STATUS_BY_KIND = {
    WindowsErrorKind.ELEMENT_NOT_FOUND: "NOT_AVAILABLE",
    WindowsErrorKind.WINDOW_NOT_FOUND: "NOT_AVAILABLE",
    WindowsErrorKind.APPLICATION_NOT_FOUND: "NOT_AVAILABLE",
    WindowsErrorKind.PROCESS_NOT_FOUND: "NOT_AVAILABLE",
    WindowsErrorKind.UNSUPPORTED_CONTROL: "NOT_SUPPORTED",
    WindowsErrorKind.ELEMENT_AMBIGUOUS: "FAILED",
    WindowsErrorKind.ELEMENT_DISABLED: "FAILED",
    WindowsErrorKind.ELEMENT_STALE: "FAILED",
    WindowsErrorKind.INVALID_ARGUMENT: "FAILED",
    WindowsErrorKind.TIMEOUT: "FAILED",
    WindowsErrorKind.ACCESS_DENIED: "FAILED",
    WindowsErrorKind.CANCELLED: "CANCELLED",
    WindowsErrorKind.OS_ERROR: "FAILED",
}


def _status_for(kind: str) -> str:
    return _STATUS_BY_KIND.get(kind, "FAILED")


# ── windows ──────────────────────────────────────────────────────────────────

def list_windows(title: str = "", include_untitled: bool = False,
                 limit: int = DEFAULT_WINDOW_LIMIT, cancel_event=None) -> WindowsResult:
    """Real top-level windows, bounded."""
    from core.windows import win32

    limit = max(1, min(int(limit), 100))

    def _fn():
        windows = win32.list_windows(visible_only=True,
                                     include_untitled=include_untitled, limit=limit + 40)
        if title:
            windows = [w for w in windows if w.matches(title)]
        return {"message": f"{len(windows)} window(s) found.",
                "windows": [w.to_dict() for w in windows[:limit]],
                "truncated": len(windows) > limit,
                "total_found": len(windows)}

    return _run("list_windows", title or "", _fn, cancel_event)


def active_window(cancel_event=None) -> WindowsResult:
    from core.windows import win32

    def _fn():
        info = win32.active_window()
        return {"message": f"The active window is '{info.label}' "
                           f"(pid {info.process_id}).",
                "window": info.to_dict()}

    return _run("active_window", "", _fn, cancel_event)


def locate_window(title: str = "", process_id: Optional[int] = None,
                  window_handle: Optional[int] = None, cancel_event=None) -> WindowsResult:
    from core.windows import win32

    def _fn():
        info = win32.find_window(title=title, process_id=process_id, handle=window_handle)
        return {"message": f"Found '{info.label}' (pid {info.process_id}).",
                "window": info.to_dict()}

    return _run("locate_window", title or (str(window_handle) if window_handle else ""),
                _fn, cancel_event)


def focus_window(title: str = "", process_id: Optional[int] = None,
                 window_handle: Optional[int] = None, cancel_event=None) -> WindowsResult:
    """Bring a window to the front, then report what the OS says afterwards."""
    from core.windows import win32

    def _fn():
        info = win32.find_window(title=title, process_id=process_id, handle=window_handle)
        after = win32.focus_window(info)
        return {"message": (f"'{after.label}' is now the active window."
                            if after.is_active else
                            f"Asked Windows to bring '{after.label}' to the front; "
                            f"the OS still reports the active window as "
                            f"{win32.active_window().label!r}."),
                "window": after.to_dict(),
                "active_window": after.label if after.is_active else None}

    return _run("focus_window", title or (str(window_handle) if window_handle else ""),
                _fn, cancel_event)


def window_state(state: str, title: str = "", process_id: Optional[int] = None,
                 window_handle: Optional[int] = None, cancel_event=None) -> WindowsResult:
    from core.windows import win32

    def _fn():
        info = win32.find_window(title=title, process_id=process_id, handle=window_handle)
        after = win32.set_window_state(info, state)
        return {"message": f"'{after.label}' is now {state}.",
                "window": after.to_dict()}

    return _run("window_state", state, _fn, cancel_event)


def close_window(title: str = "", process_id: Optional[int] = None,
                 window_handle: Optional[int] = None, cancel_event=None) -> WindowsResult:
    """Ask a window to close politely (WM_CLOSE).

    The caller is responsible for authorization: this is the operation that can
    close an application with unsaved work, and the confirmation gate is the
    only thing standing between a model's request and someone's unsaved file.
    """
    from core.windows import win32

    def _fn():
        info = win32.find_window(title=title, process_id=process_id, handle=window_handle)
        win32.close_window(info)
        return {"message": (f"Asked '{info.label}' to close. Windows sends WM_CLOSE, "
                            f"so the application decides how to handle unsaved work."),
                "window": info.to_dict()}

    return _run("close_window", title or (str(window_handle) if window_handle else ""),
                _fn, cancel_event)


# ── controls ─────────────────────────────────────────────────────────────────

def _window_for_control(title: str = "", process_id: Optional[int] = None,
                        window_handle: Optional[int] = None, timeout: float = 8.0):
    """The window a control operation should look inside.

    A title given here is used for resolution; without one the active window is
    the target. The window is located once, here, and the returned session
    carries it, so every element discovered inside it belongs to the window the
    caller asked about.
    """
    from core.windows import win32
    if window_handle:
        info = win32.find_window(handle=int(window_handle))
    elif process_id is not None:
        info = win32.find_window(process_id=process_id)
    elif title:
        info = win32.find_window(title=title)
    else:
        info = win32.active_window()
    session_cls = _uia_session()
    return session_cls(info, timeout=timeout).connect()


def _uia_session():
    from core.windows.uia import UiaSession, available
    if not available():
        from core.windows.errors import os_error
        raise os_error("UI Automation needs pywinauto on this machine.")
    return UiaSession


def _query_from(params: dict) -> ElementQuery:
    return ElementQuery(
        name=(params.get("element_name") or params.get("name") or "").strip() or None,
        automation_id=(params.get("automation_id") or "").strip() or None,
        control_type=(params.get("control_type") or "").strip() or None,
        class_name=(params.get("class_name") or "").strip() or None,
        index=params.get("index"),
    )


def list_controls(title: str = "", process_id: Optional[int] = None,
                  window_handle: Optional[int] = None, control_type: str = "",
                  limit: int = DEFAULT_CONTROL_LIMIT, max_depth: int = MAX_DEPTH,
                  visible_only: bool = False, named_only: bool = False,
                  cancel_event=None) -> WindowsResult:
    """Bounded control discovery for one window.

    Never the whole desktop: a window, a depth limit, and a result limit. The
    alternative is handing the model thousands of controls it cannot use.
    `named_only` drops the unnamed layout and decoration controls that carry no
    information a caller can act on.
    """
    def _fn():
        session = _window_for_control(title, process_id, window_handle)
        elements = session.walk(max_depth=max_depth,
                                limit=max(1, min(int(limit), MAX_CONTROL_LIMIT)),
                                control_types=({control_type} if control_type else None),
                                named_only=bool(named_only),
                                visible_only=bool(visible_only))
        from core.windows import sensitive
        return {"message": (f"{len(elements)} control(s) in "
                            f"'{session.window.label}'."),
                "window": session.window.to_dict(),
                "controls": [e.to_dict() for e in elements],
                "summary": sensitive.summarize_controls(elements)}

    target = title or (str(window_handle) if window_handle else "the active window")
    return _run("list_controls", target, _fn, cancel_event)


def find_control(query: dict, title: str = "", process_id: Optional[int] = None,
                 window_handle: Optional[int] = None, max_depth: int = MAX_DEPTH,
                 cancel_event=None) -> WindowsResult:
    """Resolve one control, unambiguously, or explain why it could not be."""
    def _fn():
        session = _window_for_control(title, process_id, window_handle)
        element, _wrapper = session.find(_query_from(query), max_depth=max_depth,
                                         limit=MAX_CONTROL_LIMIT)
        return {"message": element.describe(), "control": element.to_dict(),
                "identity": {"note": element.identity_note,
                             "automation_id": element.automation_id,
                             "runtime_id": list(element.runtime_id)}}

    target = (query or {}).get("element_name") or (query or {}).get("automation_id") or ""
    return _run("find_control", target, _fn, cancel_event)


def _interact(operation: str, params: dict, cancel_event=None,
              text: Optional[str] = None) -> WindowsResult:
    """Shared path for every control operation: resolve, check, then act."""
    def _fn():
        session = _window_for_control(params.get("title", ""),
                                      params.get("process_id"),
                                      params.get("window_handle"))
        element, wrapper = session.find(_query_from(params),
                                        max_depth=int(params.get("max_depth", MAX_DEPTH)),
                                        limit=MAX_CONTROL_LIMIT)
        if text is not None:
            from core.windows.uia import set_value_text
            data = set_value_text(session, operation, wrapper, element, text)
        else:
            data = session.perform(operation, wrapper, element)
        data["control"] = element.to_dict()
        data["message"] = (f"{operation} on {element.describe()} — "
                           f"{data.get('reported', 'the pattern returned')}")
        return data

    query = params or {}
    target = (query.get("element_name") or query.get("automation_id")
              or query.get("control_type") or "")
    return _run(operation, target, _fn, cancel_event)


def invoke_control(params: dict, cancel_event=None) -> WindowsResult:
    return _interact("invoke", params, cancel_event)


def toggle_control(params: dict, cancel_event=None) -> WindowsResult:
    return _interact("toggle", params, cancel_event)


def select_control(params: dict, cancel_event=None) -> WindowsResult:
    return _interact("select", params, cancel_event)


def expand_control(params: dict, cancel_event=None) -> WindowsResult:
    return _interact("expand", params, cancel_event)


def collapse_control(params: dict, cancel_event=None) -> WindowsResult:
    return _interact("collapse", params, cancel_event)


def focus_control(params: dict, cancel_event=None) -> WindowsResult:
    return _interact("set_focus", params, cancel_event)


def set_control_value(params: dict, cancel_event=None) -> WindowsResult:
    """Write text into a control through its Value pattern.

    Credential fields are refused. Typing a password on the model's request is
    exactly the case Phase 3's security boundary refuses: UI Automation can
    write one, which is not a reason to. `authorized_sensitive` exists for a
    future explicitly authorized path (Phase 7); no model input reaches it,
    because this function is called with the model's parameters only.
    """
    def _fn():
        session = _window_for_control(params.get("title", ""),
                                      params.get("process_id"),
                                      params.get("window_handle"))
        element, wrapper = session.find(_query_from(params),
                                        max_depth=int(params.get("max_depth", MAX_DEPTH)),
                                        limit=MAX_CONTROL_LIMIT)
        if element.sensitive and not params.get("authorized_sensitive"):
            from core.windows.errors import access_denied
            raise access_denied(
                f"'{element.element_id}' is a credential field "
                f"({element.sensitive_reason}), so NEO will not write to it. "
                f"Ask the user to enter the value themselves.")
        from core.windows.uia import set_value_text
        data = set_value_text(session, "set_value", wrapper, element,
                              params.get("text", ""))
        data["control"] = element.to_dict()
        data["message"] = (f"set_value on {element.describe()} — "
                           f"{data.get('reported', 'the pattern returned')}")
        return data

    target = (params or {}).get("element_name") or (params or {}).get("automation_id") or ""
    return _run("set_value", target, _fn, cancel_event)


def get_control_value(params: dict, cancel_event=None) -> WindowsResult:
    return _interact("get_value", params, cancel_event)


def read_control_state(params: dict, cancel_event=None) -> WindowsResult:
    """Read one observable state of a control *without touching it*.

    This is the observation primitive Phase 4 verification uses, and it is
    deliberately absent from `OPERATIONS`: the model gets no way to call it, so
    it cannot be used to turn "look at this checkbox" into an action. Reading a
    control never changes it — that separation is the whole point.
    """
    property_name = str(params.get("property") or params.get("state") or "").strip().lower()

    def _fn():
        from core.windows import uia
        session = _window_for_control(params.get("title", ""),
                                      params.get("process_id"),
                                      params.get("window_handle"))
        element, wrapper = session.find(_query_from(params),
                                        max_depth=int(params.get("max_depth", MAX_DEPTH)),
                                        limit=MAX_CONTROL_LIMIT)
        if element.sensitive:
            from core.windows.sensitive import refuse_read
            refuse_read(element)
        value, pattern = uia.read_state(wrapper, element, property_name)
        return {"message": (f"{element.describe()} is {property_name}={value!r} "
                            f"(read through {pattern})."),
                "property": property_name, "value": value, "pattern": pattern,
                "control": element.to_dict()}

    return _run("read_control_state", property_name or "state", _fn, cancel_event)


# ── input ────────────────────────────────────────────────────────────────────

def press_keys(keys: str, cancel_event=None, sensitive_target: bool = False,
               target: str = "the focused control") -> WindowsResult:
    from core.windows import input as input_mod

    def _fn():
        data = input_mod.press(keys, sensitive_target=sensitive_target, target=target)
        data["message"] = data["reported"]
        return data

    return _run("press_keys", keys, _fn, cancel_event)


def type_text(text: str, cancel_event=None, sensitive_target: bool = False,
              target: str = "the focused control",
              via_clipboard: bool = False) -> WindowsResult:
    from core.windows import input as input_mod

    def _fn():
        if via_clipboard:
            data = input_mod.type_keys_slowly(text, sensitive_target, target)
        else:
            data = input_mod.type_text(text, sensitive_target, target)
        data["message"] = data["reported"]
        return data

    return _run("type_text", target, _fn, cancel_event)


def click(x: int, y: int, button: str = "left", clicks: int = 1,
          cancel_event=None) -> WindowsResult:
    from core.windows import input as input_mod

    def _fn():
        data = input_mod.click(x, y, button=button, clicks=clicks)
        data["message"] = data["reported"]
        return data

    return _run("click", f"({x}, {y})", _fn, cancel_event)


def move_mouse(x: int, y: int, cancel_event=None) -> WindowsResult:
    from core.windows import input as input_mod

    def _fn():
        data = input_mod.move(x, y)
        data["message"] = data["reported"]
        return data

    return _run("move_mouse", f"({x}, {y})", _fn, cancel_event)


def scroll(amount: int = 3, direction: str = "down", cancel_event=None) -> WindowsResult:
    from core.windows import input as input_mod

    def _fn():
        data = input_mod.scroll(amount=amount, direction=direction)
        data["message"] = data["reported"]
        return data

    return _run("scroll", direction, _fn, cancel_event)


def drag(x1: int, y1: int, x2: int, y2: int, cancel_event=None) -> WindowsResult:
    from core.windows import input as input_mod

    def _fn():
        data = input_mod.drag(x1, y1, x2, y2)
        data["message"] = data["reported"]
        return data

    return _run("drag", f"({x1},{y1})→({x2},{y2})", _fn, cancel_event)


def cursor_position(cancel_event=None) -> WindowsResult:
    from core.windows import input as input_mod

    def _fn():
        data = input_mod.cursor_position()
        data["message"] = f"The pointer is at ({data['x']}, {data['y']})."
        return data

    return _run("cursor_position", "", _fn, cancel_event)


# ── applications and processes ───────────────────────────────────────────────

def launch_app(name: str, cancel_event=None, wait_for_window: bool = True) -> WindowsResult:
    from core.windows import apps, launch as _launch

    def _fn():
        data = apps.launch(name)
        outcome = _launch.classify(data, follow=bool(wait_for_window))
        data["message"] = outcome.describe()
        # `detection` is the new, branchable fact: whether a *controllable*
        # window exists, not merely whether a process started.
        data["detection"] = outcome.detection
        data["controlled"] = outcome.controlled
        data["caveats"] = list(outcome.caveats)
        if outcome.window:
            data["window"] = outcome.window
        return data

    return _run("launch_app", name, _fn, cancel_event)


def app_running(name: str, cancel_event=None) -> WindowsResult:
    from core.windows import apps

    def _fn():
        data = apps.is_running(name)
        data["message"] = (f"{name} is {'running' if data['running'] else 'not running'}."
                           + (f" pid(s): {', '.join(str(p['pid']) for p in data['processes'])}"
                              if data["running"] else ""))
        return data

    return _run("app_running", name, _fn, cancel_event)


def list_processes(name_contains: str = "", limit: int = 40,
                   cancel_event=None) -> WindowsResult:
    from core.windows import win32

    def _fn():
        processes = win32.list_processes(name_contains=name_contains,
                                          limit=max(1, min(int(limit), 100)))
        return {"message": f"{len(processes)} process(es).",
                "processes": [p.to_dict() for p in processes]}

    return _run("list_processes", name_contains, _fn, cancel_event)


def process_info(pid: int, cancel_event=None) -> WindowsResult:
    from core.windows import win32

    def _fn():
        info = win32.process_info(int(pid))
        return {"message": f"{info.name} (pid {info.pid})"
                           + (f" — windows: {', '.join(info.window_titles)}"
                              if info.window_titles else ""),
                "process": info.to_dict()}

    return _run("process_info", str(pid), _fn, cancel_event)


# ── snapshot ─────────────────────────────────────────────────────────────────

def desktop_snapshot(max_windows: int = 8, max_controls: int = 40,
                     include_controls: bool = True, cancel_event=None) -> WindowsResult:
    """A bounded read-only view of the real desktop.

    This is raw Windows state, not a world model: what the OS says about the
    active window, the open windows and the first controls of the active one.
    Nothing here is inferred, and nothing is kept beyond the call.
    """
    def _fn():
        from core.windows import win32
        active = win32.active_window()
        windows = win32.list_windows(visible_only=True, include_untitled=False,
                                     limit=max_windows)
        data = {"message": f"Active: '{active.label}'. {len(windows)} window(s) open.",
                "active_window": active.to_dict(),
                "windows": [w.to_dict() for w in windows],
                "screen": {"width": win32.screen_size()[0],
                           "height": win32.screen_size()[1]}}
        if include_controls:
            try:
                session = _uia_session()(active, timeout=6.0).connect()
                controls = session.walk(max_depth=8, limit=max_controls, visible_only=True)
                from core.windows import sensitive
                data["active_window_controls"] = [c.to_dict() for c in controls]
                data["active_window_control_summary"] = sensitive.summarize_controls(controls)
                data["controls_truncated"] = len(controls) >= max_controls
            except WindowsError as e:
                data["active_window_controls"] = []
                data["active_window_controls_note"] = e.message
        return data

    return _run("desktop_snapshot", "", _fn, cancel_event)


# ── Phase 6: targeted windows, structured discovery, reliable typing ────────

def resolve_window(params: dict, cancel_event=None) -> WindowsResult:
    """Resolve a window the way a person would, and refuse when it is ambiguous.

    Unlike `locate_window` — which asks Win32 for the first title match — this
    scores every live window against the request and reports the score, so a
    caller can see why one window was chosen. Two windows tied at the top score
    are reported as ambiguous and *nothing is returned to act on*: choosing would
    be a guess about which of somebody's two files to edit.
    """
    from core.windows import targeting

    def _fn():
        targetor = targeting.WindowTargetor(cancel_event)
        match = targetor.resolve(params or {}, refresh=True)
        return {"message": (f"Resolved '{match.window.label}' "
                            f"(handle {match.window.handle}, pid "
                            f"{match.window.process_id}): {match.reason}."),
                "window": match.window.to_dict(),
                "resolved": True,
                "ambiguous": match.ambiguous,
                "re_resolved": match.re_resolved,
                "used_handle": match.used_handle,
                "reason": match.reason,
                "candidates": [c.to_dict() for c in match.candidates]}

    query = params or {}
    target = (str(query.get("title", "")) or str(query.get("app_name", ""))
              or str(query.get("window_handle", "")))
    return _run("resolve_window", target, _fn, cancel_event)


def find_controls(query: dict, title: str = "", process_id: Optional[int] = None,
                  window_handle: Optional[int] = None, limit: int = DEFAULT_CONTROL_LIMIT,
                  max_depth: int = MAX_DEPTH, visible_only: bool = False,
                  cancel_event=None) -> WindowsResult:
    """Every control matching a query, scored, with ambiguity made explicit.

    The plural of `find_control`. `find_control` raises when two controls match,
    which is right for "press this button" and wrong for "what buttons are
    here" — so this one returns the candidates and lets the caller decide, and
    still never acts on any of them.
    """
    from core.windows import discovery

    def _fn():
        session = _window_for_control(title, process_id, window_handle)
        element_query = _query_from(query or {})
        elements = session.walk(max_depth=max_depth,
                                limit=MAX_CONTROL_LIMIT,
                                control_types=({element_query.control_type}
                                               if element_query.control_type else None),
                                visible_only=bool(visible_only))
        findings = discovery.find_all(elements, element_query, limit=limit)
        data = {"message": (f"{findings.count} of {findings.total_found} control(s) "
                            f"match {findings.query} in '{session.window.label}'"
                            + ("; more than one match equally well, so none can be "
                               "chosen without an index" if findings.ambiguous else "")),
                "window": session.window.to_dict(),
                "ambiguous": findings.ambiguous,
                "truncated": findings.truncated,
                "total_found": findings.total_found,
                "query": findings.query,
                "controls": [h.to_dict() for h in findings.hits],
                "summary": "\n".join(discovery.describe(h) for h in findings.hits[:12])}
        best = findings.best()
        if best is not None:
            data["control"] = best.element.to_dict()
        return data

    query = query or {}
    target = (str(query.get("element_name") or "") or str(query.get("automation_id") or "")
              or str(query.get("control_type") or ""))
    return _run("find_controls", target, _fn, cancel_event)


def describe_controls(title: str = "", process_id: Optional[int] = None,
                      window_handle: Optional[int] = None, limit: int = 120,
                      max_depth: int = MAX_DEPTH, interactive_only: bool = True,
                      visible_only: bool = False,
                      cancel_event=None) -> WindowsResult:
    """What this window contains, grouped by role. A summary, never a dump."""
    from core.windows import discovery

    def _fn():
        session = _window_for_control(title, process_id, window_handle)
        elements = session.walk(max_depth=max_depth,
                                limit=max(1, min(int(limit), MAX_CONTROL_LIMIT)),
                                visible_only=bool(visible_only))
        summary = discovery.summarize(elements, interactive_only=interactive_only)
        return {"message": discovery.summarize_text(summary),
                "window": session.window.to_dict(),
                "summary": discovery.summarize_text(summary),
                "grouped": summary,
                "controls": [e.to_dict() for e in elements[:12]]}

    target = title or (str(window_handle) if window_handle else "the active window")
    return _run("describe_controls", target, _fn, cancel_event)


def type_into(params: dict, cancel_event=None) -> WindowsResult:
    """Enter text into a *named, verified* control — not into whatever is focused.

    The chain, with every link checked rather than assumed:

        resolve the control → refuse if it is a credential field → focus it →
        re-read focus → write → read the value back and compare

    When any link fails, nothing is typed and the failure names itself. The
    read-back is what makes this different from `type_text`: that one can only
    say characters were sent, and this one can say whether the text arrived.
    """
    from core.windows import typing as _typing

    params = params or {}

    def _fn():
        session = _window_for_control(params.get("title", ""),
                                      params.get("process_id"),
                                      params.get("window_handle"))
        element, wrapper = session.find(_query_from(params),
                                        max_depth=int(params.get("max_depth", MAX_DEPTH)),
                                        limit=MAX_CONTROL_LIMIT)
        notes: list = []
        if element.sensitive:
            # Refuse before focusing: focusing a password field is harmless, but
            # this keeps the refusal in one obvious place.
            return {"written": False,
                    "message": _typing.no_target(
                        f"'{element.element_id}' is a credential field "
                        f"({element.sensitive_reason}), so NEO will not type into "
                        f"it. The user can type it themselves.").refused,
                    "control": element.to_dict(), "refused": "sensitive_field"}

        focused = False
        if _typing.choose_method(element, str(params.get("text", ""))) != _typing.METHOD_VALUE_PATTERN:
            session.perform("set_focus", wrapper, element)
            focused = _typing.is_focused(wrapper)
            notes.append("focus was set on the resolved control and re-read"
                         if focused else
                         "SetFocus returned but Windows does not report the "
                         "control as focused; the write may not land")
        written = _typing.write_into(session, element, str(params.get("text", "")),
                                     prefer=str(params.get("method", "")),
                                     clear_first=bool(params.get("replace", False)),
                                     cancel_event=cancel_event)
        value, matches = _typing._read_back(session, element, str(params.get("text", "")))
        result = _typing.entry_result(element, written, str(params.get("text", "")),
                                      value, matches, focused, notes)
        message = (f"Entered {result.to_dict()['characters']} characters into "
                   f"{element.describe()} via {result.method}"
                   + ("" if matches is None else
                      f"; read back {'and it matches' if matches else 'and it DOES NOT match'}"))
        data = result.to_dict()
        data["message"] = message
        return data

    target = (str(params.get("element_name") or "") or str(params.get("automation_id") or "")
              or str(params.get("control_type") or ""))
    return _run("type_into", target, _fn, cancel_event)


def classify_dialog(params: dict, cancel_event=None) -> WindowsResult:
    """What kind of window is blocking, from what it actually shows.

    Read-only. It names the kind, the evidence, and whether NEO may act on it —
    and for an authentication or permission dialog the answer to the last part
    is always no.
    """
    from core.windows import dialogs, discovery

    def _fn():
        session = _window_for_control(params.get("title", ""),
                                      params.get("process_id"),
                                      params.get("window_handle"))
        elements = session.walk(max_depth=int(params.get("max_depth", MAX_DEPTH)),
                                limit=MAX_CONTROL_LIMIT, visible_only=True)
        report = dialogs.classify(session.window.to_dict(), elements)
        data = report.to_dict()
        data["message"] = (f"'{session.window.label}' looks like a "
                           f"{report.kind} dialog: {report.reason}."
                           + (f" {report.advice}" if report.advice else ""))
        return data

    target = str((params or {}).get("title", "") or "the active window")
    return _run("classify_dialog", target, _fn, cancel_event)


def dismiss_dialog(params: dict, cancel_event=None) -> WindowsResult:
    """Close a dialog NEO is allowed to close. Never an authentication one.

    The confirmation gate in the action layer is what actually authorises this;
    the check here is the second lock, and it exists because a caller that
    reaches the façade directly would otherwise have only the first one.
    """
    from core.windows import dialogs

    params = params or {}

    def _fn():
        session = _window_for_control(params.get("title", ""),
                                      params.get("process_id"),
                                      params.get("window_handle"))
        elements = session.walk(max_depth=int(params.get("max_depth", MAX_DEPTH)),
                                limit=MAX_CONTROL_LIMIT, visible_only=True)
        report = dialogs.classify(session.window.to_dict(), elements)
        if not dialogs.may_act_on(report.kind):
            return {"dismissed": False, "dialog": report.to_dict(),
                    "message": (f"'{session.window.label}' is a {report.kind} dialog. "
                                f"{report.advice}")}
        if not report.dismissible:
            return {"dismissed": False, "dialog": report.to_dict(),
                    "message": (f"'{session.window.label}' is a {report.kind} window, "
                                f"and NEO does not close windows of that kind "
                                f"automatically: {report.reason}.")}
        button = dialogs.dismiss_target(report) or (report.buttons or [None])[0]
        if not button:
            return {"dismissed": False, "dialog": report.to_dict(),
                    "message": "The dialog has no button NEO could press safely."}
        element, wrapper = session.find(ElementQuery(name=button))
        session.perform("invoke", wrapper, element)
        return {"dismissed": True, "dialog": report.to_dict(), "button": button,
                "message": (f"Pressed '{button}' on the {report.kind} dialog "
                            f"'{session.window.label}'.")}

    target = str(params.get("title", "") or "the active window")
    return _run("dismiss_dialog", target, _fn, cancel_event)


#: Every operation the façade exposes. The action layer uses this to reject a
#: request it cannot satisfy, instead of silently doing nothing.
OPERATIONS = {
    "list_windows": list_windows,
    "active_window": active_window,
    "locate_window": locate_window,
    "resolve_window": resolve_window,
    "focus_window": focus_window,
    "window_state": window_state,
    "close_window": close_window,
    "list_controls": list_controls,
    "find_control": find_control,
    "find_controls": find_controls,
    "describe_controls": describe_controls,
    "invoke": invoke_control,
    "toggle": toggle_control,
    "select": select_control,
    "expand": expand_control,
    "collapse": collapse_control,
    "focus_control": focus_control,
    "set_value": set_control_value,
    "get_value": get_control_value,
    "type_into": type_into,
    "press_keys": press_keys,
    "type_text": type_text,
    "click": click,
    "move_mouse": move_mouse,
    "scroll": scroll,
    "drag": drag,
    "cursor_position": cursor_position,
    "launch_app": launch_app,
    "app_running": app_running,
    "list_processes": list_processes,
    "process_info": process_info,
    "classify_dialog": classify_dialog,
    "dismiss_dialog": dismiss_dialog,
    "desktop_snapshot": desktop_snapshot,
}

#: Operations that ask Windows to change something on the user's behalf. Used
#: by the security layer later; recorded now because the metadata a policy
#: engine needs has to exist before the policy engine does.
MUTATING_OPERATIONS = frozenset({
    "focus_window", "window_state", "close_window", "invoke", "toggle", "select",
    "expand", "collapse", "focus_control", "set_value", "press_keys", "type_text",
    "click", "move_mouse", "scroll", "drag", "launch_app",
    # Phase 6. `type_into` writes text and `dismiss_dialog` closes a window, so
    # both change the machine in the same way the operations above do. They are
    # listed here rather than assumed from their names.
    "type_into", "dismiss_dialog",
})

#: Operations that need the user to approve first.
#:
#: Phase 3 gated exactly one operation — `close_window` — because closing an
#: application can destroy unsaved work. Phase 6 adds `dismiss_dialog` on the
#: same reasoning: a dialog is often *about* unsaved work, and "press the
#: button that closes it" is a sentence with several possible meanings, only
#: one of which is safe to assume.
#:
#: What is deliberately *not* here: `type_into` and `set_value`. They are gated
#: by something better than a question — the target must be resolved
#: unambiguously and, if it is a credential field, the write is refused outright.
#: `launch_app` stays ungated for the reason Phase 3 gave: a name resolved
#: through an allowlist is a wrong guess at worst, not an arbitrary command.
CONFIRMATION_REQUIRED = frozenset({"close_window", "dismiss_dialog"})