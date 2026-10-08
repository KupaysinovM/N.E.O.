"""
UI Automation: discovering real controls and driving them through real patterns.

THE HIERARCHY THIS IMPLEMENTS
    1. UI Automation          — what this module does
    2. application automation  — Playwright, for browsers (actions/browser_control.py)
    3. controlled input        — core/windows/input.py, as a fallback
    4. screenshot + vision     — actions/screen_processor.py, last resort

    Coordinate clicking is a fallback, not a default. Invoking a button through
    its Invoke pattern does not depend on where the button is, whether the
    window moved, or whether the user scrolled.

WHAT AN OPERATION CAN CLAIM
    "Invoke() returned without error" — that is all. Whether the application
    then did the thing is verification, which is Phase 4 and is not implemented
    here. The result objects say `invoked`, never `verified`.

WHAT CAN HANG
    UIA asks the target application for its own state, so a hung app hangs the
    call. Every operation therefore runs under a deadline and reports TIMEOUT
    rather than blocking the Gemini Live loop indefinitely. Nothing is killed.

ELEMENT FRESHNESS
    A wrapper holds a live reference to an element that may be destroyed by the
    next redraw. Every attribute read and every pattern call is guarded; a dead
    element raises ELEMENT_STALE instead of silently acting on whatever
    replaced it.
"""
from __future__ import annotations

import threading
from typing import Optional

import core.windows as _boundary
from core.windows import sensitive as _sensitive
from core.windows.errors import (
    WindowsError,
    element_disabled,
    element_not_found,
    element_stale,
    invalid_argument,
    unsupported_control,
)
from core.windows.identifiers import ElementQuery, build_runtime_id
from core.windows.models import UIElement, Rect, WindowInfo

try:
    from pywinauto import Application
    from pywinauto.uia_defines import NoPatternInterfaceError
    _PYWINAUTO = True
except ImportError:                                     # pragma: no cover
    _PYWINAUTO = False


DEFAULT_TIMEOUT = 8.0
# A UI tree can be enormous. Discovery is bounded on three axes and the caller
# chooses them; an unbounded dump would flood the model's context.
MAX_DEPTH = 12
DEFAULT_LIMIT = 60

_PATTERN_ATTRS = {
    "invoke": "iface_invoke",
    "toggle": "iface_toggle",
    "value": "iface_value",
    "selection_item": "iface_selection_item",
    "expand_collapse": "iface_expand_collapse",
    "text": "iface_text",
}


def available() -> bool:
    return _boundary.is_supported() and _PYWINAUTO


def _guarded(fn, timeout: float):
    """Run a UIA call with a deadline on a worker thread (see errors docstring)."""
    box: dict = {}

    def _run():
        try:
            box["value"] = fn()
        except WindowsError as e:
            box["error"] = e
        except BaseException as e:                      # noqa: BLE001 - re-raised below
            box["error"] = e

    worker = threading.Thread(target=_run, daemon=True, name="uia-call")
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        from core.windows.errors import timeout as timeout_error
        raise timeout_error(timeout)
    if "error" in box:
        raise box["error"]
    return box.get("value")


def _safe_read(fn, default=None):
    """One attribute read that a redrawing application can invalidate."""
    try:
        return fn()
    except WindowsError:
        raise
    except Exception:
        return default


def _is_stale(exc: BaseException) -> bool:
    """pywinauto/COM report a dead element in several different ways."""
    text = f"{type(exc).__name__}: {exc}".lower()
    return any(token in text for token in (
        "no pattern interface", "element not available", "stale",
        "element is not available", "invalid interface", "the element is not",
        "com_error", "0x80040155", "rpcserver", "disconnected", "null com",
        "element not found", "out of date",
    ))


def _guard_stale(exc: BaseException, name: str):
    if _is_stale(exc):
        raise element_stale(name)
    raise exc


class UiaSession:
    """A connection to one window's UI Automation tree."""

    def __init__(self, window: WindowInfo, timeout: float = DEFAULT_TIMEOUT):
        self.window = window
        self.timeout = timeout
        self._app = None
        self._spec = None

    # -- connection ---------------------------------------------------------

    def connect(self) -> "UiaSession":
        def _connect():
            app = Application(backend="uia").connect(handle=int(self.window.handle),
                                                     timeout=self.timeout)
            spec = app.window(handle=int(self.window.handle))
            spec.wait("exists enabled", timeout=self.timeout)
            return app, spec

        self._app, self._spec = _guarded(_connect, self.timeout + 2.0)
        return self

    @property
    def spec(self):
        if self._spec is None:
            self.connect()
        return self._spec

    def root(self):
        return self.spec

    # -- conversion ---------------------------------------------------------

    def capabilities(self, wrapper) -> tuple:
        """Which automation patterns this control actually exposes."""
        found = []
        for name, attr in _PATTERN_ATTRS.items():
            try:
                if getattr(wrapper, attr, None) is not None:
                    found.append(name)
            except Exception:
                continue
        return tuple(sorted(found))

    def _is_password(self, wrapper) -> Optional[bool]:
        try:
            return bool(wrapper.element_info.element.CurrentIsPassword)
        except Exception:
            return None

    def to_element(self, wrapper, depth: int = 0) -> UIElement:
        """pywinauto wrapper → NEO's own UIElement. Raw objects stop here."""
        try:
            info = wrapper.element_info
            name = _safe_read(lambda: info.name)
            element = UIElement(
                runtime_id=build_runtime_id(_safe_read(lambda: info.runtime_id, ())),
                control_type=str(_safe_read(lambda: info.control_type, "") or ""),
                name=name if name is not None else None,
                automation_id=(_safe_read(lambda: info.automation_id) or None),
                class_name=(_safe_read(lambda: info.class_name) or None),
                framework_id=(_safe_read(lambda: info.framework_id) or None),
                enabled=_safe_read(lambda: info.enabled),
                visible=_safe_read(lambda: info.visible),
                bounds=_safe_read(lambda: _rect(_safe_read(lambda: info.rectangle))),
                capabilities=self.capabilities(wrapper),
                process_id=_safe_read(lambda: info.process_id),
                window_handle=int(self.window.handle),
                depth=depth,
            )
            offscreen = _safe_read(lambda: info.element.CurrentIsOffscreen)
            if offscreen is not None:
                element.offscreen = bool(offscreen)
            focused = _safe_read(lambda: info.element.CurrentHasKeyboardFocus)
            if focused is not None:
                element.focused = bool(focused)
        except Exception as e:                          # element died mid-read
            _guard_stale(e, str(name or "control"))
            raise
        _sensitive.apply(element)
        return element

    # -- discovery ----------------------------------------------------------

    def walk(self, max_depth: int = MAX_DEPTH, limit: int = DEFAULT_LIMIT,
             control_types: Optional[set] = None, named_only: bool = False,
             visible_only: bool = False) -> list:
        """Bounded breadth-first walk of the window's controls.

        Returns NEO elements only. `limit` and `max_depth` are hard stops: the
        caller decides how much of the tree it wants, because the desktop can
        publish a tree far larger than any model can usefully read.
        """
        max_depth = max(1, min(int(max_depth), MAX_DEPTH))
        limit = max(1, min(int(limit), 500))
        wanted = {c.lower() for c in control_types} if control_types else None

        def _walk():
            root = self.root()
            found: list = []
            queue = [(root, 0)]
            while queue and len(found) < limit:
                wrapper, depth = queue.pop(0)
                if depth >= max_depth:
                    continue
                try:
                    children = wrapper.children()
                except Exception as e:
                    _guard_stale(e, self.window.label)
                    continue
                for child in children:
                    try:
                        ctype = str(child.element_info.control_type or "")
                        if wanted is None or ctype.lower() in wanted:
                            if not named_only or (child.window_text() or "").strip():
                                if visible_only and not _safe_read(
                                        lambda: child.is_visible(), True):
                                    continue
                                found.append(self.to_element(child, depth))
                                if len(found) >= limit:
                                    break
                    except WindowsError:
                        raise
                    except Exception:
                        continue
                    if depth + 1 < max_depth:
                        queue.append((child, depth + 1))
            return found

        return _guarded(_walk, self.timeout)

    def find(self, query: ElementQuery, max_depth: int = MAX_DEPTH,
             limit: int = DEFAULT_LIMIT, visible_only: bool = False) -> tuple:
        """Resolve `query` to exactly one (UIElement, wrapper).

        The wrapper stays inside this module; callers get the element model and
        use `perform()` for actions, so no raw automation object ever reaches
        the task layer.
        """
        elements = self.walk(max_depth=max_depth, limit=limit,
                             control_types=({query.control_type}
                                            if query.control_type else None),
                             visible_only=visible_only)
        from core.windows.identifiers import resolve_one
        element = resolve_one(elements, query)

        def _resolve():
            target = None
            for wrapper in self.root().descendants():
                try:
                    if build_runtime_id(wrapper.element_info.runtime_id) == element.runtime_id:
                        target = wrapper
                        break
                except Exception:
                    continue
            if target is None:
                raise element_stale(element.element_id)
            return target

        wrapper = _guarded(_resolve, self.timeout)
        return element, wrapper

    # -- interaction --------------------------------------------------------

    # Operations `perform()` can dispatch. `set_value` is deliberately absent:
    # it takes an argument, so it goes through `set_value_text()` instead of
    # being smuggled in through instance state.
    NO_ARGUMENT_OPERATIONS = ("invoke", "toggle", "get_value", "select",
                              "select_item", "expand", "collapse", "set_focus")

    #: Operation → the capability that has to be present for it to work. An
    #: operation name is not always a pattern name ("get_value" reads the Value
    #: pattern), and checking the wrong one reports a working control as
    #: unsupported.
    OPERATION_CAPABILITY = {
        "invoke": "invoke",
        "toggle": "toggle",
        "get_value": "value",
        "set_value": "value",
        "select": "selection_item",
        "select_item": "selection_item",
        "expand": "expand_collapse",
        "collapse": "expand_collapse",
        "set_focus": None,          # SetFocus is available on every element
    }

    def perform(self, operation: str, wrapper, element: UIElement) -> dict:
        """Run one automation pattern. Returns what the call reported.

        The returned dict says which pattern ran and what the control said
        afterwards — nothing more. There is no independent verification here.
        """
        if operation not in self.NO_ARGUMENT_OPERATIONS:
            raise invalid_argument(
                f"'{operation}' is not a supported control operation. Use one of: "
                f"{', '.join(self.NO_ARGUMENT_OPERATIONS)}.")

        if element.enabled is False:
            raise element_disabled(element.element_id)

        needed = self.OPERATION_CAPABILITY.get(operation, operation)
        if needed and element.capabilities and not element.can(needed):
            raise unsupported_control(element.control_type or "Control", operation)

        handler = getattr(self, f"_do_{operation}", None)
        if handler is None:
            raise unsupported_control(element.control_type or "Control", operation)
        return _guarded(lambda: handler(wrapper, element), self.timeout)

    # each _do_* returns a small dict describing what the pattern reported

    def _do_invoke(self, wrapper, element) -> dict:
        wrapper.invoke()
        return {"operation": "invoke", "pattern": "Invoke",
                "reported": "Invoke() returned"}

    def _do_toggle(self, wrapper, element) -> dict:
        before = _safe_read(lambda: wrapper.get_toggle_state(), None)
        wrapper.toggle()
        after = _safe_read(lambda: wrapper.get_toggle_state(), None)
        return {"operation": "toggle", "pattern": "Toggle",
                "state_before": before, "state_after": after,
                "reported": f"state {before} → {after}"}

    def _do_get_value(self, wrapper, element) -> dict:
        _sensitive.refuse_read(element)
        value = wrapper.iface_value.CurrentValue
        return {"operation": "get_value", "pattern": "Value", "value": value}

    def _do_select(self, wrapper, element) -> dict:
        wrapper.select()
        return {"operation": "select", "pattern": "SelectionItem",
                "selected": bool(_safe_read(lambda: wrapper.is_selected(), None)),
                "reported": "Select() returned"}

    def _do_select_item(self, wrapper, element) -> dict:
        return self._do_select(wrapper, element)

    def _do_expand(self, wrapper, element) -> dict:
        wrapper.expand()
        return {"operation": "expand", "pattern": "ExpandCollapse",
                "expanded": bool(_safe_read(lambda: wrapper.get_expand_state(), None)),
                "reported": "Expand() returned"}

    def _do_collapse(self, wrapper, element) -> dict:
        wrapper.collapse()
        return {"operation": "collapse", "pattern": "ExpandCollapse",
                "expanded": bool(_safe_read(lambda: wrapper.get_expand_state(), None)),
                "reported": "Collapse() returned"}

    def _do_set_focus(self, wrapper, element) -> dict:
        wrapper.set_focus()
        return {"operation": "set_focus", "pattern": "SetFocus",
                "reported": "SetFocus() returned"}


#: Properties that can be read without changing anything. Phase 4 verification
#: needs exactly this: an observation of the *current* state of a control, taken
#: without touching it. Reading is not acting, so it is kept apart from
#: `perform()` — which is the only path that mutates.
READABLE_STATES = ("toggle_state", "is_selected", "is_expanded",
                   "is_enabled", "is_visible")


def read_state(wrapper, element: UIElement, kind: str) -> tuple:
    """Read one observable state of a control. Changes nothing.

    Returns `(value, pattern)`. A control that does not expose the underlying
    pattern raises UNSUPPORTED_CONTROL rather than reporting a made-up value:
    "this checkbox is not checked" and "this checkbox has no state I can read"
    are very different sentences, and only the first is true here.
    """
    readers = {
        "toggle_state": (lambda: str(wrapper.get_toggle_state()), "toggle"),
        "is_selected": (lambda: bool(wrapper.is_selected()), "selection_item"),
        "is_expanded": (lambda: bool(wrapper.get_expand_state()), "expand_collapse"),
        "is_enabled": (lambda: bool(wrapper.is_enabled()), None),
        "is_visible": (lambda: bool(wrapper.is_visible()), None),
    }
    if kind not in readers:
        from core.windows.errors import invalid_argument
        raise invalid_argument(f"'{kind}' is not a readable control state.")
    read, capability = readers[kind]
    if capability and element.capabilities and not element.can(capability):
        raise unsupported_control(element.control_type or "Control", f"read {kind}")
    value = _guarded(read, DEFAULT_TIMEOUT)
    if value is None:
        raise unsupported_control(element.control_type or "Control", f"read {kind}")
    return value, (capability or "element property")


def _rect(raw) -> Optional[Rect]:
    """Convert a pywinauto Rect into ours, or None if Windows gave nothing."""
    try:
        return Rect.from_values(raw.left, raw.top, raw.right, raw.bottom)
    except Exception:
        return None


def set_value_text(session: UiaSession, operation: str, wrapper, element: UIElement,
                   text: str) -> dict:
    """set_value needs the text, so it lives outside the uniform dispatch."""
    if element.enabled is False:
        raise element_disabled(element.element_id)
    if element.capabilities and not element.can("value"):
        raise unsupported_control(element.control_type or "Control", "setting a value")
    from core.windows.keys import validate_text
    value = validate_text(text)

    def _run():
        iface = wrapper.iface_value
        iface.SetValue(value)
        return {"operation": "set_value", "pattern": "Value",
                "reported": "SetValue() returned", "characters": len(value),
                "sensitive_field": bool(element.sensitive)}

    return _guarded(_run, session.timeout)