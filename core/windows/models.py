"""
NEO's own model of a window and a UI element.

Why NEO models these itself
    pywinauto's wrapper objects are excellent to drive and a poor thing to hand
    to the rest of an application: they hold live COM references, raise if you
    touch them after the app redraws, and would make core/task_manager.py
    import a UI library. Everything above this module — the execution layer,
    the task record, the HUD — works with these plain dataclasses, which are
    JSON-serialisable, comparable, and safe to keep after a window closes.

    Raw wrappers stay inside core/windows/uia.py. That file converts; it never
    leaks.

Availability is honest
    A field Windows did not expose is None, never a plausible default. A control
    with no automation id has automation_id=None, not "". Callers can tell the
    difference between "this app does not publish ids" and "the id is blank".
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Optional


@dataclass(frozen=True)
class Rect:
    """A screen rectangle. Width/height are 0 for a collapsed rectangle."""

    left: int = 0
    top: int = 0
    right: int = 0
    bottom: int = 0

    @property
    def width(self) -> int:
        return max(0, self.right - self.left)

    @property
    def height(self) -> int:
        return max(0, self.bottom - self.top)

    @property
    def center(self) -> tuple[int, int]:
        return (self.left + self.width // 2, self.top + self.height // 2)

    @property
    def empty(self) -> bool:
        return self.width == 0 or self.height == 0

    def to_dict(self) -> dict:
        return {"left": self.left, "top": self.top, "right": self.right,
                "bottom": self.bottom, "width": self.width, "height": self.height}

    @classmethod
    def from_dict(cls, raw: Any) -> Optional["Rect"]:
        if not isinstance(raw, dict):
            return None
        try:
            return cls(int(raw.get("left", 0)), int(raw.get("top", 0)),
                       int(raw.get("right", 0)), int(raw.get("bottom", 0)))
        except (TypeError, ValueError):
            return None

    @classmethod
    def from_values(cls, left, top, right, bottom) -> Optional["Rect"]:
        """Build from whatever the platform returned, or None if unusable."""
        try:
            rect = cls(int(left), int(top), int(right), int(bottom))
        except (TypeError, ValueError):
            return None
        return None if rect.empty else rect


# Control types NEO understands well enough to name. Anything else is kept as
# the string Windows reported — the point is to relay what the OS said, not to
# reduce it to a vocabulary that would hide information.
COMMON_CONTROL_TYPES = frozenset({
    "Button", "CheckBox", "ComboBox", "DataItem", "Document", "Edit", "Group",
    "Hyperlink", "Image", "List", "ListItem", "Menu", "MenuBar", "MenuItem",
    "Pane", "ProgressBar", "RadioButton", "ScrollBar", "Slider", "Spinner",
    "StatusBar", "Tab", "TabItem", "Text", "TitleBar", "ToolBar", "ToolTip",
    "Tree", "TreeItem", "Window", "Custom", "Thumb",
})


@dataclass
class UIElement:
    """One control discovered through UI Automation.

    `runtime_id` is the stable handle for acting on this element again inside
    the same UIA session; `element_id` is a short human label for logs and
    messages. Neither implies the element survives a redraw — see
    `identity_note` for what the caller actually promised.
    """

    runtime_id: tuple = ()
    control_type: str = ""
    name: Optional[str] = None
    automation_id: Optional[str] = None
    class_name: Optional[str] = None
    framework_id: Optional[str] = None
    enabled: Optional[bool] = None
    visible: Optional[bool] = None
    offscreen: Optional[bool] = None
    focused: Optional[bool] = None
    bounds: Optional[Rect] = None
    capabilities: tuple = ()
    process_id: Optional[int] = None
    window_handle: Optional[int] = None
    depth: int = 0
    # Populated only when this element is recognised as holding a secret. The
    # value itself is never read into it — see core/windows/sensitive.py.
    sensitive: bool = False
    sensitive_reason: str = ""

    @property
    def element_id(self) -> str:
        """Short, log-friendly label. Not a permanent identity."""
        base = self.automation_id or self.name or self.control_type or "element"
        return f"{self.control_type or 'Control'}:{str(base)[:40]}"

    @property
    def identity_note(self) -> str:
        """What this element can honestly be addressed by."""
        if self.automation_id:
            return (f"automation_id={self.automation_id!r} within the same "
                    f"application session")
        return ("this element has no automation id, so it must be located again "
                "by its visible properties (name / control type / position)")

    @property
    def supports(self) -> dict:
        return {cap: True for cap in self.capabilities}

    def can(self, operation: str) -> bool:
        return operation in self.capabilities

    def describe(self) -> str:
        bits = [self.element_id]
        if self.enabled is False:
            bits.append("disabled")
        if self.visible is False:
            bits.append("hidden")
        if self.offscreen:
            bits.append("offscreen")
        if self.sensitive:
            bits.append("sensitive")
        return f"{bits[0]}" + (f" [{', '.join(bits[1:])}]" if len(bits) > 1 else "")

    def to_dict(self) -> dict:
        data = asdict(self)
        data["runtime_id"] = list(self.runtime_id)
        data["capabilities"] = list(self.capabilities)
        data["bounds"] = self.bounds.to_dict() if self.bounds else None
        return data

    @classmethod
    def from_dict(cls, raw: dict) -> "UIElement":
        return cls(
            runtime_id=tuple(raw.get("runtime_id") or ()),
            control_type=str(raw.get("control_type", "")),
            name=raw.get("name"),
            automation_id=raw.get("automation_id") or None,
            class_name=raw.get("class_name") or None,
            framework_id=raw.get("framework_id") or None,
            enabled=raw.get("enabled"),
            visible=raw.get("visible"),
            offscreen=raw.get("offscreen"),
            focused=raw.get("focused"),
            bounds=Rect.from_dict(raw.get("bounds")),
            capabilities=tuple(raw.get("capabilities") or ()),
            process_id=raw.get("process_id"),
            window_handle=raw.get("window_handle"),
            depth=int(raw.get("depth", 0)),
            sensitive=bool(raw.get("sensitive", False)),
            sensitive_reason=str(raw.get("sensitive_reason", "")),
        )


@dataclass
class WindowInfo:
    """A real top-level window, as the OS reports it.

    `handle` is the Win32 HWND. It is the only genuinely stable identifier here:
    a window handle is reused by Windows after a window closes, so a stored
    handle is never treated as proof a window still exists — every operation
    re-validates it against the live window list.
    """

    handle: int
    title: str = ""
    process_id: Optional[int] = None
    process_name: Optional[str] = None
    class_name: Optional[str] = None
    framework_id: Optional[str] = None
    enabled: Optional[bool] = None
    visible: bool = True
    minimized: bool = False
    maximized: bool = False
    bounds: Optional[Rect] = None
    is_active: bool = False

    @property
    def label(self) -> str:
        return self.title or f"(untitled window {self.handle})"

    def matches(self, query: str) -> bool:
        """Case-insensitive title substring, the only text match Windows offers."""
        needle = (query or "").strip().lower()
        return bool(needle) and needle in (self.title or "").lower()

    def to_dict(self) -> dict:
        data = asdict(self)
        data["bounds"] = self.bounds.to_dict() if self.bounds else None
        return data

    @classmethod
    def from_dict(cls, raw: dict) -> "WindowInfo":
        return cls(
            handle=int(raw.get("handle", 0)),
            title=str(raw.get("title", "")),
            process_id=raw.get("process_id"),
            process_name=raw.get("process_name"),
            class_name=raw.get("class_name") or None,
            framework_id=raw.get("framework_id") or None,
            enabled=raw.get("enabled"),
            visible=bool(raw.get("visible", True)),
            minimized=bool(raw.get("minimized", False)),
            maximized=bool(raw.get("maximized", False)),
            bounds=Rect.from_dict(raw.get("bounds")),
            is_active=bool(raw.get("is_active", False)),
        )


@dataclass
class ProcessInfo:
    """Read-only process facts. Phase 3 deliberately cannot kill anything."""

    pid: int
    name: str = ""
    exe: Optional[str] = None
    window_titles: tuple = ()

    def to_dict(self) -> dict:
        return {"pid": self.pid, "name": self.name, "exe": self.exe,
                "window_titles": list(self.window_titles)}

    @classmethod
    def from_dict(cls, raw: dict) -> "ProcessInfo":
        return cls(pid=int(raw.get("pid", 0)), name=str(raw.get("name", "")),
                   exe=raw.get("exe"), window_titles=tuple(raw.get("window_titles") or ()))