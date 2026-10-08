"""
Controlled keyboard and mouse input — the fallback tier of the hierarchy.

WHERE THIS SITS
    UI Automation is preferred whenever a control exposes a pattern, because it
    does not depend on coordinates. These primitives exist for the cases where
    no accessible control exists: a canvas, a game, a terminal, a custom-drawn
    widget. They are also what an application needs once focus has been set on
    an element.

WHAT MAKES THEM CONTROLLED
    Every key goes through core/windows/keys.py first, so the set of keys that
    can be sent is a fixed vocabulary — not a payload. Mouse coordinates are
    checked against the real screen size, because a click at (99999, 99999) is
    a silent no-op that would otherwise look like success. Nothing here types
    into a credential field: the caller is told whether the focused element is
    sensitive before it sends, because by this point the target is no longer
    knowable.

WHAT THEY REPORT
    "A click was sent at (x, y)" or "the keys ctrl+s were sent". Whether the
    application acted on it is verification, and belongs to Phase 4.
"""
from __future__ import annotations

import time
from typing import Optional

import core.windows as _boundary
from core.windows.errors import access_denied, invalid_argument
from core.windows.keys import parse_combination, validate_text

try:
    import pyautogui
    pyautogui.FAILSAFE = True          # corner of the screen aborts a runaway loop
    pyautogui.PAUSE = 0.05
    _INPUT = True
except ImportError:                                        # pragma: no cover
    _INPUT = False

MAX_CLICKS = 3
MAX_SCROLL = 50
KEY_INTERVAL = 0.01


def available() -> bool:
    return _boundary.is_supported() and _INPUT


def _require_input():
    if not _INPUT:
        raise RuntimeError("PyAutoGUI is not installed; input is unavailable.")


def _screen() -> tuple:
    try:
        return pyautogui.size()
    except Exception:
        return (0, 0)


def _check_point(x: int, y: int) -> tuple:
    width, height = _screen()
    if width and height and not (0 <= x < width and 0 <= y < height):
        raise invalid_argument(
            f"({x}, {y}) is outside the screen, which is {width}×{height}.")
    return int(x), int(y)


def _check_sensitive(sensitive: bool, target: str):
    """Refuse to type into a field Windows marks as holding a credential."""
    if sensitive:
        raise access_denied(
            f"'{target}' is a credential field, so NEO will not type into it "
            f"without the user doing it themselves.")


# ── keyboard ─────────────────────────────────────────────────────────────────

def press(keys: str, sensitive_target: bool = False,
          target: str = "the focused control") -> dict:
    """Send a key or combination from the validated vocabulary."""
    _require_input()
    combination = parse_combination(keys)
    _check_sensitive(sensitive_target, target)
    pyautogui.hotkey(*combination) if len(combination) > 1 else pyautogui.press(combination[0])
    return {"operation": "press", "keys": combination,
            "reported": f"sent {'+'.join(combination)} to the focused window"}


def type_text(text: str, sensitive_target: bool = False,
              target: str = "the focused control", interval: float = KEY_INTERVAL) -> dict:
    """Type text into whatever currently has focus."""
    _require_input()
    value = validate_text(text)
    if not value:
        raise invalid_argument("There is no text to type.")
    _check_sensitive(sensitive_target, target)
    pyautogui.typewrite(value, interval=max(0.0, float(interval)))
    return {"operation": "type", "characters": len(value),
            "reported": f"typed {len(value)} characters into the focused window"}


def type_keys_slowly(text: str, sensitive_target: bool = False,
                     target: str = "the focused control") -> dict:
    """Type text that PyAutoGUI cannot produce directly (unicode, clipboard apps).

    Goes through the clipboard and a paste shortcut, so this is a different code
    path from `type_text` rather than a slower version of it.
    """
    _require_input()
    value = validate_text(text)
    if not value:
        raise invalid_argument("There is no text to type.")
    _check_sensitive(sensitive_target, target)
    try:
        import pyperclip
    except ImportError:
        raise RuntimeError("Clipboard typing needs pyperclip, which is not installed.")
    pyperclip.copy(value)
    time.sleep(0.05)
    pyautogui.hotkey("ctrl", "v")
    return {"operation": "type_via_clipboard", "characters": len(value),
            "reported": "pasted text into the focused window"}


# ── mouse ────────────────────────────────────────────────────────────────────

def click(x: int, y: int, button: str = "left", clicks: int = 1) -> dict:
    _require_input()
    point = _check_point(x, y)
    button = str(button or "left").lower()
    if button not in ("left", "right", "middle"):
        raise invalid_argument(f"'{button}' is not a mouse button. Use left, right or middle.")
    clicks = int(clicks)
    if clicks < 1 or clicks > MAX_CLICKS:
        raise invalid_argument(f"clicks must be between 1 and {MAX_CLICKS}.")
    pyautogui.click(point[0], point[1], button=button, clicks=clicks)
    return {"operation": "click", "x": point[0], "y": point[1], "button": button,
            "clicks": clicks,
            "reported": f"clicked at ({point[0]}, {point[1]}) with {button}"}


def move(x: int, y: int, duration: float = 0.3) -> dict:
    _require_input()
    point = _check_point(x, y)
    pyautogui.moveTo(point[0], point[1], duration=max(0.0, float(duration)))
    return {"operation": "move", "x": point[0], "y": point[1],
            "reported": f"moved the pointer to ({point[0]}, {point[1]})"}


def scroll(amount: int = 3, direction: str = "down") -> dict:
    _require_input()
    direction = str(direction or "down").lower()
    if direction not in ("up", "down", "left", "right"):
        raise invalid_argument(f"'{direction}' is not a scroll direction.")
    amount = int(amount)
    if amount == 0 or abs(amount) > MAX_SCROLL:
        raise invalid_argument(f"scroll amount must be between 1 and {MAX_SCROLL}.")
    steps = amount if direction in ("up", "right") else -amount
    pyautogui.scroll(steps) if direction in ("up", "down") else pyautogui.hscroll(steps)
    return {"operation": "scroll", "direction": direction, "amount": amount,
            "reported": f"scrolled {direction} by {amount}"}


def drag(x1: int, y1: int, x2: int, y2: int, duration: float = 0.5,
         button: str = "left") -> dict:
    _require_input()
    start = _check_point(x1, y1)
    end = _check_point(x2, y2)
    button = str(button or "left").lower()
    if button not in ("left", "right"):
        raise invalid_argument(f"'{button}' is not a draggable button.")
    pyautogui.moveTo(start[0], start[1], duration=0.2)
    pyautogui.dragTo(end[0], end[1], duration=max(0.0, float(duration)), button=button)
    return {"operation": "drag", "from": list(start), "to": list(end),
            "reported": f"dragged ({start[0]},{start[1]}) → ({end[0]},{end[1]})"}


def cursor_position() -> dict:
    _require_input()
    x, y = pyautogui.position()
    return {"x": int(x), "y": int(y)}