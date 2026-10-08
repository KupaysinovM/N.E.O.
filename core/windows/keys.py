"""
Keyboard key names: normalised, validated, and bounded.

WHY VALIDATE AT ALL
    A key specification that reaches the input layer unvalidated is a small but
    real injection surface: it decides which virtual-key codes are sent to the
    foreground application as the user. Phase 3 accepts a fixed vocabulary —
    named keys and modifiers, optionally combined with '+' — and rejects
    anything else before a single keystroke is generated. There is no
    "send this raw keycode" path, and no way to express a payload the
    vocabulary does not cover.

    Normalisation exists so a model writing 'CTRL', 'Control', 'ctrl' or
    'CONTROL+C' gets the same answer instead of a key that silently does
    nothing. Unrecognised names are an error, never a best guess: a shortcut
    that quietly fails is worse than one that is refused.
"""
from __future__ import annotations

from typing import Optional

from core.windows.errors import invalid_argument

# Canonical name → PyAutoGUI's spelling. PyAutoGUI is the input backend that
# already ships with the project; Phase 3 does not add a second input stack.
_ALIASES = {
    # modifiers
    "ctrl": "ctrl", "control": "ctrl", "ctl": "ctrl",
    "shift": "shift",
    "alt": "alt", "option": "alt", "opt": "alt",
    "win": "win", "windows": "win", "super": "win", "meta": "win",
    "cmd": "command", "command": "command",
    # editing / navigation
    "enter": "enter", "return": "enter", "ret": "enter",
    "esc": "esc", "escape": "esc",
    "tab": "tab", "backspace": "backspace", "bksp": "backspace",
    "delete": "delete", "del": "delete", "insert": "insert",
    "space": "space", " ": "space", "spacebar": "space",
    "home": "home", "end": "end", "pageup": "pageup", "pgup": "pageup",
    "pagedown": "pagedown", "pgdn": "pagedown", "pagedn": "pagedown",
    "up": "up", "down": "down", "left": "left", "right": "right",
    # function keys
    "f1": "f1", "f2": "f2", "f3": "f3", "f4": "f4", "f5": "f5",
    "f6": "f6", "f7": "f7", "f8": "f8", "f9": "f9", "f10": "f10",
    "f11": "f11", "f12": "f12",
    # common named shortcuts / keys
    "printscreen": "printscreen", "prtsc": "printscreen", "prtscn": "printscreen",
    "scrolllock": "scrolllock", "pause": "pause",
    "numlock": "numlock", "capslock": "capslock",
    # punctuation and digits, by character as well as by name
    "-": "-", "=": "=", "[": "[", "]": "]", "\\": "\\", ";": ";",
    "'": "'", ",": ",", ".": ".", "/": "/", "`": "`",
    "plus": "+", "minus": "-", "period": ".", "comma": ",",
    "slash": "/", "backslash": "\\", "space_": "space",
    "colon": ":", "semicolon": ";", "quote": "'", "doublequote": '"',
    "question": "?", "exclamation": "!", "at": "@", "hash": "#",
    "dollar": "$", "percent": "%", "caret": "^", "ampersand": "&",
    "asterisk": "*", "underscore": "_", "tilde": "~",
    "lparen": "(", "rparen": ")", "lbracket": "[", "rbracket": "]",
    "lbrace": "{", "rbrace": "}", "pipe": "|",
}

MODIFIERS = ("ctrl", "shift", "alt", "win", "command")

# A combination longer than this is not a shortcut, it is a payload.
MAX_COMBINATION = 4
# A single named key cannot be longer than this.
MAX_KEY_LENGTH = 16
# Characters allowed to reach the text-typing path. Control characters are
# excluded on purpose: newlines and escape codes in typed text are how a
# "type this" request becomes an unintended keystroke sequence.
MAX_TEXT_LENGTH = 4000
_FORBIDDEN_IN_TEXT = tuple(chr(c) for c in range(0, 32)) + ("\x7f",)


def normalize_key(raw: str) -> str:
    """One key name → its canonical spelling, or an explicit error."""
    if raw is None:
        raise invalid_argument("A key name is required.")
    key = str(raw).strip()
    if not key:
        raise invalid_argument("A key name is required.")
    if len(key) > MAX_KEY_LENGTH:
        raise invalid_argument(f"'{key[:20]}…' is not a key name NEO recognises.")
    lowered = key.lower()
    if lowered in _ALIASES:
        return _ALIASES[lowered]
    if len(lowered) == 1:      # digits and letters, as themselves
        return lowered
    raise invalid_argument(
        f"'{key}' is not a key NEO recognises. Use a name like 'enter', 'tab', "
        f"'f5', 'up', or a combination such as 'ctrl+s'.")


def parse_combination(raw: str) -> list[str]:
    """'CTRL + Shift + s' → ['ctrl', 'shift', 's'].

    '+' is both the separator and a key, so a literal plus is written '+plus+'.
    """
    if raw is None:
        raise invalid_argument("A key combination is required.")
    text = str(raw).strip()
    if not text:
        raise invalid_argument("A key combination is required.")
    parts = [p for p in text.replace(" ", "").split("+") if p != ""]
    if not parts:
        raise invalid_argument("A key combination is required.")
    if len(parts) > MAX_COMBINATION:
        raise invalid_argument(
            f"{len(parts)} keys in one combination; the limit is {MAX_COMBINATION}.")
    keys = [normalize_key(part) for part in parts]
    # One modifier alone is a hold, not a shortcut: it would do nothing visible.
    if len(keys) == 1 and keys[0] in MODIFIERS:
        raise invalid_argument(f"'{keys[0]}' on its own is a modifier — combine it "
                               f"with a key, e.g. '{keys[0]}+a'.")
    seen: set = set()
    for key in keys:
        if key in seen and key not in MODIFIERS:
            raise invalid_argument(f"'{key}' appears twice in the combination.")
        seen.add(key)
    return keys


def validate_text(text: str, max_length: int = MAX_TEXT_LENGTH) -> str:
    """Text destined for a control: bounded, and free of control characters."""
    if text is None:
        raise invalid_argument("Text is required.")
    value = str(text)
    if len(value) > max_length:
        raise invalid_argument(
            f"The text is {len(value)} characters; the limit is {max_length}.")
    bad = [c for c in value if c in _FORBIDDEN_IN_TEXT]
    if bad:
        shown = ", ".join(sorted({repr(c) for c in bad})[:5])
        raise invalid_argument(
            f"The text contains control characters ({shown}), which are not typed.")
    return value


def describe_combination(keys: list) -> str:
    return "+".join(keys)