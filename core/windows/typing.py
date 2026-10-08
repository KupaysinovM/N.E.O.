"""
Reliable text entry — identify, verify, focus, verify focus, type, read back.

THE PROBLEM THIS SOLVES
    `type_text` in Phase 3 sends characters to whatever currently has focus.
    That is the correct primitive and a dangerous default: focus at the moment
    of the call is not focus at the moment the user asked. Between "open
    Notepad" and "write the text", the user may have clicked a chat window, the
    application may have opened a modal, or another window may have stolen
    activation. The result is text typed into somebody's email draft.

    So `type_into` is a different operation, not a different spelling. It is a
    *chain*, and every link is checked:

        1. resolve the target control inside a named window
        2. refuse if that control is a credential field
        3. focus it, and re-read focus rather than assuming SetFocus worked
        4. write it — UI Automation's Value pattern when the control has one,
           keyboard only when it does not
        5. read the value back and compare

    Step 5 is what turns "NEO sent the keys" into "the text is in the field",
    and it is deliberately the same read Phase 4 verification uses, so the two
    never disagree about what is in the box.

    When the target cannot be resolved, nothing is typed. `None` is a real
    answer and the failure is reported rather than worked around by typing
    somewhere plausible.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from core.windows.errors import access_denied, element_not_found

#: How a piece of text was delivered. Kept distinct on purpose: "typed through
#: the keyboard" and "set through the Value pattern" are different facts about
#: what happened to the machine, and verification reads the result rather than
#: the method.
METHOD_VALUE_PATTERN = "value_pattern"
METHOD_KEYBOARD = "keyboard"
METHOD_CLIPBOARD = "clipboard"

#: Characters beyond which the keyboard path stops being sensible. PyAutoGUI
#: types a character per synthetic key event, so a long paragraph through it is
#: slow and lossy for anything non-ASCII.
MAX_KEYBOARD_CHARS = 500


@dataclass
class EntryResult:
    """What one text entry actually did, and what was read back."""

    written: bool = False
    method: str = ""
    text: str = ""
    control: dict = field(default_factory=dict)
    read_back: Optional[str] = None
    matches: Optional[bool] = None
    focused_confirmed: bool = False
    refused: str = ""
    notes: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"written": self.written, "method": self.method,
                "characters": len(self.text),
                "control": dict(self.control),
                "read_back_matches": self.matches,
                "focused_confirmed": self.focused_confirmed,
                "refused": self.refused, "notes": list(self.notes)}


def _input_module():
    """The keyboard module, imported lazily so discovery-only callers do not
    need PyAutoGUI installed to find a button."""
    from core.windows import input as module
    return module


def choose_method(element, text: str) -> str:
    """The Value pattern when the control has one; the keyboard otherwise.

    A UIA Value pattern writes the text as one atomic set and is immune to
    focus stealing between characters. The keyboard path is a fallback for
    editors and consoles that publish no Value pattern at all — Notepad's
    document is the everyday case.
    """
    capabilities = tuple(getattr(element, "capabilities", ()) or ())
    if "value" in capabilities:
        return METHOD_VALUE_PATTERN
    if len(text) > MAX_KEYBOARD_CHARS or not text.isascii():
        return METHOD_CLIPBOARD
    return METHOD_KEYBOARD


def _read_back(session, element, text: str) -> tuple:
    """Read the control's current value and compare it with what was asked.

    Returns `(value, matches)`. A control that publishes no readable value is
    `(None, None)` — "cannot tell", which is not the same as "wrong", and never
    reported as either.
    """
    from core.windows import uia

    capabilities = tuple(getattr(element, "capabilities", ()) or ())
    value = None
    if "value" in capabilities:
        try:
            data = session.perform("get_value", _wrapper_of(session, element), element)
            value = data.get("value")
        except Exception:
            value = None
    if value is None and method_reads_text(element):
        try:
            value, _pattern = uia.read_state(_wrapper_of(session, element),
                                             element, "value")
        except Exception:
            value = None
    if value is None:
        return None, None
    return value, _equivalent(value, text)


def is_focused(wrapper) -> bool:
    """Did SetFocus actually take? Re-read, never assume."""
    try:
        return bool(wrapper.has_keyboard_focus())
    except Exception:
        return False


def method_reads_text(element) -> bool:
    """Could this control's text be read back at all?"""
    return "value" in tuple(getattr(element, "capabilities", ()) or ())


def _equivalent(read: object, asked: str) -> bool:
    """Compare a read-back value with what was typed.

    Applications normalise text on the way in: Notepad turns "\n" into "\r\n",
    rich text fields strip trailing spaces, a spin control returns a number.
    Comparing those literally would report a correct entry as wrong, which is
    as dishonest as reporting a wrong one as right. So both sides are
    normalised for line endings and trailing whitespace only — never for
    content, case or interior spacing.
    """
    if not isinstance(read, str):
        return False
    def _norm(value: str) -> str:
        return value.replace("\r\n", "\n").replace("\r", "\n").rstrip()
    return _norm(read) == _norm(asked)


def _wrapper_of(session, element):
    """The live automation object for an element discovered earlier.

    `UiaSession.find` already returns a wrapper; when an element came from a
    walk instead, this re-resolves it by runtime id and raises the same stale
    error the rest of the layer would.
    """
    from core.windows.errors import element_stale
    from core.windows.identifiers import build_runtime_id

    for wrapper in session.root().descendants():
        try:
            if (build_runtime_id(wrapper.element_info.runtime_id)
                    == element.runtime_id):
                return wrapper
        except Exception:
            continue
    raise element_stale(element.element_id)


def write_into(session, element, text: str, prefer: str = "",
               clear_first: bool = False, cancel_event=None) -> dict:
    """Write `text` into an already-resolved element, and report how.

    The caller has already resolved and (if needed) focused the element; this
    function only writes. Separating them is what lets `type_into` verify each
    link before the next one runs.
    """
    if cancel_event is not None and cancel_event.is_set():
        from core.windows.errors import cancelled
        raise cancelled("type_into")

    if element.sensitive:
        raise access_denied(
            f"'{element.element_id}' is a credential field "
            f"({element.sensitive_reason}), so NEO will not write to it. "
            f"The user can type it themselves.")
    if element.enabled is False:
        from core.windows.errors import element_disabled
        raise element_disabled(element.element_id)

    method = prefer or choose_method(element, text)
    if method not in (METHOD_VALUE_PATTERN, METHOD_KEYBOARD, METHOD_CLIPBOARD):
        from core.windows.errors import invalid_argument
        raise invalid_argument(
            f"'{method}' is not a way to enter text. Use value_pattern, "
            f"keyboard or clipboard.")

    from core.windows import uia

    if clear_first:
        _clear_module = _input_module()
        if not _clear_module.available():
            from core.windows.errors import os_error
            raise os_error("Clearing a field needs PyAutoGUI, which is not installed.")
        from core.windows.keys import parse_combination

        # Select-all then delete: the only portable "empty this field" on
        # Windows, and bounded to two known keys rather than a script.
        combination = parse_combination("ctrl+a")
        _clear_module.pyautogui.hotkey(*combination)
        _clear_module.pyautogui.press("delete")
    if method == METHOD_VALUE_PATTERN and "value" not in tuple(element.capabilities or ()):
        method = choose_method(element, text)

    if method == METHOD_VALUE_PATTERN:
        wrapper = _wrapper_of(session, element)
        data = uia.set_value_text(session, "set_value", wrapper, element, text)
        return {"method": METHOD_VALUE_PATTERN, "reported": data.get("reported", "")}

    # Keyboard and clipboard both need focus, which the caller verified.
    _input = _input_module()
    if not _input.available():
        from core.windows.errors import os_error
        raise os_error("Keyboard input needs PyAutoGUI, which is not installed.")

    if method == METHOD_CLIPBOARD:
        data = _input.type_keys_slowly(text, False, element.describe())
    else:
        data = _input.type_text(text, False, element.describe())
    return {"method": method, "reported": data.get("reported", "")}


def entry_result(element, written: dict, text: str, read_back,
                 matches, focused_confirmed: bool, notes: list) -> EntryResult:
    """Assemble the structured answer the façade returns."""
    return EntryResult(written=True, method=str(written.get("method", "")),
                       text=text, control=element.to_dict(), read_back=read_back,
                       matches=matches, focused_confirmed=focused_confirmed,
                       notes=list(notes or []))


def no_target(what: str) -> EntryResult:
    """Nothing was typed, and this is why. An honest empty result."""
    return EntryResult(written=False, refused=what,
                       notes=["no text was entered anywhere"])