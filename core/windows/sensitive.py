"""
Sensitive-field recognition.

THE RULE
    UI Automation can read a password field's contents, and that being
    technically possible is not a reason to. This module marks controls that
    hold credentials and refuses to read them.

WHAT IS DETECTED
    Two independent signals, because neither is sufficient on its own:

      1. IsPassword — the flag Windows itself sets on a control that masks
         input. Authoritative when present.
      2. Heuristics — automation id, control type and name matching a small
         list of conventional credential field names. Reported as a heuristic,
         with the reason recorded, because a false positive costs a field its
         value (annoying) while a false negative leaks it.

WHAT IS NEVER DONE
    The value of a sensitive element is not read into the model context, not
    written to the activity log, not returned in a structured result, and not
    placed on the clipboard. `read_value` raises instead. Typing INTO a
    sensitive field is allowed but marked, because entering a credential the
    user just supplied is a legitimate, requested act — it is the reading-back
    that has no purpose.
"""
from __future__ import annotations

from typing import Optional

from core.windows.errors import access_denied

# Conventional credential-field identifiers. Deliberately short and generic:
# these catch the ordinary cases (login forms, "unlock" dialogs) without
# pretending to classify every application on the machine.
_SENSITIVE_TOKENS = (
    "password", "passwd", "passphrase", "pwd", "secret",
    "pin", "passcode", "otp", "one-time", "verification code",
    "security code", "cvv", "card number", "cardnumber", "creditcard",
    "credential", "token", "api key", "apikey", "license key",
)

# Control types that are commonly credential-bearing. A Text control named
# "Password" is a password field; a Button named "Password" is not, because a
# button cannot hold a value — so type matters.
_VALUE_BEARING_TYPES = frozenset({"Edit", "Document", "Text", "ComboBox"})

# Windows marks these as masked; useful context, never a reason to read one.
_MASKED_STYLE_TYPES = frozenset({"Edit", "Document"})


def _has_token(text: Optional[str]) -> bool:
    if not text:
        return False
    lowered = str(text).lower()
    return any(token in lowered for token in _SENSITIVE_TOKENS)


def classify(element, *, is_password: Optional[bool] = None) -> tuple:
    """Decide whether `element` is sensitive. Returns (sensitive, reason).

    `is_password` is the IsPassword flag when the caller read it; leaving it
    None means "not exposed for this element", which is not the same as False
    and does not by itself make the element safe.
    """
    if is_password is True:
        return True, "Windows marks this control as a password field (IsPassword)"

    control_type = str(getattr(element, "control_type", "") or "")
    automation_id = getattr(element, "automation_id", None)
    name = getattr(element, "name", None)
    class_name = getattr(element, "class_name", None)

    if control_type not in _VALUE_BEARING_TYPES:
        return False, ""

    for source, label in ((automation_id, "automation id"),
                          (name, "name"),
                          (class_name, "class name")):
        if _has_token(source):
            return True, (f"recognised as a credential field from its {label} "
                          f"({source!r})")

    return False, ""


def apply(element) -> object:
    """Stamp `sensitive` / `sensitive_reason` onto a UIElement in place."""
    sensitive, reason = classify(element)
    if sensitive:
        element.sensitive = True
        element.sensitive_reason = reason
    return element


def refuse_read(element) -> None:
    """Raise unless the element is safe to read. Always raises for sensitive."""
    if getattr(element, "sensitive", False):
        reason = getattr(element, "sensitive_reason", "") or "recognised as a credential field"
        raise access_denied(
            f"'{getattr(element, 'element_id', 'this field')}' holds a credential "
            f"({reason}), so its contents are not read. Type into it if the user "
            f"gave you the value; never read one back.")


def redact(text: Optional[str]) -> str:
    """For logs: the shape of a value without the value."""
    if text is None:
        return ""
    return f"<{len(str(text))} characters redacted>"


def summarize_controls(elements, limit: int = 40) -> str:
    """One bounded line for the activity log.

    Names are included because they are what the user sees; values never are,
    and a sensitive element contributes only its label and why.
    """
    parts = []
    for element in list(elements)[:limit]:
        if getattr(element, "sensitive", False):
            parts.append(f"{element.describe()} (value withheld)")
        else:
            parts.append(element.describe())
    extra = len(elements) - len(parts)
    if extra > 0:
        parts.append(f"+{extra} more")
    return ", ".join(parts)