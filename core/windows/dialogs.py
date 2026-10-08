"""
Dialogs — know what kind of window is blocking, and never bypass a security one.

WHY A DIALOG IS ITS OWN PROBLEM
    A desktop assistant's most common real-world failure is not "I cannot find
    the button". It is "an unexpected modal window appeared and everything after
    it went somewhere else". A save prompt eats the keystrokes meant for the
    document. A permission dialog eats them too. An authentication dialog is
    the one where "work around it" and "defeat a security control" are the same
    action, and NEO must never do the second.

    So this module answers one question — *what kind of dialog is this?* — from
    observable facts, and refuses to answer it by guessing.

HOW A DIALOG IS CLASSIFIED
    From what Windows and UI Automation actually publish, in this order:

      * a credential field anywhere inside it → `authentication`, unconditionally;
      * an edit field whose value is being asked for by a password pattern →
        also `authentication`;
      * buttons whose names match a known vocabulary → `confirmation`,
        `save`, `permission` or `file_picker`;
      * a window that is not the main window of its process, or that owns its
        own top-level window and blocks input → `modal`;
      * otherwise → `unknown`, which is reported as `unknown` and never upgraded
        to something the evidence does not support.

WHAT MAY BE TOUCHED
    `dismiss_kind()` lists which kinds may be closed without asking. It is a
    deliberately short list — generic confirmations and file pickers — and even
    those still go through the confirmation gate in the façade, because
    dismissing a dialog can discard a file the user wanted.

WHAT MUST NEVER BE TOUCHED
    `authentication`. NEO does not type into it, does not press its buttons,
    and does not treat it as an obstacle. The one honest response to "NEO is
    blocked by a password prompt" is to say so and stop.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

#: Dialog kinds. Plain string constants, matching the rest of the Windows layer.
CONFIRMATION = "confirmation"
SAVE = "save"
PERMISSION = "permission"
AUTHENTICATION = "authentication"
FILE_PICKER = "file_picker"
MODAL = "modal"
UNKNOWN = "unknown"

KINDS = (CONFIRMATION, SAVE, PERMISSION, AUTHENTICATION, FILE_PICKER, MODAL, UNKNOWN)

#: Kinds that may be closed on the user's behalf, and only through the gate.
DISMISSIBLE = frozenset({CONFIRMATION, FILE_PICKER})

#: Kinds where pressing a button could change a security boundary. These are
#: never automated, whatever the model asks for.
SECURITY_SENSITIVE = frozenset({AUTHENTICATION, PERMISSION})

#: Button-name vocabulary. Deliberately explicit words, not fuzzy matching: a
#: button called "Proceed" is not a confirmation, and pretending otherwise is
#: how an assistant clicks the wrong thing in a dialog it did not understand.
_CONFIRM_WORDS = ("ok", "okay", "yes", "allow", "continue", "accept", "agree",
                  "close", "got it", "fine")
_CANCEL_WORDS = ("cancel", "no", "not now", "later", "deny", "decline",
                 "disallow", "don't allow", "do not allow", "abort")
_SAVE_WORDS = ("save", "save as", "don't save", "don't save changes",
               "discard changes", "keep changes")
_PERMISSION_WORDS = ("grant", "grant access", "change permissions",
                     "allow access", "run as administrator", "elevate")
_FILE_WORDS = ("open", "save", "cancel", "browse", "upload", "choose a file",
               "select a file")
#: Words only a file chooser uses. A dialog needs one of these *and* an
#: open/save word to be a file picker: a Notepad save prompt also has "Save" and
#: "Cancel", and calling that a file picker would be calling it by the wrong
#: name.
_FILE_PICKER_MARKERS = ("browse", "upload", "choose a file", "select a file",
                        "file name", "file type", "look in", "folder")

#: Elements that mean "this window is collecting a secret", whatever their
#: labels say. Sensitive marking is decided by core/windows/sensitive.py; this
#: only reacts to it.
_SECRET_HINTS = ("password", "passcode", "pin", "credential", "one-time code",
                 "security code", "verification code", "2fa")


@dataclass
class DialogReport:
    """What kind of dialog this is, why, and what may be done about it."""

    kind: str = UNKNOWN
    window: dict = field(default_factory=dict)
    buttons: list = field(default_factory=list)
    credential_fields: int = 0
    dismissible: bool = False
    may_act: bool = True
    reason: str = ""
    advice: str = ""

    def to_dict(self) -> dict:
        return {"kind": self.kind, "window": dict(self.window),
                "buttons": list(self.buttons),
                "credential_fields": self.credential_fields,
                "dismissible": self.dismissible, "may_act": self.may_act,
                "reason": self.reason, "advice": self.advice}


def _button_names(elements: list) -> list:
    names = []
    for element in elements:
        if (element.control_type or "").lower() not in ("button", "splitbutton"):
            continue
        name = (element.name or "").strip()
        if name:
            names.append(name[:60])
    return names[:12]


def _matches_any(name: str, words) -> bool:
    lowered = name.strip().lower()
    return any(lowered == w or lowered.startswith(w) or w in lowered for w in words)


def classify(window: dict, elements: list) -> DialogReport:
    """Classify a dialog from what is actually observable. Never guesses up.

    `window` is the window's dict form; `elements` are the controls discovered
    inside it. An empty element list yields `unknown`, which is the honest
    answer when there is no evidence.
    """
    elements = list(elements or [])
    report = DialogReport(window=dict(window or {}),
                          buttons=_button_names(elements))
    secret_fields = [e for e in elements if getattr(e, "sensitive", False)]
    hinted = [e for e in elements
              if any(h in str(e.name or "").lower() for h in _SECRET_HINTS)
              and (e.control_type or "").lower() in ("edit", "password",
                                                      "document", "text")]
    # A field that is both marked sensitive *and* named "Password" is one
    # field, not two. Counting it twice would report a dialog with one prompt
    # as having two secrets.
    seen = {id(e) for e in secret_fields} | {id(e) for e in hinted}
    report.credential_fields = len(seen)

    if report.credential_fields:
        report.kind = AUTHENTICATION
        report.may_act = False
        report.reason = (f"the window asks for a secret ({report.credential_fields} "
                         f"credential field(s) inside it)")
        report.advice = ("NEO does not type into or press anything in an "
                         "authentication dialog. The user needs to complete it "
                         "themselves; NEO can pick the work back up afterwards.")
        return report

    names = report.buttons
    # File picker first: a chooser has Save and Cancel too, so testing for a
    # save prompt first would call every Open dialog a save dialog.
    is_file_picker = (
        (any(_matches_any(n, _FILE_WORDS) for n in names)
         and any(_matches_any(n, _FILE_PICKER_MARKERS) for n in names))
        or (any(_matches_any(n, ("open",)) for n in names)
            and any(_matches_any(n, ("save",)) for n in names))
    )
    if is_file_picker:
        report.kind = FILE_PICKER
        report.dismissible = True
        report.reason = "the window is a file chooser"
        return report
    if any(_matches_any(n, _SAVE_WORDS) for n in names):
        report.kind = SAVE
        report.reason = "the window offers save/discard choices"
        report.advice = ("Discarding unsaved work is not reversible, so this "
                         "dialog is not closed automatically.")
        return report
    if any(_matches_any(n, _PERMISSION_WORDS) for n in names):
        report.kind = PERMISSION
        report.may_act = False
        report.reason = "the window asks for a permission to be granted"
        report.advice = ("Granting permission changes a security boundary, so "
                         "NEO will not press these buttons.")
        return report
    if any(_matches_any(n, _CONFIRM_WORDS) for n in names):
        report.kind = CONFIRMATION
        report.dismissible = True
        report.reason = "the window offers a yes/no choice"
        report.advice = ("NEO will ask before pressing a confirmation button, "
                         "because 'yes' may mean something the user did not "
                         "intend.")
        return report
    if names and any(_matches_any(n, _CANCEL_WORDS) for n in names):
        report.kind = CONFIRMATION
        report.dismissible = True
        report.reason = "the window offers a cancel choice"
        return report
    if elements or names:
        report.kind = MODAL
        report.reason = ("the window publishes controls but none of the names "
                         "identify it as a known kind of dialog")
        report.advice = ("NEO does not know what this dialog is asking, so it "
                         "will not guess which button means yes.")
        return report

    report.kind = UNKNOWN
    report.reason = ("nothing inside the window identifies it; an empty "
                     "automation tree is the usual cause")
    report.advice = ("NEO will not act on a window it cannot identify. Ask the "
                     "user what it is, or dismiss the window manually.")
    return report


def find_dialog_candidates(windows: list, main_handles: Optional[set] = None) -> list:
    """Which of these windows look like dialogs rather than application windows.

    A dialog is, practically speaking, a top-level window that is not the
    application's main window. `main_handles` is the caller's set of known main
    windows; without one, everything titled like a dialog is reported as a
    candidate and *classified*, never acted on.
    """
    main = set(main_handles or ())
    out = []
    for window in windows or []:
        title = str((window or {}).get("title") or "").strip().lower()
        is_dialog_title = bool(title) and (
            any(word in title for word in ("dialog", "confirm", "save as",
                                           "error", "warning", "question"))
            or title.endswith(":"))
        handle = int((window or {}).get("handle") or 0)
        if handle and handle in main:
            continue
        if is_dialog_title:
            out.append(dict(window))
    return out[:8]


def may_dismiss(kind: str) -> bool:
    """Only these kinds may ever be closed, and only through the gate."""
    return str(kind) in DISMISSIBLE


def may_act_on(kind: str) -> bool:
    """Authentication and permission dialogs are off limits, always."""
    return str(kind) not in SECURITY_SENSITIVE


def dismiss_target(report: DialogReport) -> Optional[str]:
    """The safest button to press when a dismissible dialog must go.

    Cancel/No is preferred over Yes/OK for one reason: cancelling a dialog that
    was going to ask something can still lose the request, while pressing "OK"
    on a dialog NEO did not understand can commit to something. Neither is done
    without the user, so this is a recommendation rather than an action.
    """
    if not report.dismissible:
        return None
    for name in report.buttons:
        if _matches_any(name, _CANCEL_WORDS):
            return name
    return None


__all__ = [
    "AUTHENTICATION", "CONFIRMATION", "DialogReport", "FILE_PICKER", "KINDS",
    "MODAL", "PERMISSION", "SAVE", "UNKNOWN", "classify",
    "dismiss_target", "find_dialog_candidates", "may_act_on", "may_dismiss",
]