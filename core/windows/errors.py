"""
Windows error taxonomy — the same kinds, at Windows granularity.

A Windows call can fail for reasons a tool-level result cannot express: the
window vanished, two buttons share a name, the control has no Invoke pattern,
the app hung. Collapsing all of that into "failed" would throw away exactly the
information Phase 4 needs to verify what happened, so each case gets its own
kind.

These map onto core.task_models.ErrorKind — they extend that taxonomy rather
than replacing it, so a Windows failure and a task failure stay comparable.
"""
from __future__ import annotations

from core.task_models import ErrorKind


class WindowsErrorKind(str):
    """Windows-level failure kinds.

    Plain string constants rather than an Enum: `ErrorKind` is the canonical
    taxonomy and a second enum of near-identical members would create exactly
    the parallel error system this is meant to avoid. These names are the
    Windows vocabulary; `to_error_kind()` is the translation.
    """

    WINDOW_NOT_FOUND       = "WINDOW_NOT_FOUND"
    ELEMENT_NOT_FOUND      = "ELEMENT_NOT_FOUND"
    ELEMENT_AMBIGUOUS      = "ELEMENT_AMBIGUOUS"
    ELEMENT_DISABLED       = "ELEMENT_DISABLED"
    ELEMENT_STALE          = "ELEMENT_STALE"
    UNSUPPORTED_CONTROL    = "UNSUPPORTED_CONTROL"
    INVALID_ARGUMENT       = "INVALID_ARGUMENT"
    TIMEOUT                = "TIMEOUT"
    ACCESS_DENIED          = "ACCESS_DENIED"
    PROCESS_NOT_FOUND      = "PROCESS_NOT_FOUND"
    APPLICATION_NOT_FOUND  = "APPLICATION_NOT_FOUND"
    OS_ERROR               = "OS_ERROR"
    CANCELLED              = "CANCELLED"


_MAP = {
    WindowsErrorKind.WINDOW_NOT_FOUND:      ErrorKind.WINDOW_NOT_FOUND,
    WindowsErrorKind.ELEMENT_NOT_FOUND:     ErrorKind.ELEMENT_NOT_FOUND,
    WindowsErrorKind.ELEMENT_AMBIGUOUS:     ErrorKind.ELEMENT_AMBIGUOUS,
    WindowsErrorKind.ELEMENT_DISABLED:      ErrorKind.ELEMENT_DISABLED,
    WindowsErrorKind.ELEMENT_STALE:         ErrorKind.ELEMENT_STALE,
    WindowsErrorKind.UNSUPPORTED_CONTROL:   ErrorKind.UNSUPPORTED_CONTROL,
    WindowsErrorKind.INVALID_ARGUMENT:      ErrorKind.INVALID_ARGUMENTS,
    WindowsErrorKind.TIMEOUT:               ErrorKind.TIMEOUT,
    WindowsErrorKind.ACCESS_DENIED:         ErrorKind.ACCESS_DENIED,
    WindowsErrorKind.PROCESS_NOT_FOUND:     ErrorKind.PROCESS_NOT_FOUND,
    WindowsErrorKind.APPLICATION_NOT_FOUND: ErrorKind.APPLICATION_NOT_FOUND,
    WindowsErrorKind.OS_ERROR:              ErrorKind.OS_ERROR,
    WindowsErrorKind.CANCELLED:             ErrorKind.TASK_CANCELLED,
}


def to_error_kind(kind: str) -> ErrorKind:
    """Windows kind → the shared taxonomy. Unknown kinds stay honest as OS_ERROR."""
    return _MAP.get(kind, ErrorKind.OS_ERROR)


class WindowsError(Exception):
    """A Windows operation failed in a way worth naming.

    Carries the kind, an operator-facing message, and a `detail` for the log.
    The message is what may reach the model, so it never contains a stack trace.
    """

    def __init__(self, kind: str, message: str, detail: str = ""):
        self.kind = kind
        self.detail = detail
        super().__init__(message)

    @property
    def message(self) -> str:
        return str(self)

    @property
    def error_kind(self) -> ErrorKind:
        return to_error_kind(self.kind)

    def to_dict(self) -> dict:
        return {"kind": self.kind, "message": self.message,
                "detail": self.detail, "error_kind": self.error_kind.value}


# ── constructors for the common cases ────────────────────────────────────────

def window_not_found(what: str) -> WindowsError:
    return WindowsError(WindowsErrorKind.WINDOW_NOT_FOUND,
                        f"No window matching {what} is open.")


def element_not_found(what: str) -> WindowsError:
    return WindowsError(WindowsErrorKind.ELEMENT_NOT_FOUND,
                        f"No control matching {what} was found.")


def element_ambiguous(what: str, count: int, options: str = "") -> WindowsError:
    extra = f" Closest candidates: {options}" if options else ""
    return WindowsError(WindowsErrorKind.ELEMENT_AMBIGUOUS,
                        f"{count} controls match {what}, so none can be chosen safely."
                        f"{extra}")


def window_ambiguous(what: str, count: int, options: str = "") -> WindowsError:
    """Several windows match one request. Same kind, correct noun.

    The taxonomy has one ambiguity kind, so the shared `ELEMENT_AMBIGUOUS`
    stands — but a window that cannot be chosen is not a control, and saying so
    is the difference between a message a user can act on and one they cannot.
    """
    extra = f" Closest candidates: {options}" if options else ""
    return WindowsError(WindowsErrorKind.ELEMENT_AMBIGUOUS,
                        f"{count} open windows match {what}, so none can be chosen "
                        f"safely. Name one by title, or give its window handle."
                        f"{extra}")


def element_disabled(name: str) -> WindowsError:
    return WindowsError(WindowsErrorKind.ELEMENT_DISABLED,
                        f"The control '{name}' is disabled, so it cannot be used.")


def element_stale(name: str) -> WindowsError:
    return WindowsError(WindowsErrorKind.ELEMENT_STALE,
                        f"The control '{name}' no longer exists — the window was "
                        f"redrawn or closed. Look it up again.")


def unsupported_control(control_type: str, operation: str) -> WindowsError:
    return WindowsError(WindowsErrorKind.UNSUPPORTED_CONTROL,
                        f"A {control_type} does not support {operation}.")


def invalid_argument(message: str) -> WindowsError:
    return WindowsError(WindowsErrorKind.INVALID_ARGUMENT, message)


def timeout(seconds: float) -> WindowsError:
    return WindowsError(WindowsErrorKind.TIMEOUT,
                        f"The Windows operation did not finish within {seconds:g}s.")


def access_denied(message: str) -> WindowsError:
    return WindowsError(WindowsErrorKind.ACCESS_DENIED, message)


def application_not_found(name: str) -> WindowsError:
    return WindowsError(WindowsErrorKind.APPLICATION_NOT_FOUND,
                        f"No launchable application named '{name}' could be resolved.")


def process_not_found(pid: int) -> WindowsError:
    return WindowsError(WindowsErrorKind.PROCESS_NOT_FOUND,
                        f"No running process has id {pid}.")


def cancelled(operation: str = "") -> WindowsError:
    what = f"'{operation}'" if operation else "The operation"
    return WindowsError(WindowsErrorKind.CANCELLED, f"{what} was cancelled.")


def os_error(message: str, detail: str = "") -> WindowsError:
    return WindowsError(WindowsErrorKind.OS_ERROR, message, detail)