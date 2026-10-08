"""
Windows-only boundary. Nothing outside this package imports a Windows library.

WHAT LIVES HERE
    Everything that talks to Windows: Win32 window APIs (core/windows/win32.py)
    and UI Automation (core/windows/uia.py). Everything platform-independent —
    the task model, the execution layer, the action registry — imports the
    façade in core/windows/control.py, which asks `is_supported()` and returns
    NOT_AVAILABLE when the platform is not Windows.

WHY THE SEAM
    A future macOS or Linux adapter implements the same façade methods and the
    rest of NEO never learns which OS it is on. That is the whole point of the
    boundary: `control.py` is the contract, the `win32`/`uia` modules are one
    implementation of it, and nothing above this line names a Windows API.

WHAT IS DELIBERATELY NOT HERE
    No process killing, no registry editing, no arbitrary command execution, no
    screenshot-only aiming. Those are either other phases' work or would undo
    Phase 1's security work.
"""
from __future__ import annotations

import platform

IS_WINDOWS = platform.system() == "Windows"

BACKEND_NAME = "win32+uia (pywinauto / pywin32)"


def is_supported() -> bool:
    """True when this platform has an implementation behind the façade."""
    return IS_WINDOWS


def unavailable_reason() -> str:
    """Why the façade returns NOT_AVAILABLE here, in words a user can read."""
    if IS_WINDOWS:
        return ""
    return (f"Desktop control is implemented for Windows; this machine reports "
            f"{platform.system()}. The existing screenshot, mouse and keyboard "
            f"tools still work here.")