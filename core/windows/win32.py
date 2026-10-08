"""
Real Win32 window control — window facts and window state, from the OS.

This layer answers questions about windows only:
    what is open, which one is active, what process owns it, can I focus it,
    is it minimized, what are its real coordinates.

It does not look inside a window. That is core/windows/uia.py's job, and the
split matters: Win32 window APIs are instant and cannot hang on a misbehaving
app, while UIA calls into an application's own code sometimes can.

Everything reported here comes from Windows. A window handle that Windows no
longer knows about is not reported as a window, and focusing a handle that has
been reused is detected rather than guessed at.
"""
from __future__ import annotations

import threading
import time
from typing import Callable, Optional

import core.windows as _boundary
from core.windows.errors import (
    WindowsError,
    WindowsErrorKind,
    access_denied,
    os_error,
    window_not_found,
)
from core.windows.models import ProcessInfo, Rect, WindowInfo

try:  # Windows-only imports; the façade checks availability before reaching here.
    import win32api
    import win32con
    import win32gui
    import win32process
    _WIN32 = True
except ImportError:                                     # pragma: no cover
    _WIN32 = False

try:
    import psutil
    _PSUTIL = True
except ImportError:                                     # pragma: no cover
    _PSUTIL = False


# Win32 calls are quick, but a hung window owner can still stall a message
# pump. Every operation runs under this so a pathological window cannot hang the
# caller forever; the executor thread is a daemon, and nothing is killed.
DEFAULT_TIMEOUT = 5.0


def _guarded(fn: Callable, timeout: float = DEFAULT_TIMEOUT):
    """Run a Win32 call on a worker thread with a deadline.

    On expiry the operation reports TIMEOUT and the worker — which may still be
    inside a Windows call — is left to finish on its own. Terminating it would
    mean terminating a thread mid-syscall, which is exactly the unsafe thread
    killing Phase 3 is told not to introduce. The daemon thread ends when the
    call does.
    """
    box: dict = {}

    def _run():
        try:
            box["value"] = fn()
        except BaseException as e:                      # noqa: BLE001 - reported below
            box["error"] = e

    worker = threading.Thread(target=_run, daemon=True, name="win32-call")
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        from core.windows.errors import timeout as timeout_error
        raise timeout_error(timeout)
    if "error" in box:
        raise box["error"]
    return box.get("value")


def available() -> bool:
    return _boundary.is_supported() and _WIN32


# ── enumeration ──────────────────────────────────────────────────────────────

def _process_name(pid: Optional[int]) -> Optional[str]:
    if pid is None:
        return None
    try:
        handle = win32api.OpenProcess(0x1000, False, pid)   # PROCESS_QUERY_LIMITED_INFORMATION
        try:
            return win32process.GetModuleFileNameEx(handle, 0).rsplit("\\", 1)[-1]
        finally:
            win32api.CloseHandle(handle)
    except Exception:
        pass
    if _PSUTIL:
        try:
            return psutil.Process(pid).name()
        except Exception:
            return None
    return None


def _make_window_info(handle: int, active_handle: int) -> WindowInfo:
    try:
        title = win32gui.GetWindowText(handle) or ""
    except Exception:
        title = ""
    pid = None
    try:
        pid = win32process.GetWindowThreadProcessId(handle)[1]
    except Exception:
        pass
    placement = None
    try:
        placement = win32gui.GetWindowPlacement(handle)
    except Exception:
        pass
    flags = placement[1] if placement else 0
    try:
        rect = win32gui.GetWindowRect(handle)
        bounds = Rect.from_values(*rect)
    except Exception:
        bounds = None
    try:
        visible = bool(win32gui.IsWindowVisible(handle))
    except Exception:
        visible = False
    try:
        enabled = bool(win32gui.IsWindowEnabled(handle))
    except Exception:
        enabled = None
    # Each fact is read on its own. A shared try block once cost this file a
    # real answer: IsZoomed does not exist in every pywin32 build, and the
    # shared except handler reset `minimized` to False while the window was in
    # fact minimized. A wrong window state is worse than a missing one.
    show_state = placement[1] if placement else 0
    try:
        iconic = bool(win32gui.IsIconic(handle))
    except Exception:
        iconic = (show_state == 2)                  # SW_SHOWMINIMIZED
    try:
        zoomed = bool(getattr(win32gui, "IsZoomed")(handle))
    except Exception:
        zoomed = (show_state == 3)                  # SW_SHOWMAXIMIZED
    return WindowInfo(
        handle=handle, title=title, process_id=pid,
        process_name=_process_name(pid) if pid else None,
        bounds=bounds, visible=visible, enabled=enabled,
        minimized=iconic, maximized=zoomed,
        is_active=(handle == active_handle),
    )


def list_windows(visible_only: bool = True, include_untitled: bool = False,
                 limit: int = 60) -> list:
    """Real top-level windows, newest-focused first is not available; so by handle.

    Bounded by design: the desktop can hold hundreds of windows and a list that
    long is context the model cannot use.
    """
    active = _guarded(win32gui.GetForegroundWindow)
    collected: list = []

    def _callback(handle, _extra):
        if visible_only and not win32gui.IsWindowVisible(handle):
            return True
        try:
            info = _make_window_info(handle, active)
        except Exception:
            return True
        if not include_untitled and not info.title:
            return True
        collected.append(info)
        return len(collected) < limit

    win32gui.EnumWindows(_callback, None)
    return collected


def active_window() -> WindowInfo:
    handle = _guarded(win32gui.GetForegroundWindow)
    if not handle:
        raise window_not_found("the active window")
    return _make_window_info(handle, handle)


def find_window(title: str = "", process_id: Optional[int] = None,
                handle: Optional[int] = None, visible_only: bool = True) -> WindowInfo:
    """Locate exactly one window, or fail.

    A title substring that matches several windows is an ambiguity, not a
    reason to pick the first one — the user asked about one window and could
    easily mean a different one than the one that happens to be lowest in the
    list.
    """
    from core.windows.errors import window_ambiguous

    if handle:
        try:
            if not win32gui.IsWindow(handle):
                raise window_not_found(f"window handle {handle} (it is no longer valid)")
            return _make_window_info(int(handle),
                                     _guarded(win32gui.GetForegroundWindow))
        except WindowsError:
            raise
        except Exception as e:
            raise os_error("That window could not be inspected.", str(e))

    candidates = list_windows(visible_only=visible_only, include_untitled=bool(process_id),
                              limit=200)
    if title:
        candidates = [w for w in candidates if w.matches(title)]
    if process_id is not None:
        candidates = [w for w in candidates if w.process_id == int(process_id)]
    if not candidates:
        what = f"titled '{title}'" if title else f"owned by process {process_id}"
        raise window_not_found(what)
    if len(candidates) > 1:
        raise window_ambiguous(what_desc(title, process_id), len(candidates),
                               _window_summary(candidates))
    return candidates[0]


def what_desc(title: str, process_id: Optional[int]) -> str:
    if title and process_id is not None:
        return f"a window titled '{title}' from process {process_id}"
    if title:
        return f"a window titled '{title}'"
    return f"a window from process {process_id}"


def _window_summary(windows, limit: int = 5) -> str:
    parts = [f"'{w.title}' (pid {w.process_id})" for w in windows[:limit]]
    extra = len(windows) - len(parts)
    return "; ".join(parts) + (f"; +{extra} more" if extra > 0 else "")


def is_open(title: str = "", process_id: Optional[int] = None,
            handle: Optional[int] = None) -> bool:
    try:
        find_window(title=title, process_id=process_id, handle=handle)
        return True
    except WindowsError:
        return False


# ── window state ─────────────────────────────────────────────────────────────

def _require_open(info: WindowInfo) -> None:
    """A stored handle can be reused by Windows after a window closes."""
    try:
        if not win32gui.IsWindow(info.handle):
            raise window_not_found(f"'{info.label}' (it closed)")
    except WindowsError:
        raise
    except Exception:
        pass


_FOCUS_ATTEMPTS = 4
_FOCUS_RETRY_SECONDS = 0.25


def focus_window(info: WindowInfo, timeout: float = DEFAULT_TIMEOUT) -> WindowInfo:
    """Bring a window to the front and activate it.

    SetForegroundWindow is refused by Windows when the calling process does not
    own the foreground window — which is the normal case for an assistant. The
    documented workaround (attach the thread input queues, then call it) is used
    here rather than reporting a failure that a human would not see.

    Windows also applies a foreground *lock*: a window that has only just
    appeared is often refused on the first attempt and accepted on a later one.
    So activation is retried a few times over a fraction of a second, and only
    a refusal that survives every attempt is reported — as ACCESS_DENIED, which
    is what happened, rather than an unexplained OS error.
    """
    _require_open(info)
    last: Optional[Exception] = None
    for attempt in range(_FOCUS_ATTEMPTS):
        try:
            _activate(info)
            after = _guarded(win32gui.GetForegroundWindow)
            if after == info.handle:
                return _make_window_info(info.handle, after)
            last = None
        except WindowsError:
            raise
        except Exception as e:                       # refused, not broken
            last = e
        if attempt < _FOCUS_ATTEMPTS - 1:
            time.sleep(_FOCUS_RETRY_SECONDS)

    if last is not None:
        raise access_denied(
            f"Windows kept '{info.label}' behind other windows "
            f"({last}). This is the foreground lock, not a broken window: the "
            f"user can click it, or NEO can act on the window that is already "
            f"active.")
    after = _guarded(win32gui.GetForegroundWindow)
    return _make_window_info(info.handle, after)


def _activate(info: WindowInfo) -> None:
    """One genuine attempt at activating `info`. Raises if Windows refuses."""
    current = win32gui.GetForegroundWindow()
    if current == info.handle:
        return
    target_thread = win32process.GetWindowThreadProcessId(info.handle)[0]
    current_thread = win32api.GetCurrentThreadId()
    attached = False
    if target_thread != current_thread:
        try:
            attached = bool(win32process.AttachThreadInput(
                target_thread, current_thread, True))
        except Exception:
            attached = False
    try:
        if info.minimized:
            win32gui.ShowWindow(info.handle, win32con.SW_RESTORE)
        win32gui.SetForegroundWindow(info.handle)
        win32gui.SetActiveWindow(info.handle)
    finally:
        if attached:
            try:
                win32process.AttachThreadInput(target_thread, current_thread, False)
            except Exception:
                pass


def set_window_state(info: WindowInfo, state: str) -> WindowInfo:
    """minimize | maximize | restore | normal — the real Win32 ShowWindow call."""
    _require_open(info)
    commands = {
        "minimize": win32con.SW_MINIMIZE,
        "maximize": win32con.SW_MAXIMIZE,
        "restore": win32con.SW_RESTORE,
        "normal": win32con.SW_SHOWNORMAL,
    }
    if state not in commands:
        from core.windows.errors import invalid_argument
        raise invalid_argument(
            f"'{state}' is not a window state. Use minimize, maximize, restore or normal.")
    try:
        if state == "restore" and not info.minimized:
            win32gui.ShowWindow(info.handle, win32con.SW_RESTORE)
        else:
            win32gui.ShowWindow(info.handle, commands[state])
    except Exception as e:
        raise os_error(f"Could not {state} '{info.label}'.", str(e))
    return _make_window_info(info.handle, _guarded(win32gui.GetForegroundWindow))


def close_window(info: WindowInfo) -> WindowInfo:
    """Ask a window to close (WM_CLOSE), which lets it save or cancel.

    Deliberately not DestroyWindow: a polite close is the difference between a
    confirmation dialog appearing and unsaved work disappearing.
    """
    _require_open(info)
    try:
        win32gui.PostMessage(info.handle, win32con.WM_CLOSE, 0, 0)
    except Exception as e:
        raise os_error(f"Could not ask '{info.label}' to close.", str(e))
    return info


# ── processes (read-only) ────────────────────────────────────────────────────

def list_processes(name_contains: str = "", limit: int = 40) -> list:
    """Read-only process list. Phase 3 has no way to terminate anything."""
    if not _PSUTIL:
        raise os_error("Process information needs psutil, which is not installed.")
    needle = str(name_contains or "").strip().lower()
    found: list = []
    try:
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                name = proc.info.get("name") or ""
                if needle and needle not in name.lower():
                    continue
                found.append(ProcessInfo(pid=proc.info["pid"], name=name,
                                         exe=proc.info.get("exe")))
                if len(found) >= limit:
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception as e:
        raise os_error("The process list could not be read.", str(e))
    return found


def process_info(pid: int) -> ProcessInfo:
    from core.windows.errors import process_not_found
    if not _PSUTIL:
        raise os_error("Process information needs psutil, which is not installed.")
    try:
        proc = psutil.Process(int(pid))
        info = ProcessInfo(pid=proc.pid, name=proc.name(), exe=proc.exe())
    except (psutil.NoSuchProcess,):
        raise process_not_found(int(pid))
    except psutil.AccessDenied as e:
        from core.windows.errors import access_denied
        raise access_denied(f"Process {pid} belongs to another user.")
    except Exception as e:
        raise os_error(f"Process {pid} could not be inspected.", str(e))
    titles = []
    for window in list_windows(visible_only=False, include_untitled=False, limit=200):
        if window.process_id == info.pid:
            titles.append(window.title)
    info.window_titles = tuple(titles)
    return info


# ── screen geometry ──────────────────────────────────────────────────────────

def screen_size() -> tuple:
    try:
        return (win32api.GetSystemMetrics(0), win32api.GetSystemMetrics(1))
    except Exception:
        return (0, 0)