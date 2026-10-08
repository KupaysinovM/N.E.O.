"""
Application resolution and launching — structured, and without a shell.

THE PROBLEM WITH `shell=True`
    Handing a model-written string to a shell means the string is a program.
    `open_app("calc & del /s c:\\")` is not a mistyped application name, it is a
    command. The previous build launched applications exactly that way, and the
    model chose the string.

WHAT HAPPENS INSTEAD
    A requested name is resolved through an explicit table and the system's own
    executable lookup:

      1. an alias in `ALIASES` → the executable Windows ships for it;
      2. a name that already exists on PATH → that exact executable;
      3. an absolute path to an existing executable → that file;
      4. a `ms-settings:` URI → opened through the shell's own protocol handler,
         which takes a URI and not a command line.

    Everything else is refused with APPLICATION_NOT_FOUND. The executable and
    its arguments are always passed to CreateProcess as separate items, so
    there is no interpretation step where a string could become a command.

WHAT IT DOES NOT DO
    No arbitrary command string, no PowerShell, no argument interpolation, and
    no launch of a file whose type is decided by the model. Phase 3 launches
    applications; it is not a shell.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

import core.windows as _boundary
from core.windows.errors import application_not_found, invalid_argument, os_error

# Windows binaries NEO knows how to start, by the names a user actually says.
# Keyed by normalised name; values are the real executable names on Windows.
ALIASES = {
    "calculator": "calc.exe",
    "calc": "calc.exe",
    "notepad": "notepad.exe",
    "paint": "mspaint.exe",
    "explorer": "explorer.exe",
    "file explorer": "explorer.exe",
    "files": "explorer.exe",
    "task manager": "taskmgr.exe",
    "cmd": "cmd.exe",
    "command prompt": "cmd.exe",
    "powershell": "powershell.exe",
    "terminal": "wt.exe",
    "registry editor": "regedit.exe",
    "control panel": "control.exe",
    "settings": "ms-settings:",
    "snipping tool": "SnippingTool.exe",
    "character map": "charmap.exe",
    "device manager": "devmgmt.msc",
    "disk cleanup": "cleanmgr.exe",
    "system information": "msinfo32.exe",
    "windows terminal": "wt.exe",
}

# Some Windows applications are stubs: the program NEO starts exits immediately
# and hands the launch to another process, which owns the window. The mapping is
# declared here rather than guessed at runtime, so a window is only ever reported
# as this launch's window when Windows says a *known* successor owns it.
WINDOW_OWNER = {
    "calc": "calculatorapp.exe",
    "calculator": "calculatorapp.exe",
}

# Windows draws several Store apps inside a window owned by one shared host
# process, so for those apps the window cannot be recognised by process name at
# all. Their captions are declared here — the same kind of knowledge as the
# alias table above, and just as bounded — so "it was already open" can be said
# precisely instead of leaving the caller with nothing.
WINDOW_TITLES = {
    "calc": "Calculator",
    "calculator": "Calculator",
    "notepad": "Notepad",
    "paint": "Paint",
}

# System executables are resolved from System32 by name rather than through
# PATH, so "calculator" cannot be satisfied by a file of the same name sitting
# in a user-writable directory earlier on PATH.
_SYSTEM_DIRS = tuple(
    Path(os.environ.get(name, "")) for name in ("SystemRoot", "windir")
    if os.environ.get(name)
)

_SETTINGS_URI = re.compile(r"^ms-settings:([a-z0-9\-]*)$")
_MAX_NAME_LENGTH = 120


def _normalize(name: str) -> str:
    return re.sub(r"\s+", " ", str(name or "").strip().lower())


def _clean(name: str) -> str:
    """Refuse anything that is not plausibly a program name.

    This is the gate that a shell would otherwise be: no `&`, no `|`, no `;`,
    no quotes, no redirection, no spaces-as-separators. A name containing any of
    those is not an application name.
    """
    text = str(name or "").strip()
    if not text:
        raise invalid_argument("An application name is required.")
    if len(text) > _MAX_NAME_LENGTH:
        raise invalid_argument(f"'{text[:40]}…' is too long to be an application name.")
    for char in ("&", "|", ";", "<", ">", "`", "$", '"', "'", "\n", "\r", "\t",
                 "%", "^", "!", "(", ")", "{", "}", "[", "]", "*", "?", "#", "~"):
        if char in text:
            raise invalid_argument(
                f"'{text[:40]}' contains '{char}', which is not part of an "
                f"application name. NEO launches programs by name, not commands.")
    return text


def is_settings_uri(name: str) -> bool:
    return bool(_SETTINGS_URI.match(str(name or "").strip().lower()))


def resolve(name: str) -> dict:
    """Resolve a requested application to something safe to start.

    Returns the resolution actually used, or raises APPLICATION_NOT_FOUND. The
    caller is told *how* it was resolved because that is the difference between
    "Calculator is starting" and "something that claims to be Calculator is".
    """
    cleaned = _clean(name)
    normalized = _normalize(cleaned)

    if is_settings_uri(cleaned):
        return {"kind": "settings_uri", "target": cleaned.lower(),
                "how": "Windows settings protocol handler"}

    target = ALIASES.get(normalized)
    if target:
        if is_settings_uri(target):
            return {"kind": "settings_uri", "target": target,
                    "how": "known Windows settings page"}
        for directory in _SYSTEM_DIRS:
            candidate = directory / "System32" / target
            if candidate.exists():
                return {"kind": "system_executable",
                        "target": str(candidate),
                        "how": f"Windows system executable ({target})"}
        # fall through to PATH when the System32 copy is missing (unusual)

    path_candidate = Path(cleaned).expanduser()
    if path_candidate.is_absolute() and path_candidate.suffix.lower() in (
            ".exe", ".bat", ".cmd") and path_candidate.exists():
        if path_candidate.suffix.lower() != ".exe":
            raise invalid_argument(
                f"'{path_candidate.name}' is a script, and NEO does not run scripts "
                f"on the model's request. Launch the program itself instead.")
        return {"kind": "absolute_path", "target": str(path_candidate),
                "how": "the exact executable you named"}

    found = shutil.which(cleaned) or shutil.which(normalized)
    if found:
        if not str(found).lower().endswith(".exe"):
            raise invalid_argument(
                f"'{Path(found).name}' is not a Windows executable, and NEO does "
                f"not run scripts on the model's request.")
        return {"kind": "path_lookup", "target": found,
                "how": "found on PATH"}

    raise application_not_found(cleaned)


def _window_snapshot() -> set:
    """Window handles that exist right now — used to tell a new window from an old one."""
    try:
        from core.windows import win32
        return {w.handle for w in win32.list_windows(visible_only=False,
                                                      include_untitled=True, limit=300)}
    except Exception:
        return set()


def _owner_stems(executable: str) -> set:
    """Process names whose windows belong to a launch of `executable`.

    Normally just the executable's own name. For the declared hand-off
    applications it also includes the successor that really owns the window,
    so launching Calculator reports the Calculator window rather than nothing.
    """
    stem = Path(str(executable)).stem.lower()
    stems = {stem}
    owner = WINDOW_OWNER.get(stem)
    if owner:
        stems.add(Path(owner).stem.lower())
    return stems


_UI_PROBE_TIMEOUT = 2.0
_UI_PROBE_DEPTH = 6
_UI_PROBED: dict = {}


def _publishes_ui(window, _cache: dict = _UI_PROBED) -> bool:
    """Does this window publish an accessible control tree? One bounded probe.

    Used only to choose between windows this launch created. Each handle is
    probed at most once, so a slow application cannot make launching slow by
    being probed again.
    """
    if window.handle not in _cache:
        try:
            from core.windows import uia
            found = (uia.UiaSession(window, timeout=_UI_PROBE_TIMEOUT).connect()
                     .walk(max_depth=_UI_PROBE_DEPTH, limit=8, named_only=True))
            _cache[window.handle] = bool(found)
        except Exception:
            _cache[window.handle] = False
    return _cache[window.handle]


def _choose_window(matches: list, fresh: list) -> Optional[dict]:
    """Pick the window this launch really opened, and say how it was picked.

    Windows 10/11 draw many Store apps inside a window owned by a *shared* host
    process (`ApplicationFrameHost.exe`), which also owns unrelated windows —
    Settings among them. That host can never be trusted by name, so the only
    signal that separates the window a user can interact with from a window the
    app merely created is whether that window publishes an accessible UI tree.
    Calculator demonstrates why this matters: its own process creates a window
    with no controls at all, while the host window shows all 36 buttons.

    The reported `chosen_because` says which of these applied, so nobody has to
    guess why NEO picked that handle.
    """
    if not matches:
        return None

    def report(window, why: str) -> dict:
        data = window.to_dict()
        data["chosen_because"] = why
        return data

    for window in matches:
        if _publishes_ui(window):
            return report(window, "the new window this process created, and it "
                                   "publishes accessible controls")

    owner = matches[0]
    title = (owner.title or "").strip()
    if title:
        for window in fresh:
            if window.handle == owner.handle or (window.title or "").strip() != title:
                continue
            if _publishes_ui(window):
                return report(window, f"the shared Windows app host showing '{title}', "
                                       "which is the window that publishes controls")
    return report(owner, "the new window this process created; it publishes no "
                         "accessible controls, so NEO cannot drive it")


def _new_window_for(executable: str, before: set, timeout: float = 6.0) -> Optional[dict]:
    """Wait for a window that appeared after `before` and belongs to this program.

    Windows 11 hands off: `notepad.exe` is a stub that exits immediately and the
    Store build of Notepad runs in its own process. Matching the window by the
    program that owns it — not by the stub's process id — is what makes launch
    useful on a real machine, and comparing against the pre-launch snapshot is
    what keeps it honest: a window that was already open is never reported as
    something this call created.
    """
    try:
        from core.windows import win32
    except Exception:
        return None
    wanted = _owner_stems(executable)
    deadline = time.monotonic() + max(0.5, float(timeout))
    matches: list = []
    fresh: list = []
    while time.monotonic() < deadline:
        try:
            fresh = [w for w in win32.list_windows(visible_only=True,
                                                   include_untitled=True, limit=300)
                     if w.handle not in before]
        except Exception:
            fresh = []
        for window in fresh:
            # Windows reports the process as 'Notepad.exe' while the executable
            # we started was '...\notepad.exe' — compare stems, not the raw name.
            if (Path(window.process_name or "").stem.lower() in wanted
                    and window.handle not in {m.handle for m in matches}):
                matches.append(window)
        # A window that has already published its tree is a better answer than
        # one that has not, so stop waiting as soon as there is one.
        if any(_publishes_ui(window) for window in matches):
            break
        time.sleep(0.4)
    return _choose_window(matches, fresh)


def _existing_window(name: str, stems: set) -> Optional[dict]:
    """An already-open window belonging to this application, if there is one.

    Launching a single-instance application that is already running creates
    nothing — the running one is simply brought forward. Reporting that
    honestly, with its handle, is far more useful than reporting no window and
    leaving the caller to go looking for one.
    """
    title = WINDOW_TITLES.get(_normalize(name))
    if not title:
        return None
    try:
        from core.windows import win32
        windows = win32.list_windows(visible_only=True, include_untitled=True, limit=200)
    except Exception:
        return None
    for window in windows:
        owned = Path(window.process_name or "").stem.lower() in stems
        if (window.title or "").strip().lower() == title.lower() or owned:
            data = window.to_dict()
            data["chosen_because"] = "already open before this launch"
            return data
    return None


def launch(name: str, wait: float = 1.2, timeout: float = 8.0) -> dict:
    """Start an application. Returns what was started — never "it worked".

    The report says a process was created with a given executable, and whether a
    window owned by that program appeared. Whether the application then did
    anything useful is verification, which is Phase 4 and is not implemented
    here.
    """
    resolution = resolve(name)

    if resolution["kind"] == "settings_uri":
        uri = resolution["target"]
        try:
            os.startfile(uri)                      # noqa: S606 - URI, not a command
        except Exception as e:
            raise os_error(f"Windows could not open {uri}.", str(e))
        return {"operation": "launch", "application": name,
                "target": uri, "how": resolution["how"], "window": None,
                "reported": "Windows was asked to open the settings page"}

    target = resolution["target"]
    before = _window_snapshot()
    try:
        process = subprocess.Popen(
            [target],                              # executable and arguments split
            shell=False,                           # never interpreted
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=str(Path(target).parent),
        )
    except FileNotFoundError:
        raise application_not_found(name)
    except Exception as e:
        raise os_error(f"{Path(target).name} could not be started.", str(e))

    time.sleep(max(0.0, float(wait)))
    alive = process.poll() is None
    window = _new_window_for(target, before)
    existing = None if window else _existing_window(name, _owner_stems(target))
    reported = f"started {Path(target).name} (pid {process.pid})"
    if window:
        reported += (f"; a window opened: '{window['title']}' "
                     f"(pid {window['process_id']}, handle {window['handle']} — "
                     f"{window['chosen_because']})")
    elif existing:
        reported += (f"; nothing new opened because it was already running — "
                     f"'{existing['title']}' is at handle {existing['handle']} "
                     f"(pid {existing['process_id']})")
    elif not alive:
        reported += ("; that launcher exited immediately and no new window "
                     "appeared — this is normal for Windows' app stubs")
    return {"operation": "launch", "application": name, "target": target,
            "how": resolution["how"], "pid": process.pid,
            "process_alive_after_wait": alive,
            "handed_off": bool(not alive and window),
            "window": window,
            "already_open": existing,
            "reported": reported}


def is_running(name: str) -> Optional[dict]:
    """Whether a process matching this name exists. Read-only, never launches."""
    needle = Path(str(name)).stem.lower()
    from core.windows.win32 import list_processes
    matches = [p for p in list_processes(name_contains=needle, limit=20)
               if needle and needle in (p.name or "").lower()]
    return {"name": needle, "running": bool(matches),
            "processes": [p.to_dict() for p in matches[:5]]}