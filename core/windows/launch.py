"""
Launch detection — what actually opened, and can NEO drive it?

WHY THIS IS A SEPARATE FILE
    `apps.launch()` already does the hard part: it resolves a name through an
    allowlist, starts it with no shell, snapshots windows before and after, and
    tries hard to find the window that belongs to what it started — including
    the Windows 11 hand-off, where `notepad.exe` exits and a different process
    owns the window.

    What it does not do is *classify the outcome for a caller who has to act on
    it*. Three different things can all look like "launch succeeded":

      * a new window opened and publishes controls NEO can drive;
      * the application was already running and its existing window was brought
        forward — nothing new exists, but there is a real window to work with;
      * a process started and no window appeared at all, because the app is a
        tray utility, or a launcher, or it failed silently.

    Only the first two are "there is something to work with". Collapsing them
    into one boolean is how an assistant ends up reporting "Calculator is
    open" when it launched a stub process and nothing appeared.

    So this file turns the raw launch report into one honest classification with
    a `controlled` flag, a `detection` name and a list of caveats — and adds
    the one thing `apps.launch` deliberately does not do: a *second, bounded*
    look for the window after a hand-off, because the successor window often
    appears a moment after the launcher exits.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

#: How a launch ended. These are facts about the machine, not judgements.
NEW_WINDOW = "new_window"
EXISTING_WINDOW = "existing_window"
HANDED_OFF = "handed_off"
PROCESS_ONLY = "process_only"
SETTINGS_URI = "settings_uri"
NOTHING_HAPPENED = "nothing_happened"

DETECTIONS = (NEW_WINDOW, EXISTING_WINDOW, HANDED_OFF, PROCESS_ONLY,
              SETTINGS_URI, NOTHING_HAPPENED)

#: How long the post-hand-off re-look waits. The Windows 11 stub pattern is
#: genuinely a race — the successor window can appear a second or two after the
#: launcher process is gone — and one second is the difference between a goal
#: that works on Notepad and one that does not.
HANDOFF_LOOK_SECONDS = 1.5
HANDOFF_POLL_SECONDS = 0.25


@dataclass
class LaunchOutcome:
    """What a launch actually produced, in a shape a caller can branch on."""

    detection: str = NOTHING_HAPPENED
    controlled: bool = False
    window: Optional[dict] = None
    application: str = ""
    pid: Optional[int] = None
    resolved_target: str = ""
    how: str = ""
    caveats: list = field(default_factory=list)

    @property
    def has_window(self) -> bool:
        return bool(self.window and self.window.get("handle"))

    def to_dict(self) -> dict:
        return {"detection": self.detection, "controlled": self.controlled,
                "window": self.window, "application": self.application,
                "pid": self.pid, "resolved_target": self.resolved_target,
                "how": self.how, "caveats": list(self.caveats)}

    def describe(self) -> str:
        """One sentence that cannot be read as more than it is."""
        if self.detection in (NEW_WINDOW, HANDED_OFF) and self.window:
            chosen = self.window.get("chosen_because") or "it published controls"
            return (f"'{self.application}' opened '{self.window.get('title')}' "
                    f"(handle {self.window.get('handle')}, pid "
                    f"{self.window.get('process_id')}) — {chosen}.")
        if self.detection == EXISTING_WINDOW and self.window:
            return (f"'{self.application}' was already running; NEO is using its "
                    f"existing window '{self.window.get('title')}' (handle "
                    f"{self.window.get('handle')}).")
        if self.detection == SETTINGS_URI:
            return f"Windows was asked to open {self.resolved_target or self.application}."
        return (f"'{self.application}' was started (pid {self.pid}) but no window "
                f"appeared, so there is nothing for NEO to control yet.")


def _drives_controls(window: Optional[dict]) -> bool:
    """Does this window publish an accessible tree?

    Phase 3's launch already probes for this when it chooses between windows;
    the flag it wrote is the honest answer, and a window that has no such flag
    is assumed *not* drivable rather than optimistically assumed drivable.
    """
    if not window:
        return False
    chosen = str(window.get("chosen_because") or "")
    if "cannot drive it" in chosen or "publishes no accessible controls" in chosen:
        return False
    return True


def _follow_handoff(application: str, seconds: float = HANDOFF_LOOK_SECONDS) -> Optional[dict]:
    """One bounded look for a window that a launcher handed off to somebody else.

    Single-instance Windows applications (Notepad) replace their own window
    mid-session; the handle a launch reported may already be gone by the time
    the next step runs. This looks again *by application identity*, not by the
    stale handle, and only accepts a single unambiguous window.
    """
    deadline = time.monotonic() + max(0.0, float(seconds))
    from core.windows import win32

    stems = _identity_stems(application)
    if not stems:
        return None
    while time.monotonic() < deadline:
        try:
            windows = win32.list_windows(visible_only=True, include_untitled=True,
                                         limit=200)
        except Exception:
            return None
        live = [w for w in windows if _stem(w.process_name or "") in stems]
        if len(live) == 1:
            data = live[0].to_dict()
            data["chosen_because"] = ("the window this application owns, found "
                                      "after the launcher's process exited")
            return data
        if len(live) > 1:
            return None                      # ambiguous: never guess, keep waiting
        time.sleep(HANDOFF_POLL_SECONDS)
    return None


def _stem(value: str) -> str:
    """`C:\\\\Windows\\\\System32\\\\notepad.exe` → `notepad`, without importing pathlib
    at module scope for one function."""
    name = str(value or "").replace("\\", "/").rsplit("/", 1)[-1]
    return name[:-4].lower() if name.lower().endswith(".exe") else name.lower()


def _identity_stems(application: str) -> set:
    """Every process name this application might legitimately be called.

    Reuses `apps.ALIASES` / `apps.WINDOW_OWNER` — the one place that knows
    "calculator" means `calculatorapp.exe` — rather than growing a second
    mapping here that would drift away from it.
    """
    from core.windows import apps

    needle = _stem(application)
    stems = {needle}
    for alias, exe in (getattr(apps, "ALIASES", {}) or {}).items():
        if _stem(alias) == needle:
            stems.add(_stem(exe))
    owner = (getattr(apps, "WINDOW_OWNER", {}) or {}).get(needle)
    if owner:
        stems.add(_stem(owner))
    return {s for s in stems if s}


def classify(report: dict, follow: bool = True) -> LaunchOutcome:
    """Turn `apps.launch()`'s report into an honest, branchable outcome.

    `follow` controls the one bounded re-look after a hand-off. It is on by
    default because it is what makes launching Notepad usable, and it is
    bounded so it cannot delay a launch by more than a second and a half.
    """
    report = report or {}
    outcome = LaunchOutcome(
        application=str(report.get("application") or ""),
        pid=report.get("pid"),
        resolved_target=str(report.get("target") or ""),
        how=str(report.get("how") or ""),
    )
    window = report.get("window")
    existing = report.get("already_open")

    if report.get("target") and str(report.get("target", "")).startswith("ms-settings:"):
        outcome.detection = SETTINGS_URI
        outcome.caveats.append("A settings page is a system surface, not an "
                               "application window; NEO cannot drive it.")
        return outcome

    if window:
        outcome.window = window
        outcome.detection = HANDED_OFF if report.get("handed_off") else NEW_WINDOW
        outcome.controlled = _drives_controls(window)
        if not outcome.controlled:
            outcome.caveats.append(
                "the window exists but publishes no accessible controls, so NEO "
                "can see it but cannot operate its contents")
        if outcome.detection == HANDED_OFF:
            outcome.caveats.append(
                "the launcher process exited immediately and a different process "
                "owns the window (normal for Windows' app stubs)")
        return outcome

    if existing:
        outcome.window = existing
        outcome.detection = EXISTING_WINDOW
        outcome.controlled = _drives_controls(existing)
        outcome.caveats.append("nothing new was opened: the application was "
                               "already running and its window was reused")
        return outcome

    if follow and outcome.application:
        found = _follow_handoff(outcome.application)
        if found:
            outcome.window = found
            outcome.detection = HANDED_OFF
            outcome.controlled = _drives_controls(found)
            outcome.caveats.append(
                "the launcher process had already exited; the window was found by "
                "following the application's hand-off")
            return outcome

    if report.get("process_alive_after_wait"):
        outcome.detection = PROCESS_ONLY
        outcome.caveats.append(
            f"a process is alive (pid {outcome.pid}) but it published no window; "
            f"it may be a tray utility, or a launcher for something slower")
    else:
        outcome.detection = NOTHING_HAPPENED
        outcome.caveats.append(
            "the process started and exited without opening a window, and no "
            "window owned by this application was found afterwards")
    return outcome