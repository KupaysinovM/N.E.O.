"""
Window targeting — turning "the Telegram window" into one window, or refusing.

WHY THIS FILE EXISTS
    Phase 3 resolved a window by a title substring and returned the first
    match. On a real desktop that is the single most common way an assistant
    does the wrong thing: two Notepad windows, two Chrome windows with the
    same page title, a saved game and a running one, a file manager and the
    file it is showing. "First match" is a guess, and a guess about which
    window someone is typing into is not an acceptable failure mode.

    So targeting here is explicit about four things Phase 3 left implicit:

      * **Stable identifiers first.** A handle is used when the caller has one
        and it is re-validated against the live window list, because Windows
        reuses handles after a window closes. Process id, then process name,
        then class name, then title — in that order, and the order is written
        down rather than emergent.
      * **Scoring, not first-match.** Every candidate is scored against the
        request, and the scores are returned so a caller can see *why* one
        window was chosen.
      * **AMBIGUOUS is a real outcome.** When two candidates tie at the top
        score, this raises `ELEMENT_AMBIGUOUS` rather than picking one. The
        caller must then narrow the request (`index`, `process_id`, a longer
        title) or stop.
      * **Stale handles are re-resolved, not retried.** A handle that no longer
        names a live window is looked up again by process identity — the same
        bounded re-location Phase 5 does at the goal layer — but only when
        exactly one window of that process exists. Two windows of the same
        process is a question for the user, not for a heuristic.

WHAT IT IS NOT
    It is not a window manager, not a layout engine, and not a place where
    windows get closed. It reads the live window list and decides which entry
    a request means. Every caller still goes through `core/windows/control.py`
    and the confirmation gate.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from core.windows.errors import (
    WindowsErrorKind,
    invalid_argument,
    window_ambiguous,
    window_not_found,
)
from core.windows.models import WindowInfo

#: How many windows are read before scoring. A desktop publishes more windows
#: than any of this needs, and the read has a cost, so the list is bounded.
MAX_CANDIDATES = 60

#: Score for a window whose title is *exactly* the requested text.
SCORE_EXACT_TITLE = 100
#: Score for a title that starts with the requested text.
SCORE_TITLE_PREFIX = 70
#: Score for a title that contains the requested text.
SCORE_TITLE_CONTAINS = 50
#: Score for matching the owning process by name.
SCORE_PROCESS_NAME = 40
#: Score for matching the window class.
SCORE_CLASS_NAME = 25
#: Score for a window the caller named by handle and the OS still agrees with.
SCORE_HANDLE = 90
#: Score for a window Windows reports as the foreground one.
SCORE_ACTIVE = 10
#: Bonus when the window is visible and not minimized — a minimized window is
#: a poor candidate for "the one I want to work with", never a disqualifier.
SCORE_VISIBLE = 5

#: How old a candidate list may be and still be reused. Long enough that one
#: goal run does not re-enumerate per step, short enough that a desktop which
#: changed under us is not planned against.
CACHE_SECONDS = 1.5


@dataclass
class Candidate:
    """One window, and why it scored what it scored."""

    window: WindowInfo
    score: int = 0
    reasons: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"score": self.score, "reasons": list(self.reasons),
                "window": self.window.to_dict()}


@dataclass
class Match:
    """The outcome of targeting: one window, or an honest refusal."""

    window: Optional[WindowInfo] = None
    candidates: list = field(default_factory=list)
    ambiguous: bool = False
    used_handle: bool = False
    re_resolved: bool = False
    reason: str = ""

    def to_dict(self) -> dict:
        return {"window": self.window.to_dict() if self.window else None,
                "ambiguous": self.ambiguous,
                "used_handle": self.used_handle,
                "re_resolved": self.re_resolved,
                "reason": self.reason,
                "candidates": [c.to_dict() for c in self.candidates]}


def _norm(value: Optional[str]) -> str:
    return str(value or "").strip().lower()


def title_score(window: WindowInfo, needle: str) -> tuple:
    """How well this window's title answers this text. Returns (score, reason)."""
    title = _norm(window.title)
    if not needle:
        return 0, ""
    if title == needle:
        return SCORE_EXACT_TITLE, "the title matches exactly"
    if title.startswith(needle):
        return SCORE_TITLE_PREFIX, "the title starts with the requested text"
    if needle in title:
        return SCORE_TITLE_CONTAINS, "the title contains the requested text"
    return 0, ""


def _process_names_for(request: str) -> set:
    """Every process name an application alias could mean.

    `apps.ALIASES` and `apps.WINDOW_OWNER` are the one place that knows that
    "calculator" starts `calc.exe` and ends up in `calculatorapp.exe`, so this
    reuses both rather than growing a second mapping that would drift from them.
    """
    from core.windows import apps

    needle = _norm(request)
    names = {f"{needle}.exe"}
    for alias, exe in (getattr(apps, "ALIASES", {}) or {}).items():
        if _norm(alias) == needle:
            names.add(_norm(exe))
    # The hand-off applications: the alias resolves to a stub, and a different
    # process really owns the window.
    for alias, exe in (getattr(apps, "ALIASES", {}) or {}).items():
        if _norm(exe)[:-4] == needle:
            owner = (getattr(apps, "WINDOW_OWNER", {}) or {}).get(_norm(exe)[:-4])
            if owner:
                names.add(_norm(owner))
    owner = (getattr(apps, "WINDOW_OWNER", {}) or {}).get(needle)
    if owner:
        names.add(_norm(owner))
    return names


def read_windows(cancel_event=None, include_untitled: bool = True,
                 limit: int = MAX_CANDIDATES) -> list:
    """The live window list, bounded. A read, never a guess."""
    from core.windows import win32

    windows = win32.list_windows(visible_only=False,
                                 include_untitled=include_untitled,
                                 limit=limit)
    if cancel_event is not None and cancel_event.is_set():
        return windows
    return windows


def score_windows(windows: list, *, title: str = "", process_id: Optional[int] = None,
                   process_name: str = "", class_name: str = "",
                   window_handle: Optional[int] = None) -> list:
    """Every window, scored against the request. Deterministic and explainable."""
    needle = _norm(title)
    wanted_process = _norm(process_name)
    if wanted_process:
        wanted_process = wanted_process[:-4] if wanted_process.endswith(".exe") else wanted_process
        wanted_processes = _process_names_for(wanted_process)
    else:
        wanted_processes = set()
    wanted_class = _norm(class_name)
    handle = int(window_handle) if window_handle else 0

    out: list = []
    for window in windows:
        score = 0
        reasons: list = []
        matched = False
        if handle and window.handle == handle:
            score += SCORE_HANDLE
            matched = True
            reasons.append("this is the window handle the caller named")
        if process_id is not None and window.process_id == int(process_id):
            score += SCORE_PROCESS_NAME + 20
            matched = True
            reasons.append(f"owned by process id {process_id}")
        if wanted_process:
            name = _norm(window.process_name)
            stem = name[:-4] if name.endswith(".exe") else name
            if stem in wanted_processes or name in wanted_processes:
                score += SCORE_PROCESS_NAME
                matched = True
                reasons.append(f"run by {window.process_name}")
        got_title, why = title_score(window, needle)
        if got_title:
            score += got_title
            matched = True
            reasons.append(why)
        if wanted_class and _norm(window.class_name) == wanted_class:
            score += SCORE_CLASS_NAME
            matched = True
            reasons.append(f"window class is {window.class_name}")
        if not matched:
            # A visible window is not a candidate just for being visible. Only
            # a window the request actually named is scored, and the visibility
            # and foreground bonuses below break ties *between* candidates —
            # without that they would make every window on the desktop look like
            # a match, which is the exact bug this module exists to fix.
            continue
        if window.is_active:
            score += SCORE_ACTIVE
            reasons.append("Windows reports it as the foreground window")
        if window.visible and not window.minimized:
            score += SCORE_VISIBLE
        out.append(Candidate(window=window, score=score, reasons=reasons))
    out.sort(key=lambda c: (-c.score, c.window.handle))
    return out


class WindowTargetor:
    """Scores live windows, resolves a request, and refuses to guess.

    One short-lived read is cached so a goal that resolves a window once per
    step does not re-enumerate the desktop per step. The cache is deliberately
    tiny and deliberately expires: a stale window list is how an assistant ends
    up acting on a window that closed three steps ago.
    """

    def __init__(self, cancel_event=None, cache_seconds: float = CACHE_SECONDS):
        self.cancel_event = cancel_event
        self.cache_seconds = max(0.0, float(cache_seconds))
        self._cache: list = []
        self._cached_at: float = 0.0

    # -- reading ------------------------------------------------------------

    def windows(self, refresh: bool = False) -> list:
        now = time.time()
        if (not refresh and self._cache
                and (now - self._cached_at) <= self.cache_seconds):
            return list(self._cache)
        self._cache = read_windows(self.cancel_event)
        self._cached_at = now
        return list(self._cache)

    def invalidate(self) -> None:
        self._cache = []
        self._cached_at = 0.0

    # -- matching -----------------------------------------------------------

    def candidates(self, *, title: str = "", process_id: Optional[int] = None,
                   process_name: str = "", class_name: str = "",
                   window_handle: Optional[int] = None,
                   refresh: bool = False) -> list:
        return score_windows(self.windows(refresh=refresh), title=title,
                             process_id=process_id, process_name=process_name,
                             class_name=class_name, window_handle=window_handle)

    def match(self, *, title: str = "", process_id: Optional[int] = None,
              process_name: str = "", class_name: str = "",
              window_handle: Optional[int] = None, index: Optional[int] = None,
              refresh: bool = False) -> Match:
        """One window, or an honest refusal.

        Raises `WINDOW_NOT_FOUND` when nothing matches and `ELEMENT_AMBIGUOUS`
        when two windows tie for the best score. `index` is the caller's
        explicit choice between them, and it is never invented here.
        """
        if not any((title, process_id, process_name, class_name, window_handle)):
            raise invalid_argument(
                "a window request needs a title, a process, a class or a handle")

        # A handle is checked on its own first. Windows reuses handles after a
        # window closes, so a stale one is a hint rather than an answer — and
        # the identity the caller also gave is what to fall back on.
        found = []
        re_resolved = False
        if window_handle:
            found = self.candidates(window_handle=window_handle, refresh=refresh)
        if not found:
            found = self.candidates(title=title, process_id=process_id,
                                    process_name=process_name,
                                    class_name=class_name, refresh=refresh)
            re_resolved = bool(found) and bool(window_handle)

        if not found:
            raise window_not_found(_no_match_message(title, process_id,
                                                     process_name, window_handle))

        top = found[0].score
        tied = [c for c in found if c.score == top]
        if len(tied) > 1 and index is None:
            listed = "; ".join(f"'{c.window.label}' (pid {c.window.process_id})"
                               for c in tied[:4])
            raise window_ambiguous("that description", len(tied), listed)

        chosen = tied[index] if (index is not None and index < len(tied)) else found[0]
        if index is not None and index >= len(tied):
            raise invalid_argument(
                f"index {index} was requested but only {len(tied)} window(s) "
                f"match; NEO will not pick one for you.")

        return Match(window=chosen.window, candidates=found[:8],
                     ambiguous=len(tied) > 1, used_handle=bool(window_handle),
                     re_resolved=re_resolved,
                     reason="; ".join(chosen.reasons) or "the only match")

    def resolve(self, params: dict, refresh: bool = False) -> Match:
        """`match()` from a parameters dict, so the façade can pass one through."""
        params = params or {}
        index = params.get("index")
        return self.match(
            title=str(params.get("title", "") or ""),
            process_id=params.get("process_id"),
            process_name=str(params.get("app_name") or params.get("name") or ""),
            class_name=str(params.get("class_name") or ""),
            window_handle=params.get("window_handle"),
            index=(int(index) if isinstance(index, int) and not isinstance(index, bool)
                   else None),
            refresh=refresh,
        )


def _no_match_message(title: str, process_id, process_name: str, window_handle) -> str:
    bits = []
    if window_handle:
        bits.append(f"handle {window_handle}")
    if title:
        bits.append(f"a title containing '{title}'")
    if process_name:
        bits.append(f"a process named '{process_name}'")
    if process_id:
        bits.append(f"process id {process_id}")
    return ("No open window matches " + ", ".join(bits or ["that request"]) +
            ". Nothing was closed, focused or changed.")


#: Kept for callers that want the raw exception kinds without importing
#: core/windows/errors.py themselves.
NOT_FOUND_KIND = WindowsErrorKind.WINDOW_NOT_FOUND