"""
core/confirm.py — a confirmation the model cannot forge.

THE PROBLEM WITH THE OLD GATE
    computer_settings guarded shutdown and restart like this:

        confirmed = str(params.get("confirmed", "")).lower()
        if confirmed not in ("yes", "true", "1", "confirm"):
            return "Please confirm by calling again with confirmed=yes."

    `confirmed` is a tool parameter, which means the *model* writes it. Nothing
    stops it from sending confirmed=yes on the first call, and nothing checks
    that a human was ever involved. It is a convention, not a gate — and its
    coverage was two actions, so deleting files and switching off the WiFi the
    assistant is talking over went through with no gate at all.

THE DESIGN HERE
    The confirmation token is issued by the *interface*, never by the model:

      1. An action calls `request(...)` with a callable that does the real work.
      2. This module hands the UI a banner with CONFIRM / CANCEL and returns
         IMMEDIATELY with a sentence for the model to say out loud.
      3. If — and only if — the user presses CONFIRM, the UI calls `resolve()`,
         which runs the stored callable off the Qt thread.

    Nothing blocks. The model keeps talking while the banner is up, so this
    costs no latency at all; in fact it is cheaper than the old gate, which
    burned two tool round trips (reject, then re-call) on every shutdown.

WHAT BELONGS HERE AND WHAT DOES NOT
    Only genuinely irreversible things. Anything that can be reversed should be
    done at once and pushed onto core/undo.py instead — undo is faster than a
    question, and an assistant that asks before every action is one nobody uses.

WHO GETS TOLD AFTERWARDS (Phase 2)
    The gate stays the gate: the token is still issued here, still single-use,
    still expires, and the model still cannot forge it. What Phase 2 adds is
    one optional listener — `bind_resolution()` — so the core's task layer can
    learn how a parked action ended (ran, declined, expired, raised) and close
    the task truthfully instead of leaving it running forever. The listener is
    notified after the decision has already been made and never influences it;
    a broken listener is logged and ignored.

    The two strings the gate returns also carry a machine marker now
    ([CONFIRMATION_UNAVAILABLE] / [CONFIRMATION_FAILED], alongside the existing
    [CONFIRMATION_PENDING]) so that "I did not do it" can be recognised exactly
    rather than inferred from prose.
"""

from __future__ import annotations

import threading
import time
import hmac
import inspect
import secrets
from dataclasses import dataclass
from typing import Callable, Optional

# A pending confirmation is abandoned after this long. Chosen to outlast a
# normal "hang on, let me look at the screen" pause without leaving a live
# shutdown button sitting on the HUD for the rest of the day.
TIMEOUT_SECONDS = 90.0


@dataclass
class _Pending:
    key:     str
    title:   str
    detail:  str
    run:     Callable[[], str]
    token:   str
    at:      float


_pending: Optional[_Pending] = None
_lock = threading.Lock()

# Set once at startup by main.py. Signature: (title, detail) -> None for show,
# and () -> None for hide. Both are marshalled onto the Qt thread by the UI.
_show_cb: Optional[Callable[[str, str], None]] = None
_hide_cb: Optional[Callable[[], None]] = None
_log_cb:  Optional[Callable[[str], None]] = None
# Optional observer, told how a parked action ended: (key, accepted, result,
# error). Never consulted about whether to run anything — see the module docs.
_resolve_cb: Optional[Callable[[str, bool, str, str], None]] = None


def bind(show, hide, log=None) -> None:
    """Wire this module to the HUD. Called once from main.py at startup."""
    global _show_cb, _hide_cb, _log_cb
    _show_cb, _hide_cb, _log_cb = show, hide, log


def bind_resolution(callback: Optional[Callable[[str, bool, str, str], None]]) -> None:
    """Register (or clear, with None) the outcome listener described above."""
    global _resolve_cb
    _resolve_cb = callback


def _notify_resolution(key: str, accepted: bool, result: str = "", error: str = "") -> None:
    cb = _resolve_cb
    if cb is None:
        return
    try:
        cb(key, bool(accepted), result or "", error or "")
    except Exception as e:      # an observer may never break the gate
        _log(f"ERR: confirmation listener failed ({type(e).__name__}).")


def _log(msg: str) -> None:
    if _log_cb:
        try:
            _log_cb(msg)
        except Exception:
            pass


def request(key: str, title: str, detail: str, run: Callable[[], str]) -> str:
    """Park an irreversible action behind the on-screen gate.

    Returns the sentence the tool should hand back to the model — phrased as an
    instruction so the assistant asks the user out loud in their own language,
    rather than reading an English string verbatim."""
    global _pending

    if _show_cb is None:
        # No interface bound (headless, or a very early call). Refuse rather
        # than silently performing something irreversible.
        return (f"[CONFIRMATION_UNAVAILABLE] I cannot confirm '{title}' right now "
                f"because the interface is not available, so I have not done it.")

    token = secrets.token_urlsafe(32)
    with _lock:
        superseded, _pending = _pending, _Pending(
            key=key, title=title, detail=detail, run=run, token=token,
            at=time.monotonic())

    if superseded is not None:
        _log(f"SYS: Confirmation superseded — {superseded.title}")
        _notify_resolution(superseded.key, False,
                           error="the confirmation was replaced by a newer request")

    try:
        try:
            inspect.signature(_show_cb).bind(title, detail, token)
        except (TypeError, ValueError):
            _show_cb(title, detail)
        else:
            _show_cb(title, detail, token)
    except Exception as e:
        with _lock:
            if _pending is not None and hmac.compare_digest(_pending.token, token):
                _pending = None
        return (f"[CONFIRMATION_FAILED] Could not ask for confirmation "
                f"({type(e).__name__}). Nothing was done.")

    _log(f"SYS: Awaiting confirmation — {title}")
    return (
        f"[CONFIRMATION_PENDING] I have put a confirmation on screen for: {title}. "
        f"Say ONE short sentence in the user's own language telling them you need "
        f"them to confirm it on the HUD before you do it. Do not claim it is done."
    )


def resolve(accepted: bool, token: Optional[str] = None) -> None:
    """Called by the UI when the user presses CONFIRM or CANCEL.

    Runs the stored callable on a worker thread — this is invoked from the Qt
    thread, and shutting the machine down from inside a button handler would
    freeze the interface on its way out."""
    global _pending

    with _lock:
        p = _pending
        if p is None or not token or not hmac.compare_digest(p.token, str(token)):
            return
        _pending = None

    if _hide_cb:
        try:
            _hide_cb()
        except Exception:
            pass

    if p is None:
        return

    if time.monotonic() - p.at > TIMEOUT_SECONDS:
        _log(f"SYS: Confirmation expired — {p.title}")
        _notify_resolution(p.key, False, error="the confirmation expired")
        return

    if not accepted:
        _log(f"SYS: Cancelled — {p.title}")
        _notify_resolution(p.key, False)
        return

    def _worker():
        try:
            result = p.run() or "Done."
            _log(f"SYS: Confirmed — {p.title}.")
            _notify_resolution(p.key, True, result=result)
        except Exception as e:
            error = type(e).__name__
            _log(f"ERR: {p.title} failed ({error}).")
            _notify_resolution(p.key, True, error=error)

    threading.Thread(target=_worker, daemon=True,
                     name=f"confirm-{p.key}").start()


def pending_title() -> str:
    """'' when nothing is waiting. Lets an action avoid stacking two banners."""
    with _lock:
        if _pending is None:
            return ""
        if time.monotonic() - _pending.at > TIMEOUT_SECONDS:
            return ""
        return _pending.title


def pending_key() -> str:
    """'' when nothing is waiting; otherwise the key the action requested with.

    Read-only lookup used by the execution layer to tie a parked action back to
    the task that asked for it. It grants nothing: the key is the action's own
    name for the confirmation, not a token that can be presented.
    """
    with _lock:
        if _pending is None:
            return ""
        if time.monotonic() - _pending.at > TIMEOUT_SECONDS:
            return ""
        return _pending.key


def pending_token() -> str:
    """Return the current UI challenge token for the confirmation banner."""
    with _lock:
        if _pending is None or time.monotonic() - _pending.at > TIMEOUT_SECONDS:
            return ""
        return _pending.token
