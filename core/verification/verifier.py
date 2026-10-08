"""
The verification engine — observe, compare, and report the truth.

    ACTION_STARTED → action ran → observe again → compare → VERIFIED / NOT_VERIFIED

THE ONE RULE
    A successful call is not a successful outcome. `Invoke()` returning says the
    automation call completed; this module decides whether the state the user
    asked for actually exists, by looking. Where nothing observable can be
    checked, the answer is NOT_AVAILABLE — never a hopeful VERIFIED.

HOW A CHECK IS PERFORMED
    Every attempt re-observes from scratch through the Phase 3 façade. A
    remembered HWND is never compared against a remembered title: handles are
    revalidated, controls are re-resolved, and a stale reference is reported as
    stale instead of being retried onto whatever took its place.

BOUNDED, ALWAYS
    Polling has a finite timeout and a finite interval, checks cancellation
    between attempts, and returns NOT_VERIFIED when the expected state never
    appears. It never blocks forever and never invents a pass at the end.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

from core.verification import observation as obs
from core.verification.expectations import (
    DEFAULT_INTERVAL,
    DEFAULT_TIMEOUT,
    Expectation,
    ExpectationKind,
)
from core.windows.errors import WindowsErrorKind


class Status(str, Enum):
    """Verification outcomes. Deliberately more precise than a boolean."""

    VERIFIED = "VERIFIED"
    NOT_VERIFIED = "NOT_VERIFIED"       # looked, and the state is not there
    AMBIGUOUS = "AMBIGUOUS"             # more than one thing could be the target
    STALE = "STALE"                     # the reference went away under us
    NOT_AVAILABLE = "NOT_AVAILABLE"     # nothing observable to check
    FAILED = "VERIFICATION_FAILED"      # the check itself could not be run
    CANCELLED = "CANCELLED"             # cancellation stayed truthful


@dataclass
class Outcome:
    """The result of one verification, with the observations that produced it."""

    status: Status
    expectation: Optional[Expectation] = None
    observations: list = field(default_factory=list)
    reason: str = ""
    elapsed_seconds: float = 0.0
    attempts: int = 0

    @property
    def verified(self) -> bool:
        return self.status is Status.VERIFIED

    def to_dict(self) -> dict:
        return {"status": self.status.value,
                "expectation": self.expectation.to_dict() if self.expectation else None,
                "observations": [o.to_dict() for o in self.observations[-4:]],
                "reason": self.reason,
                "elapsed_seconds": round(self.elapsed_seconds, 3),
                "attempts": self.attempts}

    def describe(self) -> str:
        if self.expectation is None:
            return f"{self.status.value}: nothing observable to check."
        last = self.observations[-1] if self.observations else None
        detail = f" Last observation: {last.describe()}" if last is not None else ""
        return (f"{self.status.value}: expected {self.expectation.describe()}. "
                f"{self.reason}{detail}")


def _cancelled(cancel_event) -> bool:
    return cancel_event is not None and cancel_event.is_set()


# ── comparison ──────────────────────────────────────────────────────────────

def _matches(value: Any, expected: Any, compare: str) -> Optional[bool]:
    """Compare one observed value. None means "cannot tell"."""
    if compare == "changed":
        return None                    # only the caller has the previous value
    if compare == "exists":
        return bool(value) if value is not None else None
    if value is None:
        return None
    if compare == "is_true":
        return bool(value) is bool(expected)
    if compare == "not_equals":
        return value != expected
    if isinstance(value, str) and isinstance(expected, str):
        return value.strip() == expected.strip()
    return value == expected


def _observe(expectation: Expectation, cancel_event=None) -> Optional[obs.Observation]:
    """Read the one fact this expectation is about."""
    target = expectation.target or {}
    kind = expectation.kind

    if kind == ExpectationKind.WINDOW_EXISTS:
        return obs.window_exists(cancel_event=cancel_event, **target)
    if kind == ExpectationKind.WINDOW_CLOSED:
        # A closed window is observed as absence: the same lookup, read for the
        # fact that it is NOT there any more. If the lookup itself could not be
        # answered, that is passed straight through — an unanswered question is
        # never the same as a "no".
        found = obs.window_exists(cancel_event=cancel_event, **target)
        if not found.ok:
            return found
        return obs.Observation(
            kind=obs.Kind.WINDOW_EXISTS, source=obs.Source.WIN32,
            target=found.target, value=(found.value is False),
            note=("no window matches any more" if found.value is False
                  else found.note))
    if kind == ExpectationKind.WINDOW_ACTIVE:
        handle = target.get("window_handle")
        if handle:
            return obs.window_is_active(int(handle), cancel_event=cancel_event)
        return None                     # a title cannot be the foreground window
    if kind == ExpectationKind.APP_RUNNING:
        return obs.app_running(target.get("app_name", ""), cancel_event=cancel_event)
    if kind == ExpectationKind.CONTROL_EXISTS:
        return obs.control_exists(target, cancel_event=cancel_event)
    if kind == ExpectationKind.CONTROL_VALUE:
        return obs.control_value(target, cancel_event=cancel_event)
    if kind in (ExpectationKind.CONTROL_STATE, ExpectationKind.CONTROL_CHANGED):
        return obs.control_state(target, expectation.property or "toggle_state",
                                 cancel_event=cancel_event)
    return None


def _classify_unverifiable(observation: Optional[obs.Observation],
                           cancel_event=None) -> Optional[Outcome]:
    """Turn "could not check" into the most specific honest status."""
    if observation is None:
        return Outcome(status=Status.NOT_AVAILABLE,
                       reason="This operation has no observable consequence NEO "
                              "knows how to check.")
    if observation.cancelled or _cancelled(cancel_event):
        return Outcome(status=Status.CANCELLED, observations=[observation],
                       reason="Cancelled while waiting to observe.")
    if observation.sensitivity == obs.Sensitivity.WITHHELD:
        return Outcome(status=Status.NOT_AVAILABLE, observations=[observation],
                       reason="The target holds a credential, so its value is never "
                              "read and cannot be verified.")
    if observation.ambiguous:
        return Outcome(status=Status.AMBIGUOUS, observations=[observation],
                       reason="More than one target matches, so no single one can "
                              "be said to have changed.")
    if observation.stale:
        return Outcome(status=Status.STALE, observations=[observation],
                       reason="The control was gone when NEO looked at it.")
    if observation.error_kind:
        return Outcome(status=Status.NOT_AVAILABLE, observations=[observation],
                       reason=f"Windows did not expose this state "
                              f"({observation.error_kind}).")
    return None


# ── the engine ──────────────────────────────────────────────────────────────

def verify(expectation: Optional[Expectation], before: Optional[obs.Observation] = None,
           timeout: Optional[float] = None, interval: Optional[float] = None,
           cancel_event=None,
           observer: Optional[Callable[[Expectation], Optional[obs.Observation]]] = None
           ) -> Outcome:
    """Check one expectation against the machine, within a bounded time.

    `before` is an observation of the same fact taken *before* the action ran.
    It is only used for the one check where a previous state is the whole point
    ("this toggle actually changed"), and it is never treated as current: every
    attempt below re-reads the live state.

    The bound comes from the expectation itself unless a caller overrides it —
    a check declared to be quick is not allowed to quietly wait six seconds
    because the verifier's own default was used instead.
    """
    if expectation is None:
        return Outcome(status=Status.NOT_AVAILABLE,
                       reason="No expectation was attached to this action, so "
                              "there is nothing to verify.")

    timeout = float(expectation.timeout if timeout is None else timeout)
    interval = float(expectation.interval if interval is None else interval)
    look = observer or (lambda exp: _observe(exp, cancel_event))
    started = time.monotonic()
    deadline = started + max(0.0, timeout)
    interval = max(0.05, interval)
    attempts = 0
    latest: Optional[obs.Observation] = None

    while True:
        if _cancelled(cancel_event):
            return Outcome(status=Status.CANCELLED, expectation=expectation,
                           observations=[latest] if latest else [],
                           reason="Cancelled before the check could finish.",
                           elapsed_seconds=time.monotonic() - started, attempts=attempts)

        attempts += 1
        try:
            latest = look(expectation)
        except Exception as e:                      # a broken check, not a failed one
            return Outcome(status=Status.FAILED, expectation=expectation,
                           observations=[latest] if latest else [],
                           reason=f"The check itself could not run: {e}",
                           elapsed_seconds=time.monotonic() - started, attempts=attempts)

        unverifiable = _classify_unverifiable(latest, cancel_event)
        if unverifiable is not None:
            unverifiable.expectation = expectation
            unverifiable.elapsed_seconds = time.monotonic() - started
            unverifiable.attempts = attempts
            return unverifiable

        if expectation.kind == ExpectationKind.CONTROL_CHANGED:
            # "Changed" needs both sides. If the previous state could not be
            # read, that is reported rather than quietly treated as a pass.
            if before is None or before.value is None:
                return Outcome(status=Status.NOT_AVAILABLE, expectation=expectation,
                               observations=[latest],
                               reason="The state before the action was never "
                                      "observed, so a change cannot be claimed.",
                               elapsed_seconds=time.monotonic() - started,
                               attempts=attempts)
            if latest.value != before.value:
                return Outcome(status=Status.VERIFIED, expectation=expectation,
                               observations=[before, latest],
                               reason=f"{expectation.property}: "
                                      f"{before.value!r} → {latest.value!r}",
                               elapsed_seconds=time.monotonic() - started,
                               attempts=attempts)
        else:
            outcome = _matches(latest.value, expectation.expected, expectation.compare)
            if outcome is True:
                return Outcome(status=Status.VERIFIED, expectation=expectation,
                               observations=[latest],
                               reason=f"Observed {latest.value!r}.",
                               elapsed_seconds=time.monotonic() - started,
                               attempts=attempts)

        if time.monotonic() >= deadline:
            seen = f" it read {latest.value!r}." if latest is not None else ""
            return Outcome(status=Status.NOT_VERIFIED, expectation=expectation,
                           observations=[latest],
                           reason=f"After {attempts} observation(s) over "
                                  f"{timeout:.1f}s the expected state was not "
                                  f"observed.{seen}",
                           elapsed_seconds=time.monotonic() - started, attempts=attempts)
        time.sleep(interval)


def capture(expectation: Optional[Expectation],
            cancel_event=None) -> Optional[obs.Observation]:
    """Read the current state for `expectation` once, without judging it.

    Used before an action runs, so "did this change?" has a real answer.
    """
    if expectation is None:
        return None
    return _observe(expectation, cancel_event)