"""
Lightweight in-process task lifecycle events.

WHY THIS EXISTS
    Task state changes are only useful if something can watch them. Phase 2
    needs one place where "a task started", "an action ran", "the action
    failed" can be observed by the activity log today and by verification,
    recovery and the HUD in later phases — without either of those having to
    poll the Task Manager or re-derive what happened from strings.

WHAT THIS IS NOT
    Not a message bus, not a broker, not a persisted log. It is a plain
    subscribe/emit pair inside one process. Events are kept in a small ring
    buffer so a test (or a late subscriber) can read back what just happened;
    nothing here is written to disk — the task history is (see
    core/task_store.py), and events are not duplicated into it.

DELIVERY ORDER AND SAFETY
    Subscribers are called synchronously, in subscription order, on the thread
    that emitted the event. A subscriber that raises is logged and skipped: an
    observer must never be able to break the action that emitted the event.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

DEFAULT_HISTORY = 200


class EventType(str, Enum):
    """Everything the core announces. Values are strings for cheap logging."""

    TASK_CREATED         = "TASK_CREATED"
    TASK_STARTED         = "TASK_STARTED"
    ACTION_STARTED       = "ACTION_STARTED"
    ACTION_COMPLETED     = "ACTION_COMPLETED"
    ACTION_FAILED        = "ACTION_FAILED"
    TASK_PAUSED          = "TASK_PAUSED"
    TASK_RESUMED         = "TASK_RESUMED"
    TASK_CANCELLED       = "TASK_CANCELLED"
    TASK_COMPLETED       = "TASK_COMPLETED"
    TASK_FAILED          = "TASK_FAILED"

    # Phase 4. A verification stage exists, and these three facts about it are
    # worth announcing: a check was about to run, it reached a conclusion, and
    # it concluded the requested state was not there.
    VERIFICATION_STARTED   = "VERIFICATION_STARTED"
    VERIFICATION_COMPLETED = "VERIFICATION_COMPLETED"
    VERIFICATION_FAILED    = "VERIFICATION_FAILED"
    SECURITY_AUDIT         = "SECURITY_AUDIT"

    # Phase 5. A goal is several tasks in an order that matters, so its own
    # lifecycle is announced separately rather than being inferred from the
    # tasks inside it. One event per fact: the goal was created, planned,
    # started, paused, resumed, cancelled, or reached a terminal state; and one
    # per step transition worth watching. Nothing here is emitted for visual
    # noise — every one of these changes a decision somebody might make.
    GOAL_CREATED          = "GOAL_CREATED"
    GOAL_PLANNING         = "GOAL_PLANNING"
    GOAL_PLANNED          = "GOAL_PLANNED"
    GOAL_STARTED          = "GOAL_STARTED"
    GOAL_PAUSED           = "GOAL_PAUSED"
    GOAL_RESUMED          = "GOAL_RESUMED"
    GOAL_CANCELLED        = "GOAL_CANCELLED"
    GOAL_COMPLETED        = "GOAL_COMPLETED"
    GOAL_FAILED           = "GOAL_FAILED"
    GOAL_NOT_VERIFIED     = "GOAL_NOT_VERIFIED"
    STEP_STARTED          = "STEP_STARTED"
    STEP_FINISHED         = "STEP_FINISHED"
    STEP_VERIFIED         = "STEP_VERIFIED"
    STEP_NOT_VERIFIED     = "STEP_NOT_VERIFIED"
    STEP_FAILED           = "STEP_FAILED"
    STEP_BLOCKED          = "STEP_BLOCKED"
    STEP_CANCELLED        = "STEP_CANCELLED"
    STEP_AWAITING_CONFIRMATION = "STEP_AWAITING_CONFIRMATION"
    STEP_RECOVERY_STARTED = "STEP_RECOVERY_STARTED"
    STEP_RECOVERY_COMPLETED = "STEP_RECOVERY_COMPLETED"

    # Phase 6. Four new facts worth announcing, and a deliberate absence: there
    # is no "PLAN_ACCEPTED" event, because accepting a plan is not something a
    # watcher can act on — what it can act on is a plan that was *refused*, a
    # plan that was asked for, a plan that arrived, and a goal that cannot be
    # completed because nothing safe was left to try.
    GOAL_REPLANNING     = "GOAL_REPLANNING"
    GOAL_REPLANNED      = "GOAL_REPLANNED"
    GOAL_REPLAN_REFUSED = "GOAL_REPLAN_REFUSED"
    STEP_SUPERSEDED     = "STEP_SUPERSEDED"


@dataclass(frozen=True)
class Event:
    """One lifecycle fact. `status` is a TaskStatus or ExecStatus value (str)."""

    type: EventType
    task_id: str = ""
    #: Phase 5. A goal event still carries the Phase 2 `task_id` when one exists
    #: (a step that is executing has a real task behind it), plus the goal and
    #: step it belongs to. Additive fields with defaults: existing emitters and
    #: existing subscribers are unaffected.
    goal_id: str = ""
    step_id: str = ""
    timestamp: float = field(default_factory=time.time)
    action: str = ""
    status: str = ""
    data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "type": self.type.value,
            "task_id": self.task_id,
            "goal_id": self.goal_id,
            "step_id": self.step_id,
            "timestamp": self.timestamp,
            "action": self.action,
            "status": self.status,
            "data": self.data,
        }

    def describe(self) -> str:
        """One honest line for a log. Uses only what the event actually says."""
        bits = [self.type.value]
        if self.goal_id:
            bits.append(f"goal={self.goal_id[:8]}")
        if self.step_id:
            bits.append(f"step={self.step_id}")
        elif self.task_id:
            bits.append(f"task={self.task_id[:8]}")
        if self.action:
            bits.append(f"action={self.action}")
        if self.status:
            bits.append(f"status={self.status}")
        return " ".join(bits)


class EventBus:
    """Synchronous, in-process, exception-safe."""

    def __init__(self, logger: Optional[Callable[[str], None]] = None,
                 history: int = DEFAULT_HISTORY):
        self._subscribers: list[Callable[[Event], None]] = []
        self._history: list[Event] = []
        self._history_limit = max(0, int(history))
        self._logger = logger or (lambda _msg: None)
        self._lock = threading.RLock()

    # -- wiring -------------------------------------------------------------

    def subscribe(self, callback: Callable[[Event], None]) -> Callable[[], None]:
        """Register `callback`; returns a function that unsubscribes it."""
        with self._lock:
            self._subscribers.append(callback)

        def _unsubscribe() -> None:
            self.unsubscribe(callback)

        return _unsubscribe

    def unsubscribe(self, callback: Callable[[Event], None]) -> bool:
        with self._lock:
            try:
                self._subscribers.remove(callback)
                return True
            except ValueError:
                return False

    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)

    # -- emitting -----------------------------------------------------------

    def emit(self, event: Event) -> None:
        """Announce an event. Never raises, whoever is listening."""
        with self._lock:
            if self._history_limit:
                self._history.append(event)
                if len(self._history) > self._history_limit:
                    del self._history[: len(self._history) - self._history_limit]
            subscribers = list(self._subscribers)

        for callback in subscribers:
            try:
                callback(event)
            except Exception as e:      # an observer is not allowed to break the core
                self._logger(f"Event subscriber failed on {event.type.value}: {e}")

    # -- reading back -------------------------------------------------------

    def recent(self, limit: Optional[int] = None,
               kind: Optional[EventType] = None) -> list[Event]:
        with self._lock:
            items = list(self._history)
        if kind is not None:
            items = [e for e in items if e.type == kind]
        if limit is not None and limit >= 0:
            items = items[-limit:]
        return items

    def clear_history(self) -> None:
        with self._lock:
            self._history.clear()
