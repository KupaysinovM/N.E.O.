"""
Canonical task representation for NEO's core — one shape, one state machine.

WHY THIS FILE EXISTS
    Before Phase 2, "what NEO is doing" existed only as loose strings inside
    main.py: a tool name, a sentence, and whatever the model happened to say.
    Nothing owned the lifecycle of a request, nothing could be observed, and
    nothing prevented state from being overwritten by whoever got there last.

    This module is the single definition of a task and the only place that says
    which state changes are legal. TaskManager (core/task_manager.py) enforces
    it; the execution layer (core/execution.py) fills it in from real results.

WHAT A TASK IS NOT
    A Task is a record of one request NEO was asked to carry out. It is not a
    plan, not a conversation turn, not a memory, and not a promise that the
    request will be resumed later. Long-term user memory stays in
    memory/memory_manager.py and is deliberately not touched here.

TRANSITIONS ARE ENFORCED
    The legal edges are listed in TASK_TRANSITIONS. Everything else raises
    TaskStateError with the from/to pair attached, because a silent state
    change is exactly the failure this phase is here to remove.
"""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class TaskStatus(str, Enum):
    """The canonical task states. Phase 2 uses exactly these six."""

    PENDING   = "PENDING"
    RUNNING   = "RUNNING"
    PAUSED    = "PAUSED"
    COMPLETED = "COMPLETED"
    FAILED    = "FAILED"
    CANCELLED = "CANCELLED"


def coerce_status(value: Any) -> TaskStatus:
    """Best-effort conversion used when loading persisted state.

    Raises ValueError for anything unrecognised — callers must treat that as a
    malformed record, never as a default. This is deliberate: guessing a state
    from corrupt data is how a crash becomes a fake success.
    """
    if isinstance(value, TaskStatus):
        return value
    return TaskStatus(str(value).strip().upper())


TERMINAL_STATUSES = frozenset({TaskStatus.COMPLETED, TaskStatus.FAILED,
                               TaskStatus.CANCELLED})

# The whole state machine, in one place. PAUSED → COMPLETED / FAILED is
# deliberately absent: pausing is cooperative and does not stop an action that
# is already running, so when a result arrives for a paused task the execution
# layer resumes it first and then applies the outcome. That keeps every edge
# here describing a state change that actually happened, rather than one that
# was assumed to have happened.
TASK_TRANSITIONS: dict[TaskStatus, frozenset[TaskStatus]] = {
    TaskStatus.PENDING:   frozenset({TaskStatus.RUNNING, TaskStatus.CANCELLED}),
    TaskStatus.RUNNING:   frozenset({TaskStatus.PAUSED, TaskStatus.COMPLETED,
                                     TaskStatus.FAILED, TaskStatus.CANCELLED}),
    TaskStatus.PAUSED:    frozenset({TaskStatus.RUNNING, TaskStatus.CANCELLED}),
    TaskStatus.COMPLETED: frozenset(),
    TaskStatus.FAILED:    frozenset(),
    TaskStatus.CANCELLED: frozenset(),
}


def can_transition(src: TaskStatus, dst: TaskStatus) -> bool:
    return dst in TASK_TRANSITIONS.get(src, frozenset())


class TaskStateError(RuntimeError):
    """Raised on an illegal task transition. Carries the exact from/to pair."""

    def __init__(self, task_id: str, src: TaskStatus, dst: TaskStatus, note: str = ""):
        self.task_id = task_id
        self.src = src
        self.dst = dst
        msg = f"Task {task_id}: illegal transition {src.value} → {dst.value}"
        if note:
            msg += f" ({note})"
        super().__init__(msg)


class ErrorKind(str, Enum):
    """Why something did not succeed.

    The status alone cannot distinguish "the tool does not exist" from "the tool
    refused the request" from "the operating system said no", and Phase 4's
    verification work needs that difference to survive. These kinds are the
    machine-readable half of a failure; the message stays human-readable.
    """

    INVALID_REQUEST          = "INVALID_REQUEST"
    UNKNOWN_ACTION           = "UNKNOWN_ACTION"
    INVALID_ARGUMENTS        = "INVALID_ARGUMENTS"
    AUTHORIZATION_REQUIRED   = "AUTHORIZATION_REQUIRED"
    AUTHORIZATION_DENIED     = "AUTHORIZATION_DENIED"
    AUTHORIZATION_UNAVAILABLE = "AUTHORIZATION_UNAVAILABLE"
    ACTION_UNAVAILABLE       = "ACTION_UNAVAILABLE"
    ACTION_NOT_SUPPORTED     = "ACTION_NOT_SUPPORTED"
    ACTION_FAILED            = "ACTION_FAILED"
    TASK_CANCELLED           = "TASK_CANCELLED"
    INTERNAL_ERROR           = "INTERNAL_ERROR"
    INTERRUPTED              = "INTERRUPTED"     # NEO stopped mid-task

    # Windows control (Phase 3). Added to the same taxonomy rather than a
    # parallel one, so a Windows failure and a task failure stay comparable
    # and Phase 7's policy layer has one enum to reason about.
    WINDOW_NOT_FOUND         = "WINDOW_NOT_FOUND"
    ELEMENT_NOT_FOUND        = "ELEMENT_NOT_FOUND"
    ELEMENT_AMBIGUOUS        = "ELEMENT_AMBIGUOUS"
    ELEMENT_DISABLED         = "ELEMENT_DISABLED"
    ELEMENT_STALE            = "ELEMENT_STALE"
    UNSUPPORTED_CONTROL      = "UNSUPPORTED_CONTROL"
    TIMEOUT                  = "TIMEOUT"
    ACCESS_DENIED            = "ACCESS_DENIED"
    PROCESS_NOT_FOUND        = "PROCESS_NOT_FOUND"
    APPLICATION_NOT_FOUND    = "APPLICATION_NOT_FOUND"
    OS_ERROR                 = "OS_ERROR"

    # Verification (Phase 4). The action ran; the state it was supposed to
    # produce was not observed. A distinct kind so nothing downstream has to
    # guess whether something broke or something merely went unconfirmed.
    NOT_VERIFIED             = "NOT_VERIFIED"


@dataclass
class TaskError:
    """A structured failure. Message is safe to show; detail is for the log."""

    message: str
    kind: ErrorKind = ErrorKind.ACTION_FAILED
    detail: str = ""

    def to_dict(self) -> dict:
        return {"message": self.message, "kind": self.kind.value, "detail": self.detail}

    @classmethod
    def from_dict(cls, raw: dict) -> "TaskError":
        if not isinstance(raw, dict):
            raise ValueError("error must be an object")
        message = str(raw.get("message", "")).strip()
        if not message:
            raise ValueError("error.message is required")
        try:
            kind = ErrorKind(str(raw.get("kind", ErrorKind.ACTION_FAILED.value)).upper())
        except ValueError:
            kind = ErrorKind.ACTION_FAILED
        return cls(message=message, kind=kind, detail=str(raw.get("detail", "")))

    def __str__(self) -> str:
        return f"[{self.kind.value}] {self.message}"


def new_task_id() -> str:
    """A genuinely unique task id (uuid4 hex, 32 chars).

    Not a counter and not a timestamp: a counter collides across processes and
    a timestamp collides within the same millisecond, and both are used as a
    handle by the UI, the tests and the persisted history.
    """
    return uuid.uuid4().hex


@dataclass
class Task:
    """One request NEO was asked to carry out."""

    task_id: str
    user_request: str = ""
    status: TaskStatus = TaskStatus.PENDING
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    current_step: str = ""            # human-readable step in progress
    current_action: str = ""          # registered action bound to this task
    result: str = ""                  # the real message the action returned
    error: Optional[TaskError] = None
    metadata: dict = field(default_factory=dict)

    # -- helpers ------------------------------------------------------------

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_STATUSES

    def short_id(self) -> str:
        return self.task_id[:8]

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "user_request": self.user_request,
            "status": self.status.value,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "current_step": self.current_step,
            "current_action": self.current_action,
            "result": self.result,
            "error": self.error.to_dict() if self.error else None,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, raw: dict) -> "Task":
        """Strict on purpose: a record that cannot be read is not a task.

        Every field is validated because this runs over a file that a crash or
        an interrupted write can leave half-formed. A malformed record must be
        reported by the caller, never silently repaired into something that
        looks like a completed task.
        """
        if not isinstance(raw, dict):
            raise ValueError("task record must be an object")
        task_id = str(raw.get("task_id", "")).strip()
        if not task_id:
            raise ValueError("task_id is required")
        status = coerce_status(raw.get("status", TaskStatus.PENDING.value))
        error_raw = raw.get("error")
        metadata = raw.get("metadata")
        started = raw.get("started_at")
        completed = raw.get("completed_at")
        return cls(
            task_id=task_id,
            user_request=str(raw.get("user_request", "")),
            status=status,
            # timestamps fall back rather than failing the whole record: a
            # missing clock value is cosmetic, a missing id is not.
            created_at=float(raw.get("created_at") or 0.0),
            started_at=float(started) if started is not None else None,
            completed_at=float(completed) if completed is not None else None,
            current_step=str(raw.get("current_step", "")),
            current_action=str(raw.get("current_action", "")),
            result=str(raw.get("result", "")),
            error=TaskError.from_dict(error_raw) if error_raw else None,
            metadata=dict(metadata) if isinstance(metadata, dict) else {},
        )


@dataclass
class TaskContext:
    """What an executing action is allowed to know about its task.

    Deliberately tiny. It holds the task record and the task's cancellation
    primitive — nothing else. It is created per execution and passed down as an
    argument, so it is not a global, and an action can never reach the Task
    Manager through it to mutate state (the Manager is the only writer).
    """

    task: Task
    cancel_event: threading.Event = field(default_factory=threading.Event)
    invocation: dict = field(default_factory=dict)   # who asked, and how

    @property
    def task_id(self) -> str:
        return self.task.task_id

    @property
    def status(self) -> TaskStatus:
        return self.task.status

    @property
    def current_action(self) -> str:
        return self.task.current_action

    @property
    def metadata(self) -> dict:
        return self.task.metadata

    @property
    def cancelled(self) -> bool:
        return self.cancel_event.is_set()

    def is_cancelled(self) -> bool:
        return self.cancel_event.is_set()

    def to_dict(self) -> dict:
        """Metadata only — the task itself is not duplicated here."""
        return {
            "task_id": self.task_id,
            "status": self.status.value,
            "current_action": self.current_action,
            "cancelled": self.cancelled,
            "invocation": dict(self.invocation),
        }
