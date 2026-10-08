"""
The Task Manager — the only writer of task state.

RESPONSIBILITY
    Own the lifecycle of every task: hand out ids, enforce the transitions in
    core/task_models.py, keep the current state observable, provide real
    cancellation, announce lifecycle events, and persist task history through
    core/task_store.py.

WHAT IT DELIBERATELY DOES NOT DO
    It never touches the operating system, never calls an action, never talks
    to a model. Execution belongs to core/execution.py, which invokes the
    existing action/plugin registries; this file only records what happened.
    That split is the point of Phase 2 — if this class grew an `open_app()`
    method it would become the god-object the architecture is meant to avoid.

CONCURRENCY
    One lock guards the task table and every transition. Actions run on
    executor threads, so a cancel can arrive while an action is mid-flight;
    state changes are serialised, and a task's cancellation primitive
    (threading.Event) is created once and never replaced, so a late check by an
    action thread sees a cancel that already happened.

CANCELLATION IS HONEST
    Phase 2 cannot kill a Python call that is already running inside an action
    and will not pretend to: no thread termination, no process killing.
    Cancelling a PENDING task means the action is never invoked; cancelling a
    RUNNING task sets the flag, prevents anything further from starting, and
    reports in words that the underlying action is still finishing
    (CancellationOutcome.execution_in_flight). The execution layer composes the
    message it hands back for that case from `underlying_interruptible`, which
    it knows and this class does not.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

from core.events import Event, EventBus, EventType
from core.task_models import (
    ErrorKind,
    Task,
    TaskContext,
    TaskError,
    TaskStateError,
    TaskStatus,
    can_transition,
    new_task_id,
)
from core.task_store import LoadReport, TaskStore, default_tasks_path


@dataclass
class CancellationOutcome:
    """What actually happened when a cancel was requested."""

    task_id: str
    previous_status: TaskStatus
    status: TaskStatus
    interrupt_requested: bool = False     # the flag was set for a running task
    execution_in_flight: bool = False     # an action was bound when we were asked
    already_cancelled: bool = False
    message: str = ""

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "previous_status": self.previous_status.value,
            "status": self.status.value,
            "interrupt_requested": self.interrupt_requested,
            "execution_in_flight": self.execution_in_flight,
            "already_cancelled": self.already_cancelled,
            "message": self.message,
        }


class TaskManager:
    """Task lifecycle owner. One instance per NEO process."""

    def __init__(self, store: Optional[TaskStore] = None,
                 bus: Optional[EventBus] = None,
                 logger: Optional[Callable[[str], None]] = None,
                 notify: Optional[Callable[[str], None]] = None,
                 clock: Callable[[], float] = time.time):
        self._clock = clock
        self._logger = logger or (lambda _msg: None)
        # `notify` reaches the activity log, so only things the user has to know
        # about are sent there; the console gets everything through `logger`.
        self._notify = notify or (lambda _msg: None)
        self.store = store if store is not None else TaskStore(logger=self._logger)
        self.bus = bus if bus is not None else EventBus(logger=self._logger)

        self._lock = threading.RLock()
        self._tasks: dict[str, Task] = {}
        self._order: list[str] = []                 # creation order
        self._cancel_events: dict[str, threading.Event] = {}

        self.persistence_error: str = ""
        self.load_report: LoadReport = LoadReport()
        self.reconciled: list[str] = []             # orphans from a previous run

        self._load()

    # ── startup ─────────────────────────────────────────────────────────────

    def _load(self) -> None:
        report = self.store.load()
        self.load_report = report
        if report.error:
            self._logger(f"[Tasks] {report.summary()}")
        with self._lock:
            for task in report.tasks:
                if task.task_id not in self._tasks:
                    self._tasks[task.task_id] = task
                    self._order.append(task.task_id)
        self.reconcile_after_restart()

    def reconcile_after_restart(self) -> list[str]:
        """Mark tasks that a previous run left open, and say so plainly.

        A RUNNING/PAUSED record means NEO stopped while that task was in
        flight. Phase 2 has no resumable execution, so the honest outcome is
        FAILED/INTERRUPTED — not COMPLETED, and not a silent "still running"
        that the next launch would show forever.
        """
        events: list[Event] = []
        recovered: list[str] = []
        with self._lock:
            for task in self._tasks.values():
                if task.status in (TaskStatus.RUNNING, TaskStatus.PAUSED):
                    previous = task.status
                    task.status = TaskStatus.FAILED
                    task.completed_at = self._clock()
                    task.error = TaskError(
                        message=(f"NEO stopped while this task was {previous.value}; "
                                 f"execution is not resumable in Phase 2, so it was "
                                 f"marked failed."),
                        kind=ErrorKind.INTERRUPTED,
                    )
                    task.metadata["recovered"] = True
                    recovered.append(task.task_id)
                    events.append(Event(
                        type=EventType.TASK_FAILED,
                        task_id=task.task_id,
                        action=task.current_action,
                        status=task.status.value,
                        data={"recovered": True, "previous_status": previous.value},
                    ))
        if recovered:
            self.reconciled = recovered
            self._persist()
            for event in events:
                self.bus.emit(event)
            self._notify(f"{len(recovered)} task(s) from the previous run were "
                         f"interrupted — marked failed.")
        return recovered

    # ── creating / reading ──────────────────────────────────────────────────

    def create_task(self, user_request: str = "", metadata: Optional[dict] = None) -> Task:
        """Register a new request. Always PENDING — work starts in start_task()."""
        task = Task(task_id=new_task_id(), user_request=str(user_request or ""),
                    metadata=dict(metadata or {}), created_at=self._clock())
        event = Event(type=EventType.TASK_CREATED, task_id=task.task_id,
                      status=task.status.value,
                      data={"user_request": task.user_request[:200]})
        with self._lock:
            self._tasks[task.task_id] = task
            self._order.append(task.task_id)
        self._persist()
        self.bus.emit(event)
        return task

    def get_task(self, task_id: str) -> Optional[Task]:
        with self._lock:
            return self._tasks.get(task_id)

    def list_tasks(self, status: Optional[TaskStatus] = None,
                   limit: Optional[int] = None) -> list[Task]:
        with self._lock:
            tasks = [self._tasks[tid] for tid in self._order if tid in self._tasks]
        if status is not None:
            tasks = [t for t in tasks if t.status is status]
        tasks.reverse()                     # newest first
        if limit is not None and limit >= 0:
            tasks = tasks[:limit]
        return tasks

    def current_task(self) -> Optional[Task]:
        """The most recent task that has not finished, if any."""
        for task in self.list_tasks():
            if not task.is_terminal:
                return task
        return None

    def context_for(self, task_id: str, invocation: Optional[dict] = None) -> Optional[TaskContext]:
        """Build the execution context for a task, or None if it is unknown.

        Returns None rather than inventing a context: a caller that asks about a
        task that does not exist has a bug, and Phase 2 reports that instead of
        executing something un-owned.
        """
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return None
            event = self._cancel_events.get(task_id)
            if event is None:
                event = threading.Event()
                self._cancel_events[task_id] = event
            if task.status is TaskStatus.CANCELLED:
                event.set()          # never hand out an un-cancelled context for it
            return TaskContext(task=task, cancel_event=event,
                               invocation=dict(invocation or {}))

    # ── transitions ─────────────────────────────────────────────────────────

    def start_task(self, task_id: str) -> Task:
        with self._lock:
            task = self._require(task_id)
            # PENDING→RUNNING is legal in the map, but only a PENDING task is
            # being started: starting a paused task would silently resume it and
            # hide the fact that it was paused.
            if task.status is not TaskStatus.PENDING:
                raise TaskStateError(task.task_id, task.status, TaskStatus.RUNNING,
                                     "start_task expects a PENDING task")
            self._apply(task, TaskStatus.RUNNING)
            if task.started_at is None:
                task.started_at = self._clock()
            self._cancel_events.setdefault(task_id, threading.Event())
            event = self._event(EventType.TASK_STARTED, task)
        self._persist()
        self.bus.emit(event)
        return task

    def pause_task(self, task_id: str) -> Task:
        """Record that nothing further should start for this task.

        It does not stop an action that is already running — nothing in Phase 2
        can — and the execution layer resumes the task before applying that
        action's result, so a pause never fabricates a stopped execution.
        """
        with self._lock:
            task = self._require(task_id)
            self._apply(task, TaskStatus.PAUSED)
            event = self._event(EventType.TASK_PAUSED, task)
        self._persist()
        self.bus.emit(event)
        return task

    def resume_task(self, task_id: str) -> Task:
        with self._lock:
            task = self._require(task_id)
            if task.status is not TaskStatus.PAUSED:
                raise TaskStateError(task.task_id, task.status, TaskStatus.RUNNING,
                                     "only a paused task can be resumed")
            self._apply(task, TaskStatus.RUNNING)
            event = self._event(EventType.TASK_RESUMED, task)
        self._persist()
        self.bus.emit(event)
        return task

    def cancel_task(self, task_id: str,
                    error: Optional[TaskError] = None) -> CancellationOutcome:
        """Request cancellation. Returns what really happened.

        Idempotent on an already-cancelled task: re-requesting a cancel is a
        normal thing for a UI or a repeated confirmation callback to do, and it
        is not an error. Cancelling a COMPLETED or FAILED task is an error,
        because that would rewrite a finished outcome.
        """
        with self._lock:
            task = self._require(task_id)
            if task.status is TaskStatus.CANCELLED:
                outcome = CancellationOutcome(
                    task_id=task_id, previous_status=TaskStatus.CANCELLED,
                    status=TaskStatus.CANCELLED, already_cancelled=True,
                    message=f"Task {task.short_id()} was already cancelled.")
            else:
                previous = task.status
                in_flight = previous is TaskStatus.RUNNING and bool(task.current_action)
                self._apply(task, TaskStatus.CANCELLED)
                task.completed_at = self._clock()
                task.error = error or TaskError(
                    message="Task was cancelled.", kind=ErrorKind.TASK_CANCELLED)
                task.result = ""
                event_flag = self._cancel_events.setdefault(task_id, threading.Event())
                event_flag.set()
                if previous is TaskStatus.PENDING:
                    message = "Cancelled before it started — nothing was executed."
                elif in_flight:
                    message = (f"Cancellation requested while '{task.current_action}' "
                               f"was running. Anything further for this task will "
                               f"not start.")
                else:
                    message = (f"Cancelled from {previous.value} — no further steps "
                               f"will start for this task.")
                outcome = CancellationOutcome(
                    task_id=task_id, previous_status=previous,
                    status=TaskStatus.CANCELLED, interrupt_requested=in_flight,
                    execution_in_flight=in_flight, message=message)
                task.metadata["cancellation"] = outcome.to_dict()
                event = self._event(EventType.TASK_CANCELLED, task,
                                    data={"previous_status": previous.value,
                                          "execution_in_flight": in_flight})
        self._persist()
        if not outcome.already_cancelled:
            self.bus.emit(event)
        return outcome

    def complete_task(self, task_id: str, result: str = "",
                      data: Optional[dict] = None) -> Task:
        with self._lock:
            task = self._require(task_id)
            self._apply(task, TaskStatus.COMPLETED)
            task.completed_at = self._clock()
            task.result = str(result or "")
            task.error = None
            task.metadata.pop("awaiting_confirmation", None)
            if data:
                task.metadata["execution"] = dict(data)
            event = self._event(EventType.TASK_COMPLETED, task,
                                data={"result": task.result[:300]})
        self._persist()
        self.bus.emit(event)
        return task

    def fail_task(self, task_id: str, error: "str | TaskError",
                  kind: ErrorKind = ErrorKind.ACTION_FAILED, detail: str = "") -> Task:
        with self._lock:
            task = self._require(task_id)
            self._apply(task, TaskStatus.FAILED)
            task.completed_at = self._clock()
            task.error = (error if isinstance(error, TaskError)
                          else TaskError(message=str(error), kind=kind, detail=detail))
            task.metadata.pop("awaiting_confirmation", None)
            event = self._event(EventType.TASK_FAILED, task,
                                data={"error": task.error.message[:300],
                                      "kind": task.error.kind.value})
        self._persist()
        self.bus.emit(event)
        return task

    # ── annotations (no transition) ─────────────────────────────────────────

    def set_action(self, task_id: str, action: str, step: str = "") -> Optional[Task]:
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return None
            task.current_action = str(action or "")
            if step:
                task.current_step = str(step)[:200]
        self._persist()
        return task

    def record_result(self, task_id: str, payload: dict) -> None:
        """Attach the structured execution result for later phases to read."""
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return
            task.metadata["execution"] = dict(payload)
        self._persist()

    def mark_awaiting_confirmation(self, task_id: str, key: str, title: str) -> None:
        """The action is parked behind the existing confirmation gate.

        The task stays RUNNING on purpose: nothing has been authorized yet, so
        it is neither complete nor failed. When the user answers, the execution
        layer closes the task with the real outcome.
        """
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return
            task.metadata["awaiting_confirmation"] = {
                "key": key, "title": title, "requested_at": self._clock(),
            }
        self._persist()

    # ── internals ───────────────────────────────────────────────────────────

    def _require(self, task_id: str) -> Task:
        task = self._tasks.get(task_id)
        if task is None:
            raise KeyError(f"Unknown task: {task_id}")
        return task

    def _apply(self, task: Task, dst: TaskStatus) -> None:
        """The one place state changes; illegal edges raise."""
        if not can_transition(task.status, dst):
            raise TaskStateError(task.task_id, task.status, dst)
        task.status = dst

    @staticmethod
    def _event(kind: EventType, task: Task, data: Optional[dict] = None) -> Event:
        return Event(type=kind, task_id=task.task_id, action=task.current_action,
                     status=task.status.value, data=dict(data or {}))

    def _persist(self) -> None:
        previous, self.persistence_error = self.persistence_error, self.store.save(self.list_tasks())
        if self.persistence_error == previous:
            return                      # nothing changed; no repeated noise either way
        if self.persistence_error:
            self._logger(f"[Tasks] {self.persistence_error}")
            self._notify(f"Task history could not be saved — {self.persistence_error}")
        else:
            self._logger("[Tasks] task history saved again")
