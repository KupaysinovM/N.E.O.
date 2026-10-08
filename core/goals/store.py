"""
Goal history on disk — and an honest answer about resuming it.

WHAT IS PERSISTED
    `state/goals.json`, holding the goal records from core/goals/models.py: the
    goal's own text, its plan, each step's status and every attempt's real
    result, the bounded context, and the final `GoalResult`. That is enough to
    answer "what did NEO try, what did Windows say, and what did NEO report at
    the end" after the fact.

WHAT IS NOT PERSISTED
    No screenshots, no control trees, no credentials, no model transcripts, and
    nothing that would grow without bound. A step's stored data is the small
    shape the execution layer produced, and the goal record keeps the most
    recent attempts rather than all of them.

CRASH-RESUME IS NOT IMPLEMENTED, AND IS NOT CLAIMED
    Nothing here can put a half-finished plan back on the machine. A goal whose
    process died while it was PLANNING, READY, RUNNING, PAUSED or waiting for a
    confirmation is marked FAILED/INTERRUPTED on the next load, exactly as
    Phase 2 does for tasks — because "interrupted" is what happened, and
    pretending otherwise is how a crash becomes a fake success. There is no
    resume token, no checkpoint, no replay.

WHY THE LOADER IS AS SUSPICIOUS AS PHASE 2's
    This file is written by whatever was running when the machine went down. A
    truncated or half-written record is normal, and the only safe-honest
    options are "read it correctly" or "say it was unreadable". Malformed goal
    records are skipped and reported; an unreadable file is moved aside instead
    of being overwritten or interpreted.
"""
from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from core.goals.models import Goal

SCHEMA_VERSION = 1
STATE_DIR_NAME = "state"
GOALS_FILE_NAME = "goals.json"

#: Goals are rarer than tasks — one per request rather than one per action — so
#: a hundred is a very long history and still reads in milliseconds.
DEFAULT_MAX_GOALS = 100


def default_goals_path() -> Path:
    """`<project>/state/goals.json`, beside the task history it describes."""
    return Path(__file__).resolve().parent.parent.parent / STATE_DIR_NAME / GOALS_FILE_NAME


@dataclass
class GoalLoadReport:
    """What load() found. `error` is '' when everything read cleanly."""

    goals: list = field(default_factory=list)
    error: str = ""
    quarantined: str = ""
    skipped: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.error

    def summary(self) -> str:
        if not self.error:
            return f"{len(self.goals)} goal(s) loaded"
        extra = f"; unreadable file kept at {self.quarantined}" if self.quarantined else ""
        return f"goal history could not be read — {self.error}{extra}"


class GoalStore:
    """Read/write goal records. Never raises; every failure is returned."""

    def __init__(self, path: Optional[Path] = None, max_goals: int = DEFAULT_MAX_GOALS,
                 logger: Optional[Callable[[str], None]] = None):
        self.path = Path(path) if path is not None else default_goals_path()
        self.max_goals = max(1, int(max_goals))
        self._logger = logger or (lambda _msg: None)
        self._lock = threading.Lock()

    def load(self) -> GoalLoadReport:
        report = GoalLoadReport()
        try:
            if not self.path.exists():
                return report
            raw_text = self.path.read_text(encoding="utf-8")
        except OSError as e:
            report.error = f"could not read {self.path.name}: {e}"
            self._logger(f"[Goals] {report.error}")
            return report

        if not raw_text.strip():
            report.error = f"{self.path.name} is empty"
            report.quarantined = self._quarantine("empty file")
            return report

        try:
            payload = json.loads(raw_text)
        except (json.JSONDecodeError, ValueError) as e:
            report.error = f"{self.path.name} is not valid JSON: {e}"
            report.quarantined = self._quarantine("invalid json")
            self._logger(f"[Goals] {report.error}")
            return report

        if not isinstance(payload, dict):
            report.error = f"{self.path.name} is not an object"
            report.quarantined = self._quarantine("not an object")
            return report

        records = payload.get("goals")
        if not isinstance(records, list):
            report.error = f"{self.path.name} has no goal list"
            report.quarantined = self._quarantine("no goal list")
            return report

        version = payload.get("version")
        if version != SCHEMA_VERSION:
            report.error = (f"{self.path.name} has schema version {version!r}, "
                            f"expected {SCHEMA_VERSION}")

        for index, record in enumerate(records):
            try:
                report.goals.append(Goal.from_dict(record))
            except Exception as e:
                reason = f"record {index}: {e}"
                report.skipped.append(reason)
                self._logger(f"[Goals] skipped malformed goal {reason}")

        if report.skipped and not report.error:
            report.error = f"{len(report.skipped)} malformed goal record(s) skipped"
        return report

    def save(self, goals: list) -> str:
        """Write the goal list atomically. Returns '' on success, else why not."""
        # goal_id breaks ties so two goals created in the same millisecond keep
        # the same relative order in the file on every save.
        ordered = sorted(goals, key=lambda g: (g.created_at or 0.0, g.goal_id),
                         reverse=True)
        kept = ordered[: self.max_goals]
        payload = {"version": SCHEMA_VERSION, "saved_at": time.time(),
                   "goals": [g.to_dict() for g in kept]}
        tmp = self.path.with_name(self.path.name + ".tmp")
        try:
            with self._lock:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                               encoding="utf-8")
                os.replace(tmp, self.path)     # atomic: old file or new file
            return ""
        except Exception as e:
            self._logger(f"[Goals] save failed: {e}")
            try:
                if tmp.exists():
                    tmp.unlink()
            except Exception:
                pass
            return f"could not save goal history: {e}"

    def _quarantine(self, reason: str) -> str:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        target = self.path.with_name(f"{self.path.stem}.corrupt-{stamp}.json")
        try:
            os.replace(self.path, target)
            self._logger(f"[Goals] {self.path.name} {reason} — kept as {target.name}")
            return str(target)
        except Exception as e:
            self._logger(f"[Goals] could not set aside {self.path.name}: {e}")
            return ""


class GoalHistory:
    """What NEO remembers about goals across a restart.

    Holding history is not holding execution. On load, a goal that was open when
    NEO stopped is closed as INTERRUPTED — the same rule Phase 2 applies to
    tasks — because there is no code here that could continue it.
    """

    def __init__(self, store: Optional[GoalStore] = None,
                 logger: Optional[Callable[[str], None]] = None):
        self.store = store if store is not None else GoalStore(logger=logger)
        self.logger = logger or (lambda _msg: None)
        self.load_report: GoalLoadReport = GoalLoadReport()
        self.reconciled: list = field(default_factory=list)

    def load(self) -> GoalLoadReport:
        self.load_report = self.store.load()
        if self.load_report.error:
            self.logger(f"[Goals] {self.load_report.summary()}")
        return self.load_report

    def reconcile_after_restart(self, goals: list) -> list:
        """Close every goal the previous run left open, and say it plainly."""
        from core.goals.models import GoalStatus
        from core.task_models import ErrorKind, TaskError

        interrupted: list = []
        for goal in goals:
            if goal.is_terminal:
                continue
            previous = goal.status.value
            goal.status = GoalStatus.FAILED
            goal.completed_at = time.time()
            goal.error = TaskError(
                message=(f"NEO stopped while this goal was {previous}; goal execution "
                         f"is not resumable in Phase 5, so it was marked failed."),
                kind=ErrorKind.INTERRUPTED)
            goal.metadata["recovered"] = True
            interrupted.append(goal.goal_id)
        self.reconciled = interrupted
        if interrupted:
            self.save(goals)
        return interrupted

    def save(self, goals: list) -> str:
        return self.store.save(goals)