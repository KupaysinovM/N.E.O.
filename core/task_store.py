"""
The task persistence boundary — history only, never resumable execution.

WHAT IS PERSISTED
    One JSON file, `state/tasks.json`, holding the task records defined in
    core/task_models.py: id, request text, status, timestamps, the action that
    ran, the result message the action really returned, the error, and the
    metadata the core attached. That is history.

WHAT IS NOT PERSISTED — AND WHY IT MATTERS
    Execution is NOT resumable in Phase 2. Nothing here can put a half-finished
    action back on the OS: no process handle, no partial plan, no retry queue.
    A task that was RUNNING when NEO stopped cannot be continued, so the Task
    Manager marks it FAILED/INTERRUPTED on the next start rather than pretending
    it survived. Persisting task metadata is not memory: long-term user memory
    stays in memory/memory_manager.py and is untouched by this file.

WHY THE LOADER IS SUSPICIOUS
    This file is written by whatever was running when the machine went down.
    A truncated or half-written record is therefore a normal thing to find, and
    the two safe-honest options are "read it correctly" or "say it was
    unreadable". Repairing it into a plausible task would turn corruption into
    a fake result, so malformed records are skipped and reported, and an
    unreadable file is moved aside instead of being overwritten or trusted.

    Nothing secret belongs in here, and nothing secret is written: task records
    carry request text and results, never credentials (see core/secret_store.py
    for where those live).
"""
from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from core.task_models import Task

SCHEMA_VERSION = 1
STATE_DIR_NAME = "state"
TASKS_FILE_NAME = "tasks.json"

# How many task records the file keeps. A desktop assistant produces a handful
# of tasks per session; five hundred is months of history and still a file that
# reads in milliseconds.
DEFAULT_MAX_TASKS = 500


def default_tasks_path() -> Path:
    """`<project>/state/tasks.json`.

    Runtime state gets its own directory: config/ is configuration, config/
    secure/ is credentials, memory/ is the user's long-term memory, and none of
    those may hold the transient record of what the assistant is doing.
    """
    return Path(__file__).resolve().parent.parent / STATE_DIR_NAME / TASKS_FILE_NAME


@dataclass
class LoadReport:
    """What load() found. `error` is '' when everything read cleanly."""

    tasks: list[Task] = field(default_factory=list)
    error: str = ""
    quarantined: str = ""      # path the unreadable file was moved to, if any
    skipped: list[str] = field(default_factory=list)   # per-record reasons

    @property
    def ok(self) -> bool:
        return not self.error

    def summary(self) -> str:
        if not self.error:
            return f"{len(self.tasks)} task(s) loaded"
        extra = f"; unreadable file kept at {self.quarantined}" if self.quarantined else ""
        return f"task history could not be read — {self.error}{extra}"


class TaskStore:
    """Read/write task records. Never raises; every failure is returned."""

    def __init__(self, path: Optional[Path] = None, max_tasks: int = DEFAULT_MAX_TASKS,
                 logger: Optional[Callable[[str], None]] = None):
        self.path = Path(path) if path is not None else default_tasks_path()
        self.max_tasks = max(1, int(max_tasks))
        self._logger = logger or (lambda _msg: None)
        self._lock = threading.Lock()

    # -- reading ------------------------------------------------------------

    def load(self) -> LoadReport:
        report = LoadReport()
        try:
            if not self.path.exists():
                return report           # first run — not an error
            raw_text = self.path.read_text(encoding="utf-8")
        except OSError as e:
            report.error = f"could not read {self.path.name}: {e}"
            self._logger(f"[Store] {report.error}")
            return report

        if not raw_text.strip():
            # An empty file is a write that never completed. Keep the evidence
            # and start clean rather than guessing at content.
            report.error = f"{self.path.name} is empty"
            report.quarantined = self._quarantine("empty file")
            return report

        try:
            payload = json.loads(raw_text)
        except (json.JSONDecodeError, ValueError) as e:
            report.error = f"{self.path.name} is not valid JSON: {e}"
            report.quarantined = self._quarantine("invalid json")
            self._logger(f"[Store] {report.error}")
            return report

        if not isinstance(payload, dict):
            report.error = f"{self.path.name} is not an object"
            report.quarantined = self._quarantine("not an object")
            return report

        version = payload.get("version")
        records = payload.get("tasks")
        if not isinstance(records, list):
            report.error = f"{self.path.name} has no task list"
            report.quarantined = self._quarantine("no task list")
            return report

        if version != SCHEMA_VERSION:
            # A future/unknown version is reported, not interpreted. Guessing at
            # a schema we do not know is how a field ends up meaning two things.
            report.error = (f"{self.path.name} has schema version {version!r}, "
                            f"expected {SCHEMA_VERSION}")

        for index, record in enumerate(records):
            try:
                report.tasks.append(Task.from_dict(record))
            except Exception as e:
                reason = f"record {index}: {e}"
                report.skipped.append(reason)
                self._logger(f"[Store] skipped malformed task {reason}")

        if report.skipped and not report.error:
            report.error = f"{len(report.skipped)} malformed task record(s) skipped"
        return report

    # -- writing ------------------------------------------------------------

    def save(self, tasks: list[Task]) -> str:
        """Write the task list atomically. Returns '' on success, else why not.

        Temp file + os.replace: a reader (or the next launch) sees either the
        previous complete file or the new complete file, never a half-written
        one, so an interrupted save cannot corrupt live task state.
        """
        ordered = sorted(tasks, key=lambda t: t.created_at or 0.0, reverse=True)
        kept = ordered[: self.max_tasks]
        payload = {
            "version": SCHEMA_VERSION,
            "saved_at": time.time(),
            "tasks": [t.to_dict() for t in kept],
        }
        tmp = self.path.with_name(self.path.name + ".tmp")
        try:
            with self._lock:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                               encoding="utf-8")
                os.replace(tmp, self.path)
            return ""
        except Exception as e:
            # A failed save must not take the task down with it. The caller
            # records the failure and keeps running from memory.
            self._logger(f"[Store] save failed: {e}")
            try:
                if tmp.exists():
                    tmp.unlink()
            except Exception:
                pass
            return f"could not save task history: {e}"

    # -- internals ----------------------------------------------------------

    def _quarantine(self, reason: str) -> str:
        """Move an unreadable file aside so it cannot be silently overwritten."""
        stamp = time.strftime("%Y%m%d-%H%M%S")
        target = self.path.with_name(f"{self.path.stem}.corrupt-{stamp}.json")
        try:
            os.replace(self.path, target)
            self._logger(f"[Store] {self.path.name} {reason} — kept as {target.name}")
            return str(target)
        except Exception as e:
            self._logger(f"[Store] could not set aside {self.path.name}: {e}")
            return ""
