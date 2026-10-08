"""The canonical task model: ids, states, transitions, errors, context."""
from __future__ import annotations

import re
import threading
import unittest

from core.task_models import (
    ErrorKind,
    Task,
    TaskContext,
    TaskError,
    TaskStateError,
    TaskStatus,
    TERMINAL_STATUSES,
    TASK_TRANSITIONS,
    can_transition,
    new_task_id,
)


class TestTaskIdsAndShape(unittest.TestCase):

    def test_ids_are_unique_and_well_formed(self):
        ids = [new_task_id() for _ in range(2000)]
        self.assertEqual(len(set(ids)), len(ids), "task ids collided")
        for value in ids:
            self.assertRegex(value, re.compile(r"^[0-9a-f]{32}$"))

    def test_new_task_starts_pending_with_required_fields(self):
        task = Task(task_id=new_task_id(), user_request="open calculator")
        self.assertEqual(task.status, TaskStatus.PENDING)
        self.assertTrue(task.created_at > 0)
        self.assertIsNone(task.started_at)
        self.assertIsNone(task.completed_at)
        self.assertEqual(task.current_step, "")
        self.assertEqual(task.current_action, "")
        self.assertEqual(task.result, "")
        self.assertIsNone(task.error)
        self.assertEqual(task.metadata, {})
        self.assertFalse(task.is_terminal)

    def test_terminal_statuses(self):
        self.assertEqual(TERMINAL_STATUSES,
                         {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED})
        for status in TERMINAL_STATUSES:
            task = Task(task_id=new_task_id(), status=status)
            self.assertTrue(task.is_terminal)

    def test_round_trip_through_dict(self):
        task = Task(task_id=new_task_id(), user_request="do the thing",
                    status=TaskStatus.FAILED, created_at=1.0, started_at=2.0,
                    completed_at=3.0, current_step="step", current_action="open_app",
                    result="", error=TaskError("nope", ErrorKind.ACTION_FAILED, "detail"),
                    metadata={"k": "v"})
        again = Task.from_dict(task.to_dict())
        self.assertEqual(again.task_id, task.task_id)
        self.assertEqual(again.status, TaskStatus.FAILED)
        self.assertEqual(again.started_at, 2.0)
        self.assertEqual(again.completed_at, 3.0)
        self.assertEqual(again.error.kind, ErrorKind.ACTION_FAILED)
        self.assertEqual(again.error.detail, "detail")
        self.assertEqual(again.metadata, {"k": "v"})

    def test_from_dict_rejects_unusable_records(self):
        with self.assertRaises(ValueError):
            Task.from_dict({"status": "PENDING"})              # no task_id
        with self.assertRaises(ValueError):
            Task.from_dict({"task_id": "abc", "status": "RUNNINGISH"})   # unknown state
        with self.assertRaises(ValueError):
            Task.from_dict("not-a-record")
        with self.assertRaises(ValueError):
            Task.from_dict({"task_id": "abc", "error": {"kind": "ACTION_FAILED"}})

    def test_coerce_status_is_strict(self):
        from core.task_models import coerce_status
        self.assertEqual(coerce_status("running"), TaskStatus.RUNNING)
        self.assertEqual(coerce_status(TaskStatus.PAUSED), TaskStatus.PAUSED)
        with self.assertRaises(ValueError):
            coerce_status("banana")


class TestTransitions(unittest.TestCase):

    def test_legal_edges(self):
        legal = [
            (TaskStatus.PENDING, TaskStatus.RUNNING),
            (TaskStatus.PENDING, TaskStatus.CANCELLED),
            (TaskStatus.RUNNING, TaskStatus.PAUSED),
            (TaskStatus.RUNNING, TaskStatus.COMPLETED),
            (TaskStatus.RUNNING, TaskStatus.FAILED),
            (TaskStatus.RUNNING, TaskStatus.CANCELLED),
            (TaskStatus.PAUSED, TaskStatus.RUNNING),
            (TaskStatus.PAUSED, TaskStatus.CANCELLED),
        ]
        for src, dst in legal:
            self.assertTrue(can_transition(src, dst), f"{src.value} → {dst.value}")

    def test_illegal_edges(self):
        illegal = [
            (TaskStatus.PENDING, TaskStatus.PAUSED),
            (TaskStatus.PENDING, TaskStatus.COMPLETED),
            (TaskStatus.PENDING, TaskStatus.FAILED),
            (TaskStatus.PAUSED, TaskStatus.COMPLETED),
            (TaskStatus.PAUSED, TaskStatus.FAILED),
            (TaskStatus.COMPLETED, TaskStatus.RUNNING),
            (TaskStatus.FAILED, TaskStatus.RUNNING),
            (TaskStatus.CANCELLED, TaskStatus.RUNNING),
            (TaskStatus.CANCELLED, TaskStatus.COMPLETED),
        ]
        for src, dst in illegal:
            self.assertFalse(can_transition(src, dst), f"{src.value} → {dst.value}")

    def test_every_state_is_in_the_map_and_never_transitions_to_itself(self):
        self.assertEqual(set(TASK_TRANSITIONS), set(TaskStatus))
        for src, targets in TASK_TRANSITIONS.items():
            self.assertNotIn(src, targets)

    def test_state_error_carries_the_pair(self):
        error = TaskStateError("abc123", TaskStatus.PENDING, TaskStatus.COMPLETED)
        self.assertEqual(error.src, TaskStatus.PENDING)
        self.assertEqual(error.dst, TaskStatus.COMPLETED)
        self.assertIn("PENDING", str(error))
        self.assertIn("COMPLETED", str(error))


class TestErrorTaxonomy(unittest.TestCase):

    def test_kinds_cover_the_required_cases(self):
        required = {
            "INVALID_REQUEST", "UNKNOWN_ACTION", "INVALID_ARGUMENTS",
            "AUTHORIZATION_REQUIRED", "AUTHORIZATION_DENIED", "ACTION_UNAVAILABLE",
            "ACTION_FAILED", "TASK_CANCELLED", "INTERNAL_ERROR",
        }
        self.assertTrue(required.issubset({k.value for k in ErrorKind}))

    def test_round_trip_and_unknown_kind_falls_back_explicitly(self):
        error = TaskError("boom", ErrorKind.TASK_CANCELLED, "detail")
        again = TaskError.from_dict(error.to_dict())
        self.assertEqual(again.kind, ErrorKind.TASK_CANCELLED)
        self.assertEqual(again.detail, "detail")
        # An unrecognised kind is a fallback, never a missing error.
        self.assertEqual(TaskError.from_dict(
            {"message": "x", "kind": "MADE_UP"}).kind, ErrorKind.ACTION_FAILED)


class TestTaskContext(unittest.TestCase):

    def test_context_reflects_task_and_cancellation(self):
        task = Task(task_id=new_task_id(), user_request="q", status=TaskStatus.RUNNING,
                    current_action="open_app")
        event = threading.Event()
        ctx = TaskContext(task=task, cancel_event=event, invocation={"requested_by": "model"})
        self.assertEqual(ctx.task_id, task.task_id)
        self.assertEqual(ctx.status, TaskStatus.RUNNING)
        self.assertEqual(ctx.current_action, "open_app")
        self.assertFalse(ctx.cancelled)
        self.assertFalse(ctx.is_cancelled())
        event.set()
        self.assertTrue(ctx.cancelled)
        self.assertEqual(ctx.to_dict()["invocation"], {"requested_by": "model"})

    def test_context_view_follows_the_task_record(self):
        task = Task(task_id=new_task_id())
        ctx = TaskContext(task=task)
        task.status = TaskStatus.COMPLETED
        self.assertEqual(ctx.status, TaskStatus.COMPLETED)


if __name__ == "__main__":
    unittest.main()
