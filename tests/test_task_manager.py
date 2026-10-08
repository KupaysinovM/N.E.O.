"""TaskManager: lifecycle, enforced transitions, cancellation, persistence."""
from __future__ import annotations

import json
import pathlib
import unittest

from core.events import EventType
from core.task_manager import TaskManager
from core.task_models import ErrorKind, TaskStateError, TaskStatus
from core.task_store import TaskStore
from tests.support import Sink, make_manager, tmp_dir


class TestLifecycle(unittest.TestCase):

    def setUp(self):
        self.tmp = tmp_dir()
        self.log = Sink()
        self.tm = make_manager(self.tmp, logger=self.log, notify=self.log)

    def test_create_assigns_unique_ids_and_starts_pending(self):
        first = self.tm.create_task("open calculator")
        second = self.tm.create_task("open notepad")
        self.assertNotEqual(first.task_id, second.task_id)
        self.assertEqual(first.status, TaskStatus.PENDING)
        self.assertEqual(first.user_request, "open calculator")
        self.assertEqual(first.metadata, {})
        self.assertIs(self.tm.get_task(first.task_id), first)

    def test_list_is_newest_first_and_filterable(self):
        a = self.tm.create_task("a")
        b = self.tm.create_task("b")
        self.tm.start_task(a.task_id)
        self.assertEqual([t.task_id for t in self.tm.list_tasks()],
                         [b.task_id, a.task_id])
        self.assertEqual([t.task_id for t in self.tm.list_tasks(status=TaskStatus.PENDING)],
                         [b.task_id])
        self.assertEqual([t.task_id for t in self.tm.list_tasks(limit=1)], [b.task_id])

    def test_current_task_is_the_open_one(self):
        first = self.tm.create_task("first")
        second = self.tm.create_task("second")
        self.assertIs(self.tm.current_task(), second)
        self.tm.start_task(second.task_id)
        self.tm.complete_task(second.task_id, result="ok")
        self.assertIs(self.tm.current_task(), first)

    def test_start_sets_timestamps_and_emits(self):
        task = self.tm.create_task("q")
        self.tm.start_task(task.task_id)
        self.assertEqual(task.status, TaskStatus.RUNNING)
        self.assertIsNotNone(task.started_at)
        kinds = [e.type for e in self.tm.bus.recent()]
        self.assertEqual(kinds, [EventType.TASK_CREATED, EventType.TASK_STARTED])
        self.assertEqual(self.tm.bus.recent()[-1].status, "RUNNING")
        self.assertEqual(self.tm.bus.recent()[-1].task_id, task.task_id)

    def test_pause_and_resume(self):
        task = self.tm.create_task("q")
        self.tm.start_task(task.task_id)
        self.tm.pause_task(task.task_id)
        self.assertEqual(task.status, TaskStatus.PAUSED)
        self.tm.resume_task(task.task_id)
        self.assertEqual(task.status, TaskStatus.RUNNING)
        self.assertIn(EventType.TASK_PAUSED, [e.type for e in self.tm.bus.recent()])
        self.assertIn(EventType.TASK_RESUMED, [e.type for e in self.tm.bus.recent()])

    def test_complete_records_the_real_result(self):
        task = self.tm.create_task("q")
        self.tm.start_task(task.task_id)
        self.tm.complete_task(task.task_id, result="Opened Calculator.")
        self.assertEqual(task.status, TaskStatus.COMPLETED)
        self.assertEqual(task.result, "Opened Calculator.")
        self.assertIsNotNone(task.completed_at)
        self.assertIsNone(task.error)
        event = self.tm.bus.recent()[-1]
        self.assertEqual(event.type, EventType.TASK_COMPLETED)
        self.assertEqual(event.data["result"], "Opened Calculator.")

    def test_fail_records_a_structured_error(self):
        task = self.tm.create_task("q")
        self.tm.start_task(task.task_id)
        self.tm.fail_task(task.task_id, "the OS said no", kind=ErrorKind.ACTION_FAILED)
        self.assertEqual(task.status, TaskStatus.FAILED)
        self.assertEqual(task.error.message, "the OS said no")
        self.assertEqual(task.error.kind, ErrorKind.ACTION_FAILED)
        self.assertEqual(task.result, "", "a failed task must not carry a success result")
        self.assertEqual(self.tm.bus.recent()[-1].type, EventType.TASK_FAILED)

    def test_annotations_do_not_change_state(self):
        task = self.tm.create_task("q")
        self.tm.start_task(task.task_id)
        self.tm.set_action(task.task_id, "open_app", "open the calculator")
        self.assertEqual(task.current_action, "open_app")
        self.assertEqual(task.current_step, "open the calculator")
        self.tm.record_result(task.task_id, {"status": "SUCCESS"})
        self.assertEqual(task.metadata["execution"], {"status": "SUCCESS"})
        self.tm.mark_awaiting_confirmation(task.task_id, "shutdown", "Shut down?")
        self.assertEqual(task.metadata["awaiting_confirmation"]["key"], "shutdown")
        self.assertEqual(task.status, TaskStatus.RUNNING)
        self.tm.complete_task(task.task_id, result="done")
        self.assertNotIn("awaiting_confirmation", task.metadata)
        self.assertNotIn(EventType.ACTION_STARTED, [e.type for e in self.tm.bus.recent()])


class TestInvalidTransitions(unittest.TestCase):

    def setUp(self):
        self.tmp = tmp_dir()
        self.tm = make_manager(self.tmp)

    def test_every_illegal_move_raises_and_leaves_state_alone(self):
        cases = [
            ("complete", TaskStatus.PENDING, lambda t: self.tm.complete_task(t, result="x")),
            ("fail", TaskStatus.PENDING, lambda t: self.tm.fail_task(t, "x")),
            ("pause", TaskStatus.PENDING, lambda t: self.tm.pause_task(t)),
            ("resume", TaskStatus.PENDING, lambda t: self.tm.resume_task(t)),
            ("resume", TaskStatus.COMPLETED, lambda t: self.tm.resume_task(t)),
            ("pause", TaskStatus.COMPLETED, lambda t: self.tm.pause_task(t)),
            ("start", TaskStatus.RUNNING, lambda t: self.tm.start_task(t)),
            ("start", TaskStatus.PAUSED, lambda t: self.tm.start_task(t)),
        ]
        for label, setup, operation in cases:
            with self.subTest(operation=label, setup=setup.value):
                task = self.tm.create_task("q")
                if setup is not TaskStatus.PENDING:
                    self.tm.start_task(task.task_id)
                if setup is TaskStatus.COMPLETED:
                    self.tm.complete_task(task.task_id, result="done")
                elif setup is TaskStatus.PAUSED:
                    self.tm.pause_task(task.task_id)
                before = task.status
                with self.assertRaises(TaskStateError):
                    operation(task.task_id)
                self.assertEqual(task.status, before,
                                 "state changed despite an invalid move")

    def test_cancelling_a_finished_task_is_refused(self):
        task = self.tm.create_task("q")
        self.tm.start_task(task.task_id)
        self.tm.complete_task(task.task_id, result="done")
        with self.assertRaises(TaskStateError):
            self.tm.cancel_task(task.task_id)
        self.assertEqual(task.status, TaskStatus.COMPLETED)

    def test_unknown_task_is_reported_not_invented(self):
        self.assertIsNone(self.tm.get_task("nope"))
        self.assertIsNone(self.tm.context_for("nope"))
        with self.assertRaises(KeyError):
            self.tm.start_task("nope")


class TestCancellation(unittest.TestCase):

    def setUp(self):
        self.tmp = tmp_dir()
        self.tm = make_manager(self.tmp)

    def test_cancel_pending_stops_before_anything_runs(self):
        task = self.tm.create_task("q")
        outcome = self.tm.cancel_task(task.task_id)
        self.assertEqual(outcome.previous_status, TaskStatus.PENDING)
        self.assertEqual(outcome.status, TaskStatus.CANCELLED)
        self.assertFalse(outcome.interrupt_requested)
        self.assertFalse(outcome.execution_in_flight)
        self.assertIn("nothing was executed", outcome.message.lower())
        self.assertEqual(task.status, TaskStatus.CANCELLED)
        self.assertIsNotNone(task.completed_at)
        self.assertEqual(self.tm.bus.recent()[-1].type, EventType.TASK_CANCELLED)

    def test_cancel_running_sets_the_flag_and_says_an_action_was_in_flight(self):
        task = self.tm.create_task("q")
        self.tm.start_task(task.task_id)
        self.tm.set_action(task.task_id, "open_app")
        outcome = self.tm.cancel_task(task.task_id)
        self.assertTrue(outcome.interrupt_requested)
        self.assertTrue(outcome.execution_in_flight)
        self.assertIn("open_app", outcome.message)
        context = self.tm.context_for(task.task_id)
        self.assertTrue(context.cancelled, "a cancelled task must hand out a cancelled context")
        self.assertEqual(task.metadata["cancellation"]["execution_in_flight"], True)

    def test_cancel_paused(self):
        task = self.tm.create_task("q")
        self.tm.start_task(task.task_id)
        self.tm.pause_task(task.task_id)
        outcome = self.tm.cancel_task(task.task_id)
        self.assertEqual(outcome.previous_status, TaskStatus.PAUSED)
        self.assertEqual(task.status, TaskStatus.CANCELLED)

    def test_cancel_twice_is_idempotent_and_does_not_double_emit(self):
        task = self.tm.create_task("q")
        self.tm.cancel_task(task.task_id)
        events_after_first = len(self.tm.bus.recent())
        outcome = self.tm.cancel_task(task.task_id)
        self.assertTrue(outcome.already_cancelled)
        self.assertEqual(len(self.tm.bus.recent()), events_after_first)

    def test_cancellation_carries_a_structured_error(self):
        task = self.tm.create_task("q")
        self.tm.cancel_task(task.task_id)
        self.assertEqual(task.error.kind, ErrorKind.TASK_CANCELLED)


class TestPersistence(unittest.TestCase):

    def test_task_history_survives_a_restart(self):
        tmp = tmp_dir()
        first = make_manager(tmp)
        task = first.create_task("open calculator")
        first.start_task(task.task_id)
        first.complete_task(task.task_id, result="Opened Calculator.")

        second = make_manager(tmp)
        loaded = second.get_task(task.task_id)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.status, TaskStatus.COMPLETED)
        self.assertEqual(loaded.result, "Opened Calculator.")
        self.assertEqual(loaded.user_request, "open calculator")

    def test_running_task_from_a_previous_run_is_marked_interrupted(self):
        tmp = tmp_dir()
        notify = Sink()
        first = make_manager(tmp)
        task = first.create_task("long thing")
        first.start_task(task.task_id)
        first.set_action(task.task_id, "file_controller")

        second = make_manager(tmp, notify=notify)
        loaded = second.get_task(task.task_id)
        self.assertEqual(loaded.status, TaskStatus.FAILED)
        self.assertEqual(loaded.error.kind, ErrorKind.INTERRUPTED)
        self.assertTrue(loaded.metadata["recovered"])
        self.assertEqual(second.reconciled, [task.task_id])
        self.assertIn("interrupted", notify.text())
        # The interrupted state was written back, so a third launch sees FAILED.
        third = make_manager(tmp)
        self.assertEqual(third.get_task(task.task_id).status, TaskStatus.FAILED)
        self.assertEqual(third.reconciled, [])

    def test_paused_task_from_a_previous_run_is_closeable(self):
        tmp = tmp_dir()
        first = make_manager(tmp)
        task = first.create_task("paused thing")
        first.start_task(task.task_id)
        first.pause_task(task.task_id)
        second = make_manager(tmp)
        loaded = second.get_task(task.task_id)
        self.assertEqual(loaded.status, TaskStatus.FAILED)
        self.assertEqual(loaded.error.kind, ErrorKind.INTERRUPTED)

    def test_missing_file_is_a_first_run_not_an_error(self):
        tmp = tmp_dir()
        tm = make_manager(tmp)
        self.assertEqual(tm.load_report.tasks, [])
        self.assertEqual(tm.load_report.error, "")
        self.assertEqual(tm.persistence_error, "")

    def test_corrupt_file_is_kept_aside_not_trusted(self):
        tmp = tmp_dir()
        path = tmp / "tasks.json"
        path.write_text("{not json at all", encoding="utf-8")
        tm = make_manager(tmp)
        self.assertNotEqual(tm.load_report.error, "")
        self.assertTrue(tm.load_report.quarantined)
        self.assertTrue(pathlib.Path(tm.load_report.quarantined).exists())
        self.assertNotEqual(pathlib.Path(tm.load_report.quarantined).name, "tasks.json")
        self.assertEqual(tm.list_tasks(), [])
        # ...and the manager is still usable, writing a fresh file.
        task = tm.create_task("after corruption")
        self.assertEqual(tm.persistence_error, "")
        self.assertTrue(json.loads(path.read_text(encoding="utf-8"))["tasks"])

    def test_empty_file_is_treated_as_an_incomplete_write(self):
        tmp = tmp_dir()
        (tmp / "tasks.json").write_text("   ", encoding="utf-8")
        tm = make_manager(tmp)
        self.assertNotEqual(tm.load_report.error, "")
        self.assertEqual(tm.list_tasks(), [])

    def test_a_single_malformed_record_is_skipped_and_reported(self):
        tmp = tmp_dir()
        good = {"task_id": "a" * 32, "user_request": "ok", "status": "COMPLETED",
                "created_at": 1.0, "result": "done"}
        bad = {"user_request": "no id here", "status": "RUNNING"}
        (tmp / "tasks.json").write_text(
            json.dumps({"version": 1, "tasks": [good, bad]}), encoding="utf-8")
        tm = make_manager(tmp)
        self.assertEqual([t.task_id for t in tm.list_tasks()], ["a" * 32])
        self.assertEqual(len(tm.load_report.skipped), 1)
        self.assertIn("skipped", tm.load_report.error)

    def test_unknown_schema_version_is_reported_not_interpreted(self):
        tmp = tmp_dir()
        (tmp / "tasks.json").write_text(
            json.dumps({"version": 99, "tasks": []}), encoding="utf-8")
        tm = make_manager(tmp)
        self.assertIn("schema version", tm.load_report.error)

    def test_unwritable_history_is_reported_without_breaking_the_task(self):
        tmp = tmp_dir()
        store = TaskStore(path=tmp, logger=Sink())      # a directory, not a file
        notify = Sink()
        tm = TaskManager(store=store, notify=notify)
        task = tm.create_task("still works")
        tm.start_task(task.task_id)
        tm.complete_task(task.task_id, result="done")
        self.assertEqual(task.status, TaskStatus.COMPLETED)
        self.assertNotEqual(tm.persistence_error, "")
        self.assertIn("could not save", notify.text())

    def test_history_is_capped_keeping_the_newest(self):
        tmp = tmp_dir()
        tm = make_manager(tmp, max_tasks=3)
        ids = [tm.create_task(f"task {i}").task_id for i in range(6)]
        reloaded = make_manager(tmp, max_tasks=3)
        kept = {t.task_id for t in reloaded.list_tasks()}
        self.assertEqual(len(kept), 3)
        self.assertTrue(kept.issubset(set(ids)))


if __name__ == "__main__":
    unittest.main()
