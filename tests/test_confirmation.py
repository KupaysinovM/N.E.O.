"""The confirmation boundary: a parked action closes its task truthfully.

These tests use the real core/confirm.py gate — the same single-use token the
HUD uses — with its two UI callbacks stubbed, so no Qt window is involved and
no irreversible action is ever performed: every "run" callable in this file
only appends to a list.
"""
from __future__ import annotations

import unittest

from core import confirm
from core.events import EventType
from core.execution import ExecStatus, ExecutionRequest
from core.task_models import ErrorKind, TaskStatus
from tests.support import (
    Sink,
    bound_gate,
    make_action_registry,
    make_layer,
    make_manager,
    resolve_confirmation,
    tmp_dir,
    wait_for,
)


class ConfirmationTestCase(unittest.TestCase):

    def setUp(self):
        self.tmp = tmp_dir()
        self.log = Sink()
        self.tm = make_manager(self.tmp, logger=self.log, notify=self.log)
        self.ran: list[str] = []          # what the gate was actually allowed to run

    def _parked_action(self, label: str = "work"):
        """A fixture action that asks the real gate to authorize its real work."""
        def handler(parameters=None, player=None):
            def work():
                self.ran.append(label)
                return "Shutdown done."
            return confirm.request(key="shutdown", title="Shut down the PC",
                                   detail="This will power the machine off.", run=work)
        return handler

    def _failing_action(self):
        def handler(parameters=None, player=None):
            def work():
                self.ran.append("work")
                raise RuntimeError("the OS refused")
            return confirm.request(key="shutdown", title="Shut down the PC",
                                   detail="d", run=work)
        return handler

    def _layer(self, actions=None):
        layer = make_layer(self.tm, actions=actions or make_action_registry(("power", self._parked_action())),
                           logger=self.log, notify=self.log)
        layer.bind_confirmation_gate()
        return layer

    def _start_task(self):
        task = self.tm.create_task("shut the PC down")
        self.tm.start_task(task.task_id)
        return task

    def _execute(self, layer, task):
        return layer.execute(
            ExecutionRequest(action="power", arguments={}, task_id=task.task_id),
            context=self.tm.context_for(task.task_id), handler_ctx={"player": None})


class TestGateWithoutAnInterface(ConfirmationTestCase):

    def test_nothing_irreversible_happens_and_it_is_reported_as_a_failure(self):
        layer = self._layer()               # no confirm.bind() → no interface
        task = self._start_task()
        result = self._execute(layer, task)
        self.assertEqual(result.status, ExecStatus.FAILED)
        self.assertEqual(result.error.kind, ErrorKind.AUTHORIZATION_UNAVAILABLE)
        self.assertEqual(self.ran, [])
        self.assertEqual(task.status, TaskStatus.FAILED)
        self.assertIn("CONFIRMATION_UNAVAILABLE", result.message)

    def test_the_gate_itself_still_refuses_and_never_runs_the_work(self):
        outcome = confirm.request(key="shutdown", title="Shut down the PC",
                                  detail="d", run=lambda: self.ran.append("work") or "x")
        self.assertTrue(outcome.startswith("[CONFIRMATION_UNAVAILABLE]"))
        self.assertEqual(self.ran, [])


class TestParkedConfirmation(ConfirmationTestCase):

    def test_the_task_stays_running_and_the_pending_action_is_tracked(self):
        with bound_gate():
            layer = self._layer()
            task = self._start_task()
            result = self._execute(layer, task)
            self.assertEqual(result.status, ExecStatus.REQUIRES_CONFIRMATION)
            self.assertEqual(result.error.kind, ErrorKind.AUTHORIZATION_REQUIRED)
            self.assertEqual(task.status, TaskStatus.RUNNING,
                             "an unauthorized action must not finish the task")
            self.assertEqual(task.metadata["awaiting_confirmation"]["key"], "shutdown")
            self.assertEqual(task.metadata["execution"]["status"], "REQUIRES_CONFIRMATION")
            self.assertEqual(layer.pending_authorizations()["shutdown"]["task_id"],
                             task.task_id)
            self.assertEqual(self.ran, [])

    def test_confirming_runs_the_real_work_and_completes_the_task(self):
        with bound_gate():
            layer = self._layer()
            task = self._start_task()
            self._execute(layer, task)
            resolve_confirmation(True)
            self.assertTrue(wait_for(lambda: task.status is TaskStatus.COMPLETED),
                            f"task stayed {task.status.value}")
            self.assertEqual(self.ran, ["work"])
            self.assertEqual(task.result, "Shutdown done.")
            self.assertIsNone(task.error)
            self.assertEqual(task.metadata["execution"]["status"], "SUCCESS")
            self.assertFalse(task.metadata["execution"]["verified"])
            self.assertEqual(layer.pending_authorizations(), {})
            self.assertTrue(wait_for(lambda: any(
                event.status == "SUCCESS"
                for event in self.tm.bus.recent(kind=EventType.ACTION_COMPLETED)
            )), "successful completion event was not emitted")
            completed = self.tm.bus.recent(1, EventType.ACTION_COMPLETED)[0]
            self.assertEqual(completed.status, "SUCCESS")
            self.assertEqual(completed.data["authorization"], "granted")

    def test_declining_cancels_the_task_and_runs_nothing(self):
        with bound_gate():
            layer = self._layer()
            task = self._start_task()
            self._execute(layer, task)
            resolve_confirmation(False)
            self.assertTrue(wait_for(lambda: task.status is TaskStatus.CANCELLED))
            self.assertEqual(self.ran, [])
            self.assertEqual(task.error.kind, ErrorKind.AUTHORIZATION_DENIED)
            self.assertEqual(self.tm.bus.recent(1, EventType.TASK_CANCELLED)[0].task_id,
                             task.task_id)

    def test_expiry_is_not_a_silent_success(self):
        with bound_gate():
            layer = self._layer()
            task = self._start_task()
            self._execute(layer, task)
            token = confirm.pending_token()
            confirm.TIMEOUT_SECONDS = 0.0        # the token has already expired
            confirm.resolve(True, token=token)
            self.assertTrue(wait_for(lambda: task.status is TaskStatus.CANCELLED))
            self.assertEqual(self.ran, [])
            self.assertIn("expired", task.error.detail)

    def test_confirmed_work_that_raises_fails_the_task(self):
        with bound_gate(log=self.log):
            layer = self._layer(make_action_registry(("power", self._failing_action())))
            task = self._start_task()
            self._execute(layer, task)
            resolve_confirmation(True)
            # Wait for the event too: the status flips just before it is emitted.
            self.assertTrue(wait_for(
                lambda: task.status is TaskStatus.FAILED
                and bool(self.tm.bus.recent(1, EventType.ACTION_FAILED))))
            self.assertEqual(self.ran, ["work"])
            self.assertEqual(task.error.kind, ErrorKind.ACTION_FAILED)
            self.assertIn("RuntimeError", task.error.message)
            self.assertNotIn("the OS refused", task.error.message)
            self.assertNotIn("the OS refused", self.log.text())
            failed = self.tm.bus.recent(1, EventType.ACTION_FAILED)[0]
            self.assertEqual(failed.data["authorization"], "granted")
            audit = self.tm.bus.recent(kind=EventType.SECURITY_AUDIT)
            self.assertEqual(audit[-1].data["confirmation"], "GRANTED")
            self.assertEqual(audit[-1].data["execution"], "FAILED")

    def test_the_token_is_single_use_and_the_latest_request_wins(self):
        with bound_gate():
            layer = self._layer()
            first = self._start_task()
            self._execute(layer, first)
            second = self._start_task()
            self._execute(layer, second)        # replaces the parked token, as the gate allows
            self.assertEqual(self.ran, [])
            resolve_confirmation(True)
            self.assertTrue(wait_for(lambda: second.status is TaskStatus.COMPLETED))
            self.assertEqual(self.ran, ["work"], "the gate ran something other than once")
            resolve_confirmation(True)           # nothing is pending any more
            self.assertEqual(self.ran, ["work"])
            # The first token was thrown away by the gate, so its task can never
            # be authorized — it is closed explicitly rather than left running.
            self.assertEqual(first.status, TaskStatus.CANCELLED)
            self.assertEqual(first.error.kind, ErrorKind.AUTHORIZATION_UNAVAILABLE)

    def test_a_late_resolution_cannot_rewrite_a_finished_task(self):
        with bound_gate():
            layer = self._layer()
            task = self._start_task()
            self._execute(layer, task)
            self.tm.complete_task(task.task_id, result="finished by hand")
            resolve_confirmation(True)
            self.assertTrue(wait_for(lambda: "arrived after the task" in self.log.text()))
            # The gate is authoritative and still honours the confirmation it was
            # given; what must not happen is the core rewriting a finished task.
            self.assertEqual(self.ran, ["work"])
            self.assertEqual(task.status, TaskStatus.COMPLETED)
            self.assertEqual(task.result, "finished by hand")


if __name__ == "__main__":
    unittest.main()
