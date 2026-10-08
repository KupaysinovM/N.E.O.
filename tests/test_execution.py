"""The execution boundary: results, adapter, task state, cancellation."""
from __future__ import annotations

import threading
import unittest

from core.events import EventType
from core.execution import (
    ExecStatus,
    ExecutionLayer,
    ExecutionRequest,
    ExecutionResult,
    classify_legacy_message,
)
from core.task_models import ErrorKind, TaskStatus
from core.security import AuthorizationPolicy, RiskClass
from tests.support import Sink, make_action_registry, make_layer, make_manager, make_plugin_registry, tmp_dir


class TestLegacyAdapter(unittest.TestCase):
    """The adapter maps only markers that are already machine-shaped."""

    CASES = [
        ("[CONFIRMATION_PENDING] I have put a confirmation on screen for: X.",
         ExecStatus.REQUIRES_CONFIRMATION, ErrorKind.AUTHORIZATION_REQUIRED),
        ("[CONFIRMATION_UNAVAILABLE] I cannot confirm 'X' right now because the "
         "interface is not available, so I have not done it.",
         ExecStatus.FAILED, ErrorKind.AUTHORIZATION_UNAVAILABLE),
        ("I cannot confirm 'X' right now because the interface is not available, "
         "so I have not done it.",
         ExecStatus.FAILED, ErrorKind.AUTHORIZATION_UNAVAILABLE),
        ("[CONFIRMATION_FAILED] Could not ask for confirmation: boom. Nothing was done.",
         ExecStatus.FAILED, ErrorKind.INTERNAL_ERROR),
        ("NOT_SUPPORTED: arbitrary model-generated desktop code execution is disabled.",
         ExecStatus.NOT_SUPPORTED, ErrorKind.ACTION_NOT_SUPPORTED),
        ("NOT_AVAILABLE: no 'city' is stored in memory.",
         ExecStatus.NOT_AVAILABLE, ErrorKind.ACTION_UNAVAILABLE),
        ("Action 'open_app' is not available.",
         ExecStatus.NOT_AVAILABLE, ErrorKind.UNKNOWN_ACTION),
        ("Plugin 'chat' is not available.",
         ExecStatus.NOT_AVAILABLE, ErrorKind.UNKNOWN_ACTION),
        ("The 'chat' plugin is currently disabled.",
         ExecStatus.NOT_AVAILABLE, ErrorKind.ACTION_UNAVAILABLE),
        ("Tool 'open_app' failed: something broke",
         ExecStatus.FAILED, ErrorKind.ACTION_FAILED),
        ("The 'chat' plugin failed: something broke",
         ExecStatus.FAILED, ErrorKind.ACTION_FAILED),
        ("Unknown tool: made_up",
         ExecStatus.NOT_AVAILABLE, ErrorKind.UNKNOWN_ACTION),
        ("Unknown action: made_up",
         ExecStatus.NOT_AVAILABLE, ErrorKind.UNKNOWN_ACTION),
    ]

    def test_explicit_markers_are_mapped(self):
        for message, status, kind in self.CASES:
            with self.subTest(message=message[:40]):
                got_status, error, legacy = classify_legacy_message(message)
                self.assertEqual(got_status, status)
                self.assertIsNotNone(error)
                self.assertEqual(error.kind, kind)
                self.assertFalse(legacy, "an explicit marker is not a bare legacy message")

    def test_unmarked_prose_is_success_but_flagged_as_unverified(self):
        for message in ("Opened Calculator.", "Done.", "", None, 123,
                        "The download could not be started."):
            with self.subTest(message=repr(message)):
                status, error, legacy = classify_legacy_message(message)
                self.assertEqual(status, ExecStatus.SUCCESS)
                self.assertIsNone(error)
                self.assertTrue(legacy, "no marker means the claim rests on the action's own path")

    def test_adapter_never_returns_an_unknown_status(self):
        for text in ("", "x", "NOT_SUPPORTED:", "[CONFIRMATION_PENDING]"):
            self.assertIn(classify_legacy_message(text)[0], list(ExecStatus))


class TestExecutionStatuses(unittest.TestCase):

    def setUp(self):
        self.tmp = tmp_dir()
        self.log = Sink()
        self.notify = Sink()
        self.tm = make_manager(self.tmp, logger=self.log, notify=self.notify)

    def _layer(self, *actions, plugins=None):
        return make_layer(self.tm, actions=make_action_registry(*actions),
                          plugins=plugins, logger=self.log, notify=self.notify)

    def _run(self, layer, name, args=None, task_id=None):
        if task_id is None:
            task = self.tm.create_task(f"run {name}")
            task_id = task.task_id
            self.tm.start_task(task_id)
        ctx = self.tm.context_for(task_id)
        return layer.execute(ExecutionRequest(action=name, arguments=args or {},
                                              task_id=task_id),
                             context=ctx, handler_ctx={"player": None})

    # -- canonical statuses -------------------------------------------------

    def test_success_is_success_but_never_claimed_as_verified(self):
        def open_app(parameters=None, player=None):
            return f"Opened {parameters.get('app_name')}."

        layer = self._layer(("open_app", open_app))
        result = self._run(layer, "open_app", {"app_name": "Calculator"})
        self.assertEqual(result.status, ExecStatus.SUCCESS)
        self.assertEqual(result.message, "Opened Calculator.")
        self.assertFalse(result.verified)
        self.assertTrue(result.data["legacy_message"])
        self.assertTrue(result.data["invoked"])
        self.assertEqual(result.data["registry"], "actions")
        task = self.tm.get_task(result.task_id)
        self.assertEqual(task.status, TaskStatus.COMPLETED)
        self.assertEqual(task.result, "Opened Calculator.")
        self.assertEqual(task.metadata["execution"]["status"], "SUCCESS")

    def test_not_supported_and_not_available_are_preserved(self):
        layer = self._layer(
            ("refuser", lambda parameters=None, player=None:
                "NOT_SUPPORTED: arbitrary model-generated desktop code execution is disabled."),
            ("gone", lambda parameters=None, player=None:
                "NOT_AVAILABLE: no 'city' is stored in memory."),
        )
        refused = self._run(layer, "refuser")
        self.assertEqual(refused.status, ExecStatus.NOT_SUPPORTED)
        self.assertEqual(refused.error.kind, ErrorKind.ACTION_NOT_SUPPORTED)
        self.assertEqual(self.tm.get_task(refused.task_id).status, TaskStatus.FAILED)

        missing = self._run(layer, "gone")
        self.assertEqual(missing.status, ExecStatus.NOT_AVAILABLE)
        self.assertEqual(missing.error.kind, ErrorKind.ACTION_UNAVAILABLE)
        self.assertEqual(self.tm.get_task(missing.task_id).status, TaskStatus.FAILED)

    def test_handler_crash_is_a_failure_not_a_success(self):
        def boom(parameters=None, player=None):
            raise RuntimeError("kaboom")

        layer = self._layer(("boom", boom))
        result = self._run(layer, "boom")
        self.assertEqual(result.status, ExecStatus.FAILED)
        self.assertIn("RuntimeError", result.message)
        self.assertNotIn("kaboom", result.message)
        self.assertEqual(result.error.kind, ErrorKind.ACTION_FAILED)
        task = self.tm.get_task(result.task_id)
        self.assertEqual(task.status, TaskStatus.FAILED)
        self.assertIn("RuntimeError", task.error.message)
        self.assertNotIn("kaboom", task.error.message)

    def test_unknown_action_returns_an_explicit_result_and_does_not_crash(self):
        layer = self._layer(("open_app", lambda parameters=None, player=None: "ok"))
        result = self._run(layer, "delete_the_internet")
        self.assertEqual(result.status, ExecStatus.NOT_AVAILABLE)
        self.assertEqual(result.error.kind, ErrorKind.UNKNOWN_ACTION)
        self.assertFalse(result.invoked)
        self.assertIn("delete_the_internet", result.message)
        self.assertEqual(self.tm.get_task(result.task_id).status, TaskStatus.FAILED)

    def test_bad_arguments_are_refused_before_anything_runs(self):
        called = []
        def spy(parameters=None, player=None):
            called.append(parameters)
            return "ok"

        layer = self._layer(("spy", spy))
        task = self.tm.create_task("q")
        self.tm.start_task(task.task_id)
        result = layer.execute(ExecutionRequest(action="spy", arguments="nope",
                                                task_id=task.task_id))
        self.assertEqual(result.status, ExecStatus.FAILED)
        self.assertEqual(result.error.kind, ErrorKind.INVALID_ARGUMENTS)
        self.assertEqual(called, [])
        self.assertEqual(self.tm.get_task(task.task_id).status, TaskStatus.FAILED)

    def test_empty_action_name_is_an_invalid_request(self):
        layer = self._layer(("spy", lambda parameters=None, player=None: "ok"))
        result = layer.execute(ExecutionRequest(action="   ", arguments={}))
        self.assertEqual(result.status, ExecStatus.FAILED)
        self.assertEqual(result.error.kind, ErrorKind.INVALID_REQUEST)

    def test_a_non_request_object_is_refused(self):
        layer = self._layer(("spy", lambda parameters=None, player=None: "ok"))
        result = layer.execute({"action": "spy"})          # not an ExecutionRequest
        self.assertEqual(result.status, ExecStatus.FAILED)
        self.assertEqual(result.error.kind, ErrorKind.INVALID_REQUEST)
        self.assertFalse(result.invoked)

    def test_unknown_task_is_refused(self):
        layer = self._layer(("spy", lambda parameters=None, player=None: "ok"))
        result = layer.execute(ExecutionRequest(action="spy", arguments={},
                                                task_id="0" * 32))
        self.assertEqual(result.status, ExecStatus.FAILED)
        self.assertEqual(result.error.kind, ErrorKind.INVALID_REQUEST)

    def test_a_finished_task_cannot_be_executed_again(self):
        layer = self._layer(("spy", lambda parameters=None, player=None: "ok"))
        first = self._run(layer, "spy")
        result = self._run(layer, "spy", task_id=first.task_id)
        self.assertEqual(result.status, ExecStatus.FAILED)
        self.assertEqual(result.error.kind, ErrorKind.INVALID_REQUEST)
        self.assertFalse(result.invoked)

    def test_a_pending_task_is_started_by_the_layer(self):
        layer = self._layer(("spy", lambda parameters=None, player=None: "ok"))
        task = self.tm.create_task("q")
        result = layer.execute(ExecutionRequest(action="spy", arguments={},
                                                task_id=task.task_id))
        self.assertEqual(result.status, ExecStatus.SUCCESS)
        self.assertEqual(task.status, TaskStatus.COMPLETED)
        self.assertIsNotNone(task.started_at)

    def test_the_layer_works_without_a_task_manager(self):
        layer = ExecutionLayer(actions=make_action_registry(
            ("spy", lambda parameters=None, player=None: "no manager")), manager=None,
            security_policy=AuthorizationPolicy(
                overrides={"spy": RiskClass.LOW_RISK_REVERSIBLE}))
        result = layer.execute(ExecutionRequest(action="spy", arguments={}))
        self.assertEqual(result.status, ExecStatus.SUCCESS)
        self.assertEqual(result.task_id, "")

    # -- plugins ------------------------------------------------------------

    def test_plugins_go_through_the_same_boundary(self):
        plugins = make_plugin_registry(
            ("fixture_chat", lambda parameters=None, player=None, session_memory=None:
                "Plugin says hi."))
        layer = self._layer(plugins=plugins)
        result = self._run(layer, "fixture_chat")
        self.assertEqual(result.status, ExecStatus.SUCCESS)
        self.assertEqual(result.data["registry"], "plugins")
        self.assertEqual(self.tm.get_task(result.task_id).result, "Plugin says hi.")

    def test_actions_take_precedence_over_plugins(self):
        plugins = make_plugin_registry(("same_name", lambda parameters=None, **kw: "plugin"))
        layer = self._layer(("same_name", lambda parameters=None, player=None: "action"),
                            plugins=plugins)
        result = self._run(layer, "same_name")
        self.assertEqual(result.message, "action")
        self.assertEqual(result.data["registry"], "actions")

    # -- events -------------------------------------------------------------

    def test_lifecycle_events_are_emitted_in_order(self):
        layer = self._layer(("open_app", lambda parameters=None, player=None: "Opened it."))
        result = self._run(layer, "open_app")
        kinds = [e.type for e in self.tm.bus.recent()]
        self.assertEqual(kinds, [EventType.TASK_CREATED, EventType.TASK_STARTED,
                                 EventType.SECURITY_AUDIT, EventType.ACTION_STARTED,
                                 EventType.SECURITY_AUDIT,
                                 EventType.ACTION_COMPLETED, EventType.TASK_COMPLETED])
        started = self.tm.bus.recent(1, EventType.ACTION_STARTED)[0]
        self.assertEqual(started.action, "open_app")
        self.assertEqual(started.task_id, result.task_id)
        completed = self.tm.bus.recent(1, EventType.ACTION_COMPLETED)[0]
        self.assertEqual(completed.status, "SUCCESS")
        self.assertEqual(completed.data["registry"], "actions")

    def test_failure_emits_action_failed_then_task_failed(self):
        layer = self._layer(("gone", lambda parameters=None, player=None:
                             "NOT_AVAILABLE: nothing there."))
        self._run(layer, "gone")
        kinds = [e.type for e in self.tm.bus.recent()]
        self.assertIn(EventType.ACTION_FAILED, kinds)
        self.assertEqual(kinds[-1], EventType.TASK_FAILED)
        self.assertLess(kinds.index(EventType.ACTION_FAILED), kinds.index(EventType.TASK_FAILED))

    def test_unknown_action_emits_a_failure_without_an_action_start(self):
        layer = self._layer()
        self._run(layer, "does_not_exist")
        kinds = [e.type for e in self.tm.bus.recent()]
        self.assertNotIn(EventType.ACTION_STARTED, kinds)
        self.assertIn(EventType.ACTION_FAILED, kinds)

    # -- cancellation -------------------------------------------------------

    def test_cancelling_before_dispatch_prevents_invocation(self):
        called = []
        def spy(parameters=None, player=None):
            called.append(True)
            return "should not run"

        layer = self._layer(("spy", spy))
        task = self.tm.create_task("q")
        self.tm.cancel_task(task.task_id)
        ctx = self.tm.context_for(task.task_id)
        result = layer.execute(ExecutionRequest(action="spy", arguments={},
                                                task_id=task.task_id),
                               context=ctx, handler_ctx={"player": None})
        self.assertEqual(result.status, ExecStatus.CANCELLED)
        self.assertEqual(called, [], "the action ran even though the task was cancelled")
        self.assertFalse(result.invoked)
        self.assertEqual(result.error.kind, ErrorKind.TASK_CANCELLED)
        self.assertEqual(self.tm.get_task(task.task_id).status, TaskStatus.CANCELLED)
        self.assertNotIn(EventType.ACTION_STARTED, [e.type for e in self.tm.bus.recent()])

    def test_cancelling_a_pending_task_stops_it_from_starting(self):
        called = []
        layer = self._layer(("spy", lambda parameters=None, player=None: called.append(1)))
        task = self.tm.create_task("q")
        self.tm.cancel_task(task.task_id)
        result = layer.execute(ExecutionRequest(action="spy", arguments={},
                                               task_id=task.task_id))
        self.assertEqual(result.status, ExecStatus.CANCELLED)
        self.assertEqual(called, [])
        self.assertEqual(task.status, TaskStatus.CANCELLED)

    def test_cancel_while_running_says_so_instead_of_faking_an_interrupt(self):
        holder = {}
        def slow(parameters=None, player=None):
            holder["outcome"] = self.tm.cancel_task(holder["task_id"])
            return "The action finished anyway."

        layer = self._layer(("slow", slow))
        task = self.tm.create_task("q")
        holder["task_id"] = task.task_id
        self.tm.start_task(task.task_id)
        result = layer.execute(ExecutionRequest(action="slow", arguments={},
                                                task_id=task.task_id),
                               context=self.tm.context_for(task.task_id),
                               handler_ctx={"player": None})
        self.assertEqual(result.status, ExecStatus.CANCELLED)
        self.assertTrue(result.data["completed_after_cancellation"])
        self.assertIn("cannot interrupt", result.message)
        self.assertIn("The action finished anyway.", result.message)
        self.assertEqual(task.status, TaskStatus.CANCELLED)
        self.assertEqual(task.result, "", "a cancelled task must not keep a success result")
        events = self.tm.bus.recent()
        self.assertEqual(events[-1].type, EventType.ACTION_COMPLETED)
        self.assertEqual(events[-1].status, "CANCELLED")

    def test_cancellation_reaches_handlers_that_opt_in(self):
        seen = []
        holder = {}

        def cooperative(parameters=None, cancel_event=None):
            seen.append(cancel_event)
            holder["outcome"] = self.tm.cancel_task(holder["task_id"])   # user cancels mid-run
            return "stopped early"

        layer = self._layer(("cooperative", cooperative))
        task = self.tm.create_task("q")
        holder["task_id"] = task.task_id
        self.tm.start_task(task.task_id)
        result = layer.execute(ExecutionRequest(action="cooperative", arguments={},
                                                task_id=task.task_id),
                               context=self.tm.context_for(task.task_id),
                               handler_ctx={"player": None})
        self.assertEqual(len(seen), 1)
        self.assertIsInstance(seen[0], threading.Event)
        self.assertIs(seen[0], self.tm.context_for(task.task_id).cancel_event,
                      "the handler was given a different event than the manager's")
        self.assertTrue(seen[0].is_set(), "the handler's cancel flag was not set")
        self.assertTrue(result.data["interruptible"])
        self.assertEqual(result.status, ExecStatus.CANCELLED)

    def test_a_handler_without_the_opt_in_is_reported_as_not_interruptible(self):
        layer = self._layer(("plain", lambda parameters=None, player=None: "ok"))
        task = self.tm.create_task("q")
        self.tm.start_task(task.task_id)
        result = layer.execute(ExecutionRequest(action="plain", arguments={},
                                                task_id=task.task_id),
                               context=self.tm.context_for(task.task_id),
                               handler_ctx={"player": None})
        self.assertFalse(result.data["interruptible"])

    def test_execution_stays_ordered_when_two_tasks_run_concurrently(self):
        order = []
        def recording(parameters=None, player=None):
            order.append(parameters["tag"])
            return f"done {parameters['tag']}"

        layer = self._layer(("record", recording))
        tasks = []
        threads = []
        for tag in ("a", "b", "c"):
            task = self.tm.create_task(f"run {tag}")
            self.tm.start_task(task.task_id)
            tasks.append(task)
            threads.append(threading.Thread(
                target=layer.execute,
                args=(ExecutionRequest(action="record", arguments={"tag": tag},
                                       task_id=task.task_id),),
                kwargs={"context": self.tm.context_for(task.task_id),
                        "handler_ctx": {"player": None}}))
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        self.assertEqual(sorted(order), ["a", "b", "c"])
        for task in tasks:
            self.assertEqual(self.tm.get_task(task.task_id).status, TaskStatus.COMPLETED)

    # -- recording ----------------------------------------------------------

    def test_every_path_records_the_structured_result_on_the_task(self):
        layer = self._layer(
            ("ok", lambda parameters=None, player=None: "fine"),
            ("refuser", lambda parameters=None, player=None: "NOT_SUPPORTED: no."),
        )
        for name, expected in (("ok", "SUCCESS"), ("refuser", "NOT_SUPPORTED"),
                               ("missing_name", "NOT_AVAILABLE")):
            result = self._run(layer, name)
            record = self.tm.get_task(result.task_id).metadata["execution"]
            self.assertEqual(record["status"], expected)
            self.assertEqual(record["action"], name)
            self.assertFalse(record["verified"])


class TestResultObject(unittest.TestCase):

    def test_result_serialises_and_reports_ok(self):
        result = ExecutionResult(status=ExecStatus.SUCCESS, action="a", task_id="t",
                                 message="m", data={"invoked": True})
        self.assertTrue(result.ok)
        self.assertTrue(result.invoked)
        self.assertEqual(ExecutionResult(status=ExecStatus.FAILED, action="a").ok, False)
        self.assertEqual(result.to_dict()["status"], "SUCCESS")

    def test_request_serialises_its_arguments(self):
        request = ExecutionRequest(action="a", arguments={"x": 1}, task_id="t",
                                   requested_by="model", tool_call_id="call-1")
        self.assertEqual(request.to_dict()["arguments"], {"x": 1})
        self.assertEqual(request.to_dict()["tool_call_id"], "call-1")


if __name__ == "__main__":
    unittest.main()
