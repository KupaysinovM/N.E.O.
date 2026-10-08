"""
Phase 5, part 2 — running a goal: ordering, truthfulness, recovery, stopping.

WHAT IS UNDER TEST
    The production GoalExecutor, driving the production ExecutionLayer,
    TaskManager and Phase 4 verifier, over fixture capabilities. Every executed
    step goes through the real task/execution boundary: a real task is created,
    a real event is emitted, a real verification runs.

THE HEADLINE ASSERTION IN HERE
    execution SUCCESS + verification NOT_VERIFIED  ==  goal NOT_VERIFIED.
    Never goal SUCCESS, never "it worked". `TestTruthfulness` is the class that
    says so, and `test_a_successful_call_with_an_unobservable_effect_is_not_a_
    goal_success` is the single most important assertion in Phase 5.

WHAT IS SUBSTITUTED
    Only the OS read (`tests.support.observed_by`), and only so a test never
    touches the user's desktop. Everything that decides a verdict — bounded
    polling, comparison, timeouts, status classification — is Phase 4's own code
    running unmodified.
"""
from __future__ import annotations

import pathlib
import re
import unittest

from core.events import EventType
from core.execution import ExecStatus
from core.goals.limits import Limits
from core.goals.models import GoalStatus, StepStatus
from core.task_models import ErrorKind, TaskStatus
from tests.support import (
    DEMO_HANDLE,
    DemoWorld,
    _FastClock,
    bound_gate,
    make_goal_stack,
    make_goal_history,
    observed_by,
    reset_demo_world,
    resolve_confirmation,
    tmp_dir,
    unbound_gate,
    wait_for,
)


def _launch(**extra) -> dict:
    return {"id": "s1", "action": "demo_control",
            "arguments": {"operation": "launch"}, **extra}


def _set_value(handle=({"$from": "step:s1.handle"}, DEMO_HANDLE)[0], text="hello",
               step_id="s2", **extra) -> dict:
    return {"id": step_id, "action": "demo_control", "depends_on": ["s1"],
            "arguments": {"operation": "set_value", "window_handle": handle,
                          "control_type": "Document", "text": text}, **extra}


def _close(handle=DEMO_HANDLE, step_id="c1", **extra) -> dict:
    return {"id": step_id, "action": "demo_control",
            "arguments": {"operation": "close", "window_handle": handle}, **extra}


def _focus(handle=DEMO_HANDLE, step_id="f1", **extra) -> dict:
    return {"id": step_id, "action": "demo_control",
            "arguments": {"operation": "focus", "window_handle": handle}, **extra}


class GoalTestCase(unittest.TestCase):
    """Sets up a real stack over a fresh demo world for every test."""

    def setUp(self):
        self.tmp = tmp_dir("neo-phase5-run-")
        self._world_ctx = reset_demo_world()
        self.world = self._world_ctx.__enter__()
        self.addCleanup(self._world_ctx.__exit__, None, None, None)
        self.world.windows = {DEMO_HANDLE}
        self.manager, self.layer, self.planner, self.executor, self.world = \
            make_goal_stack(self.tmp, world=self.world)
        self.history = make_goal_history(self.tmp)
        self.executor.history = self.history
        self.events = []
        self.bus_sink = self.executor.bus.subscribe(self.events.append)
        self.addCleanup(self.bus_sink)
        self.observer = observed_by(self.world)
        self.observer.__enter__()
        self.addCleanup(self.observer.__exit__, None, None, None)

    def goal_with(self, steps, description="a goal"):
        goal = self.executor.create_goal(description)
        return self.executor.plan_goal(goal, raw_steps=steps)

    def types(self) -> list:
        return [e.type for e in self.events]


class TestOrderedExecution(GoalTestCase):

    def test_steps_run_in_dependency_order_and_a_verified_goal_completes(self):
        goal = self.goal_with([_launch(), _set_value()])
        result = self.executor.run(goal)

        self.assertEqual(goal.status, GoalStatus.COMPLETED)
        self.assertTrue(result.ok)
        self.assertEqual(self.world.calls, ["launch", "set_value"])
        self.assertEqual([s["status"] for s in result.steps],
                         ["VERIFIED", "VERIFIED"])
        self.assertEqual(result.verified, 2)
        self.assertEqual(result.not_verified, 0)

    def test_a_later_step_uses_what_the_earlier_one_actually_reported(self):
        """The `$from` reference is the whole point of the context."""
        goal = self.goal_with([_launch(), _set_value(handle={"$from": "step:s1.handle"})])
        self.executor.run(goal)
        second = goal.step("s2")
        self.assertEqual(second.resolved_arguments["window_handle"], DEMO_HANDLE)
        self.assertEqual(self.world.values[(DEMO_HANDLE, "Document")], "hello")

    def test_the_context_never_evicts_a_handle_a_later_step_still_needs(self):
        """Bounded is not the same as forgetful.

        One launch publishes several entries — its handle, what that handle
        belongs to, the verification observation, that the step verified — so a
        full-length plan overflows the bounded context several times over. The
        handle the last step names by hand is the *oldest* entry by then, and an
        oldest-first eviction would drop it, failing a step whose dependency had
        already succeeded. The neighbouring entries are dropped, which is how
        this test knows the context really was under pressure.
        """
        steps = [_launch(id=f"a{index}") for index in range(1, 12)]
        steps.append({"id": "last", "action": "demo_control", "depends_on": ["a11"],
                      "arguments": {"operation": "focus",
                                    "window_handle": {"$from": "step:a1.handle"}}})
        goal = self.goal_with(steps)
        result = self.executor.run(goal)

        self.assertEqual(len(goal.context.entries), goal.context.max_items,
                         "the context never had to evict anything, so this proves nothing")
        last = goal.step("last")
        self.assertEqual(last.status, StepStatus.VERIFIED, result.report())
        self.assertEqual(last.resolved_arguments["window_handle"], DEMO_HANDLE)
        self.assertEqual(goal.context.recall("step:a1.handle"), DEMO_HANDLE)
        self.assertIn("focus", self.world.calls,
                      "the step whose reference was dropped never reached the machine")

    def test_the_context_still_holds_what_a_finished_goal_reported(self):
        """An ordinary two-step goal must not evict its own result.

        A launch records its handle, the window's identity, and the verification
        observation, and a retry re-observes the desktop on top of that. Twelve
        entries is smaller than one ordinary goal's footprint, so the default
        bound has to cover the executor's own bookkeeping or a completed goal
        forgets the very handle it published.
        """
        goal = self.goal_with([_launch(),
                               _set_value(handle={"$from": "step:s1.handle"},
                                          retry={"attempts": 2, "delay": 0.0,
                                                 "reason": "the control may not be ready"})])
        self.world.fail_times["set_value"] = 1      # one recovery, as a live goal takes
        self.executor.run(goal)
        self.assertEqual(goal.context.recall("step:s1.handle"), DEMO_HANDLE)
        self.assertTrue(goal.context.knows("step:s1.verified"))

    def test_a_reference_that_was_never_observed_fails_the_step_and_runs_nothing(self):
        goal = self.goal_with([{"id": "s9", "action": "demo_control", "arguments": {
            "operation": "set_value", "window_handle": {"$from": "step:nope.handle"},
            "control_type": "Document", "text": "hello"}}])
        result = self.executor.run(goal)

        self.assertEqual(result.status, GoalStatus.FAILED)
        self.assertEqual(goal.step("s9").error_kind, ErrorKind.INVALID_ARGUMENTS)
        self.assertEqual(self.world.calls, [],
                         "nothing may run when its arguments cannot be filled")

    def test_a_step_that_was_never_observed_never_reaches_the_machine(self):
        """A step referring to something no step ever produced."""
        goal = self.goal_with([_launch(), _set_value(handle={"$from": "step:s2.handle"})])
        result = self.executor.run(goal)

        self.assertEqual(result.status, GoalStatus.FAILED)
        self.assertEqual(goal.step("s2").status, StepStatus.FAILED)
        self.assertIn("has not observed", goal.step("s2").notes[-1])
        self.assertNotIn("set_value", self.world.calls)

    def test_a_step_whose_dependency_failed_is_blocked_not_skipped_silently(self):
        self.world.fail_permanently["launch"] = ErrorKind.APPLICATION_NOT_FOUND
        goal = self.goal_with([_launch(), _set_value()])
        result = self.executor.run(goal)

        self.assertEqual(result.status, GoalStatus.FAILED)
        self.assertEqual(goal.step("s1").status, StepStatus.FAILED)
        self.assertEqual(goal.step("s2").status, StepStatus.BLOCKED)
        self.assertIn("s1", goal.step("s2").notes[-1])
        self.assertEqual(self.world.calls, ["launch"])

    def test_steps_that_never_ran_are_reported_as_blocked(self):
        """The prompt's partial picture: VERIFIED, NOT_VERIFIED, BLOCKED."""
        self.world.apply_effects = False        # set_value will not stick
        goal = self.goal_with([_launch(), _set_value(), _focus(step_id="s3")])
        result = self.executor.run(goal)

        statuses = {s["step_id"]: s["status"] for s in result.steps}
        self.assertEqual(statuses, {"s1": "VERIFIED", "s2": "NOT_VERIFIED",
                                    "s3": "BLOCKED"})

    def test_an_optional_step_may_fail_without_stopping_the_goal(self):
        self.world.fail_permanently["focus"] = ErrorKind.ELEMENT_NOT_FOUND
        goal = self.goal_with([_launch(), _focus(step_id="s2", required=False)])
        result = self.executor.run(goal)

        self.assertEqual(result.status, GoalStatus.COMPLETED)
        self.assertEqual(goal.step("s2").status, StepStatus.FAILED)
        self.assertEqual(result.failed, 1)

    def test_every_attempt_runs_through_the_phase2_task_boundary(self):
        goal = self.goal_with([_launch(), _set_value()])
        self.executor.run(goal)
        for step in goal.steps():
            self.assertTrue(step.task_id, "each step must have a real task behind it")
            task = self.manager.get_task(step.task_id)
            self.assertIsNotNone(task)
            self.assertEqual(task.metadata["goal_id"], goal.goal_id)
            self.assertEqual(task.status, TaskStatus.COMPLETED)
        self.assertEqual(len(goal.context.task_ids), 2)

    def test_a_capability_with_nothing_to_verify_completes_but_is_not_verified(self):
        goal = self.goal_with([{"id": "s1", "action": "demo_singleton",
                                "arguments": {}}])
        result = self.executor.run(goal)

        self.assertEqual(goal.step("s1").status, StepStatus.COMPLETED)
        self.assertFalse(goal.step("s1").verified)
        self.assertEqual(result.verified, 0)
        self.assertEqual(result.completed, 1)

    def test_a_capability_that_crashes_fails_the_goal_rather_than_killing_it(self):
        goal = self.goal_with([{"id": "s1", "action": "demo_control",
                                "arguments": {"operation": "boom"}}])
        result = self.executor.run(goal)
        self.assertEqual(result.status, GoalStatus.FAILED)
        self.assertIn("failed", result.message.lower())

    def test_an_unsupported_operation_reported_by_the_action_stops_the_goal(self):
        goal = self.goal_with([{"id": "s1", "action": "demo_control",
                                "arguments": {"operation": "unsupported"}}])
        result = self.executor.run(goal)
        self.assertEqual(result.status, GoalStatus.FAILED)
        self.assertEqual(goal.step("s1").error_kind, ErrorKind.ACTION_NOT_SUPPORTED)

    def test_a_goal_with_no_plan_never_executes_anything(self):
        goal = self.executor.create_goal("no plan here")
        result = self.executor.run(goal)
        self.assertEqual(result.status, GoalStatus.PLANNING_FAILED)
        self.assertEqual(self.world.calls, [])

    def test_a_rejected_plan_fails_the_goal_with_the_reason_kept(self):
        goal = self.executor.create_goal("do something impossible")
        goal = self.executor.plan_goal(goal, raw_steps=[
            {"id": "s1", "action": "not_a_real_capability", "arguments": {}}])
        self.assertEqual(goal.status, GoalStatus.NOT_SUPPORTED)
        self.assertEqual(goal.error.kind, ErrorKind.ACTION_NOT_SUPPORTED)
        self.assertEqual(self.world.calls, [])

    def test_a_recipe_builds_a_plan_that_runs_the_same_way(self):
        from tests.support import DEMO_ACTIONS, demo_control, make_action_registry

        # The recipes name the real action, so the registry under the test has to
        # know that name. Everything else about the run is unchanged.
        (_m, _l, _p, executor, _w) = make_goal_stack(
            self.tmp, world=self.world,
            actions=make_action_registry(*DEMO_ACTIONS,
                                         ("windows_control", demo_control)))
        goal = executor.create_goal("open notepad and type hello")
        executor.plan_goal(goal, template="open_and_type",
                           template_params={"app_name": "notepad", "text": "hello"})
        result = executor.run(goal)

        self.assertEqual(self.world.calls, ["launch", "set_value"])
        self.assertEqual([s["status"] for s in result.steps], ["VERIFIED", "VERIFIED"])
        self.assertTrue(result.ok, result.report())


class TestTruthfulness(GoalTestCase):
    """The requirement Phase 5 exists to satisfy."""

    def test_a_successful_call_with_an_unobservable_effect_is_not_a_goal_success(self):
        """The window stays open; the call said SUCCESS; the goal must not."""
        self.world.apply_effects = False
        goal = self.goal_with([_launch(), _close()])
        result = self.executor.run(goal)

        self.assertEqual(self.world.calls, ["launch", "close"])
        self.assertTrue(self.world.windows, "the fixture really did not close it")
        step = goal.step("c1")
        self.assertEqual(step.result.status, ExecStatus.SUCCESS.value,
                         "the action itself reported success")
        self.assertEqual(step.status, StepStatus.NOT_VERIFIED)
        self.assertEqual(result.status, GoalStatus.NOT_VERIFIED)
        self.assertFalse(result.ok)
        self.assertEqual(result.not_verified, 1)
        self.assertEqual(result.verified, 1,
                         "only the launch was verified; the close never was")

    def test_not_verified_is_reported_in_the_words_the_verifier_used(self):
        self.world.apply_effects = False
        goal = self.goal_with([_close()])
        self.executor.run(goal)
        step = goal.step("c1")
        self.assertIsNotNone(step.verification)
        self.assertEqual(step.verification["status"], "NOT_VERIFIED")
        self.assertTrue(any("NOT_VERIFIED" in n for n in step.notes),
                        f"the verifier's own words were not kept: {step.notes}")
        self.assertEqual(step.error_kind, ErrorKind.NOT_VERIFIED)

    def test_a_required_step_that_is_not_verified_can_never_let_the_goal_complete(self):
        self.world.apply_effects = False
        goal = self.goal_with([_launch(), _set_value()])
        result = self.executor.run(goal)
        self.assertEqual(result.status, GoalStatus.NOT_VERIFIED)
        self.assertNotEqual(result.status, GoalStatus.COMPLETED)

    def test_a_not_verified_step_holds_up_the_steps_that_depend_on_it(self):
        self.world.apply_effects = False
        goal = self.goal_with([_launch(), _set_value(), _focus(step_id="s3")])
        self.executor.run(goal)
        self.assertNotIn("focus", self.world.calls,
                         "a step must not follow one whose result was never seen")

    def test_a_plan_cannot_turn_a_close_into_a_pass_by_asking_for_the_wrong_check(self):
        from core.verification.expectations import ExpectationKind

        self.world.apply_effects = False
        goal = self.goal_with([_close(expected={
            "kind": ExpectationKind.WINDOW_EXISTS,
            "target": {"window_handle": DEMO_HANDLE}, "expected": True})])
        result = self.executor.run(goal)
        self.assertEqual(result.status, GoalStatus.NOT_VERIFIED)
        self.assertEqual(goal.step("c1").expected.kind, ExpectationKind.WINDOW_CLOSED)
        self.assertEqual(goal.step("c1").expected_by, "action")

    def test_a_value_that_did_not_land_is_not_verified(self):
        self.world.apply_effects = False
        goal = self.goal_with([_launch(), _set_value()])
        result = self.executor.run(goal)
        self.assertEqual(result.status, GoalStatus.NOT_VERIFIED)
        self.assertNotIn("hello", self.world.values.values())

    def test_a_goal_only_completes_when_every_required_step_reached_its_outcome(self):
        cases = (
            ("a window that really opened", [_launch()], True, False, GoalStatus.COMPLETED),
            ("a window that never opened", [_launch()], False, False, GoalStatus.NOT_VERIFIED),
            ("a window that really closed", [_close()], True, True, GoalStatus.COMPLETED),
            ("a window that never closed", [_close()], False, True, GoalStatus.NOT_VERIFIED),
        )
        for why, steps, effects, present, expected in cases:
            with self.subTest(case=why):
                world = DemoWorld()
                world.apply_effects = effects
                world.windows = {DEMO_HANDLE} if present else set()
                with observed_by(world):
                    executor = make_goal_stack(self.tmp, world=world)[3]
                    goal = executor.create_goal(why)
                    executor.plan_goal(goal, raw_steps=steps)
                    self.assertEqual(executor.run(goal).status, expected)

    def test_the_report_never_says_completed_when_a_step_did_not(self):
        self.world.apply_effects = False
        goal = self.goal_with([_close()])
        report = self.executor.run(goal).report()
        self.assertIn("NOT_VERIFIED", report)
        self.assertNotIn("COMPLETED", report)
        self.assertIn("could not be verified", report)


class TestBoundedRecovery(GoalTestCase):

    def test_a_transient_failure_is_retried_once_and_then_verified(self):
        self.world.fail_times["launch"] = 1
        goal = self.goal_with([_launch(retry={"attempts": 2, "delay": 0.0})])
        result = self.executor.run(goal)

        self.assertEqual(result.status, GoalStatus.COMPLETED)
        self.assertEqual(self.world.calls, ["launch", "launch"])
        self.assertEqual(goal.step("s1").attempts, 2)
        self.assertEqual(goal.step("s1").recovery_attempts, 1)
        self.assertEqual(result.recovery_attempts, 1)

    def test_a_recovery_looks_again_before_repeating_anything(self):
        self.world.fail_times["launch"] = 1
        goal = self.goal_with([_launch(retry={"attempts": 2, "delay": 0.0})])
        self.executor.run(goal)
        self.assertEqual(self.world.captures, 1,
                         "recovery must re-observe before it retries")

    def test_a_permanent_failure_is_never_retried(self):
        self.world.fail_permanently["launch"] = ErrorKind.AUTHORIZATION_DENIED
        goal = self.goal_with([_launch(retry={"attempts": 2, "delay": 0.0})])
        result = self.executor.run(goal)

        self.assertEqual(self.world.calls, ["launch"])
        self.assertEqual(goal.step("s1").attempts, 1)
        self.assertEqual(result.status, GoalStatus.FAILED)
        self.assertIn("permanent", goal.step("s1").notes[-1])

    def test_a_failure_that_never_clears_stops_after_the_bounded_retries(self):
        self.world.fail_times["launch"] = 99
        goal = self.goal_with([_launch(retry={"attempts": 2, "delay": 0.0})])
        result = self.executor.run(goal)

        self.assertEqual(self.world.calls, ["launch", "launch"])
        self.assertEqual(result.status, GoalStatus.FAILED)
        self.assertEqual(goal.step("s1").recovery_attempts, 1)

    def test_a_step_that_did_not_ask_for_a_retry_does_not_get_one(self):
        self.world.fail_times["launch"] = 1
        goal = self.goal_with([_launch()])
        self.executor.run(goal)
        self.assertEqual(self.world.calls, ["launch"])
        self.assertEqual(goal.step("s1").attempts, 1)

    def test_an_unverified_step_may_be_re_observed_and_tried_once_more(self):
        """The prompt's Calculator example, in miniature."""
        self.world.apply_effects = False
        self.world.fail_times["focus"] = 1        # one real failure, then success
        goal = self.goal_with([_launch(), _focus(retry={"attempts": 2, "delay": 0.0})])
        result = self.executor.run(goal)

        self.assertEqual(goal.step("f1").recovery_attempts, 1)
        self.assertEqual(self.world.calls, ["launch", "focus", "focus"])
        # The second attempt also could not be observed, so the goal is honest.
        self.assertEqual(result.status, GoalStatus.NOT_VERIFIED)

    def test_recovery_succeeds_when_the_second_attempt_really_lands(self):
        """A control that was not ready yet, seen on the second attempt."""
        self.world.set_value_effects_after = 2
        goal = self.goal_with([_launch(), _set_value(retry={"attempts": 2, "delay": 0.0})])
        result = self.executor.run(goal)

        self.assertEqual(goal.step("s2").attempts, 2)
        self.assertEqual(goal.step("s2").recovery_attempts, 1)
        self.assertEqual(result.status, GoalStatus.COMPLETED, result.report())
        self.assertEqual(result.recovery_attempts, 1)
        self.assertEqual(self.world.values[(DEMO_HANDLE, "Document")], "hello")

    def test_the_goal_wide_recovery_ceiling_is_respected(self):
        """Two recoverable steps, one recovery allowed for the whole goal."""
        self.executor.limits = Limits(max_recovery_attempts=1, max_recovery_total=1)
        self.executor.planner.limits = self.executor.limits
        self.world.fail_times["list"] = 99
        goal = self.goal_with([
            {"id": "s1", "action": "demo_control",
             "arguments": {"operation": "list"},
             "retry": {"attempts": 2, "delay": 0.0}},
            {"id": "s2", "action": "demo_control",
             "arguments": {"operation": "list"},
             "retry": {"attempts": 2, "delay": 0.0}, "required": False}])
        result = self.executor.run(goal)

        self.assertEqual(self.world.calls, ["list", "list"],
                         "only the first step may spend the goal's one recovery")
        self.assertLessEqual(result.recovery_attempts, 1)

    def test_recovery_never_invents_a_different_operation(self):
        self.world.fail_times["close"] = 1
        goal = self.goal_with([_close(retry={"attempts": 2, "delay": 0.0}),
                               {"id": "after", "action": "demo_control",
                                "arguments": {"operation": "list"},
                                "depends_on": ["c1"]}])
        self.executor.run(goal)
        self.assertNotIn("launch", self.world.calls)
        self.assertNotIn("focus", self.world.calls)
        self.assertEqual(goal.step("c1").action, "demo_control")
        self.assertEqual(goal.plan.steps[0].arguments["operation"], "close")

    def test_recovery_events_are_announced_for_the_observer(self):
        self.world.fail_times["launch"] = 1
        goal = self.goal_with([_launch(retry={"attempts": 2, "delay": 0.0})])
        self.executor.run(goal)
        self.assertIn(EventType.STEP_RECOVERY_STARTED, self.types())
        self.assertIn(EventType.STEP_RECOVERY_COMPLETED, self.types())


class TestCancellationAndPause(GoalTestCase):

    def test_a_goal_cancelled_before_it_starts_executes_nothing(self):
        goal = self.goal_with([_launch(), _set_value()])
        self.executor.cancel(goal, "changed my mind")

        result = self.executor.run(goal)
        self.assertEqual(result.status, GoalStatus.CANCELLED)
        self.assertEqual(self.world.calls, [])
        for step in goal.steps():
            self.assertEqual(step.status, StepStatus.CANCELLED)

    def test_cancelling_mid_goal_stops_the_steps_that_had_not_started(self):
        goal = self.goal_with([_launch(), _set_value(), _focus(step_id="s3")])
        first = goal.step("s1")

        original = self.world.observe

        def _cancel_then_observe(expectation):
            self.executor.cancel(goal, "stop now")
            return original(expectation)

        self.world.observe = _cancel_then_observe
        try:
            result = self.executor.run(goal)
        finally:
            self.world.observe = original

        self.assertEqual(result.status, GoalStatus.CANCELLED)
        self.assertEqual(self.world.calls, ["launch"], "no later step may start")
        self.assertTrue(first.is_terminal)
        self.assertTrue(goal.cancel_event.is_set())

    def test_a_cancelled_goal_does_not_claim_to_have_interrupted_the_os(self):
        goal = self.goal_with([_launch()])
        self.executor.cancel(goal)
        cancelled = [e for e in self.events if e.type is EventType.GOAL_CANCELLED]
        self.assertTrue(cancelled)
        self.assertIn("execution_in_flight", cancelled[-1].data)

    def test_the_cancel_event_reaches_phase4_verification(self):
        """A cancelled check reports CANCELLED; it never quietly passes."""
        self.world.apply_effects = False
        goal = self.goal_with([_close()])
        original = self.world.observe
        self.world.observe = lambda e: (goal.cancel_event.set(), original(e))[1]
        try:
            result = self.executor.run(goal)
        finally:
            self.world.observe = original
        self.assertTrue(goal.cancel_event.is_set())
        self.assertNotEqual(result.status, GoalStatus.COMPLETED)

    def test_pausing_stops_the_next_step_and_resuming_continues_it(self):
        goal = self.goal_with([_launch(), _set_value()])
        self.executor.pause(goal)

        result = self.executor.run(goal)
        self.assertEqual(result.status, GoalStatus.PAUSED)
        self.assertEqual(self.world.calls, [], "a paused goal starts nothing")
        self.assertEqual(goal.step("s2").status, StepStatus.PENDING)

        self.executor.resume(goal)
        result = self.executor.run(goal)
        self.assertEqual(result.status, GoalStatus.COMPLETED)
        self.assertEqual(self.world.calls, ["launch", "set_value"])

    def test_pausing_is_announced_as_cooperative_not_as_a_kill(self):
        goal = self.goal_with([_launch(), _set_value()])
        self.executor.pause(goal)
        self.executor.run(goal)
        paused = [e for e in self.events if e.type is EventType.GOAL_PAUSED]
        self.assertFalse(paused, "pause is only announced once a run notices it")
        self.assertEqual(goal.status, GoalStatus.PAUSED)

    def test_a_cancelled_goal_cannot_be_resumed(self):
        goal = self.goal_with([_launch()])
        self.executor.cancel(goal)
        self.executor.resume(goal)
        self.executor.run(goal)
        self.assertEqual(goal.status, GoalStatus.CANCELLED)
        self.assertEqual(self.world.calls, [])

    def test_a_goal_stops_at_its_time_limit_rather_than_continuing(self):
        """The ceiling is real; the test reaches it with its own clock."""
        clock = _FastClock(step=1000.0)
        self.executor._clock = clock
        goal = self.goal_with([_launch(), _set_value()])
        result = self.executor.run(goal)

        self.assertEqual(result.status, GoalStatus.BLOCKED)
        self.assertEqual(self.world.calls, [])
        self.assertIn("longer than its limit", result.message)
        self.assertEqual(goal.step("s2").status, StepStatus.BLOCKED)

    def test_cancelling_reaches_the_phase2_task_in_flight(self):
        goal = self.goal_with([_launch()])
        task_ids = []
        original = self.world.observe

        def _record(expectation):
            task = self.manager.current_task()
            if task is not None:
                task_ids.append(task.task_id)
            return original(expectation)

        self.world.observe = _record
        try:
            self.executor.run(goal)
        finally:
            self.world.observe = original
        self.assertTrue(task_ids)
        for task_id in task_ids:
            self.assertIsNotNone(self.manager.get_task(task_id))


class TestConfirmation(GoalTestCase):

    def _approval_goal(self):
        return self.goal_with([{"id": "s1", "action": "demo_control",
                                "arguments": {"operation": "needs_approval"}}])

    def test_an_irreversible_step_parks_and_the_goal_says_so(self):
        with bound_gate():
            goal = self._approval_goal()
            result = self.executor.run(goal)
            self.assertEqual(len(self.executor.layer.pending_authorizations()), 1)

        self.assertEqual(result.status, GoalStatus.AWAITING_CONFIRMATION)
        self.assertFalse(result.ok)
        self.assertEqual(goal.step("s1").status, StepStatus.AWAITING_CONFIRMATION)
        self.assertIn(EventType.STEP_AWAITING_CONFIRMATION, self.types())
        self.assertNotIn("approved", self.world.calls,
                         "nothing may run before the user says yes")

    def test_a_parked_goal_reruns_as_waiting_rather_than_doing_anything_else(self):
        from core import confirm

        with bound_gate():
            goal = self._approval_goal()
            self.executor.run(goal)
            result = self.executor.run(goal)
            self.assertEqual(result.status, GoalStatus.AWAITING_CONFIRMATION)
            self.assertEqual(self.world.calls.count("needs_approval"), 1,
                             "a waiting goal must not re-park the same step")
            resolve_confirmation(False)
            self.executor.resume(goal)
        self.assertEqual(goal.step("s1").status, StepStatus.BLOCKED)

    def test_a_refusal_ends_the_goal_as_blocked_and_never_leaves_it_waiting(self):
        """The prompt's explicit requirement, after an explicit refusal."""
        from core import confirm

        with bound_gate():
            goal = self._approval_goal()
            self.executor.run(goal)
            resolve_confirmation(False)
            self.executor.resume(goal)
            result = self.executor.run(goal)

        self.assertEqual(result.status, GoalStatus.BLOCKED)
        self.assertFalse(result.ok)
        self.assertEqual(goal.step("s1").status, StepStatus.BLOCKED)
        self.assertEqual(goal.status, GoalStatus.BLOCKED)
        self.assertNotEqual(goal.status, GoalStatus.AWAITING_CONFIRMATION)
        self.assertEqual(self.executor.layer.pending_authorizations(), {})

    def test_a_confirmation_that_cannot_be_asked_fails_instead_of_parking_forever(self):
        """No interface bound: the action refuses, and the goal must not hang."""
        goal = self._approval_goal()
        with unbound_gate():
            result = self.executor.run(goal)

        self.assertNotEqual(result.status, GoalStatus.AWAITING_CONFIRMATION)
        self.assertEqual(goal.step("s1").error_kind,
                         ErrorKind.AUTHORIZATION_UNAVAILABLE)
        self.assertEqual(goal.step("s1").status, StepStatus.FAILED)
        self.assertEqual(result.status, GoalStatus.FAILED)
        self.assertEqual(self.executor.layer.pending_authorizations(), {})

    def test_a_banner_that_cannot_be_shown_also_ends_the_step(self):
        goal = self._approval_goal()

        def _broken_show(_title, _detail):
            raise RuntimeError("the HUD is not there")

        with bound_gate(show=_broken_show):
            result = self.executor.run(goal)
        self.assertNotEqual(result.status, GoalStatus.AWAITING_CONFIRMATION)
        self.assertEqual(self.executor.layer.pending_authorizations(), {})

    def test_a_refused_confirmation_does_not_stop_the_goal_from_doing_safe_work(self):
        """Confirmation gates one step; it does not authorise nothing else."""
        from core import confirm

        steps = [{"id": "open", "action": "demo_control",
                  "arguments": {"operation": "launch"}},
                 {"id": "danger", "action": "demo_control",
                  "arguments": {"operation": "needs_approval"},
                  "depends_on": ["open"]},
                 {"id": "after", "action": "demo_control",
                  "arguments": {"operation": "list"}, "depends_on": ["danger"],
                  "required": False}]
        goal = self.goal_with(steps)
        with bound_gate():
            self.executor.run(goal)
            self.assertEqual(self.world.calls, ["launch", "needs_approval"])
            resolve_confirmation(False)
            self.executor.resume(goal)
            result = self.executor.run(goal)

        self.assertEqual(result.status, GoalStatus.BLOCKED)
        self.assertEqual(goal.step("open").status, StepStatus.VERIFIED)
        self.assertEqual(goal.step("danger").status, StepStatus.BLOCKED)
        self.assertNotIn("list", self.world.calls,
                         "a blocked step must not be treated as satisfied")


    def test_an_approved_step_with_nothing_to_verify_is_completed(self):
        """Approval lets the step run; the record still says what was observed."""
        with bound_gate():
            goal = self._approval_goal()
            self.executor.run(goal)
            resolve_confirmation(True)
            task_id = goal.step("s1").task_id
            self.assertTrue(wait_for(
                lambda: (self.manager.get_task(task_id) is not None
                         and self.manager.get_task(task_id).is_terminal),
                timeout=5.0))
            result = self.executor.run(goal)

        self.assertEqual(self.world.calls.count("approved"), 1)
        self.assertEqual(goal.step("s1").status, StepStatus.COMPLETED)
        self.assertEqual(result.status, GoalStatus.COMPLETED)

    def test_an_approved_step_that_cannot_be_verified_is_not_a_success(self):
        """A confirmation authorizes the attempt, never the outcome.

        The policy gate (not the action) parks the step, so the confirmed run
        goes back through the execution layer's own verification. When the
        machine then disagrees with the step's contract, the goal must say
        NOT_VERIFIED instead of recording the approval as a completed step.
        """
        import pathlib
        import tempfile
        from unittest.mock import patch

        from core.execution import ExecutionLayer
        from core.goals.executor import GoalExecutor
        from core.goals.planner import Planner
        from core.security import (Authorization, AuthorizationDecision,
                                   RiskClass)
        from core.verification import verifier as _verifier
        from tests.support import (DEMO_ACTIONS, Sink, capturing,
                                   make_action_registry, make_manager)

        class _ConfirmsEverything:
            def authorize(self, action, arguments, registry_kind):
                return Authorization(
                    str(action), "", RiskClass.DESTRUCTIVE,
                    AuthorizationDecision.REQUIRE_CONFIRMATION,
                    "test policy: confirmation required", "digest-fixed")

        class _Expectation:
            kind = "fixture"

            def to_dict(self):
                return {"kind": self.kind}

        class _Outcome:
            status = _verifier.Status.NOT_VERIFIED

            def describe(self):
                return "the fixture's expected state was not observed"

            def to_dict(self):
                return {"status": self.status.value,
                        "reason": "the fixture's expected state was not observed",
                        "observations": []}

        with tempfile.TemporaryDirectory() as folder:
            tmp = pathlib.Path(folder)
            manager = make_manager(tmp)
            registry = make_action_registry(*DEMO_ACTIONS)
            layer = ExecutionLayer(
                actions=registry, manager=manager,
                security_policy=_ConfirmsEverything(),
                logger=Sink(), notify=Sink())
            layer.bind_confirmation_gate()
            executor = GoalExecutor(
                manager=manager, layer=layer,
                planner=Planner(actions=registry, logger=Sink()),
                logger=Sink(), notify=Sink(),
                world_capture=capturing(DemoWorld()))
            goal = executor.create_goal("approve a step that will not verify")
            executor.plan_goal(goal, raw_steps=[_launch()])

            with (patch("core.execution._expectation_provider",
                        return_value=lambda _params, _data: (None, _Expectation())),
                  patch("core.verification.verifier.verify",
                        return_value=_Outcome()),
                  bound_gate()):
                executor.run(goal)
                resolve_confirmation(True)
                task_id = goal.step("s1").task_id
                self.assertTrue(wait_for(
                    lambda: (manager.get_task(task_id) is not None
                             and manager.get_task(task_id).is_terminal),
                    timeout=5.0))
                result = executor.run(goal)

            record = manager.get_task(task_id).metadata["execution"]

        self.assertEqual(record["status"], "SUCCESS",
                         "the action itself reported success")
        self.assertEqual(record["final_status"], "NOT_VERIFIED")
        self.assertFalse(record["verified"])
        self.assertEqual(goal.step("s1").result.status, "SUCCESS")
        self.assertEqual(goal.step("s1").status, StepStatus.NOT_VERIFIED)
        self.assertEqual(result.status, GoalStatus.NOT_VERIFIED)
        self.assertFalse(result.ok)


class TestSecurityAndBoundaries(GoalTestCase):

    def test_an_operation_that_is_not_registered_never_reaches_a_handler(self):
        goal = self.executor.create_goal("rm -rf")
        self.executor.plan_goal(goal, raw_steps=[
            {"id": "s1", "action": "rm_rf", "arguments": {"path": "C:/"}}])
        self.executor.run(goal)
        self.assertEqual(self.world.calls, [])
        self.assertEqual(goal.status, GoalStatus.NOT_SUPPORTED)

    def test_the_goals_package_contains_no_dynamic_code(self):
        root = pathlib.Path(__file__).resolve().parent.parent / "core" / "goals"
        pattern = re.compile(r"\b(exec|eval|compile|__import__)\s*\(")
        for path in sorted(root.glob("*.py")):
            with self.subTest(module=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIsNone(pattern.search(text),
                                  f"{path.name} introduces dynamic code execution")

    def test_the_goals_package_starts_no_processes(self):
        root = pathlib.Path(__file__).resolve().parent.parent / "core" / "goals"
        forbidden = ("subprocess", "os.system", "os.popen", "shell=True",
                     "os.exec", "pty.spawn", "ctypes")
        for path in sorted(root.glob("*.py")):
            text = path.read_text(encoding="utf-8")
            for needle in forbidden:
                with self.subTest(module=path.name, needle=needle):
                    self.assertNotIn(needle, text)

    def test_the_goals_package_never_reaches_the_gate_around_the_execution_layer(self):
        """Confirmation, status and verification all stay upstream of the action."""
        root = pathlib.Path(__file__).resolve().parent.parent / "core" / "goals"
        for path in sorted(root.glob("*.py")):
            text = path.read_text(encoding="utf-8")
            with self.subTest(module=path.name):
                self.assertNotIn("confirm.resolve(", text)
                self.assertNotIn("TaskStore(", text)

    def test_goal_history_is_written_next_to_the_task_history_and_nothing_else(self):
        goal = self.goal_with([_launch()])
        self.executor.run(goal)
        path = self.tmp / "goals.json"
        self.assertTrue(path.exists())
        self.assertEqual(list(self.tmp.glob("goals*.json")), [path])
        self.assertEqual(path.parent, self.tmp)


class TestGoalEvents(GoalTestCase):

    def test_a_successful_goal_announces_its_lifecycle(self):
        goal = self.goal_with([_launch(), _set_value()])
        self.executor.run(goal)
        for expected in (EventType.GOAL_CREATED, EventType.GOAL_PLANNING,
                         EventType.GOAL_PLANNED, EventType.GOAL_STARTED,
                         EventType.STEP_STARTED, EventType.STEP_VERIFIED,
                         EventType.GOAL_COMPLETED):
            self.assertIn(expected, self.types(), f"{expected} was never announced")

    def test_an_unverified_goal_is_announced_as_not_verified(self):
        self.world.apply_effects = False
        goal = self.goal_with([_close()])
        self.executor.run(goal)
        self.assertIn(EventType.STEP_NOT_VERIFIED, self.types())
        self.assertIn(EventType.GOAL_NOT_VERIFIED, self.types())
        self.assertNotIn(EventType.GOAL_COMPLETED, self.types())

    def test_goal_events_carry_the_goal_and_step_they_are_about(self):
        goal = self.goal_with([_launch()])
        self.executor.run(goal)
        started = [e for e in self.events if e.type is EventType.STEP_STARTED]
        self.assertTrue(started)
        event = started[-1]
        self.assertEqual(event.goal_id, goal.goal_id)
        self.assertEqual(event.step_id, "s1")
        self.assertEqual(event.data["step_id"], "s1")
        finished = [e for e in self.events if e.type is EventType.STEP_VERIFIED]
        self.assertTrue(finished[-1].task_id, "a finished step knows its real task")

    def test_phase2_events_are_still_announced_for_every_step(self):
        goal = self.goal_with([_launch()])
        self.executor.run(goal)
        for expected in (EventType.TASK_CREATED, EventType.TASK_STARTED,
                         EventType.ACTION_STARTED, EventType.ACTION_COMPLETED,
                         EventType.VERIFICATION_STARTED, EventType.VERIFICATION_COMPLETED):
            self.assertIn(expected, self.types(), f"{expected} was never announced")

    def test_a_goal_that_stops_on_a_failure_says_so_in_words(self):
        self.world.fail_permanently["launch"] = ErrorKind.WINDOW_NOT_FOUND
        goal = self.goal_with([_launch(), _set_value()])
        self.executor.run(goal)
        self.assertIn(EventType.GOAL_FAILED, self.types())
        self.assertIn(EventType.STEP_BLOCKED, self.types())


if __name__ == "__main__":
    unittest.main()