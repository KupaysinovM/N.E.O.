"""
Phase 5, part 1 — the goal model, bounded planning, and goal history.

WHAT IS UNDER TEST
    The production classes only: `Goal`, `Plan`, `Step`, `GoalContext`,
    `GoalResult`, `Planner`, `Limits` and `GoalStore`/`GoalHistory`. No test
    here reaches Windows, and none of them substitutes the class under test.

THE QUESTIONS THESE ANSWER
    Can a goal be created, moved through its states, and refused an illegal
    move? Can a plan be built from an operation that does not exist? What
    happens when a plan is too long, self-dependent, circular, or carries
    something that is not data? And when planning is delegated to a proposer,
    does it stop — or does it ask again until something works?
"""
from __future__ import annotations

import json
import pathlib
import tempfile
import threading
import time
import unittest

from core.goals.limits import Limits
from core.goals.models import Goal, GoalResult, GoalStatus, Plan, Step, StepStatus
from core.goals.planner import EXPECTATION_KINDS, TEMPLATES, PlanRejected, Planner
from core.goals.recovery import (
    NO_RETRIES,
    PERMANENT_ERROR_KINDS,
    TRANSIENT_ERROR_KINDS,
    RetryPolicy,
    classify,
    is_recoverable,
)
from core.goals.store import GoalHistory, GoalStore, default_goals_path
from core.task_models import ErrorKind
from core.verification.expectations import ExpectationKind
from tests.support import DemoWorld, make_action_registry, tmp_dir

from tests.support import DEMO_ACTIONS


def _planner(**kwargs) -> Planner:
    registry = kwargs.pop("registry", None) or make_action_registry(*DEMO_ACTIONS)
    return Planner(actions=registry, **kwargs)


def _product_planner(**kwargs) -> Planner:
    """A registry that also holds a stand-in named windows_control.

    The recipes in core/goals/planner.py name the real action, and that is
    correct: they are for the product, not for the fixtures. This builds the
    registry they expect so a recipe can be checked without a desktop.
    """
    from tests.support import demo_control

    return Planner(actions=make_action_registry(*DEMO_ACTIONS,
                                                ("windows_control", demo_control)),
                   **kwargs)


def _launch_step(**extra) -> dict:
    arguments = {"operation": "launch"}
    arguments.update(extra.pop("arguments_extra", {}))
    return {"id": "s1", "action": "demo_control", "arguments": arguments, **extra}


class TestGoalModel(unittest.TestCase):

    def test_a_new_goal_is_pending_with_a_unique_id_and_no_plan(self):
        goal = Goal(description="Open Notepad and put hello in it")
        self.assertEqual(goal.status, GoalStatus.PENDING)
        self.assertEqual(len(goal.goal_id), 32)
        self.assertIsNone(goal.plan)
        self.assertFalse(goal.is_terminal)
        self.assertNotEqual(Goal().goal_id, Goal().goal_id)

    def test_goal_ids_are_derived_not_guessed(self):
        goal = Goal()
        self.assertEqual(goal.short_id(), goal.goal_id[:8])

    def test_terminal_statuses_are_the_ones_that_cannot_continue(self):
        terminal = {GoalStatus.COMPLETED, GoalStatus.FAILED, GoalStatus.NOT_VERIFIED,
                    GoalStatus.BLOCKED, GoalStatus.CANCELLED, GoalStatus.NOT_SUPPORTED,
                    GoalStatus.PLANNING_FAILED}
        for status in GoalStatus:
            goal = Goal(status=status)
            with self.subTest(status=status):
                self.assertEqual(goal.is_terminal, status in terminal)

    def test_step_statuses_reuse_the_vocabulary_the_other_layers_use(self):
        """A NOT_VERIFIED step is the same word the execution layer uses."""
        from core.execution import ExecStatus
        from core.task_models import TaskStatus
        from core.verification.verifier import Status

        self.assertEqual(StepStatus.NOT_VERIFIED.value, ExecStatus.NOT_VERIFIED.value)
        self.assertEqual(StepStatus.VERIFIED.value, Status.VERIFIED.value)
        self.assertEqual(StepStatus.NOT_VERIFIED.value, Status.NOT_VERIFIED.value)
        for shared in ("PENDING", "RUNNING", "FAILED", "CANCELLED"):
            with self.subTest(status=shared):
                self.assertEqual(StepStatus(shared).value, TaskStatus(shared).value)
        # AWAITING_CONFIRMATION is the goal layer's word for the same pause the
        # execution layer calls REQUIRES_CONFIRMATION; it is not a new state.
        self.assertEqual(StepStatus.AWAITING_CONFIRMATION.value,
                         "AWAITING_CONFIRMATION")
        self.assertIn(StepStatus.AWAITING_CONFIRMATION, tuple(
            s for s in StepStatus if s.value == "AWAITING_CONFIRMATION"))

    def test_a_step_that_never_ran_is_not_a_successful_step(self):
        for status in StepStatus:
            step = Step(step_id="s1", status=status)
            expected = status in (StepStatus.VERIFIED, StepStatus.COMPLETED)
            with self.subTest(status=status):
                self.assertEqual(step.succeeded, expected)
                if status is StepStatus.VERIFIED:
                    self.assertTrue(step.verified)
                else:
                    self.assertFalse(step.verified)

    def test_goal_round_trips_through_its_record(self):
        goal = Goal(description="two steps")
        goal.plan = Plan(goal_id=goal.goal_id, steps=[Step(
            step_id="s1", action="demo_control",
            arguments={"operation": "launch"},
            status=StepStatus.VERIFIED, attempts=1, required=True)])
        goal.status = GoalStatus.COMPLETED
        goal.result = GoalResult(goal_id=goal.goal_id, status=GoalStatus.COMPLETED,
                                 message="done", verified=1, step_count=1)

        again = Goal.from_dict(json.loads(json.dumps(goal.to_dict())))
        self.assertEqual(again.goal_id, goal.goal_id)
        self.assertEqual(again.status, GoalStatus.COMPLETED)
        self.assertEqual(again.plan.steps[0].status, StepStatus.VERIFIED)
        self.assertEqual(again.result.verified, 1)
        self.assertEqual(again.plan.steps[0].arguments["operation"], "launch")

    def test_a_malformed_goal_record_is_refused_rather_than_repaired(self):
        for raw, why in (({}, "no goal_id"),
                         ({"goal_id": "x", "status": "HAPPY"}, "unknown status"),
                         ("not a dict", "not an object"),
                         ({"goal_id": "x", "plan": {"steps": "nope"}}, "no step list")):
            with self.subTest(why=why):
                with self.assertRaises((ValueError, TypeError)):
                    Goal.from_dict(raw)

    def test_notes_are_bounded_so_a_step_cannot_grow_without_limit(self):
        step = Step(step_id="s1")
        for index in range(50):
            step.note(f"reason {index}", limit=4)
        self.assertEqual(len(step.notes), 4)
        self.assertEqual(step.notes[-1], "reason 49")

    def test_context_remembers_the_newest_values_and_drops_the_oldest(self):
        goal = Goal()
        goal.context.max_items = 3
        for index in range(6):
            goal.context.remember(f"k{index}", index)
        self.assertEqual(list(goal.context.entries), ["k3", "k4", "k5"])
        self.assertTrue(goal.context.knows("k5"))
        self.assertFalse(goal.context.knows("k0"))

    def test_a_result_is_only_ok_when_the_goal_completed(self):
        self.assertTrue(GoalResult(goal_id="g", status=GoalStatus.COMPLETED).ok)
        for status in GoalStatus:
            if status is GoalStatus.COMPLETED:
                continue
            with self.subTest(status=status):
                self.assertFalse(GoalResult(goal_id="g", status=status).ok)

    def test_the_goal_report_says_what_happened_to_every_step(self):
        goal = Goal(description="Open Notepad")
        goal.plan = Plan(goal_id=goal.goal_id, steps=[
            Step(step_id="s1", description="open", status=StepStatus.VERIFIED),
            Step(step_id="s2", description="type", status=StepStatus.NOT_VERIFIED),
            Step(step_id="s3", description="confirm", status=StepStatus.BLOCKED),
        ])
        report = "\n".join(s["status"] for s in goal.step_report())
        self.assertEqual(report, "VERIFIED\nNOT_VERIFIED\nBLOCKED")


class TestBounds(unittest.TestCase):

    def test_the_default_limits_are_all_positive_and_finite(self):
        limits = Limits()
        self.assertGreaterEqual(limits.max_steps, 1)
        self.assertGreaterEqual(limits.max_planning_attempts, 1)
        self.assertGreaterEqual(limits.max_step_attempts, 1)
        self.assertGreaterEqual(limits.max_goal_seconds, 1.0)
        self.assertGreaterEqual(limits.max_expectation_timeout, 0.2)

    def test_a_caller_cannot_raise_the_ceilings_by_asking(self):
        """Nonsense and greed are clamped, not honoured."""
        greedy = Limits(max_steps=10_000, max_step_attempts=99, max_goal_seconds=1e9,
                        max_recovery_total=-5, proposer_seconds=0.0).clamped()
        self.assertLessEqual(greedy.max_steps, 100)
        self.assertLessEqual(greedy.max_step_attempts, Limits().max_step_attempts)
        self.assertLessEqual(greedy.max_goal_seconds, 3600.0)
        self.assertGreaterEqual(greedy.max_recovery_total, 0)
        self.assertGreater(greedy.proposer_seconds, 0.0)

    def test_every_bound_is_reported_for_the_record(self):
        reported = Limits().to_dict()
        for key in ("max_steps", "max_planning_attempts", "max_step_attempts",
                    "max_recovery_attempts", "max_recovery_total", "max_goal_seconds"):
            self.assertIn(key, reported)


class TestRetryPolicy(unittest.TestCase):

    def test_permanent_failures_are_listed_and_never_retryable(self):
        for kind in (ErrorKind.ACTION_NOT_SUPPORTED, ErrorKind.UNKNOWN_ACTION,
                     ErrorKind.AUTHORIZATION_DENIED, ErrorKind.AUTHORIZATION_UNAVAILABLE,
                     ErrorKind.INVALID_REQUEST, ErrorKind.INVALID_ARGUMENTS,
                     ErrorKind.TASK_CANCELLED, ErrorKind.INTERRUPTED):
            with self.subTest(kind=kind):
                self.assertIn(kind, PERMANENT_ERROR_KINDS)
                self.assertFalse(is_recoverable(kind))
                allowed, why = RetryPolicy(attempts=5).allows(kind, 1)
                self.assertFalse(allowed, why)

    def test_a_permission_refusal_is_not_repeated_fifty_times(self):
        """The prompt's explicit example, as an assertion."""
        policy = RetryPolicy(attempts=100)
        allowed, why = policy.allows(ErrorKind.ACCESS_DENIED, 1)
        self.assertTrue(allowed, why)
        allowed, why = policy.allows(ErrorKind.AUTHORIZATION_DENIED, 1)
        self.assertFalse(allowed)
        self.assertIn("permanent", why)

    def test_an_unsupported_operation_is_never_retried(self):
        allowed, why = RetryPolicy(attempts=3).allows(ErrorKind.ACTION_NOT_SUPPORTED, 1)
        self.assertFalse(allowed)
        self.assertIn("permanent", why)

    def test_a_step_is_only_retried_as_many_times_as_its_policy_says(self):
        policy = RetryPolicy(attempts=2)
        self.assertTrue(policy.allows(ErrorKind.TIMEOUT, 1)[0])
        self.assertFalse(policy.allows(ErrorKind.TIMEOUT, 2)[0])

    def test_the_default_policy_is_a_single_attempt(self):
        self.assertEqual(NO_RETRIES.attempts, 1)
        self.assertFalse(NO_RETRIES.allows(ErrorKind.TIMEOUT, 1)[0])

    def test_not_verified_is_recoverable_only_as_one_bounded_extra_attempt(self):
        self.assertIn(ErrorKind.NOT_VERIFIED, TRANSIENT_ERROR_KINDS)
        self.assertTrue(is_recoverable(ErrorKind.NOT_VERIFIED))
        self.assertEqual(classify(ErrorKind.NOT_VERIFIED), "transient")
        self.assertFalse(RetryPolicy(attempts=1).allows(ErrorKind.NOT_VERIFIED, 1)[0])

    def test_an_unreadable_failure_is_not_treated_as_transient(self):
        allowed, why = RetryPolicy(attempts=3).allows(None, 1)
        self.assertFalse(allowed)
        self.assertIn("no error kind", why)
        self.assertEqual(classify(None), "unknown")

    def test_a_policy_round_trips_and_drops_kinds_it_cannot_parse(self):
        again = RetryPolicy.from_dict({"attempts": 3, "kinds": ["TIMEOUT", "NOT_A_KIND"]})
        self.assertEqual(again.attempts, 3)
        self.assertEqual(again.kinds, frozenset({ErrorKind.TIMEOUT}))
        self.assertEqual(RetryPolicy.from_dict(None).attempts, 1)
        self.assertEqual(RetryPolicy.from_dict("nonsense").attempts, 1)


class TestPlanning(unittest.TestCase):

    def test_a_valid_plan_is_built_and_ordered(self):
        plan = _planner().build("g1", [_launch_step(), {
            "id": "s2", "action": "demo_control",
            "arguments": {"operation": "focus", "window_handle": 7},
            "depends_on": ["s1"]}])
        self.assertEqual([s.step_id for s in plan.steps], ["s1", "s2"])
        self.assertEqual(plan.source, "explicit")
        self.assertEqual(plan.goal_id, "g1")

    def test_dependencies_decide_the_order_even_when_declared_out_of_order(self):
        plan = _planner().build("g1", [
            {"id": "second", "action": "demo_control",
             "arguments": {"operation": "focus"}, "depends_on": ["first"]},
            {"id": "first", "action": "demo_control",
             "arguments": {"operation": "launch"}}])
        self.assertEqual([s.step_id for s in plan.steps], ["first", "second"])

    def test_steps_that_do_not_depend_on_each_other_keep_their_order(self):
        plan = _planner().build("g1", [
            {"id": "a", "action": "demo_control", "arguments": {"operation": "list"}},
            {"id": "b", "action": "demo_singleton", "arguments": {}}])
        self.assertEqual([s.step_id for s in plan.steps], ["a", "b"])

    def test_an_operation_that_is_not_registered_is_refused(self):
        """The prompt's rule: a name that 'looks reasonable' must not run."""
        with self.assertRaises(PlanRejected) as caught:
            _planner().build("g1", [{"id": "s1", "action": "delete_everything",
                                     "arguments": {"path": "C:/"}}])
        self.assertEqual(caught.exception.kind, ErrorKind.ACTION_NOT_SUPPORTED)
        self.assertIn("delete_everything", str(caught.exception))

    def test_a_name_that_is_a_prefix_of_a_real_action_is_still_refused(self):
        with self.assertRaises(PlanRejected):
            _planner().build("g1", [{"id": "s1", "action": "demo", "arguments": {}}])

    def test_a_plan_that_is_too_long_is_refused_rather_than_truncated(self):
        steps = [{"id": f"s{i}", "action": "demo_control",
                  "arguments": {"operation": "list"}} for i in range(40)]
        with self.assertRaises(PlanRejected) as caught:
            _planner(limits=Limits(max_steps=12)).build("g1", steps)
        self.assertIn("the limit is 12", str(caught.exception))

    def test_a_plan_with_no_steps_is_refused(self):
        for empty in ([], {}, None):
            with self.subTest(raw=empty):
                with self.assertRaises(PlanRejected):
                    _planner().build("g1", empty)

    def test_duplicate_step_ids_are_refused(self):
        with self.assertRaises(PlanRejected) as caught:
            _planner().build("g1", [_launch_step(), _launch_step()])
        self.assertIn("share the id", str(caught.exception))

    def test_a_dependency_on_a_step_that_is_not_there_is_refused(self):
        with self.assertRaises(PlanRejected) as caught:
            _planner().build("g1", [_launch_step(depends_on=["ghost"])])
        self.assertIn("ghost", str(caught.exception))

    def test_a_step_that_depends_on_itself_is_refused(self):
        with self.assertRaises(PlanRejected):
            _planner().build("g1", [_launch_step(depends_on=["s1"])])

    def test_a_dependency_loop_is_refused_rather_than_broken(self):
        with self.assertRaises(PlanRejected) as caught:
            _planner().build("g1", [
                {"id": "a", "action": "demo_control", "arguments": {},
                 "depends_on": ["b"]},
                {"id": "b", "action": "demo_control", "arguments": {},
                 "depends_on": ["c"]},
                {"id": "c", "action": "demo_control", "arguments": {},
                 "depends_on": ["a"]}])
        self.assertIn("depend on each other in a loop", str(caught.exception))

    def test_arguments_that_are_not_inert_data_are_refused(self):
        """A plan carries values. It never carries something runnable."""
        for value, why in (
            (lambda: None, "a callable"),
            (print, "a builtin"),
            (object(), "a live object"),
            (threading.Lock(), "a lock"),
        ):
            with self.subTest(why=why):
                with self.assertRaises(PlanRejected) as caught:
                    _planner().build("g1", [
                        _launch_step(arguments_extra={"text": value})])
                self.assertIn("never code", str(caught.exception))

    def test_an_argument_tree_that_nests_too_deeply_is_refused(self):
        deep = {"operation": "list"}
        for _ in range(30):
            deep = {"nest": deep}
        with self.assertRaises(PlanRejected):
            _planner(limits=Limits(max_argument_depth=6)).build(
                "g1", [_launch_step(arguments_extra=deep)])

    def test_an_expectation_must_name_a_kind_the_verifier_knows(self):
        with self.assertRaises(PlanRejected) as caught:
            _planner().build("g1", [_launch_step(
                expected={"kind": "run_this_shell_command", "expected": True})])
        self.assertIn("not a verification NEO knows how to perform",
                      str(caught.exception))

    def test_every_expectation_kind_the_vocabulary_offers_is_accepted(self):
        for kind in sorted(EXPECTATION_KINDS):
            with self.subTest(kind=kind):
                plan = _planner().build("g1", [{
                    "id": "s1", "action": "demo_singleton", "arguments": {},
                    "expected": {"kind": kind, "target": {"window_handle": 1},
                                 "expected": True}}])
                self.assertEqual(plan.steps[0].expected.kind, kind)

    def test_a_plan_cannot_extend_a_verification_wait_without_bound(self):
        plan = _planner(limits=Limits(max_expectation_timeout=5.0)).build("g1", [{
            "id": "s1", "action": "demo_singleton", "arguments": {},
            "expected": {"kind": ExpectationKind.WINDOW_EXISTS,
                         "target": {"window_handle": 1}, "expected": True,
                         "timeout": 9999}}])
        self.assertLessEqual(plan.steps[0].expected.timeout, 5.0)

    def test_an_action_owns_its_verification_contract_and_a_plan_cannot_weaken_it(self):
        """close_window must still be checked as *closed*, whatever the plan says."""
        plan = _planner().build("g1", [{
            "id": "s1", "action": "demo_control",
            "arguments": {"operation": "close", "window_handle": 7},
            "expected": {"kind": ExpectationKind.WINDOW_EXISTS,
                         "target": {"window_handle": 7}, "expected": True}}])
        step = plan.steps[0]
        self.assertEqual(step.expected.kind, ExpectationKind.WINDOW_CLOSED)
        self.assertEqual(step.expected_by, "action")

    def test_a_plan_may_add_a_check_for_an_action_that_declares_none(self):
        plan = _planner().build("g1", [{
            "id": "s1", "action": "demo_singleton", "arguments": {},
            "expected": {"kind": ExpectationKind.APP_RUNNING,
                         "target": {"app_name": "notepad"}, "expected": True}}])
        self.assertEqual(plan.steps[0].expected_by, "plan")

    def test_a_step_that_declares_nothing_to_verify_says_so(self):
        plan = _planner().build("g1", [{"id": "s1", "action": "demo_singleton",
                                        "arguments": {}}])
        self.assertEqual(plan.steps[0].expected_by, "none")
        self.assertIsNone(plan.steps[0].expected)

    def test_a_plan_may_ask_for_fewer_attempts_but_not_more(self):
        plan = _planner(limits=Limits(max_step_attempts=1)).build("g1", [
            _launch_step(retry={"attempts": 9})])
        self.assertEqual(plan.steps[0].retry.attempts, 1)
        plan = _planner(limits=Limits(max_step_attempts=2)).build("g1", [
            _launch_step(retry={"attempts": 1})])
        self.assertEqual(plan.steps[0].retry.attempts, 1)

    def test_a_step_that_did_not_ask_for_a_retry_does_not_get_one(self):
        plan = _planner().build("g1", [_launch_step()])
        self.assertEqual(plan.steps[0].retry.attempts, 1)

    def test_plans_from_plugins_are_validated_the_same_way(self):
        from tests.support import make_plugin_registry

        def nothing(**_kwargs):
            return "Done."

        registry = make_plugin_registry(("demo_control", nothing))
        planner = Planner(actions=None, plugins=registry)
        self.assertIn("demo_control", planner.supported_actions())
        plan = planner.build("g1", [_launch_step()])
        self.assertEqual(len(plan), 1)
        with self.assertRaises(PlanRejected):
            planner.build("g1", [{"id": "s1", "action": "demo_singleton"}])


class TestTemplates(unittest.TestCase):

    def test_the_recipe_list_is_small_whitelisted_and_deterministic(self):
        self.assertEqual(sorted(TEMPLATES),
                         ["close_window", "open_and_focus", "open_and_type", "open_app"])

    def test_open_and_type_produces_two_dependent_steps(self):
        plan = _product_planner().build("g1", TEMPLATES["open_and_type"](
            {"app_name": "notepad", "text": "hello"}))
        self.assertEqual([s.step_id for s in plan.steps], ["open", "type"])
        self.assertEqual(plan.steps[1].depends_on, ["open"])
        self.assertEqual(plan.steps[1].action, "windows_control")
        self.assertEqual(plan.steps[1].arguments["operation"], "set_value")

    def test_a_recipe_that_is_missing_its_parameter_is_refused(self):
        with self.assertRaises(PlanRejected):
            TEMPLATES["open_and_type"]({"text": "hello"})
        with self.assertRaises(PlanRejected):
            TEMPLATES["close_window"]({})

    def test_an_unknown_recipe_name_is_not_supported(self):
        with self.assertRaises(PlanRejected) as caught:
            _planner().template("take_over_the_world", "g1", {})
        self.assertEqual(caught.exception.kind, ErrorKind.ACTION_NOT_SUPPORTED)

    def test_a_recipe_is_validated_like_any_other_plan(self):
        """The recipes go through build(); they are not a privileged path."""
        planner = _product_planner()
        plan = planner.template("open_and_focus", "g1", {"app_name": "calc"})
        self.assertEqual(plan.source, "template:open_and_focus")
        self.assertEqual(len(plan), 2)
        # And the validation is real: a fixture registry without windows_control
        # refuses the same recipe rather than trusting it.
        with self.assertRaises(PlanRejected):
            _planner().template("open_and_focus", "g1", {"app_name": "calc"})


class TestBoundedProposing(unittest.TestCase):

    def test_the_first_valid_proposal_is_used(self):
        seen = []

        def proposer(index):
            seen.append(index)
            return [_launch_step()]

        plan = _planner().propose("g1", proposer)
        self.assertEqual(seen, [0])
        self.assertEqual(plan.source, "proposal:1")

    def test_proposing_stops_after_a_bounded_number_of_attempts(self):
        """The prompt's central prohibition, as a test."""
        attempts = []

        def proposer(index):
            attempts.append(index)
            return [{"id": "s1", "action": "not_a_real_capability"}]

        with self.assertRaises(PlanRejected) as caught:
            _planner(limits=Limits(max_planning_attempts=3)).propose("g1", proposer)
        self.assertEqual(len(attempts), 3)
        self.assertIn("no usable plan after 3 attempt(s)", str(caught.exception))

    def test_a_proposer_that_crashes_is_a_logged_failure_not_a_dead_process(self):
        def proposer(index):
            raise RuntimeError("the model call failed")

        with self.assertRaises(PlanRejected) as caught:
            _planner(limits=Limits(max_planning_attempts=2)).propose("g1", proposer)
        self.assertIn("no usable plan", str(caught.exception))

    def test_a_proposer_that_hangs_is_abandoned_rather_than_waited_on(self):
        release = threading.Event()

        def proposer(index):
            release.wait(30)
            return [_launch_step()]

        started = time.monotonic()
        try:
            with self.assertRaises(PlanRejected) as caught:
                _planner(limits=Limits(max_planning_attempts=1,
                                       proposer_seconds=0.2)).propose("g1", proposer)
            self.assertLess(time.monotonic() - started, 5.0)
            self.assertIn("abandoned", str(caught.exception))
        finally:
            release.set()

    def test_a_proposer_that_returns_nothing_usable_is_refused(self):
        for junk in (None, "a sentence", 42, {"steps": []}):
            with self.subTest(junk=junk):
                with self.assertRaises(PlanRejected):
                    _planner(limits=Limits(max_planning_attempts=1)).propose(
                        "g1", lambda _index, j=junk: j)


class TestGoalHistory(unittest.TestCase):
    """Persistence is history, never resumable execution."""

    def setUp(self):
        self.tmp = tmp_dir("neo-phase5-store-")

    def _goal(self, goal_id="g1", status=GoalStatus.COMPLETED):
        goal = Goal(goal_id=goal_id, description="write a test")
        goal.status = status
        goal.plan = Plan(goal_id=goal_id, steps=[Step(
            step_id="s1", action="demo_control",
            arguments={"operation": "launch"}, status=StepStatus.VERIFIED)])
        return goal

    def test_goals_are_saved_and_read_back(self):
        store = GoalStore(path=self.tmp / "goals.json")
        self.assertEqual(store.save([self._goal()]), "")
        report = store.load()
        self.assertTrue(report.ok, report.summary())
        self.assertEqual(len(report.goals), 1)
        self.assertEqual(report.goals[0].description, "write a test")

    def test_a_first_run_with_no_file_is_not_an_error(self):
        self.assertTrue(GoalStore(path=self.tmp / "nothing.json").load().ok)

    def test_a_corrupt_file_is_kept_aside_rather_than_trusted(self):
        path = self.tmp / "goals.json"
        path.write_text("{not json at all", encoding="utf-8")
        report = GoalStore(path=path).load()
        self.assertFalse(report.ok)
        self.assertTrue(report.quarantined)
        self.assertTrue(pathlib.Path(report.quarantined).exists())
        self.assertFalse(path.exists())

    def test_an_empty_file_is_treated_as_an_unfinished_write(self):
        path = self.tmp / "goals.json"
        path.write_text("   ", encoding="utf-8")
        report = GoalStore(path=path).load()
        self.assertFalse(report.ok)
        self.assertIn("empty", report.error)

    def test_a_malformed_record_is_skipped_and_reported(self):
        path = self.tmp / "goals.json"
        path.write_text(json.dumps({"version": 1, "goals": [
            self._goal().to_dict(), {"goal_id": ""}, "rubbish"]}), encoding="utf-8")
        report = GoalStore(path=path).load()
        self.assertEqual(len(report.goals), 1)
        self.assertEqual(len(report.skipped), 2)
        self.assertFalse(report.ok)

    def test_an_unknown_schema_version_is_reported_not_interpreted(self):
        path = self.tmp / "goals.json"
        path.write_text(json.dumps({"version": 99, "goals": []}), encoding="utf-8")
        report = GoalStore(path=path).load()
        self.assertIn("schema version 99", report.error)

    def test_the_file_is_written_atomically(self):
        """A reader sees the old file or the new one, never half of either."""
        path = self.tmp / "goals.json"
        store = GoalStore(path=path)
        store.save([self._goal("g1")])
        before = path.read_text(encoding="utf-8")
        store.save([self._goal("g2")])
        self.assertNotEqual(path.read_text(encoding="utf-8"), before)
        self.assertFalse((self.tmp / "goals.json.tmp").exists())

    def test_the_number_of_records_is_bounded(self):
        store = GoalStore(path=self.tmp / "goals.json", max_goals=3)
        store.save([self._goal(f"g{i}") for i in range(20)])
        self.assertEqual(len(store.load().goals), 3)

    def test_the_newest_goals_are_the_ones_kept(self):
        store = GoalStore(path=self.tmp / "goals.json", max_goals=2)
        goals = [self._goal(name) for name in ("old", "middle", "new")]
        for index, goal in enumerate(goals):
            goal.created_at = 1000.0 + index * 1000.0
        store.save(goals)
        kept = {g.goal_id for g in store.load().goals}
        self.assertEqual(kept, {"middle", "new"})

    def test_two_goals_created_in_the_same_millisecond_keep_a_stable_order(self):
        store = GoalStore(path=self.tmp / "goals.json", max_goals=2)
        a, b = self._goal("aaa"), self._goal("bbb")
        a.created_at = b.created_at = 1000.0
        store.save([a, b])
        first = [g.goal_id for g in store.load().goals]
        store.save([b, a])
        self.assertEqual([g.goal_id for g in store.load().goals], first)

    def test_no_secret_shaped_value_is_ever_written(self):
        goal = self._goal()
        goal.metadata["api_key"] = "AIza" + "B" * 30
        goal.metadata["access_token"] = "AIza" + "C" * 30
        goal.metadata["note"] = "AIza" + "D" * 30
        goal.metadata["harmless"] = "the user asked for notepad"
        store = GoalStore(path=self.tmp / "goals.json")
        store.save([goal])
        text = (self.tmp / "goals.json").read_text(encoding="utf-8")
        self.assertNotIn("AIza", text,
                         "goal history is not where credentials belong")
        self.assertIn("harmless", text, "ordinary metadata is still recorded")
        self.assertEqual(goal.metadata["api_key"], "AIza" + "B" * 30,
                         "scrubbing happens on the way to disk, not in the running goal")

    def test_a_goal_left_open_by_a_crash_is_marked_interrupted_not_resumed(self):
        history = GoalHistory(store=GoalStore(path=self.tmp / "goals.json"))
        goal = self._goal("g1", status=GoalStatus.RUNNING)
        interrupted = history.reconcile_after_restart([goal])
        self.assertEqual(interrupted, ["g1"])
        self.assertEqual(goal.status, GoalStatus.FAILED)
        self.assertEqual(goal.error.kind, ErrorKind.INTERRUPTED)
        self.assertIn("not resumable", goal.error.message)

    def test_a_finished_goal_is_left_alone_by_reconciliation(self):
        history = GoalHistory(store=GoalStore(path=self.tmp / "goals.json"))
        done = self._goal("g1", status=GoalStatus.COMPLETED)
        self.assertEqual(history.reconcile_after_restart([done]), [])
        self.assertEqual(done.status, GoalStatus.COMPLETED)

    def test_goal_history_lives_beside_the_task_history_not_in_config(self):
        self.assertEqual(default_goals_path().name, "goals.json")
        self.assertNotIn("config", default_goals_path().parts)
        self.assertEqual(default_goals_path().parent.name, "state")

    def test_a_save_that_cannot_happen_returns_a_reason_instead_of_raising(self):
        store = GoalStore(path=pathlib.Path(tempfile.gettempdir()) / "neo-nope-dir" / "g.json")
        # A directory where the file should be makes the write fail honestly.
        blocked = self.tmp / "blocked.json"
        blocked.mkdir()
        store = GoalStore(path=blocked)
        self.assertNotEqual(store.save([self._goal()]), "")


if __name__ == "__main__":
    unittest.main()