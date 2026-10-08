"""
Phase 6 — bounded adaptive replanning.

The failure mode this file exists to rule out is an assistant that talks itself
into trying the same thing forever. So the tests below are mostly about the
*bounds*: how many replans, how many per step, how many steps in total, what
happens when the replanner says nothing, and what happens when it says
something unsupported.

They are also about the truthfulness of the result. A step that failed and was
replaced is not a step that succeeded, and the goal's own verdict has to be
readable without knowing any of this code.
"""
from __future__ import annotations

import shutil
import threading
import unittest

from core.events import EventType
from core.goals.limits import Limits
from core.goals.models import GoalStatus, StepStatus
from core.planning import model_planner
from tests import support


def plan(*operations, action: str = "demo_control") -> list:
    """Raw steps for the demo capability, one per operation.

    A local helper rather than `tests.support.demo_plan`, which predates the
    `{action, arguments}` step shape these tests need.
    """
    steps = []
    previous = None
    for index, entry in enumerate(operations):
        name, extra = (entry if isinstance(entry, tuple) else (entry, {}))
        step = {"id": f"s{index + 1}", "action": action,
                "arguments": {"operation": name, **dict(extra)}}
        if previous:
            step["depends_on"] = [previous]
        previous = step["id"]
        steps.append(step)
    return steps


class ReplanningIsBounded(unittest.TestCase):
    """Part 3. Every ceiling, exercised from the outside."""

    def setUp(self):
        self.tmp = support.tmp_dir("neo-phase6-replan-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        # The one substitution the suite makes: the OS read. Everything above
        # it — execution, verification, recovery, replanning — is production.
        self._world_ctx = support.reset_demo_world()
        self.world = self._world_ctx.__enter__()
        self.addCleanup(self._world_ctx.__exit__, None, None, None)
        self.observed = support.observed_by(self.world)
        self.observed.__enter__()
        self.addCleanup(self.observed.__exit__, None, None, None)

    def _stack(self, replanner, limits=None):
        manager, layer, planner, executor, world = support.make_goal_stack(
            self.tmp, world=self.world, limits=limits or Limits(),
            actions=support.make_action_registry(*support.PLANNING_ACTIONS),
            replanner=replanner)
        return manager, layer, planner, executor, world

    def _goal(self, executor, plan_steps):
        goal = executor.create_goal("adaptive test")
        executor.plan_goal(goal, raw_steps=plan_steps)
        return goal

    # -- nothing to recover ------------------------------------------------

    def test_no_replanner_means_the_goal_just_stops(self):
        _, _, _, executor, world = self._stack(None)
        world.fail_permanently["focus"] = support.ErrorKind.ACCESS_DENIED
        goal = self._goal(executor, plan(("launch", {}),
                                                      ("focus", {})))
        result = executor.run(goal)
        self.assertIs(result.status, GoalStatus.FAILED)
        self.assertEqual(result.replans, 0)

    def test_a_replanner_that_proposes_nothing_stops_the_goal_with_a_reason(self):
        asked = []

        def replanner(goal, step, view):
            asked.append(step.step_id)
            return None

        _, _, _, executor, world = self._stack(replanner)
        world.fail_permanently["focus"] = support.ErrorKind.ACCESS_DENIED
        goal = self._goal(executor, plan(("launch", {}),
                                                      ("focus", {})))
        result = executor.run(goal)
        self.assertIs(result.status, GoalStatus.FAILED)
        self.assertEqual(asked, ["s2"])
        refusals = [r for r in goal.replan_history if r["outcome"] == "refused"]
        self.assertTrue(refusals)
        self.assertIn("no supported recovery", refusals[0]["reason"])

    def test_a_replanner_that_returns_an_empty_list_is_also_nothing(self):
        _, _, _, executor, world = self._stack(lambda g, s, v: [])
        world.fail_permanently["focus"] = support.ErrorKind.ACCESS_DENIED
        goal = self._goal(executor, plan(("launch", {}),
                                                      ("focus", {})))
        result = executor.run(goal)
        self.assertIs(result.status, GoalStatus.FAILED)

    def test_the_goal_uses_a_bounded_number_of_replans(self):
        counter = {"n": 0}

        def replanner(goal, step, view):
            counter["n"] += 1
            return [{"id": "again", "action": "demo_control",
                     "arguments": {"operation": "focus",
                                   "window_handle": support.DEMO_HANDLE}}]

        _, _, _, executor, world = self._stack(replanner,
                                               Limits(max_replans=2))
        world.fail_permanently["focus"] = support.ErrorKind.ACCESS_DENIED
        goal = self._goal(executor, plan(("launch", {}),
                                                      ("focus", {})))
        result = executor.run(goal)
        self.assertLessEqual(goal.replans, 2)
        self.assertLessEqual(counter["n"], 2)
        self.assertIs(result.status, GoalStatus.FAILED)

    def test_one_step_cannot_spend_the_whole_goal_replan_budget(self):
        counter = {"n": 0}

        def replanner(goal, step, view):
            counter["n"] += 1
            # Always refused, so the budget is spent on the *same* step and the
            # per-step ceiling is what stops it.
            return [{"id": "x", "action": "not_a_real_action"}]

        _, _, _, executor, world = self._stack(replanner,
                                               Limits(max_replans=5,
                                                      max_replans_per_step=1))
        world.fail_permanently["focus"] = support.ErrorKind.ACCESS_DENIED
        goal = self._goal(executor, plan(("launch", {}),
                                         ("focus", {})))
        executor.run(goal)
        self.assertEqual(counter["n"], 1)

    def test_a_chain_of_replacements_is_bounded_by_the_goal_budget(self):
        counter = {"n": 0}

        def replanner(goal, step, view):
            counter["n"] += 1
            return [{"id": f"again{counter['n']}", "action": "demo_control",
                     "arguments": {"operation": "focus",
                                   "window_handle": support.DEMO_HANDLE}}]

        _, _, _, executor, world = self._stack(replanner,
                                               Limits(max_replans=3))
        world.fail_permanently["focus"] = support.ErrorKind.ACCESS_DENIED
        goal = self._goal(executor, plan(("launch", {}),
                                         ("focus", {})))
        executor.run(goal)
        # Each replacement is a new step, so the per-step ceiling does not
        # apply; the goal-wide ceiling does, and it is the one that holds.
        self.assertLessEqual(counter["n"], 3)
        self.assertLessEqual(goal.replans, 3)

    def test_the_plan_length_is_bounded_across_replans(self):
        def replanner(goal, step, view):
            return [{"id": f"pad{i}", "action": "demo_control",
                     "arguments": {"operation": "list"}}
                    for i in range(6)]

        _, _, _, executor, world = self._stack(replanner,
                                               Limits(max_replans=4,
                                                      max_total_steps=9))
        world.fail_permanently["focus"] = support.ErrorKind.ACCESS_DENIED
        goal = self._goal(executor, plan(("launch", {}),
                                                      ("focus", {})))
        executor.run(goal)
        self.assertLessEqual(len(goal.plan.steps), 9)

    def test_a_replanner_that_hangs_is_abandoned_rather_than_waited_on(self):
        release = threading.Event()

        def replanner(goal, step, view):
            release.wait(30)
            return None

        _, _, _, executor, world = self._stack(
            replanner, Limits(replanner_seconds=0.2))
        world.fail_permanently["focus"] = support.ErrorKind.ACCESS_DENIED
        goal = self._goal(executor, plan(("launch", {}),
                                                      ("focus", {})))
        result = executor.run(goal)
        release.set()
        self.assertIs(result.status, GoalStatus.FAILED)
        self.assertEqual(goal.replans, 0)

    def test_a_replanner_that_raises_does_not_take_the_goal_with_it(self):
        def replanner(goal, step, view):
            raise RuntimeError("the replanner crashed")

        _, _, _, executor, world = self._stack(replanner)
        world.fail_permanently["focus"] = support.ErrorKind.ACCESS_DENIED
        goal = self._goal(executor, plan(("launch", {}),
                                                      ("focus", {})))
        result = executor.run(goal)
        self.assertIs(result.status, GoalStatus.FAILED)

    def test_zero_replans_is_a_supported_configuration(self):
        counter = {"n": 0}

        def replanner(goal, step, view):
            counter["n"] += 1
            return []

        _, _, _, executor, world = self._stack(replanner,
                                               Limits(max_replans=0))
        world.fail_permanently["focus"] = support.ErrorKind.ACCESS_DENIED
        goal = self._goal(executor, plan(("launch", {}),
                                                      ("focus", {})))
        executor.run(goal)
        self.assertEqual(counter["n"], 0)

    # -- what the replanner may propose -------------------------------------

    def test_an_unregistered_capability_is_refused_by_the_phase5_gate(self):
        _, _, _, executor, world = self._stack(
            lambda g, s, v: [{"id": "x", "action": "not_a_real_action"}])
        world.fail_permanently["focus"] = support.ErrorKind.ACCESS_DENIED
        goal = self._goal(executor, plan(("launch", {}),
                                                      ("focus", {})))
        executor.run(goal)
        self.assertEqual(goal.replans, 0)
        self.assertTrue(any("refused by the Phase 5 gate"
                            in r["reason"] or "not a registered action"
                            in r["reason"] for r in goal.replan_history))

    def test_a_replan_cannot_rename_a_step_that_already_exists(self):
        def replanner(goal, step, view):
            return [{"id": "open", "action": "demo_control",
                     "arguments": {"operation": "launch"}}]

        _, _, _, executor, world = self._stack(replanner)
        world.fail_permanently["focus"] = support.ErrorKind.ACCESS_DENIED
        goal = self._goal(executor, plan(("launch", {}),
                                         ("focus", {})))
        executor.run(goal)
        ids = [s.step_id for s in goal.plan.steps]
        self.assertEqual(len(ids), len(set(ids)))

    def test_a_replan_that_works_makes_the_goal_complete_truthfully(self):
        attempts = {"n": 0}
        holder = {}

        def replanner(goal, step, view):
            attempts["n"] += 1
            # The recovery that works: the same operation, once the machine is
            # in a state where it can actually take effect.
            holder["world"].apply_effects = True
            return [{"id": "focus_again", "action": "demo_control",
                     "arguments": {"operation": "focus",
                                   "window_handle": support.DEMO_HANDLE}}]

        _, _, _, executor, world = self._stack(replanner)
        holder["world"] = world
        world.apply_effects = False     # the first focus reports success and
                                        # changes nothing: exactly the situation
                                        # Phase 4 exists to catch
        goal = self._goal(executor, plan(
            ("launch", {}), ("focus", {"window_handle": support.DEMO_HANDLE})))
        result = executor.run(goal)

        self.assertEqual(attempts["n"], 1)
        self.assertEqual(goal.replans, 1)
        self.assertIs(result.status, GoalStatus.COMPLETED)
        self.assertEqual(result.superseded, 1)
        self.assertEqual(result.replans, 1)
        # The original failure is still on the record, next to the success.
        self.assertEqual(result.steps[1]["status"], "SUPERSEDED")
        self.assertEqual(result.steps[-1]["status"], "VERIFIED")

    def test_a_superseded_step_is_recorded_as_a_failure_not_a_success(self):
        def replanner(goal, step, view):
            return [{"id": "later", "action": "demo_control",
                     "arguments": {"operation": "list"}}]

        _, _, _, executor, world = self._stack(replanner)
        world.fail_permanently["focus"] = support.ErrorKind.ACCESS_DENIED
        goal = self._goal(executor, plan(("launch", {}),
                                                      ("focus", {})))
        executor.run(goal)
        superseded = [s for s in goal.steps()
                      if s.status is StepStatus.SUPERSEDED]
        self.assertTrue(superseded)
        # The failure is still on the record, not quietly rewritten away.
        self.assertTrue(superseded[0].history)
        self.assertTrue(any("replan" in note for note in superseded[0].notes))

    def test_later_steps_wait_for_the_replacement_not_the_superseded_step(self):
        def replanner(goal, step, view):
            return [{"id": "replacement", "action": "demo_control",
                     "arguments": {"operation": "list"}}]

        _, _, _, executor, world = self._stack(replanner)
        world.fail_permanently["focus"] = support.ErrorKind.ACCESS_DENIED
        steps = plan(("launch", {}), ("focus", {}), ("list", {}))
        goal = self._goal(executor, steps)
        executor.run(goal)
        tail = [s for s in goal.steps() if s.step_id == "s3"]
        self.assertTrue(tail)
        self.assertIn("replacement", tail[0].depends_on)

    def test_the_replan_view_is_bounded_and_factual(self):
        seen = {}

        def replanner(goal, step, view):
            seen.update(view)
            return None

        _, _, _, executor, world = self._stack(replanner)
        world.fail_permanently["focus"] = support.ErrorKind.ACCESS_DENIED
        goal = self._goal(executor, plan(("launch", {}),
                                                      ("focus", {})))
        executor.run(goal)
        self.assertLessEqual(len(seen["context"]),
                             executor.limits.max_replan_context_chars)
        self.assertIn("failure", seen)
        self.assertIn("available_actions", seen)
        self.assertIn("demo_control", seen["available_actions"])

    def test_events_report_the_replan_and_its_refusal(self):
        events = []
        _, _, _, executor, world = self._stack(lambda g, s, v: None)
        executor.bus.subscribe(events.append)
        world.fail_permanently["focus"] = support.ErrorKind.ACCESS_DENIED
        goal = self._goal(executor, plan(("launch", {}),
                                                      ("focus", {})))
        executor.run(goal)
        kinds = [e.type for e in events]
        self.assertIn(EventType.GOAL_REPLANNING, kinds)
        self.assertIn(EventType.GOAL_REPLAN_REFUSED, kinds)

    def test_a_cancelled_goal_is_not_replanned(self):
        asked = []

        def replanner(goal, step, view):
            asked.append(step.step_id)
            return []

        _, _, _, executor, world = self._stack(replanner)
        world.fail_permanently["focus"] = support.ErrorKind.ACCESS_DENIED
        goal = self._goal(executor, plan(("launch", {}),
                                                      ("focus", {})))
        executor.cancel(goal)
        executor.run(goal)
        self.assertEqual(asked, [])


class TheModelReplannerHasTheSameGates(unittest.TestCase):
    """Part 3 + Part 2. The model's recovery path is gated exactly like a plan."""

    def setUp(self):
        self.tmp = support.tmp_dir("neo-phase6-model-replan-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self._world_ctx = support.reset_demo_world()
        self.world = self._world_ctx.__enter__()
        self.addCleanup(self._world_ctx.__exit__, None, None, None)
        self.actions = support.make_action_registry(*support.PLANNING_ACTIONS)
        self.planner = support.Planner(actions=self.actions, logger=support.Sink())
        manager = support.make_manager(self.tmp)
        layer = support.make_layer(manager, actions=self.actions,
                                   logger=support.Sink())
        self.executor = support.GoalExecutor(manager=manager, layer=layer,
                                             planner=self.planner,
                                             logger=support.Sink())
        self.goal = self.executor.create_goal("replan gate test")

    def _planner(self, proposer):
        return model_planner.ModelPlanner(
            planner=self.planner, actions=self.actions, proposer=proposer,
            limits=Limits(), logger=support.Sink())

    def test_a_well_formed_recovery_comes_back_as_steps(self):
        with support.audited("demo_control"):
            steps = self._planner(lambda prompt, attempt: [
                {"id": "retry", "action": "demo_control",
                 "arguments": {"operation": "list"}}]).replan(
                     self.goal, {"failure": {"step_id": "s1"},
                                 "objective": "x"})
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0]["id"], "retry")

    def test_a_recovery_naming_an_unknown_action_comes_back_as_nothing(self):
        with support.audited("demo_control"):
            steps = self._planner(lambda prompt, attempt: [
                {"id": "retry", "action": "imaginary_capability"}]).replan(
                    self.goal, {"failure": {"step_id": "s1"}})
        self.assertIsNone(steps)

    def test_a_recovery_naming_an_unsafe_capability_comes_back_as_nothing(self):
        with support.marked_unsafe("demo_control"):
            steps = self._planner(lambda prompt, attempt: [
                {"id": "retry", "action": "demo_control",
                 "arguments": {"operation": "list"}}]).replan(
                     self.goal, {"failure": {"step_id": "s1"}})
        self.assertIsNone(steps)

    def test_a_malformed_recovery_comes_back_as_nothing(self):
        with support.audited("demo_control"):
            steps = self._planner(lambda prompt, attempt: [
                {"id": "retry", "action": "demo_control", "command": "rm -rf /"}]
            ).replan(self.goal, {"failure": {"step_id": "s1"}})
        self.assertIsNone(steps)

    def test_the_recovery_prompt_says_that_empty_is_a_good_answer(self):
        captured = {}

        def proposer(prompt, attempt):
            captured["prompt"] = prompt
            return []

        with support.audited("demo_control"):
            self._planner(proposer).replan(self.goal, {
                "objective": "open notepad",
                "failure": {"step_id": "s2", "action": "windows_control",
                            "status": "NOT_VERIFIED", "detail": "no window"},
                "context": "Desktop as observed 1.0s ago"})
        self.assertIn("good answer", captured["prompt"])
        self.assertIn("no window", captured["prompt"])


if __name__ == "__main__":
    unittest.main()