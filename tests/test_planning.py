"""
Phase 6 — natural-language planning.

These tests cover the bridge Phase 5 was missing and the bounded model
planner that sits on top of it: what a sentence yields, what shape a model's
plan has to fit, and what happens to every attempt to get around that.

The gates being tested, one per group of tests:

  * the extractor reads a sentence into slots and admits what it could not
    explain, rather than inventing the rest;
  * the schema refuses a plan that does not fit, before `Planner.build()` is
    ever consulted;
  * the planner refuses an unregistered capability, an unaudited capability,
    an UNSAFE capability, a plan over the limit, and a plan whose limits the
    model tried to raise;
  * the refusals say exactly what was wrong, in the shared error taxonomy.
"""
from __future__ import annotations

import shutil
import unittest

from core import capabilities
from core.goals.limits import Limits
from core.goals.planner import Planner
from core.planning import intent, model_planner, schema, workflows
from core.task_models import ErrorKind
from tests import support


class NaturalLanguageBecomesIntent(unittest.TestCase):
    """Part 1. A sentence becomes slots, and the residue is reported."""

    def test_an_application_and_quoted_text_both_come_out(self):
        parsed = intent.extract('Open Notepad and write "NEO Phase 6 test"')
        self.assertEqual(parsed.slots["app_name"], "notepad")
        self.assertEqual(parsed.slots["text"], "NEO Phase 6 test")
        self.assertEqual(parsed.kind, intent.OPEN_APP)

    def test_an_arithmetic_expression_is_recognised_and_normalised(self):
        for sentence, expected in (("calculate 123 * 456", "123*456"),
                                   ("calculate 123 × 456", "123*456"),
                                   ("what is 12 + 3?", "12+3")):
            with self.subTest(sentence=sentence):
                self.assertEqual(intent.extract(sentence).slots["expression"],
                                 expected)

    def test_an_expression_outranks_an_earlier_cue_word(self):
        # "Open calculator and calculate 123*456" is one request. Reading it as
        # "open calculator" and dropping the rest would execute half of it.
        parsed = intent.extract("open calculator and calculate 123*456")
        self.assertEqual(parsed.kind, intent.CALCULATE)

    def test_words_it_cannot_explain_are_reported_rather_than_dropped(self):
        parsed = intent.extract("open notepad and write my homework notes")
        self.assertIn("homework", parsed.unmatched)
        self.assertIn("notes", parsed.unmatched)
        self.assertFalse(parsed.complete)

    def test_a_request_with_no_cue_words_is_unknown_not_guessed(self):
        parsed = intent.extract("make me a sandwich")
        self.assertEqual(parsed.kind, intent.UNKNOWN)
        self.assertEqual(parsed.confidence, 0.0)
        self.assertEqual(intent.summary(parsed).split(":")[0],
                         "NEO could not tell what this request is about")

    def test_ambiguity_lowers_confidence_and_is_kept(self):
        parsed = intent.extract("close the window and focus notepad")
        self.assertTrue(parsed.alternatives)
        self.assertLess(parsed.confidence, 1.0)

    def test_a_sentence_with_no_length_limit_cannot_blow_up_the_planner(self):
        parsed = intent.extract("open notepad " + "x" * 5000)
        self.assertLessEqual(len(parsed.text), intent.MAX_TEXT_CHARS)

    def test_an_empty_request_is_unknown_and_safe(self):
        self.assertEqual(intent.extract("").kind, intent.UNKNOWN)


class APlanHasToFitTheSchema(unittest.TestCase):
    """Part 2. Shape is checked before substance."""

    def test_a_well_formed_plan_has_no_problems(self):
        payload = {"steps": [
            {"id": "open", "action": "demo_control",
             "arguments": {"operation": "launch_app", "app_name": "notepad"}},
            {"id": "type", "action": "demo_control", "depends_on": ["open"],
             "arguments": {"operation": "set_value", "text": "hello"}}]}
        self.assertEqual(schema.validate(payload), [])
        self.assertEqual(len(schema.enforce(payload)), 2)

    def test_an_unknown_key_is_refused_rather_than_ignored(self):
        # "Ignore the extra key" is how a field called `command` eventually gets
        # implemented by accident.
        payload = [{"id": "s1", "action": "demo_control",
                    "arguments": {"operation": "list"},
                    "shell": "rm -rf /"}]
        problems = schema.validate(payload)
        self.assertTrue(any("unknown key 'shell'" in p.message for p in problems))

    def test_a_value_that_is_not_data_is_refused(self):
        payload = [{"id": "s1", "action": "demo_control",
                    "arguments": {"operation": "list", "fn": len}}]
        problems = schema.validate(payload)
        self.assertTrue(any("not plain data" in p.message for p in problems))

    def test_an_unknown_retry_mode_is_refused(self):
        payload = [{"id": "s1", "action": "demo_control",
                    "arguments": {"operation": "list"},
                    "retry": {"attempts": 9, "on": "forever"}}]
        problems = schema.validate(payload)
        self.assertTrue(any("retry.on" in p.where for p in problems))

    def test_a_plan_longer_than_the_limit_is_refused_not_truncated(self):
        payload = [{"id": f"s{i}", "action": "demo_control",
                    "arguments": {"operation": "list"}} for i in range(30)]
        problems = schema.validate(payload, max_steps=12)
        self.assertTrue(any("the limit is 12" in p.message for p in problems))

    def test_every_problem_is_reported_not_just_the_first(self):
        payload = [{"id": "s1", "action": "", "arguments": "nope", "extra": 1}]
        self.assertGreaterEqual(len(schema.validate(payload)), 2)

    def test_a_reference_must_name_an_observed_value(self):
        payload = [{"id": "s1", "action": "demo_control",
                    "arguments": {"window_handle": {"$from": 7}}}]
        self.assertTrue(schema.validate(payload))

    def test_a_deeply_nested_value_tree_is_refused(self):
        deep = current = {}
        for _ in range(12):
            current["nested"] = {}
            current = current["nested"]
        payload = [{"id": "s1", "action": "demo_control", "arguments": deep}]
        self.assertTrue(any("nests deeper" in p.message
                            for p in schema.validate(payload)))

    def test_the_payload_preview_is_scrubbed(self):
        preview = schema.safe_preview({"text": "hunter2 password"})
        self.assertIsInstance(preview, str)
        self.assertLessEqual(len(preview), 400)

    def test_the_described_schema_names_only_real_keys(self):
        described = schema.describe_schema()
        for key in sorted(schema.STEP_KEYS):
            self.assertIn(key, described)


class ThePlannerIsBounded(unittest.TestCase):
    """Parts 2 and 6. Every gate, and the exact refusal each one produces."""

    def setUp(self):
        self.tmp = support.tmp_dir("neo-phase6-planning-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.actions = support.make_action_registry(*support.PLANNING_ACTIONS)
        self.planner = Planner(actions=self.actions, logger=support.Sink())
        self.limits = Limits()

    def _planner(self, proposer=None, **kwargs) -> model_planner.ModelPlanner:
        return model_planner.ModelPlanner(
            planner=self.planner, actions=self.actions, proposer=proposer,
            limits=self.limits, logger=support.Sink(), **kwargs)

    def _goal(self, executor, sentence):
        return executor.create_goal(sentence)

    def test_a_deterministic_request_needs_no_model_at_all(self):
        manager = support.make_manager(self.tmp)
        layer = support.make_layer(manager, actions=self.actions, logger=support.Sink())
        executor = support.GoalExecutor(manager=manager, layer=layer,
                                        planner=self.planner, logger=support.Sink())
        goal = self._goal(executor, 'Open Notepad and write "hello"')
        outcome = self._planner().plan(goal)
        self.assertTrue(outcome.ok)
        self.assertFalse(outcome.used_model)
        self.assertEqual([s.step_id for s in outcome.plan], ["open", "type"])

    def test_a_model_plan_that_names_an_unregistered_action_is_refused(self):
        manager = support.make_manager(self.tmp)
        layer = support.make_layer(manager, actions=self.actions, logger=support.Sink())
        executor = support.GoalExecutor(manager=manager, layer=layer,
                                        planner=self.planner, logger=support.Sink())
        goal = self._goal(executor, "do the unmentionable thing")
        outcome = self._planner(proposer=lambda prompt, attempt: [
            {"id": "s1", "action": "rm_rf_slash", "arguments": {}}]).plan(goal)
        self.assertFalse(outcome.ok)
        self.assertIn("not a registered action", outcome.refused)

    def test_a_model_plan_that_names_an_unaudited_capability_is_refused(self):
        # The registry has it; the audit does not. The safe direction is to
        # refuse, so a capability becomes reachable by being audited.
        manager = support.make_manager(self.tmp)
        layer = support.make_layer(manager, actions=self.actions, logger=support.Sink())
        executor = support.GoalExecutor(manager=manager, layer=layer,
                                        planner=self.planner, logger=support.Sink())
        goal = self._goal(executor, "use the unaudited thing")
        outcome = self._planner(proposer=lambda prompt, attempt: [
            {"id": "s1", "action": "demo_singleton", "arguments": {}}]).plan(goal)
        self.assertFalse(outcome.ok)
        self.assertIn("may not use", outcome.refused)

    def test_an_unsafe_capability_is_refused_even_though_it_is_registered(self):
        manager = support.make_manager(self.tmp)
        layer = support.make_layer(manager, actions=self.actions, logger=support.Sink())
        executor = support.GoalExecutor(manager=manager, layer=layer,
                                        planner=self.planner, logger=support.Sink())
        goal = self._goal(executor, "run some code")
        with support.marked_unsafe("demo_control"):
            outcome = self._planner(proposer=lambda prompt, attempt: [
                {"id": "s1", "action": "demo_control",
                 "arguments": {"operation": "list"}}]).plan(goal)
        self.assertFalse(outcome.ok)
        self.assertIn("may not use", outcome.refused)

    def test_a_known_safe_capability_plans_through_the_same_gates(self):
        manager = support.make_manager(self.tmp)
        layer = support.make_layer(manager, actions=self.actions, logger=support.Sink())
        executor = support.GoalExecutor(manager=manager, layer=layer,
                                        planner=self.planner, logger=support.Sink())
        goal = self._goal(executor, "list the windows please")
        with support.audited("demo_control"):
            outcome = self._planner(proposer=lambda prompt, attempt: [
                {"id": "s1", "action": "demo_control",
                 "arguments": {"operation": "list"}}]).plan(goal)
        self.assertTrue(outcome.ok)
        self.assertTrue(outcome.used_model)

    def test_a_proposer_that_hangs_is_abandoned_rather_than_waited_on(self):
        import threading

        manager = support.make_manager(self.tmp)
        layer = support.make_layer(manager, actions=self.actions, logger=support.Sink())
        executor = support.GoalExecutor(manager=manager, layer=layer,
                                        planner=self.planner, logger=support.Sink())
        goal = self._goal(executor, "something the planner will never finish")
        release = threading.Event()

        def hang(prompt, attempt):
            release.wait(30)
            return []

        fast = Limits(proposer_seconds=0.2)
        self.limits = fast
        outcome = self._planner(proposer=hang).plan(goal)
        release.set()
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.candidates, 0)

    def test_a_proposer_that_raises_does_not_take_the_process_with_it(self):
        manager = support.make_manager(self.tmp)
        layer = support.make_layer(manager, actions=self.actions, logger=support.Sink())
        executor = support.GoalExecutor(manager=manager, layer=layer,
                                        planner=self.planner, logger=support.Sink())
        goal = self._goal(executor, "explode please")

        def explode(prompt, attempt):
            raise RuntimeError("the planner crashed")

        outcome = self._planner(proposer=explode).plan(goal)
        self.assertFalse(outcome.ok)

    def test_the_planner_is_attempted_a_bounded_number_of_times(self):
        manager = support.make_manager(self.tmp)
        layer = support.make_layer(manager, actions=self.actions, logger=support.Sink())
        executor = support.GoalExecutor(manager=manager, layer=layer,
                                        planner=self.planner, logger=support.Sink())
        goal = self._goal(executor, "never planable at all")
        calls = []

        def never(prompt, attempt):
            calls.append(attempt)
            return [{"id": "s1", "action": "not_registered", "arguments": {}}]

        self.limits = Limits(max_planning_attempts=2)
        outcome = self._planner(proposer=never).plan(goal)
        self.assertFalse(outcome.ok)
        self.assertEqual(len(calls), 2)

    def test_the_planner_sees_the_limits_it_cannot_raise(self):
        manager = support.make_manager(self.tmp)
        layer = support.make_layer(manager, actions=self.actions, logger=support.Sink())
        executor = support.GoalExecutor(manager=manager, layer=layer,
                                        planner=self.planner, logger=support.Sink())
        goal = self._goal(executor, "open notepad")
        self.limits = Limits(max_steps=4)
        prompt = self._planner().build_prompt(goal, intent.extract(goal.description))
        self.assertIn("at most 4 steps", prompt)

    def test_limits_from_a_model_are_clamped_before_anything_runs(self):
        # The documented contract: a Limits that arrives from a model-backed
        # planner goes through clamped(), so "I need 5000 steps" becomes 100.
        outrageous = Limits(max_steps=5000, max_goal_seconds=1e9,
                            max_step_attempts=99, max_replans=400).clamped()
        self.assertLessEqual(outrageous.max_steps, 100)
        self.assertLessEqual(outrageous.max_goal_seconds, 3600.0)
        self.assertLessEqual(outrageous.max_step_attempts,
                             Limits().max_step_attempts)
        self.assertLessEqual(outrageous.max_replans, 6)

    def test_the_prompt_carries_the_schema_and_the_capability_list(self):
        manager = support.make_manager(self.tmp)
        layer = support.make_layer(manager, actions=self.actions, logger=support.Sink())
        executor = support.GoalExecutor(manager=manager, layer=layer,
                                        planner=self.planner, logger=support.Sink())
        goal = self._goal(executor, "open notepad")
        prompt = self._planner().build_prompt(goal, intent.extract(goal.description))
        self.assertIn("CAPABILITIES", prompt)
        self.assertIn("SCHEMA", prompt)
        self.assertIn("demo_control", prompt)

    def test_a_refusal_carries_the_shared_error_taxonomy(self):
        manager = support.make_manager(self.tmp)
        layer = support.make_layer(manager, actions=self.actions, logger=support.Sink())
        executor = support.GoalExecutor(manager=manager, layer=layer,
                                        planner=self.planner, logger=support.Sink())
        goal = self._goal(executor, "something impossible")
        outcome = self._planner().plan(goal)
        error = model_planner.refusal_to_error(outcome)
        self.assertIsNotNone(error)
        self.assertIsInstance(error.kind, ErrorKind)


class WorkflowsAreJustPlans(unittest.TestCase):
    """Part 8. Recipes get no privilege a model plan does not have."""

    def test_the_four_documented_workflows_exist(self):
        self.assertEqual(workflows.names(),
                         ["browser_search", "calculate", "open_and_type",
                          "open_recent_file"])

    def test_open_and_type_carries_the_window_handle_forward(self):
        steps = workflows.open_and_type({"app_name": "notepad", "text": "hi"})
        self.assertEqual(steps[1]["arguments"]["window_handle"],
                         {"$from": "step:open.handle"})
        self.assertTrue(steps[1]["re_resolve"])

    def test_opening_an_application_with_no_text_is_one_step(self):
        self.assertEqual(len(workflows.open_and_type({"app_name": "notepad"})), 1)

    def test_a_workflow_that_cannot_be_built_says_why(self):
        from core.goals.planner import PlanRejected

        with self.assertRaises(PlanRejected):
            workflows.open_and_type({})
        with self.assertRaises(PlanRejected):
            workflows.calculate({"expression": ""})

    def test_open_recent_file_refuses_a_description_rather_than_guessing(self):
        from core.goals.planner import PlanRejected

        with self.assertRaises(PlanRejected) as caught:
            workflows.open_recent_file({"description": "the file I worked on today"})
        self.assertIn("path", str(caught.exception))

    def test_every_workflow_step_passes_the_phase5_gate(self):
        self.tmp = support.tmp_dir("neo-phase6-workflows-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        actions = support.make_action_registry(*support.PLANNING_ACTIONS)
        planner = Planner(actions=actions, logger=support.Sink())
        cases = [
            (workflows.open_and_type, {"app_name": "notepad", "text": "x"}),
            (workflows.calculate, {"expression": "2+2"}),
            (workflows.browser_search, {"query": "python release"}),
            (workflows.open_recent_file, {"path": r"C:\notes.txt"}),
        ]
        for builder, params in cases:
            with self.subTest(recipe=builder.__name__):
                # No try/except: a recipe that names something unregistered must
                # fail here, loudly, rather than be waved through.
                plan = planner.build("goal", builder(params),
                                     source=f"workflow:{builder.__name__}")
                self.assertTrue(plan.steps)

    def test_a_workflow_never_names_a_capability_the_audit_calls_unsafe(self):
        self.tmp = support.tmp_dir("neo-phase6-workflow-audit-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        actions = support.make_action_registry(*support.PLANNING_ACTIONS)
        with support.audited("demo_control", "windows_control", "web_search",
                             "open_app"):
            for name in workflows.names():
                with self.subTest(recipe=name):
                    builder = workflows.WORKFLOWS[name]
                    try:
                        steps = builder({"app_name": "notepad", "text": "x",
                                         "expression": "1+1", "query": "q",
                                         "path": "p"})
                    except Exception:
                        continue
                    for step in steps:
                        self.assertFalse(
                            capabilities.is_unsafe(step["action"]),
                            f"{name} names an unsafe capability")


class TheAuditDecidesWhatAPlanMayReach(unittest.TestCase):
    """Part 6. The audit is a gate, not a document."""

    def test_every_verdict_is_used(self):
        counts = capabilities.audit_report()["counts"]
        for verdict in capabilities.VERDICTS:
            self.assertIn(verdict, counts)
        self.assertGreater(counts[capabilities.UNSAFE], 0)
        self.assertGreater(counts[capabilities.DEAD], 0)

    def test_an_unregistered_name_is_unsafe_not_assumed_fine(self):
        self.assertEqual(capabilities.verdict_of("something_invented"),
                         capabilities.UNSAFE)
        self.assertFalse(capabilities.is_plannable("something_invented"))
        self.assertEqual(capabilities.risk_of("something_invented"),
                         capabilities.HIGH)

    def test_the_code_writing_capabilities_are_never_plannable(self):
        for action in ("code_helper", "dev_agent", "send_message",
                       "desktop_control"):
            with self.subTest(action=action):
                self.assertFalse(capabilities.is_plannable(action))

    def test_the_audited_desktop_control_capability_is_the_reference(self):
        capability = capabilities.get("windows_control")
        self.assertEqual(capability.verdict, capabilities.EXISTING_WORKING)
        self.assertTrue(capability.verifiable)

    def test_a_catalogue_reflects_the_live_registry(self):
        actions = support.make_action_registry(*support.PLANNING_ACTIONS)
        catalogue = capabilities.build_catalogue(actions)
        names = catalogue.names()
        self.assertEqual(names, {"demo_control", "demo_singleton",
                                 "windows_control", "web_search", "open_app",
                                 "reminder"})
        self.assertIn("demo_control", catalogue.missing_from_audit)
        self.assertNotIn("demo_control", catalogue.allowed())

    def test_a_catalogue_becomes_permissive_only_after_auditing(self):
        actions = support.make_action_registry(*support.PLANNING_ACTIONS)
        with support.audited("demo_control"):
            catalogue = capabilities.build_catalogue(actions)
            self.assertIn("demo_control", catalogue.allowed())
            self.assertTrue(catalogue.entry("demo_control")["verifiable"])

    def test_the_catalogue_never_carries_a_handler(self):
        actions = support.make_action_registry(*support.PLANNING_ACTIONS)
        catalogue = capabilities.build_catalogue(actions)
        for entry in catalogue.entries:
            self.assertNotIn("handler", entry)
            self.assertNotIn("module", entry)

    def test_the_prompt_block_is_bounded(self):
        actions = support.make_action_registry(*support.PLANNING_ACTIONS)
        catalogue = capabilities.build_catalogue(actions)
        block = capabilities.prompt_block(catalogue, limit=1)
        self.assertLessEqual(block.count("- "), 2)


if __name__ == "__main__":
    unittest.main()