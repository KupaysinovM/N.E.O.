"""
Phase 6 — the assistant pipeline, bounded memory, and world state.

Three things that are easy to fake and must not be:

  * `AssistantGoals.submit` is the whole "a person asked for something" path.
    The tests drive it with real sentences and assert on what it *reports*,
    including the cases where the honest answer is a refusal or a NOT_VERIFIED;
  * the memory adapter is read-only and bounded. It reaches prompts and nothing
    else, so a stored fact can never become an observed value;
  * world state answers "is that still true?" and "what does this step mean?",
    and says UNKNOWN rather than answering from a stale capture.
"""
from __future__ import annotations

import shutil
import unittest

from core.goals.models import GoalStatus
from core.planning import memory_context
from core.verification import world as _world
from tests import support

from core.planning.assistant import AssistantGoals


class ARequestBecomesAGoal(unittest.TestCase):
    """Parts 1, 2 and 8 through the one call a conversation makes."""

    def setUp(self):
        self.tmp = support.tmp_dir("neo-phase6-assistant-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self._world_ctx = support.reset_demo_world()
        self.world = self._world_ctx.__enter__()
        self.addCleanup(self._world_ctx.__exit__, None, None, None)
        self.observed = support.observed_by(self.world)
        self.observed.__enter__()
        self.addCleanup(self.observed.__exit__, None, None, None)

        self.actions = support.make_action_registry(*support.PLANNING_ACTIONS)
        self.planner = support.Planner(actions=self.actions, logger=support.Sink())
        self.manager = support.make_manager(self.tmp)
        self.layer = support.make_layer(self.manager, actions=self.actions,
                                        logger=support.Sink())
        self.layer.bind_confirmation_gate()
        self.executor = support.GoalExecutor(
            manager=self.manager, layer=self.layer, planner=self.planner,
            limits=support.Limits(), logger=support.Sink(), notify=support.Sink(),
            world_capture=support.capturing(self.world))
        self.assistant = AssistantGoals(
            executor=self.executor, planner=self.planner, actions=self.actions,
            memory=memory_context.MemoryContext(reader=self._facts), logger=support.Sink())

    @staticmethod
    def _facts():
        return [{"category": "preferences", "key": "editor",
                 "value": "the user writes notes in Notepad"},
                {"category": "identity", "key": "editor password",
                 "value": "hunter2"},
                {"category": "sessions", "key": "last", "value": "a long transcript"}]

    # -- the happy paths ---------------------------------------------------

    def test_open_an_application_and_write_to_it(self):
        with support.audited("windows_control", "demo_control"):
            reply = self.assistant.submit('Open Notepad and write "NEO Phase 6"')
        self.assertTrue(reply.planned)
        self.assertTrue(reply.ran)
        self.assertIs(reply.result.status, GoalStatus.COMPLETED)
        self.assertEqual(reply.result.replans, 0)

    def test_the_text_actually_reached_the_control(self):
        with support.audited("windows_control", "demo_control"):
            self.assistant.submit('Open Notepad and write "NEO Phase 6"')
        self.assertIn("type_into", self.world.calls)
        self.assertEqual(self.world.values[(support.DEMO_HANDLE, "Document")],
                         "NEO Phase 6")

    def test_calculate_picks_the_calculator_workflow(self):
        with support.audited("windows_control", "demo_control"):
            reply = self.assistant.submit("calculate 123*456")
        self.assertTrue(reply.planned)
        self.assertIn("calc", [s.step_id for s in reply.goal.plan.steps])

    def test_a_named_workflow_bypasses_planning_but_not_validation(self):
        with support.audited("windows_control", "demo_control"):
            reply = self.assistant.submit("", run=False,
                                          workflow="open_and_type",
                                          params={"app_name": "notepad",
                                                  "text": "hi"})
        self.assertTrue(reply.planned)
        self.assertEqual(reply.goal.plan.source, "workflow:open_and_type")

    def test_an_unknown_workflow_is_refused_by_name(self):
        reply = self.assistant.submit("", run=False, workflow="teleport")
        self.assertFalse(reply.planned)
        self.assertIn("not a workflow NEO knows", reply.refused)

    # -- the honest failures -----------------------------------------------

    def test_a_request_nothing_can_do_is_a_refusal_not_a_plan(self):
        reply = self.assistant.submit("make me a sandwich")
        self.assertFalse(reply.planned)
        self.assertFalse(reply.ran)
        self.assertIn("could not plan", reply.summary().lower())
        self.assertIs(reply.goal.status, GoalStatus.PLANNING_FAILED)
        self.assertIsNotNone(reply.goal.error)

    def test_a_refused_goal_runs_nothing_at_all(self):
        self.assistant.submit("make me a sandwich")
        self.assertEqual(self.world.calls, [])

    def test_a_silent_failure_is_reported_as_not_verified(self):
        # The classic Phase 4 case: the call reports success and changes
        # nothing. The goal must not say it worked.
        with support.audited("windows_control", "demo_control"):
            self.world.apply_effects = False
            reply = self.assistant.submit('Open Notepad and write "x"')
        self.assertIs(reply.result.status, GoalStatus.NOT_VERIFIED)
        self.assertFalse(reply.result.ok)

    def test_a_step_the_machine_refuses_ends_the_goal_as_failed(self):
        with support.audited("windows_control", "demo_control"):
            self.world.fail_permanently["type_into"] = support.ErrorKind.ACCESS_DENIED
            reply = self.assistant.submit('Open Notepad and write "x"')
        self.assertIs(reply.result.status, GoalStatus.FAILED)

    def test_the_reply_says_the_counts_rather_than_an_adjective(self):
        with support.audited("windows_control", "demo_control"):
            reply = self.assistant.submit('Open Notepad and write "x"')
        summary = reply.summary()
        self.assertIn("verified", summary)
        self.assertIn("not verified", summary)

    # -- confirmation ------------------------------------------------------

    def test_a_confirmation_the_user_declines_blocks_the_goal(self):
        from core import confirm

        with support.bound_gate():
            goal = self.executor.create_goal("needs approval")
            self.executor.plan_goal(goal, raw_steps=[
                {"id": "ask", "action": "demo_control",
                 "arguments": {"operation": "needs_approval"}}])
            first = self.executor.run(goal)
            self.assertIs(first.status, GoalStatus.AWAITING_CONFIRMATION)
            self.assertTrue(confirm.pending_key())

            support.resolve_confirmation(False)
            support.wait_for(lambda: bool(confirm.pending_key()) is False,
                             timeout=2.0)
            self.executor.resume(goal)
            final = self.executor.run(goal)

        self.assertIn(final.status, (GoalStatus.BLOCKED, GoalStatus.CANCELLED))
        self.assertNotIn("approved", self.world.calls)

    # -- shape of the pipeline ---------------------------------------------

    def test_an_empty_request_is_refused_before_anything_is_created(self):
        reply = self.assistant.submit("   ")
        self.assertFalse(reply.planned)
        self.assertIsNone(reply.goal)

    def test_the_pipeline_reports_what_it_can_do(self):
        described = self.assistant.capabilities()
        self.assertIn("open_and_type", described["workflows"])
        names = {e["name"] for e in described["capabilities"]["entries"]}
        self.assertIn("windows_control", names)
        self.assertIn("max_steps", described["limits"])

    def test_two_submissions_do_not_share_context(self):
        with support.audited("windows_control", "demo_control"):
            first = self.assistant.submit('Open Notepad and write "one"')
            second = self.assistant.submit('Open Notepad and write "two"')
        self.assertNotEqual(first.goal.goal_id, second.goal.goal_id)
        self.assertEqual(self.world.values[(support.DEMO_HANDLE, "Document")],
                         "two")


class MemoryIsReadOnlyAndBounded(unittest.TestCase):
    """Part 10."""

    def setUp(self):
        self.memory = memory_context.MemoryContext(reader=lambda: [
            {"category": "preferences", "key": "notes app",
             "value": "the user writes homework notes in Notepad"},
            {"category": "projects", "key": "phase6",
             "value": "working on the NEO orchestration phase"},
            {"category": "identity", "key": "api_token",
             "value": "sk-do-not-leak-this"},
            {"category": "sessions", "key": "transcript",
             "value": "a very long previous conversation"},
        ])

    def test_only_matching_facts_come_back(self):
        found = self.memory.facts("homework notes", limit=5)
        self.assertTrue(found)
        self.assertTrue(any("homework" in f.value for f in found))

    def test_the_block_is_bounded_in_every_direction(self):
        block = self.memory.relevant("notes phase6 transcript")
        self.assertLessEqual(len(block), memory_context.MAX_BLOCK_CHARS)
        self.assertLessEqual(len(self.memory.found), memory_context.MAX_FACTS)

    def test_a_stored_secret_never_reaches_a_prompt(self):
        block = self.memory.relevant("api token")
        self.assertNotIn("sk-do-not-leak", block)

    def test_session_transcripts_are_not_planning_context(self):
        self.assertEqual(self.memory.facts("transcript"), [])

    def test_each_fact_carries_the_category_it_came_from(self):
        line = self.memory.relevant("homework")[0]
        self.assertTrue(line.startswith("["))

    def test_the_adapter_cannot_write(self):
        writers = [name for name in dir(memory_context)
                   if not name.startswith("_") and "remember" in name.lower()
                   or "update" in name.lower() or "forget" in name.lower()]
        self.assertEqual(writers, [])

    def test_a_broken_reader_returns_nothing_rather_than_raising(self):
        def explode():
            raise OSError("the memory file is locked")

        self.assertEqual(memory_context.MemoryContext(reader=explode)
                         .relevant("anything"), "")

    def test_no_reader_is_not_an_error(self):
        self.assertEqual(memory_context.MemoryContext().relevant("x"), "")

    def test_the_preamble_says_memory_is_not_instructions(self):
        self.assertIn("not", memory_context.PROMPT_PREAMBLE)
        self.assertIn("instructions", memory_context.PROMPT_PREAMBLE)


class WorldStateKnowsWhenItIsOld(unittest.TestCase):
    """Part 9."""

    def _state(self):
        state = _world.WorldState()
        state.put_value("visible_windows",
                        [{"handle": 1, "title": "Notes", "process_id": 10,
                          "process_name": "notepad.exe"},
                         {"handle": 2, "title": "Notes", "process_id": 11,
                          "process_name": "notepad.exe"}],
                        source="windows_win32", note="test")
        state.put_value("active_window_handle", 1, source="windows_win32")
        return state

    def test_an_entry_within_its_bound_is_current(self):
        state = self._state()
        self.assertFalse(state.is_stale("visible_windows", max_age=30))
        self.assertEqual(state.current("active_window_handle", 30), 1)

    def test_an_entry_past_its_bound_is_stale_and_reads_as_nothing(self):
        state = self._state()
        self.assertTrue(state.is_stale("visible_windows", max_age=0))
        self.assertIsNone(state.current("visible_windows", 0))

    def test_a_missing_entry_is_stale_rather_than_a_default(self):
        self.assertTrue(self._state().is_stale("nothing_was_ever_seen"))

    def test_a_marked_stale_entry_is_stale(self):
        state = self._state()
        state.mark_stale(["active_window_handle"])
        self.assertTrue(state.is_stale("active_window_handle", 300))

    def test_a_handle_resolves_to_exactly_one_window(self):
        found = self._state().resolve_target({"window_handle": 2}, max_age=300)
        self.assertEqual(found["resolved"]["handle"], 2)
        self.assertFalse(found["ambiguous"])

    def test_two_windows_that_match_a_title_are_ambiguous(self):
        found = self._state().resolve_target({"title": "notes"}, max_age=300)
        self.assertTrue(found["ambiguous"])
        self.assertIsNone(found["resolved"])

    def test_a_handle_that_is_gone_is_reported_as_gone(self):
        found = self._state().resolve_target({"window_handle": 999}, max_age=300)
        self.assertIsNone(found["resolved"])
        self.assertIn("may have closed", found["reason"])

    def test_a_stale_capture_resolves_nothing_rather_than_stale_answers(self):
        found = self._state().resolve_target({"title": "notes"}, max_age=0)
        self.assertIsNone(found["resolved"])
        self.assertIn("too old", found["reason"])

    def test_an_unobserved_value_is_unknown_not_missing(self):
        state = _world.WorldState()
        state.put("battery", None)
        self.assertFalse(state.is_known("battery"))
        self.assertIsNone(state.get("battery"))

    def test_the_prompt_block_is_bounded_and_says_how_old_it_is(self):
        text = self._state().describe_for_prompt(limit=3)
        self.assertIn("observed", text)
        self.assertLessEqual(len(text.splitlines()), 4)

    def test_a_target_with_nothing_to_match_is_not_a_match(self):
        found = self._state().resolve_target({}, max_age=300)
        self.assertIsNone(found["resolved"])
        self.assertIn("no captured window matches", found["reason"])


if __name__ == "__main__":
    unittest.main()