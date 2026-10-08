"""
Phase 4 in unit tests — observation, world state, expectations, verification.

The point of these tests is not that the verifier returns the right string. It
is that it cannot manufacture certainty: no path may produce VERIFIED without a
real observation behind it, and every "I could not tell" case has to stay a
"could not tell".

Fake observations are used here on purpose — this file tests the reasoning, and
it must run on any platform. The real-machine proof lives in
tests/test_verification_integration.py, which drives actual Windows UI.
"""
from __future__ import annotations

import threading
import time
import unittest

from core.execution import ExecutionLayer, ExecutionRequest, ExecStatus, ExecutionResult
from core.task_models import ErrorKind
from core.security import AuthorizationPolicy, RiskClass
from core.verification import expectations as ex
from core.verification import observation as obs
from core.verification import verifier as vf
from core.verification.expectations import Expectation, ExpectationKind
from core.verification.verifier import Outcome, Status
from core.verification.world import EntryState, WorldState
from core.windows import is_supported as _is_supported
from core.windows.errors import WindowsErrorKind

from tests.support import make_action_registry


def make_observation(value=None, kind="window_exists", error="", **kwargs):
    kwargs.setdefault("source", obs.Source.WIN32)
    kwargs.setdefault("target", "the target")
    return obs.Observation(kind=kind, value=value, error_kind=error, **kwargs)


# ── observation ─────────────────────────────────────────────────────────────

class ObservationIsHonest(unittest.TestCase):

    def test_a_value_without_an_error_is_ok(self):
        self.assertTrue(make_observation(True).ok)

    def test_an_error_means_not_ok_even_with_a_value(self):
        self.assertFalse(make_observation(False, error=WindowsErrorKind.ELEMENT_STALE).ok)

    def test_no_value_is_never_ok(self):
        self.assertFalse(make_observation(None).ok)

    def test_ambiguity_and_staleness_are_recognised(self):
        self.assertTrue(make_observation(None, error=WindowsErrorKind.ELEMENT_AMBIGUOUS).ambiguous)
        self.assertTrue(make_observation(None, error=WindowsErrorKind.ELEMENT_STALE).stale)
        self.assertTrue(make_observation(None, error=WindowsErrorKind.CANCELLED).cancelled)

    def test_provenance_survives_serialisation(self):
        observation = make_observation("Calculator", kind="window")
        data = observation.to_dict()
        for field in ("source", "observed_at", "target", "kind", "freshness",
                      "sensitivity", "observation_id"):
            self.assertIn(field, data)
        self.assertEqual(data["source"], obs.Source.WIN32)

    def test_a_withheld_value_is_never_serialised(self):
        # The refusal is the observation. There is no branch that attaches the
        # secret anyway.
        withheld = obs.Observation(kind=obs.Kind.CONTROL_VALUE, source=obs.Source.UIA,
                                   value=None, sensitivity=obs.Sensitivity.WITHHELD,
                                   error_kind=WindowsErrorKind.ACCESS_DENIED)
        self.assertIsNone(withheld.to_dict()["value"])
        self.assertNotIn("password", withheld.describe().lower())


# ── world state ─────────────────────────────────────────────────────────────

class WorldStateIsExplicitAboutUncertainty(unittest.TestCase):

    def test_an_observed_value_is_marked_observed_with_its_source(self):
        state = WorldState()
        state.put("active_window", make_observation({"title": "Calculator"}))
        entry = state.entries["active_window"]
        self.assertEqual(entry.state, EntryState.OBSERVED)
        self.assertEqual(entry.source, obs.Source.WIN32)
        self.assertTrue(entry.usable)

    def test_a_failed_observation_becomes_unknown_not_a_default(self):
        state = WorldState()
        state.put("battery", make_observation(None,
                                              error=WindowsErrorKind.UNSUPPORTED_CONTROL))
        entry = state.entries["battery"]
        self.assertEqual(entry.state, EntryState.UNKNOWN)
        self.assertIsNone(entry.value)
        self.assertFalse(state.is_known("battery"))

    def test_stale_entries_keep_their_value_but_stop_being_usable(self):
        state = WorldState()
        state.put("window", make_observation(True))
        aged = state.mark_stale(["window"])
        self.assertEqual(aged, 1)
        self.assertEqual(state.entries["window"].state, EntryState.STALE)
        self.assertFalse(state.entries["window"].usable)
        self.assertIsNone(state.get("window"), "a stale value must not be served")

    def test_an_inferred_entry_says_it_is_inferred(self):
        state = WorldState()
        state.put_value("busy", True, source="rule:any_window_modal", state=EntryState.INFERRED)
        self.assertEqual(state.entries["busy"].state, EntryState.INFERRED)
        self.assertIn("inferred", state.entries["busy"].describe())

    def test_summary_counts_states(self):
        state = WorldState()
        state.put("a", make_observation(1))
        state.put("b", None)
        self.assertEqual(state.summary["states"][EntryState.OBSERVED], 1)
        self.assertEqual(state.summary["states"][EntryState.UNKNOWN], 1)


# ── expectations ────────────────────────────────────────────────────────────

class ExpectationsAreStructuredNotGenerated(unittest.TestCase):

    def test_focus_is_checked_by_looking_at_the_foreground_window(self):
        expectation = ex.expected_after("focus_window", {"window_handle": 4242})
        self.assertEqual(expectation.kind, ex.ExpectationKind.WINDOW_ACTIVE)
        self.assertEqual(expectation.target["window_handle"], 4242)

    def test_close_is_checked_by_absence(self):
        expectation = ex.expected_after("close_window", {"window_handle": 9})
        self.assertEqual(expectation.kind, ex.ExpectationKind.WINDOW_CLOSED)
        self.assertTrue(expectation.expected,
                        "the observation already means 'is gone', so True is expected")
        self.assertEqual(expectation.compare, "equals")

    def test_a_window_that_is_still_open_never_satisfies_the_closed_check(self):
        # The inversion this guards against: for this expectation the observed
        # boolean already means "is gone", so a window that is still open
        # (observed False) must not verify.
        expectation = ex.window_closed({"window_handle": 9})
        still_there = vf.verify(expectation, timeout=0.2,
                                observer=lambda e: make_observation(False))
        self.assertEqual(still_there.status, Status.NOT_VERIFIED)
        gone = vf.verify(expectation, observer=lambda e: make_observation(True))
        self.assertEqual(gone.status, Status.VERIFIED)

    def test_set_value_is_checked_by_reading_the_value_back(self):
        expectation = ex.expected_after(
            "set_value", {"window_handle": 1, "control_type": "Edit", "text": "abc"})
        self.assertEqual(expectation.kind, ex.ExpectationKind.CONTROL_VALUE)
        self.assertEqual(expectation.expected, "abc")

    def test_invoke_gets_no_expectation_because_no_button_means_one_thing(self):
        self.assertIsNone(ex.expected_after("invoke", {"window_handle": 1,
                                                        "element_name": "Send"}))

    def test_toggle_checks_the_state_the_action_reported_it_left_in(self):
        class Result:
            data = {"state_after": 1}
        expectation = ex.expected_after("toggle", {"window_handle": 1}, Result())
        self.assertEqual(expectation.kind, ex.ExpectationKind.CONTROL_STATE)
        self.assertEqual(expectation.property, "toggle_state")

    def test_toggle_captures_a_precondition_but_invoke_does_not(self):
        self.assertIsNotNone(ex.preconditions("toggle", {"window_handle": 1}))
        self.assertIsNone(ex.preconditions("invoke", {"window_handle": 1}))

    def test_expectations_round_trip_through_a_dict(self):
        original = ex.window_exists({"title": "Notepad"}, timeout=3.0)
        restored = ex.Expectation.from_dict(original.to_dict())
        self.assertEqual(restored.kind, original.kind)
        self.assertEqual(restored.target, original.target)
        self.assertEqual(restored.timeout, original.timeout)

    def test_only_declared_operations_are_claimed_verifiable(self):
        # The claim has to be true: anything listed must actually produce a
        # check, and the famous-but-unprovable ones must not be listed.
        class Result:
            data = {"state_after": 1, "selected": True, "expanded": True}

        for operation in ex.VERIFIABLE_OPERATIONS:
            self.assertIsNotNone(ex.expected_after(operation, {
                "window_handle": 1, "element_name": "File", "text": "abc",
                "app_name": "notepad"}), f"{operation} is listed but verifies nothing")
        for operation in ex.CONDITIONALLY_VERIFIABLE_OPERATIONS:
            self.assertIsNotNone(
                ex.expected_after(operation, {"window_handle": 1}, Result()),
                f"{operation} is listed as conditional but never verifies")
            self.assertIsNone(
                ex.expected_after(operation, {"window_handle": 1},
                                  type("Empty", (), {"data": {}})()),
                f"{operation} claims nothing when the action observed no state")
        self.assertNotIn("invoke", ex.VERIFIABLE_OPERATIONS)
        self.assertNotIn("click", ex.VERIFIABLE_OPERATIONS)
        self.assertNotIn("press_keys", ex.VERIFIABLE_OPERATIONS)

    def test_an_expectation_carries_its_own_bound(self):
        quick = ex.window_exists({"window_handle": 1}, timeout=1.25)
        self.assertEqual(quick.timeout, 1.25)


# ── the engine ──────────────────────────────────────────────────────────────

class VerificationNeverManufacturesCertainty(unittest.TestCase):

    def test_no_expectation_means_not_available(self):
        outcome = vf.verify(None)
        self.assertEqual(outcome.status, Status.NOT_AVAILABLE)
        self.assertFalse(outcome.verified)

    def test_a_matching_observation_is_verified(self):
        outcome = vf.verify(ex.window_exists({"window_handle": 7}),
                            observer=lambda e: make_observation(True))
        self.assertEqual(outcome.status, Status.VERIFIED)
        self.assertTrue(outcome.verified)

    def test_a_mismatched_observation_is_not_verified(self):
        outcome = vf.verify(ex.window_active({"window_handle": 7}, timeout=0.2),
                            interval=0.05,
                            observer=lambda e: make_observation(False))
        self.assertEqual(outcome.status, Status.NOT_VERIFIED)
        self.assertFalse(outcome.verified)
        self.assertGreaterEqual(outcome.attempts, 1)

    def test_an_unreadable_state_is_not_available_not_a_pass(self):
        outcome = vf.verify(ex.window_exists({"window_handle": 7}),
                            observer=lambda e: make_observation(
                                None, error=WindowsErrorKind.UNSUPPORTED_CONTROL))
        self.assertEqual(outcome.status, Status.NOT_AVAILABLE)

    def test_ambiguity_is_its_own_outcome(self):
        outcome = vf.verify(ex.control_exists({"element_name": "Minimize"}),
                            observer=lambda e: make_observation(
                                False, error=WindowsErrorKind.ELEMENT_AMBIGUOUS))
        self.assertEqual(outcome.status, Status.AMBIGUOUS)

    def test_a_stale_target_is_reported_as_stale(self):
        outcome = vf.verify(ex.control_value({"element_name": "x"}, "abc"),
                            observer=lambda e: make_observation(
                                None, error=WindowsErrorKind.ELEMENT_STALE))
        self.assertEqual(outcome.status, Status.STALE)

    def test_a_withheld_sensitive_value_is_never_verified(self):
        withheld = obs.Observation(kind=obs.Kind.CONTROL_VALUE, source=obs.Source.UIA,
                                   value=None, sensitivity=obs.Sensitivity.WITHHELD,
                                   error_kind=WindowsErrorKind.ACCESS_DENIED)
        outcome = vf.verify(ex.control_value({"element_name": "password"}, "abc"),
                            observer=lambda e: withheld)
        self.assertEqual(outcome.status, Status.NOT_AVAILABLE)
        self.assertNotIn("password", outcome.to_dict()["reason"].lower())

    def test_cancellation_during_the_wait_stays_truthful(self):
        cancelled = threading.Event()
        cancelled.set()
        outcome = vf.verify(ex.window_exists({"window_handle": 7}),
                            cancel_event=cancelled,
                            observer=lambda e: make_observation(True))
        self.assertEqual(outcome.status, Status.CANCELLED)
        self.assertFalse(outcome.verified)

    def test_polling_is_bounded_and_never_loops_forever(self):
        started = time.monotonic()
        outcome = vf.verify(ex.window_exists({"window_handle": 7}, timeout=0.3),
                            interval=0.05, observer=lambda e: make_observation(False))
        self.assertEqual(outcome.status, Status.NOT_VERIFIED)
        self.assertLess(time.monotonic() - started, 3.0)
        self.assertLess(outcome.attempts, 20)

    def test_a_broken_check_is_a_failed_verification_not_a_crash(self):
        def explode(_expectation):
            raise RuntimeError("the observer itself is broken")

        outcome = vf.verify(ex.window_exists({"window_handle": 7}), observer=explode)
        self.assertEqual(outcome.status, Status.FAILED)

    def test_state_that_appears_late_is_verified_rather_than_missed(self):
        answers = [False, False, True]

        def eventually(_expectation):
            return make_observation(answers.pop(0) if answers else True)

        outcome = vf.verify(ex.window_exists({"window_handle": 7}, timeout=2.0),
                            interval=0.05, observer=eventually)
        self.assertEqual(outcome.status, Status.VERIFIED)
        self.assertEqual(outcome.attempts, 3)

    def test_a_change_needs_both_sides_and_says_so_when_it_has_only_one(self):
        change = ex.Expectation(kind=ex.ExpectationKind.CONTROL_CHANGED,
                                target={"element_name": "Wrap"},
                                property="toggle_state")
        with_no_before = vf.verify(change, before=None,
                                   observer=lambda e: make_observation(True))
        self.assertEqual(with_no_before.status, Status.NOT_AVAILABLE)

        before = make_observation(0, kind="control_state")
        after = make_observation(1, kind="control_state")
        outcome = vf.verify(change, before=before, observer=lambda e: after)
        self.assertEqual(outcome.status, Status.VERIFIED)
        self.assertIn("0", outcome.reason)

    def test_an_unchanged_state_is_not_a_change(self):
        change = ex.Expectation(kind=ex.ExpectationKind.CONTROL_CHANGED,
                                target={"element_name": "Wrap"},
                                property="toggle_state", timeout=0.2)
        outcome = vf.verify(change, before=make_observation(1),
                            interval=0.05, observer=lambda e: make_observation(1))
        self.assertEqual(outcome.status, Status.NOT_VERIFIED)

    def test_the_outcome_says_what_was_expected(self):
        outcome = vf.verify(ex.window_exists({"title": "Notepad"}),
                            observer=lambda e: make_observation(True))
        self.assertIn("Notepad", outcome.describe())
        self.assertIn("VERIFIED", outcome.describe())


# ── execution layer integration ─────────────────────────────────────────────

class ResultsSeparateExecutionFromVerification(unittest.TestCase):

    def test_an_unverified_success_is_not_reported_as_success(self):
        result = ExecutionResult(status=ExecStatus.SUCCESS, action="windows_control",
                                 verified=False, verification_status="NOT_VERIFIED",
                                 final_status=ExecStatus.NOT_VERIFIED)
        self.assertEqual(result.status, ExecStatus.SUCCESS)
        self.assertEqual(result.outcome, ExecStatus.NOT_VERIFIED)
        self.assertFalse(result.verified)
        self.assertIn("final_status", result.to_dict())

    def test_a_verified_success_is_success(self):
        result = ExecutionResult(status=ExecStatus.SUCCESS, action="windows_control",
                                 verified=True, verification_status="VERIFIED",
                                 final_status=ExecStatus.SUCCESS)
        self.assertEqual(result.outcome, ExecStatus.SUCCESS)

    def test_an_action_without_verification_keeps_its_phase_2_meaning(self):
        result = ExecutionResult(status=ExecStatus.SUCCESS, action="weather_report")
        self.assertEqual(result.outcome, ExecStatus.SUCCESS)
        self.assertEqual(result.verification_status, "NOT_AVAILABLE")
        self.assertFalse(result.verified)

    def test_a_failed_action_still_fails_whatever_verification_says(self):
        result = ExecutionResult(status=ExecStatus.FAILED, action="windows_control",
                                 error=None)
        self.assertEqual(result.outcome, ExecStatus.FAILED)

    def test_not_verified_is_part_of_the_shared_error_taxonomy(self):
        self.assertEqual(ErrorKind.NOT_VERIFIED.value, "NOT_VERIFIED")


class ExecutionLayerDowngradesHonestResults(unittest.TestCase):
    """The layer, not just the engine: SUCCESS must not survive an absent effect.

    The fixture action below lives in *this* module, so the execution layer
    finds the module-level `expectation_for` and treats it like any action that
    declares a verification contract.
    """

    @unittest.skipUnless(_is_supported(), "Windows control is not available here")
    def test_a_successful_action_whose_effect_is_absent_is_not_reported_as_success(self):
        layer = ExecutionLayer(actions=make_action_registry(
            ("liar", lambda parameters=None, **kwargs: "Done.")), manager=None,
            security_policy=AuthorizationPolicy(
                overrides={"liar": RiskClass.LOW_RISK_REVERSIBLE}))
        result = layer.execute(ExecutionRequest(action="liar",
                                                arguments={"claim_window": True}))
        self.assertEqual(result.status, ExecStatus.SUCCESS, "the call itself did return")
        self.assertEqual(result.outcome, ExecStatus.NOT_VERIFIED)
        self.assertFalse(result.verified)
        self.assertEqual(result.verification_status, "NOT_VERIFIED")
        self.assertIn("Not verified", result.message)

    def test_an_action_that_declares_no_expectation_is_left_alone(self):
        layer = ExecutionLayer(actions=make_action_registry(
            ("plain", lambda parameters=None, **kwargs: "Done.")), manager=None,
            security_policy=AuthorizationPolicy(
                overrides={"plain": RiskClass.LOW_RISK_REVERSIBLE}))
        result = layer.execute(ExecutionRequest(action="plain", arguments={}))
        self.assertEqual(result.outcome, ExecStatus.SUCCESS)
        self.assertEqual(result.verification_status, "NOT_AVAILABLE")
        self.assertFalse(result.verified)

    def test_a_failing_action_is_never_rescued_by_verification(self):
        layer = ExecutionLayer(actions=make_action_registry(
            ("broken", lambda parameters=None, **kwargs: "Tool 'broken' failed: boom")),
            manager=None, security_policy=AuthorizationPolicy(
                overrides={"broken": RiskClass.LOW_RISK_REVERSIBLE}))
        result = layer.execute(ExecutionRequest(action="broken", arguments={}))
        self.assertEqual(result.status, ExecStatus.FAILED)
        self.assertEqual(result.outcome, ExecStatus.FAILED)
        self.assertFalse(result.verified)


def expectation_for(params: dict, data: dict):
    """The test double above claims to have opened a window that cannot exist.

    Declared at module level on purpose: the execution layer finds an action's
    verification contract by looking at the handler's own module, so this is
    exactly what a real action looks like from its side. It answers `None` for
    any call that did not ask to be checked, which is how the "no expectation"
    path is exercised against the very same module.
    """
    if not (params or {}).get("claim_window"):
        return None, None
    return None, Expectation(kind=ExpectationKind.WINDOW_EXISTS,
                             target={"window_handle": 0x7FFFFF00},
                             expected=True, compare="equals",
                             timeout=0.4, interval=0.1,
                             note="a window that does not exist")


if __name__ == "__main__":
    unittest.main()