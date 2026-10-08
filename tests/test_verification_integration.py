"""
Phase 4 on real Windows — observation and verification against live UI.

Run with:

    NEO_WINDOWS_INTEGRATION=1 python -m unittest tests.test_verification_integration -v

WHAT THIS PROVES
    That a VERIFIED verdict here came from reading the actual machine, and that
    the refusals — unverifiable, ambiguous, stale, cancelled — happen on real UI
    too, not only in unit tests built from invented observations.

WHAT IT DOES NOT PROVE
    It does not prove NEO can verify arbitrary actions. `invoke` deliberately
    has no rule, and the test below asserts exactly that: an unverifiable
    operation must come back NOT_AVAILABLE, not quietly pass.

THE SAME SAFETY RULE AS PHASE 3
    Windows that existed before this module started are never acted on and never
    closed. Notepad is single-instance, so the window under test is usually the
    user's own; anything written into it is read back and restored afterwards.
"""
from __future__ import annotations

import os
import threading
import time
import unittest

from core.verification import observation as obs
from core.verification import verifier as vf
from core.verification.expectations import (
    Expectation,
    ExpectationKind,
    expected_after,
    preconditions,
)
from core.verification.verifier import Status
from core.verification.world import EntryState, capture
from core.windows import control

ENABLED = bool(os.environ.get("NEO_WINDOWS_INTEGRATION"))
REASON = "set NEO_WINDOWS_INTEGRATION=1 to run tests that verify against real Windows"

PRE_EXISTING: set = set()


def _record_baseline():
    global PRE_EXISTING
    try:
        result = control.list_windows(include_untitled=True, limit=300)
        PRE_EXISTING = {w["handle"] for w in result.data.get("windows", [])}
    except Exception:
        PRE_EXISTING = set()


if ENABLED:
    _record_baseline()


def _wait_for(predicate, timeout=15.0, interval=0.4):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    return predicate()


class _RealNotepad:
    """A live Notepad window plus restore helpers, shared by the classes below."""

    opened: list = []
    handle = None

    @classmethod
    def notepad(cls) -> int:
        if cls.handle and control.locate_window(window_handle=cls.handle).status == "SUCCESS":
            return cls.handle
        launch = control.launch_app("notepad")
        window = launch.data.get("window") or launch.data.get("already_open") or {}
        cls.handle = window.get("handle")
        if not cls.handle:
            found = _wait_for(lambda: next(
                (w for w in control.list_windows(include_untitled=True, limit=200).data["windows"]
                 if (w.get("process_name") or "").lower() == "notepad.exe"), None))
            cls.handle = found["handle"] if found else None
        if cls.handle and cls.handle not in PRE_EXISTING and cls.handle not in cls.opened:
            cls.opened.append(cls.handle)
        if not cls.handle:
            raise AssertionError("Notepad never produced a window")
        return cls.handle

    @classmethod
    def document(cls):
        """The real text area, addressed the same way a caller would address it."""
        handle = cls.notepad()
        editors = _wait_for(lambda: control.list_controls(
            window_handle=handle, control_type="Document", limit=5,
            max_depth=10).data.get("controls", []), timeout=12.0)
        if not editors:
            raise AssertionError("Notepad published no Document control")
        return handle, editors[0]

    @classmethod
    def editor_args(cls):
        handle, editor = cls.document()
        args = {"window_handle": handle, "control_type": editor["control_type"]}
        if editor.get("automation_id"):
            args["automation_id"] = editor["automation_id"]
        return handle, args

    @classmethod
    def restore(cls, args):
        original = control.get_control_value(args)
        return original.data.get("value") if original.status == "SUCCESS" else None


@unittest.skipUnless(ENABLED, REASON)
class RealWindowVerification(unittest.TestCase):
    """Window existence, closure and focus, checked against Windows itself."""

    def test_a_window_that_exists_is_verified_by_asking_windows(self):
        launch = control.launch_app("notepad")
        self.assertEqual(launch.status, "SUCCESS", launch.message)
        window = launch.data.get("window") or launch.data.get("already_open") or {}
        handle = window.get("handle")
        self.assertIsNotNone(handle, "no window to verify")

        expectation = expected_after("launch_app", {"app_name": "notepad"},
                                     type("R", (), {"data": launch.data})())
        outcome = vf.verify(expectation)
        self.assertEqual(outcome.status, Status.VERIFIED, outcome.describe())
        self.assertTrue(outcome.observations[-1].ok)
        self.assertIn(outcome.observations[-1].source, (obs.Source.WIN32, obs.Source.APPS))

    def test_a_window_that_was_never_there_is_not_verified(self):
        expectation = Expectation(kind=ExpectationKind.WINDOW_EXISTS,
                                  target={"title": "zzz_no_such_window_zzz"},
                                  expected=True, compare="is_true", timeout=0.8)
        outcome = vf.verify(expectation)
        self.assertEqual(outcome.status, Status.NOT_VERIFIED, outcome.describe())
        self.assertFalse(outcome.verified)

    def test_focus_is_verified_against_the_real_foreground_window(self):
        handle = _RealNotepad.notepad()
        focused = control.focus_window(window_handle=handle)
        if focused.status != "SUCCESS":
            # Windows' foreground lock refuses activation when the user is
            # working at the same time. NEO reports that honestly, and there is
            # nothing to verify against — this is the environment, not a defect.
            self.skipTest(f"Windows refused to bring the window forward: "
                          f"{focused.message}")
        outcome = vf.verify(expected_after("focus_window", {"window_handle": handle}))
        self.assertEqual(outcome.status, Status.VERIFIED, outcome.describe())
        self.assertTrue(outcome.observations[-1].ok)

    def test_closing_a_window_that_is_still_open_is_not_verified(self):
        # The window is certainly there, so "it closed" must fail honestly rather
        # than pass because the close call returned. Both ends are checked here
        # rather than assumed: on a desktop someone is actually using, a window
        # can be closed by someone else mid-test, and then the test would be
        # measuring nothing at all.
        handle = _RealNotepad.notepad()
        before = control.locate_window(window_handle=handle)
        self.assertEqual(before.status, "SUCCESS",
                         f"the window under test is already gone: {before.message}")
        outcome = vf.verify(expected_after("close_window", {"window_handle": handle},
                                           timeout=0.8))
        after = control.locate_window(window_handle=handle)
        if after.status != "SUCCESS":
            self.skipTest("the window was closed by something else during the test, "
                          "so this would have measured nothing")
        self.assertEqual(outcome.status, Status.NOT_VERIFIED, outcome.describe())

    def test_a_handle_that_was_never_a_window_is_reported_gone(self):
        # Proved rather than assumed: Windows is asked first whether this handle
        # addresses anything, and only then is it used as the target.
        stale = 0x7FFFFFFF
        self.assertNotEqual(control.locate_window(window_handle=stale).status, "SUCCESS",
                            "this handle turned out to address a real window")
        expectation = Expectation(kind=ExpectationKind.WINDOW_EXISTS,
                                  target={"window_handle": stale},
                                  expected=True, compare="is_true", timeout=1.0)
        outcome = vf.verify(expectation)
        self.assertEqual(outcome.status, Status.NOT_VERIFIED, outcome.describe())
        self.assertFalse(outcome.verified)


@unittest.skipUnless(ENABLED, REASON)
class RealControlVerification(unittest.TestCase):
    """Value round-trips on a real control, without destroying what was there."""

    def setUp(self):
        self.handle, self.args = _RealNotepad.editor_args()
        self.original = _RealNotepad.restore(self.args)

    def tearDown(self):
        if self.original is not None:
            control.set_control_value({**self.args, "text": self.original})

    def test_written_text_is_verified_by_reading_it_back(self):
        marker = "neo phase 4 verification"
        written = control.set_control_value({**self.args, "text": marker})
        self.assertEqual(written.status, "SUCCESS", written.message)

        observation = obs.control_value(self.args)
        self.assertTrue(observation.ok, observation.describe())
        self.assertEqual(observation.value, marker)
        self.assertEqual(observation.source, obs.Source.UIA)

        outcome = vf.verify(expected_after(
            "set_value", {**self.args, "text": marker}))
        self.assertEqual(outcome.status, Status.VERIFIED, outcome.describe())

    def test_a_value_that_was_never_written_is_not_verified(self):
        outcome = vf.verify(expected_after(
            "set_value", {**self.args, "text": "this text was never written"},
            timeout=1.2))
        self.assertEqual(outcome.status, Status.NOT_VERIFIED, outcome.describe())

    def test_an_unverifiable_operation_is_not_available_rather_than_verified(self):
        # `invoke` has no universal rule. This is the honest answer, and it is
        # the whole reason Phase 4 cannot be faked.
        self.assertIsNone(expected_after("invoke", {**self.args,
                                                    "element_name": "File"}))
        outcome = vf.verify(expected_after("invoke", {**self.args,
                                                      "element_name": "File"}))
        self.assertEqual(outcome.status, Status.NOT_AVAILABLE)
        self.assertFalse(outcome.verified)

    def test_an_ambiguous_control_cannot_be_verified(self):
        discovered = control.list_controls(window_handle=self.handle, limit=140,
                                           max_depth=12, named_only=True)
        counts: dict = {}
        for element in discovered.data.get("controls", []):
            name = (element.get("name") or "").strip()
            if name:
                counts[name] = counts.get(name, 0) + 1
        duplicates = sorted(name for name, count in counts.items() if count > 1)
        if not duplicates:
            self.skipTest("this Notepad build published no duplicate control names")

        expectation = Expectation(kind=ExpectationKind.CONTROL_EXISTS,
                                  target={"window_handle": self.handle,
                                          "element_name": duplicates[0]},
                                  expected=True, compare="is_true", timeout=1.0)
        outcome = vf.verify(expectation)
        self.assertEqual(outcome.status, Status.AMBIGUOUS, outcome.describe())

    def test_cancelling_the_wait_is_truthful(self):
        cancelled = threading.Event()
        cancelled.set()
        outcome = vf.verify(expected_after("close_window", {"window_handle": self.handle}),
                            cancel_event=cancelled)
        self.assertEqual(outcome.status, Status.CANCELLED)
        self.assertFalse(outcome.verified)


@unittest.skipUnless(ENABLED, REASON)
class RealWorldState(unittest.TestCase):

    def test_the_world_state_is_made_of_real_observations(self):
        state = capture(max_windows=5)
        self.assertTrue(state.is_known("active_window"))
        self.assertEqual(state.entries["active_window"].source, obs.Source.WIN32)
        self.assertTrue(state.entries["active_window"].observed_at > 0)
        self.assertLessEqual(len(state.entries["visible_windows"].value or []), 5)

    def test_a_process_that_is_not_running_is_unknown_not_assumed(self):
        state = capture(max_windows=2, app_names=["zzz_no_such_process_zzz"])
        entry = state.entries["app:zzz_no_such_process_zzz"]
        self.assertIsNotNone(entry)
        self.assertIn(entry.state, (EntryState.OBSERVED, EntryState.UNKNOWN))
        if entry.state == EntryState.OBSERVED:
            self.assertFalse(entry.value)
        else:
            self.assertIsNone(entry.value)

    def test_stale_entries_stop_being_served_as_current(self):
        state = capture(max_windows=2)
        self.assertTrue(state.get("active_window"))
        state.mark_stale(["active_window"])
        self.assertIsNone(state.get("active_window"),
                          "a stale observation must not be served as current")
        self.assertEqual(state.entries["active_window"].state, EntryState.STALE)


if __name__ == "__main__":
    unittest.main()