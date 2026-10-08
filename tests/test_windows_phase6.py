"""
Phase 6 — PC control improvements, tested without a desktop.

Every test here replaces the one thing it must: the Windows read. The scoring
rules, the refusal conditions, the classification rules and the entry chain are
the production ones, and a test that passes here is saying something about the
code that runs on a real machine — not about a mock.

What is being pinned down, per part:

  * targeting scores live windows and refuses to guess between two that tie;
  * discovery answers "what can I press here" as a summary, not a tree;
  * dialogs are classified from what they show, and authentication is off
    limits whatever the button says;
  * launch detection distinguishes "a process started" from "there is a window
    NEO can drive";
  * text entry chooses a method, refuses credential fields, and compares what
    was written with what was read back.
"""
from __future__ import annotations

import unittest

from core.windows import control, dialogs, discovery, launch, targeting, typing
from core.windows.errors import WindowsError, WindowsErrorKind
from core.windows.identifiers import ElementQuery
from core.windows.models import Rect, UIElement, WindowInfo
from core.windows.targeting import WindowTargetor


def window(handle: int, title: str = "", pid: int = 100,
           process: str = "notepad.exe", active: bool = False,
           minimized: bool = False, cls: str = "Notepad") -> WindowInfo:
    return WindowInfo(handle=handle, title=title, process_id=pid,
                      process_name=process, class_name=cls, is_active=active,
                      minimized=minimized, visible=True,
                      bounds=Rect.from_values(0, 0, 100, 100))


def element(control_type: str = "Button", name: str = "", automation_id: str = "",
            enabled: bool = True, offscreen: bool = False,
            sensitive: bool = False, capabilities=("invoke",),
            window_handle: int = 1) -> UIElement:
    return UIElement(control_type=control_type, name=name or None,
                     automation_id=automation_id or None,
                     enabled=enabled, offscreen=offscreen, sensitive=sensitive,
                     sensitive_reason="a password pattern" if sensitive else "",
                     capabilities=tuple(capabilities), window_handle=window_handle,
                     runtime_id=(42,))


class _NoWindows:
    """A targetor whose window list is whatever a test gives it."""

    def __init__(self, windows):
        self._windows = list(windows)

    def windows(self, refresh: bool = False):
        return list(self._windows)

    def candidates(self, **kwargs):
        kwargs.pop("refresh", None)
        return targeting.score_windows(self._windows, **kwargs)

    match = WindowTargetor.match
    resolve = WindowTargetor.resolve


class WindowTargetingIsScoredNotGuessed(unittest.TestCase):
    """4.1 Window targeting."""

    def test_an_exact_title_beats_a_partial_one(self):
        windows = [window(1, "Notes"), window(2, "Notes — backup")]
        scored = targeting.score_windows(windows, title="notes")
        self.assertEqual(scored[0].window.handle, 1)
        self.assertGreater(scored[0].score, scored[1].score)

    def test_a_process_name_matches_even_when_the_title_does_not(self):
        windows = [window(1, "Something else", process="CalculatorApp.exe")]
        scored = targeting.score_windows(windows, process_name="calculator")
        self.assertEqual(len(scored), 1)

    def test_two_windows_that_tie_are_ambiguous_not_guessed(self):
        windows = [window(1, "Notes"), window(2, "Notes")]
        scored = targeting.score_windows(windows, title="notes")
        top = [c for c in scored if c.score == scored[0].score]
        self.assertEqual(len(top), 2)

        targetor = _NoWindows(windows)
        with self.assertRaises(WindowsError) as caught:
            targetor.match(title="notes")
        self.assertEqual(caught.exception.kind,
                         WindowsErrorKind.ELEMENT_AMBIGUOUS)
        self.assertIn("notes", caught.exception.message.lower())

    def test_an_index_is_the_callers_own_choice_not_the_planners(self):
        windows = [window(1, "Notes"), window(2, "Notes")]
        targetor = _NoWindows(windows)
        match = targetor.match(title="notes", index=1)
        self.assertEqual(match.window.handle, 2)
        self.assertTrue(match.ambiguous)

    def test_an_index_past_the_end_is_refused_rather_than_clamped(self):
        targetor = _NoWindows([window(1, "Notes"), window(2, "Notes")])
        with self.assertRaises(WindowsError) as caught:
            targetor.match(title="notes", index=7)
        self.assertEqual(caught.exception.kind, WindowsErrorKind.INVALID_ARGUMENT)

    def test_nothing_matching_is_a_window_not_found_with_a_real_reason(self):
        targetor = _NoWindows([window(1, "Calculator")])
        with self.assertRaises(WindowsError) as caught:
            targetor.match(title="telegram")
        self.assertEqual(caught.exception.kind,
                         WindowsErrorKind.WINDOW_NOT_FOUND)
        self.assertIn("telegram", caught.exception.message)
        self.assertIn("Nothing was closed", caught.exception.message)

    def test_a_stale_handle_is_re_resolved_by_identity_when_there_is_one(self):
        # The handle is gone, but the process that owned it still has a window.
        windows = [window(99, "Notes", process="notepad.exe")]
        targetor = _NoWindows(windows)
        match = targetor.match(window_handle=4242, process_name="notepad")
        self.assertEqual(match.window.handle, 99)
        self.assertTrue(match.re_resolved)

    def test_a_window_that_does_not_match_the_request_is_not_a_candidate(self):
        # The bug this module exists to prevent: "every visible window is a
        # candidate" turns "telegram" into whichever window happens to be open.
        targetor = _NoWindows([window(1, "Calculator"), window(2, "Photos")])
        with self.assertRaises(WindowsError):
            targetor.match(title="telegram")

    def test_a_stale_handle_is_not_re_resolved_into_a_guess(self):
        # Two windows of the same process is a question for the user.
        windows = [window(98, "Notes — a", process="notepad.exe"),
                   window(99, "Notes — b", process="notepad.exe")]
        targetor = _NoWindows(windows)
        with self.assertRaises(WindowsError):
            targetor.match(window_handle=4242, process_name="notepad")

    def test_a_request_with_nothing_to_match_is_an_argument_error(self):
        with self.assertRaises(WindowsError) as caught:
            _NoWindows([window(1)]).match()
        self.assertEqual(caught.exception.kind, WindowsErrorKind.INVALID_ARGUMENT)

    def test_the_match_records_why_it_chose(self):
        targetor = _NoWindows([window(1, "Notes")])
        match = targetor.match(title="notes")
        self.assertTrue(match.reason)
        self.assertEqual(match.to_dict()["window"]["handle"], 1)

    def test_a_foreground_window_is_preferred_when_nothing_else_says(self):
        windows = [window(1, "Notes"), window(2, "Notes", active=True)]
        scored = targeting.score_windows(windows, title="note")
        self.assertEqual(scored[0].window.handle, 2)


class DiscoveryAnswersTheQuestion(unittest.TestCase):
    """4.2 UI Automation discovery."""

    def test_two_controls_that_match_are_reported_as_ambiguous(self):
        elements = [element(name="Send"), element(name="Send")]
        found = discovery.find_all(elements, ElementQuery(name="Send"))
        self.assertEqual(found.count, 2)
        self.assertTrue(found.ambiguous)

    def test_an_automation_id_wins_over_a_name(self):
        elements = [element(name="Send", automation_id="sendButton"),
                    element(name="Send")]
        found = discovery.find_all(elements, ElementQuery(name="Send"))
        self.assertEqual(found.best().element.automation_id, "sendButton")

    def test_a_disabled_or_offscreen_control_scores_lower(self):
        elements = [element(name="Save"), element(name="Save", enabled=False,
                                                   offscreen=True)]
        found = discovery.find_all(elements, ElementQuery(name="Save"))
        self.assertTrue(found.best().element.enabled)
        self.assertIn("off screen", " ".join(found.hits[-1].reasons))

    def test_a_credential_field_is_deprioritised_and_says_so(self):
        elements = [element(name="Password", sensitive=True,
                            capabilities=("value",)),
                    element(name="Password", sensitive=False)]
        found = discovery.find_all(elements, ElementQuery(name="Password"))
        self.assertFalse(found.best().element.sensitive)
        self.assertIn("withheld", " ".join(found.hits[-1].reasons))

    def test_the_result_is_bounded(self):
        elements = [element(name="Item") for _ in range(200)]
        found = discovery.find_all(elements, ElementQuery(name="Item"),
                                   limit=5)
        self.assertEqual(found.count, 5)
        self.assertTrue(found.truncated)
        self.assertEqual(found.total_found, 200)

    def test_a_summary_groups_by_role_instead_of_listing_controls(self):
        elements = ([element("Button", name=f"B{i}") for i in range(4)]
                    + [element("Edit", name="Field")]
                    + [element("Pane", name="")])
        summary = discovery.summarize(elements)
        self.assertEqual(summary["total_controls"], 6)
        self.assertEqual(summary["control_types"], 3)
        by_type = {g["control_type"]: g["count"] for g in summary["groups"]}
        self.assertEqual(by_type["Button"], 4)

    def test_an_interactive_summary_drops_the_layout_furniture(self):
        elements = ([element("Button", name="OK")] + [element("Pane", name="")]
                    + [element("Separator", name="")])
        everything = discovery.summarize(elements, interactive_only=False)
        interactive = discovery.summarize(elements, interactive_only=True)
        self.assertGreater(everything["control_types"], interactive["control_types"])

    def test_the_summary_counts_credential_fields_without_reading_them(self):
        summary = discovery.summarize([element("Edit", name="Pin", sensitive=True)])
        self.assertEqual(summary["sensitive_controls"], 1)

    def test_the_text_summary_is_bounded(self):
        elements = [element("Button", name=f"B{i}") for i in range(500)]
        text = discovery.summarize_text(discovery.summarize(elements))
        self.assertLessEqual(len(text.splitlines()), 13)

    def test_describe_mentions_a_controls_abilities_and_limits(self):
        line = discovery.describe(discovery.Hit(element=element(name="Send",
                                                                 sensitive=True)))
        self.assertIn("credential", line)


class DialogsAreClassifiedNotGuessed(unittest.TestCase):
    """4.5 Dialog handling."""

    def _classify(self, buttons, extra=()):
        elements = [element("Button", name=b) for b in buttons] + list(extra)
        return dialogs.classify({"handle": 1, "title": "Test"}, elements)

    def test_a_confirmation_dialog_is_recognised(self):
        report = self._classify(["OK", "Cancel"])
        self.assertEqual(report.kind, dialogs.CONFIRMATION)
        self.assertTrue(report.dismissible)

    def test_a_save_dialog_is_recognised_and_not_dismissible(self):
        report = self._classify(["Save", "Don't Save", "Cancel"])
        self.assertEqual(report.kind, dialogs.SAVE)
        self.assertFalse(report.dismissible)

    def test_a_permission_dialog_is_off_limits_however_it_is_worded(self):
        report = self._classify(["Allow", "Deny", "Grant access"])
        self.assertEqual(report.kind, dialogs.PERMISSION)
        self.assertFalse(report.may_act)

    def test_a_credential_field_makes_it_an_authentication_dialog(self):
        report = self._classify(["OK", "Cancel"],
                                extra=[element("Edit", name="Password",
                                               sensitive=True)])
        self.assertEqual(report.kind, dialogs.AUTHENTICATION)
        self.assertFalse(report.may_act)
        self.assertEqual(report.credential_fields, 1)
        self.assertIn("themselves", report.advice)

    def test_a_file_picker_is_recognised_and_may_be_cancelled(self):
        report = self._classify(["Open", "Save", "Cancel"])
        self.assertEqual(report.kind, dialogs.FILE_PICKER)
        self.assertTrue(dialogs.may_dismiss(report.kind))
        self.assertEqual(dialogs.dismiss_target(report), "Cancel")

    def test_a_save_prompt_is_not_mistaken_for_a_file_chooser(self):
        # Same "Save" and "Cancel" words, but no "Open": a chooser offers both.
        report = self._classify(["Save", "Don't Save", "Cancel"])
        self.assertEqual(report.kind, dialogs.SAVE)

    def test_a_dialog_with_unrecognised_buttons_is_modal_not_a_yes_no(self):
        report = self._classify(["Proceed", "Resume", "Something Else"])
        self.assertEqual(report.kind, dialogs.MODAL)
        self.assertFalse(report.dismissible)
        self.assertIn("does not know", report.advice)

    def test_an_empty_window_is_unknown_and_never_upgraded(self):
        report = dialogs.classify({"handle": 1}, [])
        self.assertEqual(report.kind, dialogs.UNKNOWN)
        self.assertFalse(report.may_act is False and report.kind != dialogs.UNKNOWN)

    def test_authentication_is_never_actionable_whatever_the_buttons(self):
        self.assertFalse(dialogs.may_act_on(dialogs.AUTHENTICATION))
        self.assertFalse(dialogs.may_act_on(dialogs.PERMISSION))
        self.assertTrue(dialogs.may_act_on(dialogs.CONFIRMATION))

    def test_only_two_dialog_kinds_may_ever_be_closed(self):
        self.assertEqual(set(dialogs.DISMISSIBLE),
                         {dialogs.CONFIRMATION, dialogs.FILE_PICKER})

    def test_dismiss_prefers_cancel_over_ok(self):
        report = self._classify(["OK", "Cancel"])
        self.assertEqual(dialogs.dismiss_target(report), "Cancel")


class LaunchDetectionSeparatesTheFacts(unittest.TestCase):
    """4.6 Application launching."""

    def test_a_new_controllable_window_is_reported_as_one(self):
        report = {"application": "notepad", "pid": 1, "process_alive_after_wait": True,
                  "window": {"handle": 7, "title": "Untitled - Notepad",
                             "process_id": 2,
                             "chosen_because": "it publishes accessible controls"}}
        outcome = launch.classify(report, follow=False)
        self.assertEqual(outcome.detection, launch.NEW_WINDOW)
        self.assertTrue(outcome.controlled)
        self.assertEqual(outcome.window["handle"], 7)

    def test_a_process_with_no_window_is_not_a_controllable_window(self):
        report = {"application": "traytool", "pid": 5,
                  "process_alive_after_wait": True, "window": None}
        outcome = launch.classify(report, follow=False)
        self.assertEqual(outcome.detection, launch.PROCESS_ONLY)
        self.assertFalse(outcome.controlled)
        self.assertIsNone(outcome.window)
        self.assertIn("no window", outcome.describe())

    def test_a_stub_that_exited_and_opened_nothing_says_so(self):
        report = {"application": "stubapp", "pid": 6,
                  "process_alive_after_wait": False, "window": None}
        outcome = launch.classify(report, follow=False)
        self.assertEqual(outcome.detection, launch.NOTHING_HAPPENED)
        self.assertFalse(outcome.controlled)

    def test_an_already_running_application_is_not_reported_as_new(self):
        report = {"application": "notepad", "pid": 7, "process_alive_after_wait": True,
                  "window": None,
                  "already_open": {"handle": 3, "title": "Notes",
                                   "process_id": 4,
                                   "chosen_because": "already open"}}
        outcome = launch.classify(report, follow=False)
        self.assertEqual(outcome.detection, launch.EXISTING_WINDOW)
        self.assertIn("already running", outcome.describe())

    def test_a_window_that_publishes_no_controls_is_flagged_as_undrivable(self):
        report = {"application": "weird", "pid": 8, "process_alive_after_wait": True,
                  "window": {"handle": 9, "title": "Weird", "process_id": 10,
                             "chosen_because": "it publishes no accessible "
                                               "controls, so NEO cannot drive it"}}
        outcome = launch.classify(report, follow=False)
        self.assertFalse(outcome.controlled)
        self.assertTrue(any("cannot operate" in c for c in outcome.caveats))

    def test_a_handed_off_launch_is_named_as_such(self):
        report = {"application": "notepad", "pid": 9, "handed_off": True,
                  "process_alive_after_wait": False,
                  "window": {"handle": 10, "title": "Untitled", "process_id": 11,
                             "chosen_because": "it publishes accessible controls"}}
        outcome = launch.classify(report, follow=False)
        self.assertEqual(outcome.detection, launch.HANDED_OFF)
        self.assertTrue(any("app stubs" in c for c in outcome.caveats))

    def test_a_settings_uri_is_not_an_application_window(self):
        report = {"application": "settings", "target": "ms-settings:display",
                  "window": None}
        outcome = launch.classify(report, follow=False)
        self.assertEqual(outcome.detection, launch.SETTINGS_URI)
        self.assertFalse(outcome.controlled)


class TextEntryIsAChainNotAKeystroke(unittest.TestCase):
    """4.4 Keyboard and input reliability."""

    def test_the_value_pattern_is_preferred_where_the_control_has_one(self):
        self.assertEqual(typing.choose_method(element(capabilities=("value",)),
                                              "hello"),
                         typing.METHOD_VALUE_PATTERN)

    def test_the_keyboard_is_the_fallback_for_an_editor(self):
        self.assertEqual(typing.choose_method(element(capabilities=()), "hello"),
                         typing.METHOD_KEYBOARD)

    def test_long_or_non_ascii_text_goes_through_the_clipboard(self):
        self.assertEqual(typing.choose_method(element(capabilities=()),
                                              "x" * typing.MAX_KEYBOARD_CHARS + "x"),
                         typing.METHOD_CLIPBOARD)
        self.assertEqual(typing.choose_method(element(capabilities=()),
                                              "café — naïve"),
                         typing.METHOD_CLIPBOARD)

    def test_a_normalised_read_back_counts_as_a_match(self):
        # Applications normalise line endings on the way in; reporting that as
        # a failed entry would be as dishonest as the reverse.
        self.assertTrue(typing._equivalent("line1\r\nline2\r\n", "line1\nline2"))

    def test_trailing_whitespace_is_normalised_but_content_is_not(self):
        self.assertTrue(typing._equivalent("hello   ", "hello"))
        self.assertFalse(typing._equivalent("hello", "hello there"))
        self.assertFalse(typing._equivalent("HELLO", "hello"))

    def test_a_non_string_read_back_is_never_a_match(self):
        self.assertFalse(typing._equivalent(42, "42"))

    def test_a_credential_field_is_refused_before_anything_is_written(self):
        secret = element(control_type="Edit", name="Password", sensitive=True,
                         capabilities=("value",))
        with self.assertRaises(WindowsError) as caught:
            typing.write_into(None, secret, "hunter2")
        self.assertEqual(caught.exception.kind, WindowsErrorKind.ACCESS_DENIED)
        self.assertIn("themselves", caught.exception.message)

    def test_a_disabled_control_is_refused(self):
        with self.assertRaises(WindowsError) as caught:
            typing.write_into(None, element(enabled=False), "x")
        self.assertEqual(caught.exception.kind, WindowsErrorKind.ELEMENT_DISABLED)

    def test_an_unknown_write_method_is_refused(self):
        with self.assertRaises(WindowsError) as caught:
            typing.write_into(None, element(), "x", prefer="telepathy")
        self.assertEqual(caught.exception.kind, WindowsErrorKind.INVALID_ARGUMENT)

    def test_a_cancelled_goal_stops_before_anything_is_written(self):
        import threading

        cancelled = threading.Event()
        cancelled.set()
        with self.assertRaises(WindowsError) as caught:
            typing.write_into(None, element(), "x", cancel_event=cancelled)
        self.assertEqual(caught.exception.kind, WindowsErrorKind.CANCELLED)

    def test_nothing_written_is_reported_as_nothing_written(self):
        result = typing.no_target("no such field")
        self.assertFalse(result.written)
        self.assertEqual(result.to_dict()["refused"], "no such field")
        self.assertEqual(result.to_dict()["characters"], 0)

    def test_an_entry_result_carries_the_read_back_verdict(self):
        result = typing.entry_result(element(), {"method": "keyboard"}, "hi",
                                     "hi", True, True, ["focused"])
        payload = result.to_dict()
        self.assertTrue(payload["written"])
        self.assertTrue(payload["read_back_matches"])
        self.assertTrue(payload["focused_confirmed"])


class TheFacadeExposesEveryNewCapability(unittest.TestCase):
    """The contract Phase 6 added to the Windows façade."""

    def test_every_phase6_operation_is_registered(self):
        for name in ("resolve_window", "find_controls", "describe_controls",
                     "type_into", "classify_dialog", "dismiss_dialog"):
            self.assertIn(name, control.OPERATIONS)

    def test_the_new_mutating_operations_are_listed_as_mutating(self):
        for name in ("type_into", "dismiss_dialog"):
            self.assertIn(name, control.MUTATING_OPERATIONS)

    def test_dismissing_a_dialog_needs_the_user_and_closing_a_window_still_does(self):
        self.assertIn("dismiss_dialog", control.CONFIRMATION_REQUIRED)
        self.assertIn("close_window", control.CONFIRMATION_REQUIRED)

    def test_typing_is_not_gated_because_the_target_check_is_stronger(self):
        # `type_into` is refused on a credential field and must resolve its
        # target unambiguously; a question there would be noise, not safety.
        self.assertNotIn("type_into", control.CONFIRMATION_REQUIRED)

    def test_launching_stays_ungated_for_the_phase3_reason(self):
        self.assertNotIn("launch_app", control.CONFIRMATION_REQUIRED)

    def test_reading_a_control_state_is_still_not_model_callable(self):
        self.assertNotIn("read_control_state", control.OPERATIONS)


if __name__ == "__main__":
    unittest.main()