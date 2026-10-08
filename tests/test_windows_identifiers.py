"""Element identification, key validation and sensitive-field handling."""
from __future__ import annotations

import unittest

from core.windows.errors import (
    WindowsError,
    WindowsErrorKind,
    access_denied,
    invalid_argument,
)
from core.windows.identifiers import (
    ElementQuery,
    build_runtime_id,
    describe_identity,
    filter_elements,
    matches,
    resolve_one,
)
from core.windows.keys import (
    MAX_COMBINATION,
    MAX_TEXT_LENGTH,
    describe_combination,
    normalize_key,
    parse_combination,
    validate_text,
)
from core.windows.models import UIElement
from core.windows.sensitive import apply, classify, redact, refuse_read, summarize_controls


def element(name="Save", control_type="Button", automation_id=None, **overrides) -> UIElement:
    base = dict(runtime_id=(id(name),), control_type=control_type, name=name,
                automation_id=automation_id)
    base.update(overrides)
    return UIElement(**base)


class TestMatching(unittest.TestCase):

    def test_every_supplied_field_must_match(self):
        target = element(name="Save", automation_id="saveBtn")
        self.assertTrue(matches(target, ElementQuery(automation_id="saveBtn")))
        self.assertFalse(matches(target, ElementQuery(automation_id="otherBtn")))
        self.assertTrue(matches(target, ElementQuery(name="Save", automation_id="saveBtn")))
        self.assertFalse(matches(target, ElementQuery(name="Save", automation_id="otherBtn")))

    def test_missing_fields_never_exclude(self):
        target = element(name="Save", automation_id=None)
        self.assertTrue(matches(target, ElementQuery(control_type="Button")))

    def test_matching_is_case_insensitive(self):
        target = element(name="Save")
        self.assertTrue(matches(target, ElementQuery(name="save")))

    def test_filter_returns_all_candidates(self):
        elements = [element("Save", automation_id="a"), element("Save", automation_id="b"),
                    element("Cancel")]
        self.assertEqual(len(filter_elements(elements, ElementQuery(name="Save"))), 2)
        self.assertEqual(len(filter_elements(elements, ElementQuery())), 3)


class TestResolution(unittest.TestCase):

    def test_single_match_resolves(self):
        found = resolve_one([element("Save"), element("Cancel")],
                            ElementQuery(name="Save"))
        self.assertEqual(found.name, "Save")

    def test_no_match_is_an_explicit_error(self):
        with self.assertRaises(WindowsError) as ctx:
            resolve_one([element("Save")], ElementQuery(name="Delete"))
        self.assertEqual(ctx.exception.kind, WindowsErrorKind.ELEMENT_NOT_FOUND)
        self.assertIn("Delete", ctx.exception.message)

    def test_several_matches_is_ambiguity_not_a_guess(self):
        candidates = [element("OK", automation_id="a"), element("OK", automation_id="b")]
        with self.assertRaises(WindowsError) as ctx:
            resolve_one(candidates, ElementQuery(name="OK"))
        error = ctx.exception
        self.assertEqual(error.kind, WindowsErrorKind.ELEMENT_AMBIGUOUS)
        self.assertIn("2 controls", error.message)
        self.assertIn("Button:a", error.message, "the caller must see the candidates")

    def test_index_is_the_deliberate_way_to_choose(self):
        candidates = [element("OK", automation_id="a"), element("OK", automation_id="b")]
        chosen = resolve_one(candidates, ElementQuery(name="OK", index=1))
        self.assertEqual(chosen.automation_id, "b")

    def test_out_of_range_index_is_refused_not_clamped(self):
        candidates = [element("OK", automation_id="a"), element("OK", automation_id="b")]
        with self.assertRaises(WindowsError) as ctx:
            resolve_one(candidates, ElementQuery(name="OK", index=5))
        self.assertEqual(ctx.exception.kind, WindowsErrorKind.INVALID_ARGUMENT)

    def test_non_numeric_index_is_refused(self):
        candidates = [element("OK", automation_id="a"), element("OK", automation_id="b")]
        with self.assertRaises(WindowsError):
            resolve_one(candidates, ElementQuery(name="OK", index="first"))

    def test_out_of_range_index_is_refused_even_with_one_candidate(self):
        # The caller's picture of the window is wrong either way; saying so is
        # better than quietly using the only match.
        with self.assertRaises(WindowsError):
            resolve_one([element("OK", automation_id="a")],
                        ElementQuery(name="OK", index=3))

    def test_query_describes_itself(self):
        described = ElementQuery(name="Save", control_type="Button").describe()
        self.assertIn("name='Save'", described)
        self.assertIn("type=Button", described)
        self.assertEqual(ElementQuery().describe(), "any control")

    def test_runtime_id_normalisation(self):
        self.assertEqual(build_runtime_id([1, 2, 3]), (1, 2, 3))
        self.assertEqual(build_runtime_id(None), ())
        self.assertEqual(build_runtime_id(["x"]), ())

    def test_identity_description_carries_the_caveat(self):
        info = describe_identity(element("Save", automation_id="saveBtn"))
        self.assertEqual(info["automation_id"], "saveBtn")
        self.assertIn("within the same application session", info["note"])


class TestKeys(unittest.TestCase):

    def test_aliases_normalise_to_one_spelling(self):
        for raw in ("CTRL", "Control", "ctl", "ctrl"):
            self.assertEqual(normalize_key(raw), "ctrl")
        self.assertEqual(normalize_key("Return"), "enter")
        self.assertEqual(normalize_key("Esc"), normalize_key("escape"))
        self.assertEqual(normalize_key("PgUp"), "pageup")
        self.assertEqual(normalize_key("a"), "a")
        self.assertEqual(normalize_key("7"), "7")

    def test_unknown_key_is_an_error_not_a_guess(self):
        with self.assertRaises(WindowsError) as ctx:
            normalize_key("definitely_not_a_key")
        self.assertEqual(ctx.exception.kind, WindowsErrorKind.INVALID_ARGUMENT)

    def test_combinations(self):
        self.assertEqual(parse_combination("ctrl+shift+s"), ["ctrl", "shift", "s"])
        self.assertEqual(parse_combination("CTRL + Shift + S"), ["ctrl", "shift", "s"])
        self.assertEqual(parse_combination("enter"), ["enter"])
        self.assertEqual(parse_combination("ctrl+plus"), ["ctrl", "+"])

    def test_modifier_alone_is_refused(self):
        with self.assertRaises(WindowsError):
            parse_combination("ctrl")

    def test_oversized_and_duplicate_combinations_are_refused(self):
        with self.assertRaises(WindowsError):
            parse_combination("ctrl+shift+alt+win+a")
        with self.assertRaises(WindowsError):
            parse_combination("a+a")
        with self.assertRaises(WindowsError):
            parse_combination("")

    def test_no_raw_keycode_escape_hatch(self):
        # There is no syntax that turns an arbitrary number into a keystroke.
        for attempt in ("0x41", "65", "VK_FOO", "scan_code:29"):
            with self.assertRaises(WindowsError):
                parse_combination(attempt)

    def test_text_validation_rejects_control_characters(self):
        self.assertEqual(validate_text("hello"), "hello")
        with self.assertRaises(WindowsError):
            validate_text("line\nbreak")
        with self.assertRaises(WindowsError):
            validate_text("esc\x1b[2J")
        with self.assertRaises(WindowsError) as ctx:
            validate_text("x" * (MAX_TEXT_LENGTH + 1))
        self.assertIn("limit", ctx.exception.message)

    def test_describe(self):
        self.assertEqual(describe_combination(["ctrl", "s"]), "ctrl+s")


class TestSensitiveFields(unittest.TestCase):

    def test_is_password_flag_is_authoritative(self):
        item = element("Password", control_type="Edit")
        sensitive, reason = classify(item, is_password=True)
        self.assertTrue(sensitive)
        self.assertIn("IsPassword", reason)

    def test_conventional_names_are_detected_on_value_bearing_controls(self):
        for name in ("Password", "passwordField", "Pwd", "API key", "Card number",
                     "Verification code", "PIN"):
            with self.subTest(name=name):
                item = element(name, control_type="Edit")
                self.assertTrue(classify(item)[0])

    def test_automation_id_is_considered(self):
        item = element("txt1", control_type="Edit", automation_id="currentPassword")
        self.assertTrue(classify(item)[0])

    def test_buttons_are_never_treated_as_credential_fields(self):
        # A button named "Password" cannot hold a value.
        self.assertFalse(classify(element("Password", control_type="Button"))[0])

    def test_ordinary_fields_are_not_flagged(self):
        self.assertFalse(classify(element("Search", control_type="Edit"))[0])

    def test_apply_stamps_the_element(self):
        item = element("Password", control_type="Edit")
        apply(item)
        self.assertTrue(item.sensitive)
        self.assertTrue(item.sensitive_reason)

    def test_reading_a_credential_is_refused(self):
        item = element("Password", control_type="Edit")
        apply(item)
        with self.assertRaises(WindowsError) as ctx:
            refuse_read(item)
        self.assertEqual(ctx.exception.kind, WindowsErrorKind.ACCESS_DENIED)
        self.assertNotIn("value", ctx.exception.message.lower().split("credential")[0])

    def test_reading_an_ordinary_field_is_allowed(self):
        refuse_read(element("Search", control_type="Edit"))     # must not raise

    def test_redaction_keeps_the_shape_not_the_value(self):
        self.assertEqual(redact("hunter2"), "<7 characters redacted>")
        self.assertEqual(redact(None), "")

    def test_summary_never_leaks_a_value(self):
        items = [element("Password", control_type="Edit"),
                 element("Search", control_type="Edit")]
        apply(items[0])
        summary = summarize_controls(items)
        self.assertIn("value withheld", summary)
        self.assertIn("Edit:Search", summary)


class TestPlatformBoundary(unittest.TestCase):

    def test_facade_reports_not_available_off_windows(self):
        import core.windows as boundary
        import core.windows.control as control
        original = boundary.IS_WINDOWS
        try:
            boundary.IS_WINDOWS = False
            result = control.active_window()
            self.assertEqual(result.status, "NOT_AVAILABLE")
            self.assertFalse(result.ok)
            self.assertIn("Windows", result.message)
            self.assertIsNotNone(boundary.unavailable_reason())
        finally:
            boundary.IS_WINDOWS = original

    def test_status_mapping_covers_every_windows_kind(self):
        from core.windows.control import _STATUS_BY_KIND
        from core.windows.errors import WindowsErrorKind as K
        self.assertEqual(_STATUS_BY_KIND[K.ELEMENT_NOT_FOUND], "NOT_AVAILABLE")
        self.assertEqual(_STATUS_BY_KIND[K.UNSUPPORTED_CONTROL], "NOT_SUPPORTED")
        self.assertEqual(_STATUS_BY_KIND[K.CANCELLED], "CANCELLED")
        self.assertEqual(_STATUS_BY_KIND[K.ELEMENT_STALE], "FAILED")

    def test_cancellation_stops_before_windows_is_touched(self):
        import threading

        import core.windows.control as control
        event = threading.Event()
        event.set()
        result = control.active_window(cancel_event=event)
        self.assertEqual(result.status, "CANCELLED")
        self.assertFalse(result.ok)
        self.assertEqual(result.error.kind, WindowsErrorKind.CANCELLED)

    def test_mutating_operations_are_listed_for_the_later_policy_layer(self):
        import core.windows.control as control
        self.assertIn("invoke", control.MUTATING_OPERATIONS)
        self.assertIn("close_window", control.CONFIRMATION_REQUIRED)
        self.assertNotIn("list_windows", control.MUTATING_OPERATIONS)


if __name__ == "__main__":
    unittest.main()