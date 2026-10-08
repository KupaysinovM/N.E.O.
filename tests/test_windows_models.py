"""UI element, window and rectangle models — serialisation and honest absence."""
from __future__ import annotations

import unittest

from core.windows.errors import (
    WindowsError,
    WindowsErrorKind,
    application_not_found,
    element_ambiguous,
    element_not_found,
    invalid_argument,
    timeout,
    to_error_kind,
)
from core.windows.models import (
    COMMON_CONTROL_TYPES,
    ProcessInfo,
    Rect,
    UIElement,
    WindowInfo,
)


class TestRect(unittest.TestCase):

    def test_geometry(self):
        rect = Rect(10, 20, 110, 220)
        self.assertEqual(rect.width, 100)
        self.assertEqual(rect.height, 200)
        self.assertEqual(rect.center, (60, 120))
        self.assertFalse(rect.empty)

    def test_collapsed_rectangle_is_empty(self):
        self.assertTrue(Rect(5, 5, 5, 5).empty)
        self.assertTrue(Rect().empty)

    def test_from_values_rejects_what_windows_cannot_report(self):
        self.assertIsNone(Rect.from_values(0, 0, 0, 0))
        self.assertIsNone(Rect.from_values(None, None, None, None))
        self.assertIsNone(Rect.from_values("a", 0, 1, 1))
        self.assertIsNotNone(Rect.from_values(1, 2, 3, 4))

    def test_round_trip(self):
        rect = Rect(1, 2, 3, 4)
        again = Rect.from_dict(rect.to_dict())
        self.assertEqual((again.left, again.top, again.right, again.bottom), (1, 2, 3, 4))
        self.assertIsNone(Rect.from_dict(None))
        self.assertIsNone(Rect.from_dict({"left": "x"}))


class TestUIElement(unittest.TestCase):

    def _element(self, **overrides) -> UIElement:
        base = dict(runtime_id=(1, 2, 3), control_type="Button", name="Save",
                    automation_id="saveButton", class_name=None, framework_id="WPF",
                    enabled=True, visible=True, offscreen=False, bounds=Rect(0, 0, 10, 10),
                    capabilities=("invoke",), process_id=42, window_handle=99, depth=2)
        base.update(overrides)
        return UIElement(**base)

    def test_absent_fields_are_none_not_fake_values(self):
        element = self._element(automation_id=None, class_name=None, framework_id=None,
                                enabled=None, visible=None, bounds=None)
        self.assertIsNone(element.automation_id)
        self.assertIsNone(element.class_name)
        self.assertIsNone(element.enabled)
        self.assertIsNone(element.bounds)
        self.assertIn("no automation id", element.identity_note)

    def test_serialisation_round_trip(self):
        element = self._element()
        again = UIElement.from_dict(element.to_dict())
        self.assertEqual(again.runtime_id, (1, 2, 3))
        self.assertEqual(again.capabilities, ("invoke",))
        self.assertEqual(again.bounds, Rect(0, 0, 10, 10))
        self.assertEqual(again.automation_id, "saveButton")

    def test_element_id_is_a_label_not_an_identity(self):
        element = self._element(automation_id=None, name="Save")
        self.assertEqual(element.element_id, "Button:Save")
        self.assertNotIn("permanent", element.identity_note)

    def test_capabilities(self):
        element = self._element(capabilities=("invoke", "toggle"))
        self.assertTrue(element.can("invoke"))
        self.assertFalse(element.can("value"))
        self.assertEqual(element.supports, {"invoke": True, "toggle": True})

    def test_describe_flags_state(self):
        element = self._element(enabled=False, visible=True, offscreen=True, sensitive=True)
        text = element.describe()
        self.assertIn("disabled", text)
        self.assertIn("offscreen", text)
        self.assertIn("sensitive", text)

    def test_sensitive_element_survives_serialisation(self):
        element = self._element(sensitive=True, sensitive_reason="IsPassword")
        again = UIElement.from_dict(element.to_dict())
        self.assertTrue(again.sensitive)
        self.assertEqual(again.sensitive_reason, "IsPassword")

    def test_control_type_vocabulary_is_documented_not_enforced(self):
        # An unknown type is kept as Windows reported it, never coerced.
        element = self._element(control_type="SomeFutureControl")
        self.assertEqual(element.control_type, "SomeFutureControl")
        self.assertIn("Button", COMMON_CONTROL_TYPES)


class TestWindowAndProcess(unittest.TestCase):

    def test_window_serialisation(self):
        window = WindowInfo(handle=123, title="Notepad", process_id=7,
                            process_name="Notepad.exe", minimized=False,
                            bounds=Rect(0, 0, 800, 600), is_active=True)
        again = WindowInfo.from_dict(window.to_dict())
        self.assertEqual(again.handle, 123)
        self.assertEqual(again.bounds.height, 600)
        self.assertTrue(again.is_active)

    def test_untitled_window_gets_a_honest_label(self):
        self.assertIn("untitled", WindowInfo(handle=5).label)

    def test_title_match_is_case_insensitive_substring(self):
        window = WindowInfo(handle=1, title="Untitled - Notepad")
        self.assertTrue(window.matches("notepad"))
        self.assertTrue(window.matches("Untitled"))
        self.assertFalse(window.matches(""))
        self.assertFalse(window.matches("calculator"))

    def test_process_serialisation(self):
        again = ProcessInfo.from_dict(ProcessInfo(pid=3, name="a.exe",
                                                  window_titles=("x",)).to_dict())
        self.assertEqual(again.window_titles, ("x",))


class TestErrorTaxonomy(unittest.TestCase):

    def test_every_required_case_exists(self):
        required = {
            "WINDOW_NOT_FOUND", "ELEMENT_NOT_FOUND", "ELEMENT_AMBIGUOUS",
            "ELEMENT_DISABLED", "ELEMENT_STALE", "UNSUPPORTED_CONTROL",
            "INVALID_ARGUMENT", "TIMEOUT", "ACCESS_DENIED", "PROCESS_NOT_FOUND",
            "APPLICATION_NOT_FOUND", "OS_ERROR", "CANCELLED",
        }
        available = {getattr(WindowsErrorKind, name) for name in dir(WindowsErrorKind)
                     if name.isupper()}
        self.assertTrue(required.issubset(available))

    def test_windows_kinds_map_into_the_shared_taxonomy(self):
        from core.task_models import ErrorKind
        pairs = [
            (WindowsErrorKind.ELEMENT_STALE, ErrorKind.ELEMENT_STALE),
            (WindowsErrorKind.ELEMENT_AMBIGUOUS, ErrorKind.ELEMENT_AMBIGUOUS),
            (WindowsErrorKind.UNSUPPORTED_CONTROL, ErrorKind.UNSUPPORTED_CONTROL),
            (WindowsErrorKind.TIMEOUT, ErrorKind.TIMEOUT),
            (WindowsErrorKind.ACCESS_DENIED, ErrorKind.ACCESS_DENIED),
            (WindowsErrorKind.CANCELLED, ErrorKind.TASK_CANCELLED),
            (WindowsErrorKind.INVALID_ARGUMENT, ErrorKind.INVALID_ARGUMENTS),
        ]
        for windows_kind, expected in pairs:
            self.assertEqual(to_error_kind(windows_kind), expected)

    def test_unknown_kind_does_not_invent_one(self):
        from core.task_models import ErrorKind
        self.assertEqual(to_error_kind("SOMETHING_NEW"), ErrorKind.OS_ERROR)

    def test_constructors_carry_their_own_kind(self):
        self.assertEqual(element_not_found("a Button named 'x'").kind,
                         WindowsErrorKind.ELEMENT_NOT_FOUND)
        self.assertEqual(application_not_found("Foo").kind,
                         WindowsErrorKind.APPLICATION_NOT_FOUND)
        self.assertIn("0.5", timeout(0.5).message)
        self.assertIn("3 controls", element_ambiguous("buttons", 3).message)

    def test_error_serialisation_has_no_stack_trace(self):
        error = WindowsError(WindowsErrorKind.OS_ERROR, "it broke", "traceback here")
        self.assertEqual(error.error_kind.value, "OS_ERROR")
        self.assertEqual(error.to_dict()["detail"], "traceback here")
        self.assertNotIn("File ", error.message)


if __name__ == "__main__":
    unittest.main()