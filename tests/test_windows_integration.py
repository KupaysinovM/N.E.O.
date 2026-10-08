"""
Real Windows integration tests — opt-in, because they touch the desktop.

Run them with:

    NEO_WINDOWS_INTEGRATION=1 python -m unittest tests.test_windows_integration -v

They launch Calculator and Notepad, discover their real controls, act on them
and close them again. Nothing personal is touched.

THE SAFETY RULE
    Notepad and Calculator are single-instance: launching them when you already
    have one open reuses YOUR window. So this module records every window that
    existed before it started, never acts on one of those, and never closes one
    of those. Only windows this module opened are closed again. An earlier
    revision of this file got that wrong and closed the user's own Notepad
    window; the baseline below is the fix.

What these tests prove and what they do not: they prove NEO can find and drive
real Windows UI elements. They are not a verification layer — nothing here
checks that an application *did* what a button said it would. That is Phase 4
and is not implemented.
"""
from __future__ import annotations

import os
import time
import unittest

from core.windows import control
from core.windows.errors import WindowsErrorKind
from tests.support import resolve_confirmation

ENABLED = bool(os.environ.get("NEO_WINDOWS_INTEGRATION"))
REASON = "set NEO_WINDOWS_INTEGRATION=1 to run tests that drive the real desktop"

# Windows that existed before this module ran. Never touched.
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


def _calculator_windows() -> list:
    """Every real window titled 'Calculator', whoever owns it."""
    return [w for w in control.list_windows(include_untitled=True,
                                            limit=200).data.get("windows", [])
            if (w.get("title") or "").strip().lower() == "calculator"]


def _named_buttons(handle) -> list:
    result = control.list_controls(window_handle=handle, control_type="Button",
                                   limit=60, max_depth=14)
    return [c for c in result.data.get("controls", []) if c.get("name")]


class _RestoredText:
    """Put a document back the way it was found.

    The Notepad these tests drive is usually the user's own, with whatever they
    had written in it. Writing 'NEO phase 3 check' over someone's unsaved work
    to prove a Value pattern works is not an acceptable price for a test, so the
    original text is read first and written back afterwards — through the same
    pattern the test just exercised.
    """

    def __init__(self, handle: int, editor: dict, case: unittest.TestCase):
        self.handle, self.editor, self.case = handle, editor, case
        self.original = None

    def _args(self) -> dict:
        args = {"window_handle": self.handle, "control_type": self.editor["control_type"]}
        if self.editor.get("automation_id"):
            args["automation_id"] = self.editor["automation_id"]
        if "_pin_index" in self.editor:
            args["index"] = self.editor["_pin_index"]
        return args

    def __enter__(self):
        read = control.get_control_value(self._args())
        if read.status == "SUCCESS":
            self.original = read.data.get("value")
        return self

    def __exit__(self, *exc):
        if self.original is None:
            return False
        restored = control.set_control_value({**self._args(), "text": self.original})
        if restored.status != "SUCCESS":
            self.case.fail(f"could not restore the original document text: "
                           f"{restored.message}")
        return False


def open_app_window(app: str, opened: list) -> tuple:
    """Launch `app`; return (window handle, owned_by_this_call).

    Windows 11 hands `notepad.exe` to a Store build running in another process,
    so the window is matched by the program that owns it — which is what
    `launch_app` reports. `owned_by_this_call` is False when the window already
    existed (the user's, or one an earlier test opened): such a window is never
    closed by the tests, because single-instance applications make "the window
    I just launched" and "the window that was already open" the same window.
    """
    launch = control.launch_app(app)
    if launch.status != "SUCCESS":
        raise AssertionError(f"{app} did not launch: {launch.message}")

    window = launch.data.get("window")
    if window is not None:
        if window["handle"] in opened or window["handle"] in PRE_EXISTING:
            return window["handle"], False
        opened.append(window["handle"])
        return window["handle"], True

    candidates = [w for w in control.list_windows(include_untitled=True,
                                                   limit=120).data.get("windows", [])
                  if (w.get("process_name") or "").lower() == f"{app}.exe"]
    for existing in candidates:
        if existing["handle"] in PRE_EXISTING or existing["handle"] in opened:
            return existing["handle"], False
    found = _wait_for(lambda: [w for w in control.list_windows(
        include_untitled=True, limit=120).data.get("windows", [])
        if (w.get("process_name") or "").lower() == f"{app}.exe"
        and w["handle"] not in PRE_EXISTING and w["handle"] not in opened])
    if not found:
        raise AssertionError(f"{app} never produced a window")
    opened.append(found[0]["handle"])
    return found[0]["handle"], True


@unittest.skipUnless(ENABLED, REASON)
class RealWindowDiscovery(unittest.TestCase):
    """Windows really are enumerable, and the OS is the one telling us."""

    def test_windows_are_enumerable_with_real_titles_and_processes(self):
        result = control.list_windows(limit=10)
        self.assertEqual(result.status, "SUCCESS", result.message)
        self.assertTrue(result.data["windows"], "no visible windows were found")
        for window in result.data["windows"]:
            self.assertIsInstance(window["handle"], int)
            self.assertTrue(window["title"], "a listed window had no title")
            self.assertIsNotNone(window["process_id"])

    def test_the_active_window_is_a_real_window(self):
        result = control.active_window()
        self.assertEqual(result.status, "SUCCESS", result.message)
        window = result.data["window"]
        self.assertTrue(window["is_active"])
        self.assertIsInstance(window["handle"], int)
        self.assertIsNotNone(window["process_id"])

        # The foreground window is not always titled. When the shell owns focus
        # — after a window NEO opened was closed, for instance — Windows reports
        # a real window with no caption, and NEO must report that empty title
        # rather than invent one. What has to hold is that both independent paths
        # (the foreground query and window enumeration) agree.
        enumerated = control.list_windows(include_untitled=True,
                                          limit=200).data["windows"]
        same = [w for w in enumerated if w["handle"] == window["handle"]]
        self.assertTrue(same, "the active window was not in the enumerated windows")
        self.assertEqual(same[0]["title"], window["title"])
        self.assertEqual(same[0]["process_id"], window["process_id"])

    def test_list_windows_is_bounded(self):
        self.assertLessEqual(len(control.list_windows(limit=3).data["windows"]), 3)

    def test_a_missing_window_is_reported_not_invented(self):
        result = control.locate_window(title="zzz_no_such_window_zzz")
        self.assertEqual(result.status, "NOT_AVAILABLE")
        self.assertEqual(result.error.kind, WindowsErrorKind.WINDOW_NOT_FOUND)

    def test_process_information_is_read_only_and_real(self):
        result = control.list_processes(name_contains="explorer", limit=5)
        self.assertEqual(result.status, "SUCCESS", result.message)
        for process in result.data["processes"]:
            self.assertIsInstance(process["pid"], int)
            self.assertTrue(process["name"])

    def test_desktop_snapshot_reports_the_live_desktop(self):
        result = control.desktop_snapshot(max_windows=5, max_controls=20)
        self.assertEqual(result.status, "SUCCESS", result.message)
        active = result.data["active_window"]
        self.assertIsInstance(active["handle"], int)
        self.assertTrue(active["is_active"])
        # Bounded: a snapshot is raw state for later phases, never the whole tree.
        self.assertLessEqual(len(result.data["windows"]), 5)


@unittest.skipUnless(ENABLED, REASON)
class RealNotepadControl(unittest.TestCase):
    """Discovery, text entry, keyboard, menus — against real Windows UI.

    Notepad is single-instance, so this class usually ends up driving the window
    the user already had open. Two consequences shape every test here:

      * the handle can go stale at any moment — the user closes Notepad, or a
        save prompt left over from an earlier run swallows it — so each test
        re-establishes a live window instead of failing on a dead handle;
      * the document belongs to whoever opened it. Anything written here is put
        back the way it was, or the text is never touched at all.
    """

    opened: list = []
    handle = None

    @classmethod
    def setUpClass(cls):
        cls.handle, _owned = open_app_window("notepad", cls.opened)

    @classmethod
    def tearDownClass(cls):
        for handle in cls.opened:
            if handle in PRE_EXISTING:
                continue                      # never the user's window
            try:
                control.close_window(window_handle=handle)
            except Exception:
                pass
        time.sleep(1.0)

    def _window(self) -> int:
        """A live Notepad window handle, re-opening the app if it went away."""
        if self.handle:
            located = control.locate_window(window_handle=self.handle)
            if located.status == "SUCCESS":
                return self.handle
        handle, _owned = open_app_window("notepad", type(self).opened)
        type(self).handle = handle
        return handle

    def _editor(self, handle: int) -> dict:
        """The Document control of a real Notepad window.

        A freshly launched Notepad publishes its tree a moment after the window
        appears, so this waits for it rather than declaring the control missing.
        """
        editors = _wait_for(
            lambda: control.list_controls(window_handle=handle, control_type="Document",
                                          limit=10, max_depth=10).data.get("controls", []),
            timeout=12.0)
        if not editors:
            self.skipTest("this Notepad build exposes no Document control")
        # An automation id is preferred because names are duplicated; when this
        # build publishes none, the position is pinned explicitly instead.
        addressable = [e for e in editors if e.get("automation_id")]
        if addressable:
            return addressable[0]
        return {**editors[0], "_pin_index": 0}

    def _editor_args(self, handle: int, editor: dict) -> dict:
        """Arguments that address exactly this Document and nothing else."""
        args = {"window_handle": handle, "control_type": editor["control_type"]}
        if editor.get("automation_id"):
            args["automation_id"] = editor["automation_id"]
        if "_pin_index" in editor:
            args["index"] = editor["_pin_index"]
        return args

    def _with_text_restored(self, handle: int, editor: dict):
        """Snapshot the document so a test can type into it and undo that."""
        return _RestoredText(handle, editor, self)

    def test_the_window_exists_and_names_a_real_process(self):
        window = control.locate_window(window_handle=self._window())
        self.assertEqual(window.status, "SUCCESS", window.message)
        self.assertEqual(window.data["window"]["process_name"].lower(), "notepad.exe")

    def test_controls_are_discovered_with_real_capabilities(self):
        handle = self._window()
        controls = control.list_controls(window_handle=handle, limit=80, max_depth=10)
        self.assertEqual(controls.status, "SUCCESS", controls.message)
        editors = [c for c in controls.data["controls"]
                   if c["control_type"] in ("Document", "Edit")]
        self.assertTrue(editors, "Notepad's text area was not exposed as a control")
        self.assertIn("value", editors[0]["capabilities"])
        self.assertEqual(controls.data["window"]["handle"], handle)

    def test_set_value_writes_through_the_value_pattern(self):
        handle = self._window()
        editor = self._editor(handle)
        args = self._editor_args(handle, editor)
        with self._with_text_restored(handle, editor):
            written = control.set_control_value({**args, "text": "NEO phase 3 check"})
            self.assertEqual(written.status, "SUCCESS", written.message)
            self.assertEqual(written.data["pattern"], "Value")
            self.assertEqual(written.data["characters"], len("NEO phase 3 check"))
            self.assertFalse(written.data.get("verified"),
                             "Phase 3 must never claim verification")

            read_back = control.get_control_value(args)
            self.assertEqual(read_back.status, "SUCCESS", read_back.message)
            self.assertEqual(read_back.data["value"], "NEO phase 3 check")

    def test_focus_really_makes_the_window_active(self):
        handle = self._window()
        focused = control.focus_window(window_handle=handle)
        self.assertEqual(focused.status, "SUCCESS", focused.message)
        active = control.active_window()
        self.assertEqual(active.data["window"]["handle"], handle,
                         "focusing the window did not make it the active window")

    def test_window_state_changes_are_reported_by_windows(self):
        handle = self._window()
        minimized = control.window_state("minimize", window_handle=handle)
        self.assertEqual(minimized.status, "SUCCESS", minimized.message)
        self.assertTrue(minimized.data["window"]["minimized"])
        restored = control.window_state("restore", window_handle=handle)
        self.assertEqual(restored.status, "SUCCESS", restored.message)
        self.assertFalse(restored.data["window"]["minimized"])

    def test_keyboard_primitives_reach_the_real_application(self):
        handle = self._window()
        editor = self._editor(handle)
        control.focus_window(window_handle=handle)
        with self._with_text_restored(handle, editor):
            typed = control.type_text("abc")
            self.assertEqual(typed.status, "SUCCESS", typed.message)
            self.assertEqual(typed.data["characters"], 3)
            selected = control.press_keys("ctrl+a")
            self.assertEqual(selected.status, "SUCCESS", selected.message)
            self.assertEqual(selected.data["keys"], ["ctrl", "a"])

    def test_menu_items_are_discovered_in_a_real_application(self):
        menus = control.list_controls(window_handle=self._window(), control_type="MenuItem",
                                      limit=40, max_depth=12)
        self.assertEqual(menus.status, "SUCCESS", menus.message)
        names = {c["name"] for c in menus.data["controls"] if c["name"]}
        self.assertTrue({"File", "Edit", "View"} & names,
                        f"expected the standard menus, saw {sorted(names)[:10]}")

    def test_an_unknown_control_is_reported_not_clicked(self):
        result = control.invoke_control({
            "window_handle": self._window(),
            "element_name": "A Button That Does Not Exist"})
        self.assertEqual(result.status, "NOT_AVAILABLE")
        self.assertEqual(result.error.kind, WindowsErrorKind.ELEMENT_NOT_FOUND)

    def test_ambiguous_controls_are_refused_rather_than_guessed(self):
        # Real applications publish duplicate names — Notepad exposes both a
        # 'System' MenuBar and a 'System' MenuItem. Which control that is
        # depends on the build, so this looks for a name that is genuinely
        # duplicated right now and then insists NEO refuses to pick one.
        #
        # A UI Automation tree is live: it can change between two calls while
        # the application redraws, so a name seen in one listing may be gone by
        # the next. That is Windows behaving normally, not a failure, so the
        # search retries before concluding anything.
        handle = self._window()
        for _attempt in range(3):
            discovered = control.list_controls(window_handle=handle, limit=140,
                                               max_depth=12, named_only=True)
            self.assertEqual(discovered.status, "SUCCESS", discovered.message)
            counts: dict = {}
            for element in discovered.data["controls"]:
                name = (element.get("name") or "").strip()
                if name:
                    counts[name] = counts.get(name, 0) + 1
            duplicates = sorted(name for name, count in counts.items() if count > 1)
            if not duplicates:
                continue

            result = control.find_control({"window_handle": handle,
                                           "element_name": duplicates[0]})
            if result.error and result.error.kind == WindowsErrorKind.ELEMENT_NOT_FOUND:
                continue                     # the tree moved; look again
            self.assertEqual(result.status, "FAILED",
                             f"'{duplicates[0]}' is ambiguous, so it must not resolve")
            self.assertEqual(result.error.kind, WindowsErrorKind.ELEMENT_AMBIGUOUS)
            self.assertIn(f"{counts[duplicates[0]]} controls", result.message)
            return
        self.skipTest("Notepad's tree did not hold still long enough to observe a "
                      "duplicate control name")

    def test_an_unsupported_pattern_is_reported_as_not_supported(self):
        # A Document is not a button; asking to invoke it must be refused by
        # pattern support, not by clicking it.
        result = control.invoke_control({"window_handle": self._window(),
                                         "control_type": "Document", "index": 0})
        self.assertEqual(result.status, "NOT_SUPPORTED", result.message)
        self.assertEqual(result.error.kind, WindowsErrorKind.UNSUPPORTED_CONTROL)

    def test_closing_the_window_goes_through_the_confirmation_gate(self):
        from core import confirm
        from actions.windows_control import windows_control
        confirm.bind(show=lambda t, d: None, hide=lambda: None, log=lambda m: None)
        try:
            handle = self._window()
            parked = windows_control({"operation": "close_window",
                                      "window_handle": handle})
            self.assertEqual(parked.status.value, "REQUIRES_CONFIRMATION")
            self.assertTrue(confirm.pending_title(), "no confirmation was parked")
            resolve_confirmation(False)            # decline: nothing must close
            time.sleep(0.8)
            still_open = control.locate_window(window_handle=handle)
            self.assertEqual(still_open.status, "SUCCESS",
                             "a declined confirmation still closed the window")
        finally:
            with confirm._lock:
                confirm._pending = None
            confirm.bind(None, None, None)
            confirm.bind_resolution(None)

    def test_a_closed_window_is_reported_as_gone_not_reused(self):
        opened: list = []
        handle, owned = open_app_window("notepad", opened)
        if not owned:
            self.skipTest("only the user's own Notepad was available; not closing it")
        control.close_window(window_handle=handle)
        gone = _wait_for(lambda: control.locate_window(window_handle=handle).status
                         == "NOT_AVAILABLE", timeout=10.0)
        self.assertTrue(gone, "a closed window was still reported as open")
        result = control.locate_window(window_handle=handle)
        self.assertEqual(result.error.kind, WindowsErrorKind.WINDOW_NOT_FOUND)


@unittest.skipUnless(ENABLED, REASON)
class RealMouseAndScreenshot(unittest.TestCase):

    def test_mouse_primitives_are_bounded_by_the_real_screen(self):
        screen = control.desktop_snapshot(include_controls=False).data["screen"]
        good = control.click(10, 10)
        self.assertEqual(good.status, "SUCCESS", good.message)
        bad = control.click(screen["width"] + 500, 10)
        self.assertEqual(bad.status, "FAILED")
        self.assertEqual(bad.error.kind, WindowsErrorKind.INVALID_ARGUMENT)

    def test_scroll_and_cursor_position(self):
        position = control.cursor_position()
        self.assertEqual(position.status, "SUCCESS", position.message)
        self.assertIn("x", position.data)
        scrolled = control.scroll(amount=2, direction="down")
        self.assertEqual(scrolled.status, "SUCCESS", scrolled.message)

    def test_screenshot_fallback_still_works(self):
        # The existing vision path must keep working; Phase 3 sits above it.
        from actions.screen_processor import _capture_screen
        image, mime = _capture_screen()
        self.assertTrue(image, "the screenshot capture returned no bytes")
        self.assertIn("image", mime)


@unittest.skipUnless(ENABLED, REASON)
class RealCalculator(unittest.TestCase):

    opened: list = []

    @classmethod
    def tearDownClass(cls):
        for handle in cls.opened:
            if handle in PRE_EXISTING:
                continue
            try:
                control.close_window(window_handle=handle)
            except Exception:
                pass

    def test_calculator_launches_and_exposes_real_controls(self):
        launch = control.launch_app("calculator")
        self.assertEqual(launch.status, "SUCCESS", launch.message)
        reported = launch.data.get("window")

        # The guarantee being pinned down: the window `launch_app` hands back is
        # one NEO can actually drive. That is not free on Windows 11, where the
        # calculator's own process also creates a window with no controls at all,
        # while the shared app-host window holds all the buttons.
        if reported is not None:
            self.assertTrue(reported.get("chosen_because"),
                            "a reported window must say why it was chosen")
        window = reported or _wait_for(
            lambda: next((w for w in _calculator_windows()
                          if _named_buttons(w["handle"])), None), timeout=20.0)
        self.assertIsNotNone(window, "no Calculator window exposed controls")
        if window["handle"] not in PRE_EXISTING:
            self.opened.append(window["handle"])

        buttons = _named_buttons(window["handle"])
        self.assertGreaterEqual(len(buttons), 20,
                                "Calculator exposed far fewer buttons than expected")
        self.assertTrue([c for c in buttons if "invoke" in c["capabilities"]],
                        "no Calculator button exposed an Invoke pattern")

    def test_a_real_button_is_invoked_through_the_automation_pattern(self):
        launch = control.launch_app("calculator")
        self.assertEqual(launch.status, "SUCCESS", launch.message)
        window = (launch.data.get("window") or launch.data.get("already_open")
                  or _wait_for(lambda: next((w for w in _calculator_windows()
                                              if _named_buttons(w["handle"])), None),
                               timeout=20.0))
        self.assertIsNotNone(window, "no Calculator window was available to drive")

        # A digit and Clear: harmless, disposable, and undone in the same test.
        # Nothing here claims the calculator computed anything — that is Phase 4
        # verification. What is being tested is that Invoke() reached a real
        # button and that NEO reports exactly which one it acted on.
        button = next((b for b in _named_buttons(window["handle"])
                       if (b["name"] or "").lower() in ("seven", "7")), None)
        self.assertIsNotNone(button, "Calculator exposed no 'Seven' button to invoke")

        invoked = control.invoke_control({"window_handle": window["handle"],
                                          "automation_id": button["automation_id"],
                                          "control_type": button["control_type"],
                                          "element_name": button["name"]})
        self.assertEqual(invoked.status, "SUCCESS", invoked.message)
        self.assertEqual(invoked.data["pattern"], "Invoke")
        self.assertFalse(invoked.data.get("verified"),
                         "an invoke must never claim to be verified")

        clear = next((b for b in _named_buttons(window["handle"])
                      if (b["name"] or "").lower() == "clear"), None)
        if clear is not None:
            undone = control.invoke_control({"window_handle": window["handle"],
                                             "automation_id": clear["automation_id"],
                                             "control_type": clear["control_type"],
                                             "element_name": clear["name"]})
            self.assertEqual(undone.status, "SUCCESS", undone.message)


if __name__ == "__main__":
    unittest.main()