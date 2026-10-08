"""
Phase 5 on real Windows — whole goals against the live desktop.

Run with:

    NEO_WINDOWS_INTEGRATION=1 python -m unittest tests.test_goals_integration -v

WHAT THIS PROVES
    That a goal's SUCCESS came from Windows agreeing with every required step,
    not from NEO believing itself. Nothing here is stubbed: the real action
    registry, the real ExecutionLayer, the real TaskManager, the real UI
    Automation, the real Phase 4 verifier. A VERIFIED step means a live read of
    a live window.

THE THREE GOALS
    A  Open Notepad → verify the window exists → put text in it → verify the
       text. Two dependent steps, the second using the handle the first
       reported.
    B  Open Calculator → verify the window → focus it → verify Windows says it
       is in front.
    C  Try to close a window that will not close. The call reports success; the
       verification sees the window still there; the goal must NOT report
       success. This is the one that matters: it is the proof that Phase 5
       trusts Phase 4 rather than the action's own good intentions.

THE SAME SAFETY RULES AS PHASES 3 AND 4
    Windows that existed before this module started are never acted on and never
    closed — Notepad is single-instance, so the window under test is usually the
    user's own. Text written into it is read back and restored afterwards.
    Windows refuses to let anything take the foreground while the user is
    working, so a focus test that is refused says so and skips with the reason
    instead of weakening the check.
"""
from __future__ import annotations

import contextlib
import os
import pathlib
import threading
import time
import unittest

from core import confirm
from core.action_loader import ActionRegistry, discover_actions
from core.execution import ExecStatus, ExecutionLayer
from core.goals.executor import GoalExecutor
from core.goals.limits import Limits
from core.goals.models import GoalStatus, StepStatus
from core.goals.planner import Planner
from core.goals.store import GoalHistory, GoalStore
from core.task_manager import TaskManager
from core.task_models import ErrorKind
from core.task_store import TaskStore
from core.windows import control
from tests.support import REPO_ROOT, wait_for

ENABLED = bool(os.environ.get("NEO_WINDOWS_INTEGRATION"))
REASON = "set NEO_WINDOWS_INTEGRATION=1 to run tests that drive real Windows"

#: Windows that existed before this module started. Never acted on, never closed.
PRE_EXISTING: set = set()
#: Windows this module opened. Only these are ever cleaned up.
OPENED_HERE: list = []

TEST_TEXT = "phase 5 goal test"


def _record_baseline():
    global PRE_EXISTING
    try:
        result = control.list_windows(include_untitled=True, limit=300)
        PRE_EXISTING = {w["handle"] for w in result.data.get("windows", [])}
    except Exception:
        PRE_EXISTING = set()


def _now() -> float:
    return time.time()


@contextlib.contextmanager
def _approving_interface():
    """The HUD's CONFIRM button, stood in for by the test.

    Phase 7 routes destructive operations through core/confirm.py, and a
    window close is one. This module drives the real stack, and the point of
    Goal C is what happens *after* the user approves: the call succeeds, the
    window stays up, and the goal must not claim victory. So the human's
    press is simulated here; every other property of the gate — one pending
    token, one shot, expiry — stays intact.
    """

    def show(_title, _detail, token=None):
        # Deliberately not instant: a human press takes at least a moment, and
        # resolving inside the show callback would beat the layer's own
        # bookkeeping of the pending token (the sub-second window the execution
        # layer logs about). Approving a heartbeat later is both realistic and
        # what the layer expects.
        def _press_confirm():
            time.sleep(0.1)
            pending = confirm.pending_token()
            if pending:
                confirm.resolve(True, token=pending)

        threading.Thread(target=_press_confirm, daemon=True,
                         name="test-confirm-press").start()

    confirm.bind(show=show, hide=lambda: None, log=lambda _message: None)
    try:
        yield
    finally:
        confirm.bind(None, None, None)
        confirm.bind_resolution(None)
        with confirm._lock:
            confirm._pending = None


class RealGoalStack:
    """The real Phase 2 and Phase 5 stack over the real action registry.

    Only the *store* points somewhere temporary: a test must not write the
    developer's `state/goals.json`. Everything else is the production wiring —
    the same `discover_actions` main.py uses, the same ExecutionLayer, the same
    GoalExecutor.
    """

    def __init__(self, tmp: pathlib.Path) -> None:
        self.tmp = tmp
        self.logs: list = []

        self.manager = TaskManager(
            store=TaskStore(path=tmp / "tasks.json", logger=self.log),
            logger=self.log, notify=self.log)
        self.actions = discover_actions(REPO_ROOT / "actions", set(),
                                        logger=self.log)
        self.layer = ExecutionLayer(actions=self.actions, manager=self.manager,
                                    logger=self.log, notify=self.log)
        # main.py wiring: the layer must hear how a parked confirmation ended.
        self.layer.bind_confirmation_gate()
        self.planner = Planner(actions=self.actions, logger=self.log)
        self.history = GoalHistory(store=GoalStore(path=tmp / "goals.json",
                                                    logger=self.log),
                                   logger=self.log)
        self.executor = GoalExecutor(manager=self.manager, layer=self.layer,
                                     planner=self.planner, history=self.history,
                                     limits=Limits(max_goal_seconds=180.0),
                                     logger=self.log, notify=self.log)

    def log(self, message) -> None:
        self.logs.append(str(message))

    def goal(self, description: str, steps: list):
        goal = self.executor.create_goal(description)
        return self.executor.plan_goal(goal, raw_steps=steps)


@unittest.skipUnless(ENABLED, REASON)
class RealMultiStepGoals(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = pathlib.Path(__import__("tempfile").mkdtemp(prefix="neo-phase5-live-"))
        _record_baseline()

    def setUp(self):
        self.stack = RealGoalStack(self.tmp)
        self._gate = _approving_interface()
        self._gate.__enter__()
        self.addCleanup(self._gate.__exit__, None, None, None)
        self._dismiss_notepad_dialogs()
        self.addCleanup(self._dismiss_notepad_dialogs)
        self.addCleanup(self._close_what_this_test_opened)

    # -- cleanup ----------------------------------------------------------

    def _dismiss_notepad_dialogs(self):
        """Cancel any save prompt this suite left on screen.

        Goal C deliberately provokes Notepad's save prompt. WM_CLOSE on that
        dialog is exactly what pressing Cancel does, so this undoes the test's
        own side effect and leaves the document open with its unsaved text —
        which is how the test found it. Only dialogs owned by Notepad are
        touched, and a dialog the user opened themselves is not Notepad's to
        take away, so nothing else is even looked at.

        Without this, Notepad is single-instance: a prompt left by one run
        poisons the next one, and the failure looks like a product bug.
        """
        try:
            import win32con
            import win32gui
            import win32process
            import psutil
        except Exception:
            return

        handles: list = []
        win32gui.EnumWindows(lambda h, _d: handles.append(h), None)
        for handle in handles:
            try:
                if win32gui.GetClassName(handle) != "#32770":
                    continue
                pid = win32process.GetWindowThreadProcessId(handle)[1]
                if (psutil.Process(pid).name() or "").lower() != "notepad.exe":
                    continue
                win32gui.PostMessage(handle, win32con.WM_CLOSE, 0, 0)
            except Exception:
                continue
        if handles:
            time.sleep(0.6)

    # -- helpers ------------------------------------------------------------

    def _close_what_this_test_opened(self):
        """Only ever closes windows this module opened, and only if still open."""
        for handle in list(OPENED_HERE):
            try:
                still_there = control.locate_window(window_handle=handle)
                if still_there.status == "SUCCESS" and handle not in PRE_EXISTING:
                    control.close_window(window_handle=handle, confirmed=True)
            except Exception:
                pass

    def _launch(self, app: str) -> int:
        result = control.launch_app(app)
        self.assertEqual(result.status, "SUCCESS", result.message)
        window = result.data.get("window") or result.data.get("already_open") or {}
        handle = window.get("handle")
        self.assertIsNotNone(handle, f"{app} produced no window: {result.message}")
        if handle not in PRE_EXISTING and handle not in OPENED_HERE:
            OPENED_HERE.append(handle)
        return int(handle)

    def _notepad_document(self, handle: int):
        """Wait for the real text area, the way a caller would find it."""
        deadline = time.monotonic() + 15.0
        editors: list = []
        while time.monotonic() < deadline:
            listed = control.list_controls(window_handle=handle, control_type="Document",
                                           limit=5, max_depth=10)
            if listed.status == "SUCCESS":
                editors = listed.data.get("controls", [])
                if editors:
                    break
            self._dismiss_notepad_dialogs()
            time.sleep(0.4)
        if not editors:
            return None
        editor = editors[0]
        args = {"window_handle": handle, "control_type": editor["control_type"]}
        if editor.get("automation_id"):
            args["automation_id"] = editor["automation_id"]
        return args

    def _restore_text(self, args: dict):
        try:
            original = control.get_control_value(args)
            if original.status == "SUCCESS":
                control.set_control_value({**args,
                                           "text": original.data.get("value") or ""})
        except Exception as e:
            self.logs.append(f"could not restore the document: {e}")

    def _calculator_window(self) -> int:
        """The window that actually publishes controls, per Phase 3's rule.

        Calculator is a packaged app that hands off to ApplicationFrameHost.exe,
        and on a busy desktop that handover can take several seconds — or the
        launch can report `already_open` for an instance that is still coming
        up. So this waits rather than guessing, and gives up with the reason.
        """
        result = control.launch_app("calc")
        self.assertEqual(result.status, "SUCCESS", result.message)
        window = result.data.get("window") or result.data.get("already_open") or {}

        def _publishes(handle) -> bool:
            if not handle:
                return False
            probe = control.list_controls(window_handle=int(handle),
                                          control_type="Button", limit=5, max_depth=8)
            return probe.status == "SUCCESS" and bool(probe.data.get("controls"))

        candidates = [w.get("handle") for w in
                      control.list_windows(include_untitled=True,
                                           limit=200).data.get("windows", [])
                      if (w.get("process_name") or "").lower()
                      in ("applicationframehost.exe", "calculatorapp.exe", "calc.exe")]
        candidates.append(window.get("handle"))

        deadline = time.monotonic() + 45.0
        relaunch_at = time.monotonic() + 12.0
        how = result.message
        while time.monotonic() < deadline:
            for handle in candidates:
                if _publishes(handle):
                    if handle not in PRE_EXISTING and handle not in OPENED_HERE:
                        OPENED_HERE.append(int(handle))
                    return int(handle)
            if time.monotonic() > relaunch_at:
                # The previous instance may still be shutting down; asking again
                # is idempotent for a single-instance app and starts the handover
                # over. Bounded by the deadline above.
                relaunch_at = time.monotonic() + 12.0
                retried = control.launch_app("calc")
                how = retried.message
                candidates = [w.get("handle") for w in
                              control.list_windows(include_untitled=True,
                                                   limit=200).data.get("windows", [])
                              if (w.get("process_name") or "").lower()
                              in ("applicationframehost.exe", "calculatorapp.exe",
                                  "calc.exe")]
            time.sleep(1.0)
        # The reason names what Windows actually said, so a reader can tell an
        # environment condition from a product failure without re-running.
        self.skipTest(f"Calculator would not open on this machine in 45s "
                      f"(launch reported: {how}). Nothing was asserted.")

    # -- Goal A -------------------------------------------------------------

    def test_goal_a_open_notepad_write_text_and_verify_both_steps(self):
        """The prompt's first example, end to end, against the real desktop."""
        handle = self._launch("notepad")
        # Wait for the instance to finish handing off before the goal launches a
        # second one. Notepad is single-instance: starting it while the first
        # window is still coming up is a race the test creates, not one the
        # product has to survive.
        args = self._notepad_document(handle)
        if args:
            self.addCleanup(self._restore_text, args)
        steps = [
            {"id": "open", "action": "windows_control", "description": "Open Notepad",
             "arguments": {"operation": "launch_app", "app_name": "notepad"}},
            {"id": "type", "action": "windows_control", "description": "Put the text in",
             "depends_on": ["open"],
             "arguments": {"operation": "set_value",
                           "window_handle": {"$from": "step:open.handle"},
                           "control_type": "Document", "text": TEST_TEXT},
             "re_resolve": True,
             "retry": {"attempts": 2, "delay": 0.25,
                       "reason": "the text area may not be ready the instant it opens"}},
        ]
        goal = self.stack.goal("Open Notepad and put text in it", steps)
        result = self.stack.executor.run(goal)

        handle = goal.context.recall("step:open.handle")
        if handle:
            args = self._notepad_document(handle)
            if args:
                self.addCleanup(self._restore_text, args)

        self.assertEqual([s["status"] for s in result.steps], ["VERIFIED", "VERIFIED"],
                         result.report())
        self.assertTrue(result.ok, result.report())
        self.assertEqual(result.verified, 2)
        self.assertEqual(result.not_verified, 0)

        # And the second step really did use the handle the first one reported.
        second = goal.step("type")
        self.assertIsNotNone(handle, "the first step never reported a window")
        self.assertEqual(second.resolved_arguments["window_handle"], handle)
        read_back = control.get_control_value({**second.resolved_arguments,
                                              "operation": "get_value"})
        self.assertEqual(read_back.status, "SUCCESS", read_back.message)
        self.assertEqual(read_back.data.get("value"), TEST_TEXT)

    def test_goal_a_writes_through_the_phase2_task_boundary(self):
        self._launch("notepad")
        goal = self.stack.goal("Open Notepad", [
            {"id": "open", "action": "windows_control",
             "arguments": {"operation": "launch_app", "app_name": "notepad"}}])
        self.stack.executor.run(goal)

        step = goal.step("open")
        self.assertTrue(step.task_id)
        task = self.stack.manager.get_task(step.task_id)
        self.assertIsNotNone(task)
        self.assertEqual(task.metadata["goal_id"], goal.goal_id)
        self.assertEqual(task.current_action, "windows_control")

    # -- Goal B -------------------------------------------------------------

    def test_goal_b_open_calculator_focus_it_and_verify_the_foreground(self):
        """The prompt's second example, against the real foreground lock."""
        self._calculator_window()
        steps = [
            {"id": "open", "action": "windows_control", "description": "Open Calculator",
             "arguments": {"operation": "launch_app", "app_name": "calc"}},
            {"id": "focus", "action": "windows_control",
             "description": "Bring it to the front", "depends_on": ["open"],
             "arguments": {"operation": "focus_window",
                           "window_handle": {"$from": "step:open.handle"}},
             "re_resolve": True,
             "retry": {"attempts": 2, "delay": 0.25,
                       "reason": "Windows refuses activation while the user is working"}},
        ]
        goal = self.stack.goal("Open Calculator and bring it to the front", steps)
        result = self.stack.executor.run(goal)

        focus = goal.step("focus")
        if focus.status is StepStatus.FAILED and \
                focus.error_kind in (ErrorKind.ACCESS_DENIED, ErrorKind.ELEMENT_NOT_FOUND):
            self.skipTest(f"the environment refused foreground activation "
                          f"({focus.result.error.message}) — the user is using the desktop")

        self.assertEqual(result.steps[0]["status"], "VERIFIED", result.report())
        if focus.status is StepStatus.NOT_VERIFIED:
            # Windows did not put it in front. The goal says so; it does not
            # claim a foreground it could not read back.
            self.assertEqual(result.status, GoalStatus.NOT_VERIFIED)
            self.fail(f"focus was not verified on this machine: {result.report()}")
        self.assertEqual(focus.status, StepStatus.VERIFIED, result.report())
        self.assertTrue(result.ok, result.report())

        active = control.active_window()
        self.assertEqual(active.status, "SUCCESS", active.message)
        self.assertEqual(int(active.data["window"]["handle"]),
                         focus.resolved_arguments["window_handle"])

    # -- Goal C -------------------------------------------------------------

    def test_goal_c_a_close_that_does_not_close_is_never_a_success(self):
        """The prompt's third example, and the one that proves Phase 5 works.

        The goal types into Notepad first, so the window has unsaved work.
        WM_CLOSE then reaches Notepad, Notepad puts up its save prompt, and the
        window stays exactly where it was. `close_window` reports SUCCESS for
        that — the automation call completed. If the goal trusted the call
        rather than the machine, it would report success. It must not.
        """
        self._launch("notepad")
        steps = [
            {"id": "open", "action": "windows_control",
             "arguments": {"operation": "launch_app", "app_name": "notepad"}},
            {"id": "type", "action": "windows_control", "depends_on": ["open"],
             "arguments": {"operation": "set_value",
                           "window_handle": {"$from": "step:open.handle"},
                           "control_type": "Document", "text": TEST_TEXT},
             "re_resolve": True,
             "retry": {"attempts": 2, "delay": 0.25,
                       "reason": "the text area may not be ready the instant it opens"}},
            {"id": "close", "action": "windows_control", "depends_on": ["type"],
             "arguments": {"operation": "close_window",
                           "window_handle": {"$from": "step:open.handle"}}},
        ]
        goal = self.stack.goal("Put text in Notepad and close it", steps)
        result = self.stack.executor.run(goal)

        opened, typed, closed = (goal.step("open"), goal.step("type"),
                                 goal.step("close"))
        if closed.status is StepStatus.AWAITING_CONFIRMATION:
            # The gate owns the next word. _approving_interface presses CONFIRM,
            # which runs the confirmed action on the gate's worker thread; the
            # goal then has to be asked to pick the answer up, exactly as the
            # app does with a parked goal.
            task_id = closed.task_id
            self.assertTrue(
                wait_for(lambda: (self.stack.manager.get_task(task_id) is not None
                                  and self.stack.manager.get_task(task_id).is_terminal),
                         timeout=15.0),
                "the confirmed close never reached a terminal state")
            result = self.stack.executor.run(goal)
        if opened.status is not StepStatus.VERIFIED:
            self.skipTest(f"Notepad did not report a window: {opened.notes}")
        if typed.status is not StepStatus.VERIFIED:
            self.skipTest(f"Notepad's text area was not writable here: {typed.notes}")
        if closed.status in (StepStatus.AWAITING_CONFIRMATION, StepStatus.CANCELLED):
            self.skipTest("the confirmation gate claimed the close; nothing was tested")

        handle = goal.context.recall("step:open.handle")
        if handle:
            args = self._notepad_document(handle)
            if args:
                self.addCleanup(self._restore_text, args)

        still_there = control.locate_window(
            window_handle=closed.resolved_arguments["window_handle"])
        if still_there.status != "SUCCESS":
            # It really did close. Then there is nothing to be honest about, and
            # this particular test says nothing — Goal A already covers success.
            self.skipTest("the window really closed; the not-verified path was "
                          "not exercised on this machine")

        # This is the assertion the whole phase exists for.
        self.assertEqual(closed.result.status, ExecStatus.SUCCESS.value,
                         "the action itself reported success")
        self.assertEqual(closed.status, StepStatus.NOT_VERIFIED)
        self.assertEqual(result.status, GoalStatus.NOT_VERIFIED)
        self.assertFalse(result.ok)
        self.assertIn("could not be verified", result.message)
        self.assertNotEqual(result.status, GoalStatus.COMPLETED)
        self.assertEqual(result.steps[0]["status"], "VERIFIED")
        self.assertEqual(result.steps[1]["status"], "VERIFIED")

    # -- honesty about the environment --------------------------------------

    def test_a_goal_whose_step_does_nothing_is_not_verified_on_real_windows(self):
        """The same honesty, reached without a save dialog.

        `set_value` into a control that will not take text is the simplest real
        version of Goal C. If the value happens to land, the test says so
        instead of pretending to have proved anything.
        """
        handle = self._launch("notepad")
        args = self._notepad_document(handle)
        if not args:
            self.skipTest("Notepad published no Document control on this machine")
        original = control.get_control_value(args).data.get("value") or ""
        self.addCleanup(self._restore_text, args)

        goal = self.stack.goal("Set text to something that will not stick", [
            {"id": "type", "action": "windows_control",
             "arguments": {"operation": "set_value", **args,
                           "text": original + " " + TEST_TEXT}}])
        result = self.stack.executor.run(goal)
        step = goal.step("type")

        read_back = control.get_control_value(args).data.get("value") or ""
        if read_back.endswith(TEST_TEXT):
            self.assertEqual(step.status, StepStatus.VERIFIED, result.report())
            return
        self.assertNotEqual(step.status, StepStatus.VERIFIED)
        self.assertIn(result.status, (GoalStatus.NOT_VERIFIED, GoalStatus.FAILED),
                      result.report())

    def test_an_unknown_operation_is_refused_before_anything_is_touched(self):
        before = len(control.list_windows(include_untitled=True, limit=300).data["windows"])
        goal = self.stack.goal("Do something impossible", [
            {"id": "s1", "action": "definitely_not_an_action",
             "arguments": {"operation": "launch_app", "app_name": "notepad"}}])
        after = len(control.list_windows(include_untitled=True, limit=300).data["windows"])

        self.assertEqual(goal.status, GoalStatus.NOT_SUPPORTED)
        self.assertEqual(goal.error.kind, ErrorKind.ACTION_NOT_SUPPORTED)
        self.assertEqual(before, after, "a refused plan must not have started anything")


if __name__ == "__main__":
    unittest.main()