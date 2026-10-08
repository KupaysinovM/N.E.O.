"""
The `windows_control` action — the only door a model request goes through.

These tests cover the parts that must hold before anything is touched: what the
action accepts, how it reports a refusal, and the fact that it can never report
success it did not observe. Nothing here launches an application, types into
one, or closes one — the destructive paths are the integration suite's job, on a
real window it opened itself.
"""
from __future__ import annotations

import threading
import unittest

from core import confirm
from core.execution import ExecStatus
from core.task_models import ErrorKind
from core.windows import control
from core.windows import is_supported
from core.windows.errors import WindowsErrorKind
from actions.windows_control import TOOL, windows_control
from tests.support import bound_gate, resolve_confirmation


class _NoInterface:
    """Guarantee the confirmation gate has no HUD bound, then restore it."""

    def __enter__(self):
        confirm.bind(None, None, None)
        confirm.bind_resolution(None)
        return self

    def __exit__(self, *exc):
        confirm.bind(None, None, None)
        confirm.bind_resolution(None)
        with confirm._lock:
            confirm._pending = None
        return False


class ActionAcceptsOnlyRealOperations(unittest.TestCase):

    def test_an_unknown_operation_is_refused_and_lists_the_real_ones(self):
        result = windows_control({"operation": "reboot_everything"})
        self.assertEqual(result.status, ExecStatus.NOT_SUPPORTED)
        self.assertEqual(result.error.kind, ErrorKind.ACTION_NOT_SUPPORTED)
        self.assertIn("list_controls", result.data["available_operations"])

    def test_naming_no_operation_is_an_invalid_request(self):
        result = windows_control({})
        self.assertEqual(result.status, ExecStatus.FAILED)
        self.assertEqual(result.error.kind, ErrorKind.INVALID_REQUEST)

    def test_model_written_code_is_just_an_unknown_operation(self):
        # Phase 1 removed model-written Python. The cheapest way back in would be
        # a "run this" operation, so the door refuses anything unrecognised
        # instead of interpreting it.
        result = windows_control({"operation": "import os; os.system('calc')"})
        self.assertEqual(result.status, ExecStatus.NOT_SUPPORTED)
        self.assertFalse(result.data.get("invoked"))

    def test_the_declared_operations_are_exactly_the_real_ones(self):
        # A tool declaration that drifts from the code is how a model ends up
        # calling something that does not exist.
        declared = TOOL["parameters"]["properties"]["operation"]["description"]
        for operation in control.OPERATIONS:
            self.assertIn(operation, declared, f"{operation} is implemented but undeclared")
        self.assertEqual(set(control.CONFIRMATION_REQUIRED) - set(control.OPERATIONS), set())


class ActionRefusesWhatItCannotDo(unittest.TestCase):

    def test_the_confirmation_gate_refusal_ends_the_task_instead_of_parking_it(self):
        # With no interface bound the gate cannot ask, so nothing is awaiting the
        # user. Reporting "awaiting confirmation" here would leave the task
        # RUNNING for the rest of the session, waiting for an answer that can
        # never come.
        with _NoInterface():
            result = windows_control({"operation": "close_window",
                                      "window_handle": 1, "title": "notepad"})
            self.assertEqual(result.status, ExecStatus.FAILED)
            self.assertEqual(result.error.kind, ErrorKind.AUTHORIZATION_UNAVAILABLE)
            self.assertFalse(result.data["awaiting_confirmation"])
            self.assertFalse(result.data["invoked"])
            self.assertFalse(confirm.pending_title(),
                             "the gate parked something it could never show")

    def test_model_supplied_confirmed_flag_cannot_bypass_the_gate(self):
        with bound_gate():
            result = windows_control({"operation": "close_window",
                                      "title": "zzz_no_window_with_this_name_zzz",
                                      "confirmed": True})
            self.assertEqual(result.status, ExecStatus.REQUIRES_CONFIRMATION)
            resolve_confirmation(False)

    def test_a_cancelled_task_is_refused_before_the_desktop_is_touched(self):
        if not is_supported():
            self.skipTest("Windows control is not available on this platform")
        cancelled = threading.Event()
        cancelled.set()
        result = windows_control({"operation": "list_windows"}, cancel_event=cancelled)
        self.assertEqual(result.status, ExecStatus.CANCELLED)
        self.assertFalse(result.data.get("invoked"))


class ActionNeverClaimsMoreThanItKnows(unittest.TestCase):

    def test_no_result_is_ever_reported_as_verified(self):
        # Phase 4 owns verification. Everything this action returns describes
        # what Windows reported, which is a strictly weaker claim.
        if not is_supported():
            self.skipTest("Windows control is not available on this platform")
        result = windows_control({"operation": "list_windows", "limit": 2})
        self.assertFalse(result.verified,
                         "a Windows operation must never claim to be verified")
        self.assertIn("windows_operation", result.data)
        self.assertIn("duration_seconds", result.data)


if __name__ == "__main__":
    unittest.main()