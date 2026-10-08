"""
Phase 8 — the automatic voice-response boundary in the live session.

WHAT IS UNDER TEST
    `NeoLive.speak()` is the automatic narration path: `main.py` hands it to
    every action as `handler_ctx["speak"]`, and `speak_error()` reports through
    it. Every one of those calls therefore happens *while a tool is in flight*
    — while the server is waiting for the `function_response` that follows.

    Ending the turn from inside that window hands the model a `role: user`
    message the user never said and races the response a moment later. That is
    how the automatic spoken reply to a tool run gets lost while a typed
    command, which goes through the same code with no tool in flight, still
    works.

    These tests drive the real `NeoLive` methods with a fake session and a fake
    HUD. Nothing here opens a window, touches the desktop, or needs a network:
    the seam is the same `NeoLive.__new__(NeoLive)` the security suite already
    uses for the typed-command path.

WHAT IS NOT TESTED
    Whether Gemini actually speaks after a function response. That needs a live
    API session; these tests pin the invariant that makes the reply possible —
    that a tool's own narration never ends the turn it belongs to.
"""
from __future__ import annotations

import asyncio
import unittest
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import patch

from main import NeoLive


class FakeSession:
    """Records what would have gone to the live session."""

    def __init__(self) -> None:
        self.sent: list = []

    async def send_client_content(self, **payload):
        self.sent.append(payload)


class FakeUI:
    def __init__(self) -> None:
        self.lines: list = []
        self.states: list = []
        self.muted = False

    def write_log(self, text) -> None:
        self.lines.append(str(text))

    def set_state(self, state) -> None:
        self.states.append(state)


class Registries:
    """The only thing `_execute_tool` reads off the two registries."""

    def scheduling(self, name):
        return None


def make_app() -> NeoLive:
    """A `NeoLive` with just the live-session state these paths touch.

    `NeoLive.__new__` skips `__init__`, which is deliberate: `__init__` builds
    config, audio and a wake-word detector, none of which is what is under test
    and all of which would need a real desktop to stand up.
    """
    app = NeoLive.__new__(NeoLive)
    app._loop = object()
    app.session = FakeSession()
    app._tool_call_depth = 0
    app._asst_name = "NEO"
    app.ui = FakeUI()
    app._inline_action_names = frozenset()
    app._action_registry = Registries()
    app._plugin_registry = Registries()
    return app


def _fc(name: str = "code_helper", args: dict | None = None):
    return SimpleNamespace(id="fc-1", name=name, args=dict(args or {}))


@contextmanager
def _capturing_sends():
    """Capture every send `speak()` schedules instead of running it.

    `speak()` hands its send to `run_coroutine_threadsafe`, which in production
    lands on the live session's loop. Awaiting that here — from a context with
    no running loop — is what lets a test inspect the payload.
    """
    scheduled: list = []

    def _record(coroutine, _loop):
        scheduled.append(coroutine)
        return None

    with patch("main.asyncio.run_coroutine_threadsafe", side_effect=_record):
        yield scheduled


def _deliver(scheduled: list) -> None:
    """Run the captures so the fake session records their payloads."""
    for coroutine in scheduled:
        asyncio.run(coroutine)


class NarrationNeverCompletesAToolTurn(unittest.TestCase):

    def test_a_tool_run_narrates_to_the_hud_and_never_to_the_conversation(self):
        """The whole point: narration inside a tool is a log line, not a turn."""
        app = make_app()
        depth_while_running: list = []

        async def fake_tool(name, args, fc=None):
            depth_while_running.append(app._tool_call_depth)
            app.speak("Build complete. Saved to out.py")
            return "Build complete."

        app._run_registered_tool = fake_tool
        with _capturing_sends() as scheduled:
            asyncio.run(app._execute_tool(_fc()))

        self.assertEqual(depth_while_running, [1],
                         "the action ran outside the tool-depth guard")
        self.assertEqual(scheduled, [],
                         "narration must never complete a turn while a tool "
                         "owes the server a function response")
        self.assertEqual(app.session.sent, [])
        self.assertIn("Build complete. Saved to out.py", app.ui.lines)
        self.assertEqual(app._tool_call_depth, 0)

    def test_a_failed_tool_is_reported_once_to_the_hud_and_not_as_a_user_turn(self):
        """`speak_error` is reached only from inside a tool — same rule."""
        app = make_app()

        async def failing_tool(name, args, fc=None):
            raise RuntimeError("the fixture failed")

        app._run_registered_tool = failing_tool
        with _capturing_sends() as scheduled:
            result = asyncio.run(app._execute_tool(_fc()))

        self.assertEqual(scheduled, [],
                         "a tool failure must not become a user message")
        self.assertEqual(app.ui.lines,
                         ["ERR: code_helper failed. RuntimeError"])
        self.assertEqual(app._tool_call_depth, 0)
        self.assertIn("RuntimeError", str(result.response))

    def test_a_tool_call_that_raises_still_releases_the_depth(self):
        """The guard is released on every exit, including an unexpected one."""
        app = make_app()

        class BrokenUI(FakeUI):
            def set_state(self, state):
                raise RuntimeError("the HUD is gone")

        app.ui = BrokenUI()
        with self.assertRaises(RuntimeError):
            asyncio.run(app._execute_tool(_fc()))
        self.assertEqual(app._tool_call_depth, 0)

        # And the very next call is ordinary narration again: the guard does not
        # stay stuck and silence NEO for the rest of the session.
        app.ui = FakeUI()
        with _capturing_sends() as scheduled:
            app.speak("back to normal")
            _deliver(scheduled)
        self.assertEqual(len(app.session.sent), 1)
        self.assertIn("back to normal", app.session.sent[0]["turns"]["parts"][0]["text"])

    def test_narration_outside_a_tool_still_completes_the_turn(self):
        """The manual path is untouched: no tool in flight means it is a turn."""
        app = make_app()

        with _capturing_sends() as scheduled:
            app.speak("Tell the user the battery is low.")
            _deliver(scheduled)

        self.assertEqual(len(scheduled), 1)
        self.assertEqual(len(app.session.sent), 1)
        sent = app.session.sent[0]
        self.assertTrue(sent["turn_complete"])
        self.assertEqual(sent["turns"]["role"], "user")
        self.assertIn("battery is low", sent["turns"]["parts"][0]["text"])
        self.assertEqual(app.ui.lines, [])

    def test_a_nested_tool_dispatch_sees_a_deeper_guard_and_leaves_it_at_zero(self):
        """A tool started from inside another tool sees depth 2, not 1."""
        app = make_app()
        seen: list = []

        async def dispatcher(name, args, fc=None):
            seen.append(app._tool_call_depth)
            if name != "reminder":
                # A second tool started from inside the first one. `reminder`
                # has no inline branch of its own, so it comes back round to
                # this dispatcher exactly as a registered capability does.
                await app._execute_tool(_fc(name="reminder"))
                app.speak("outer finished")
            return "ok"

        app._run_registered_tool = dispatcher
        with _capturing_sends() as scheduled:
            asyncio.run(app._execute_tool(_fc()))

        self.assertEqual(seen, [1, 2])
        self.assertEqual(app._tool_call_depth, 0)
        self.assertEqual(scheduled, [])
        self.assertIn("outer finished", app.ui.lines)


if __name__ == "__main__":
    unittest.main()
