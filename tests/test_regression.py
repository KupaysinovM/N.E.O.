"""Regression checks: the existing system still behaves as Phase 1 left it.

These run against the real repository — the real actions/ directory, the real
settings file, the real secret store — because the question they answer is
"did adding the task layer break or weaken anything that was already working".
Nothing here writes to the repository or performs an OS action.
"""
from __future__ import annotations

import json
import re
import unittest

from tests.support import REPO_ROOT, Sink, with_prompts

NEW_CORE_MODULES = (
    "core/task_models.py", "core/events.py", "core/task_store.py",
    "core/task_manager.py", "core/execution.py",
)
EXPECTED_ACTIONS = {
    "browser_control", "code_helper", "computer_control", "computer_settings",
    "desktop_control", "dev_agent", "file_controller", "file_processor",
    "flight_finder", "game_updater", "open_app", "reminder", "send_message",
    "video_player", "weather_report", "web_search", "youtube_video",
}


class TestRegistriesStillLoad(unittest.TestCase):

    def test_the_real_action_registry_loads(self):
        from core.action_loader import discover_actions
        log = Sink()
        registry = discover_actions(REPO_ROOT / "actions", set(), logger=log)
        names = registry.names()
        self.assertTrue(EXPECTED_ACTIONS.issubset(names),
                        f"missing: {sorted(EXPECTED_ACTIONS - names)}")
        self.assertGreaterEqual(len(names), 17)
        self.assertTrue(registry.get_tool_declarations())

    def test_the_real_plugin_directory_is_scanned_without_error(self):
        from core.plugin_loader import discover_plugins
        registry = discover_plugins(REPO_ROOT / "plugins", set(), logger=Sink(),
                                    notify=Sink())
        self.assertEqual(registry.list_for_ui(), [],
                         "the plugins/ directory should only hold the template")

    def test_core_modules_the_phase_depends_on_still_import(self):
        import importlib
        for module in ("core.gemini", "core.confirm", "core.undo", "core.secret_store",
                       "core.audio_devices", "core.action_loader", "core.plugin_loader",
                       "core.task_models", "core.events", "core.task_store",
                       "core.task_manager", "core.execution"):
            with self.subTest(module=module):
                importlib.import_module(module)


class TestPhase1Protections(unittest.TestCase):

    def test_secret_store_is_still_the_credential_path(self):
        from core import secret_store
        self.assertEqual(secret_store.SETTINGS_FILE.name, "neo_settings.json")
        self.assertIsInstance(secret_store.looks_configured(), bool)
        self.assertIn(secret_store.credential_source(),
                      ("store", "environment", "legacy-plaintext", ""))

    def test_no_key_shaped_string_in_the_settings_file(self):
        path = REPO_ROOT / "config" / "neo_settings.json"
        if not path.exists():
            self.skipTest("no settings file on this machine")
        text = path.read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"AIza[0-9A-Za-z_\-]{20,}", text),
                          "a plaintext Gemini key is back in the settings file")

    def test_task_state_is_not_written_into_configuration(self):
        from core.task_store import default_tasks_path
        path = REPO_ROOT / "config" / "neo_settings.json"
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            for key in ("tasks", "task_history", "task_state"):
                self.assertNotIn(key, data)
        self.assertEqual(default_tasks_path(),
                         REPO_ROOT / "state" / "tasks.json")
        self.assertNotIn("config", default_tasks_path().parts)

    def test_removed_fake_data_behaviour_is_still_removed(self):
        from actions.computer_control import computer_control
        random_data = computer_control(parameters={"action": "random_data"})
        self.assertIn("Unknown action", random_data)
        missing = computer_control(parameters={
            "action": "user_data", "field": "zzz_phase2_missing_field_zzz"})
        self.assertTrue(missing.startswith("NOT_AVAILABLE:"), missing[:80])

    def test_model_generated_desktop_code_is_still_refused(self):
        from actions.desktop import desktop_control
        outcome = desktop_control(parameters={"task": "delete every file on the desktop"})
        self.assertTrue(outcome.startswith("NOT_SUPPORTED:"), outcome[:80])

    def test_the_new_core_never_uses_exec_or_eval(self):
        pattern = re.compile(r"\b(exec|eval)\s*\(")
        for relative in NEW_CORE_MODULES:
            text = (REPO_ROOT / relative).read_text(encoding="utf-8")
            with self.subTest(module=relative):
                self.assertIsNone(pattern.search(text),
                                  f"{relative} introduces exec()/eval()")

    def test_the_dashboard_stays_gated_by_default(self):
        from memory.config_manager import get_remote_dashboard_enabled
        from core import secret_store
        if secret_store.looks_configured():
            self.assertFalse(get_remote_dashboard_enabled(),
                             "the remote dashboard is enabled on this machine")


class TestRealCapabilityThroughTheBoundary(unittest.TestCase):

    @with_prompts
    def test_a_real_action_returns_a_structured_result(self):
        """A real action, the real registry, through the Phase 2 boundary.

        `computer_control` with `user_data` is used because it is a genuine
        production action whose path reads the real memory file and touches
        nothing on the OS — so the assertion is about the boundary, not about
        this machine's desktop. The OS-touching read-only check runs at runtime
        (see the Phase 2 report).
        """
        from core.action_loader import discover_actions
        from core.execution import ExecStatus, ExecutionRequest
        from tests.support import (
            bound_gate, make_layer, make_manager, resolve_confirmation,
            tmp_dir, wait_for, with_prompts,
        )

        registry = discover_actions(REPO_ROOT / "actions", set(), logger=Sink())
        tm = make_manager(tmp_dir())
        layer = make_layer(tm, actions=registry, logger=Sink(), notify=Sink())
        layer.bind_confirmation_gate()
        task = tm.create_task("read a field that was never stored")
        tm.start_task(task.task_id)
        with bound_gate():
            result = layer.execute(
                ExecutionRequest(action="computer_control",
                                 arguments={"action": "user_data",
                                            "field": "zzz_phase2_missing_field_zzz"},
                                 task_id=task.task_id),
                context=tm.context_for(task.task_id),
                handler_ctx={"player": None, "session_memory": None})

            self.assertEqual(result.status, ExecStatus.REQUIRES_CONFIRMATION)
            resolve_confirmation(True)
            self.assertTrue(wait_for(lambda: task.status.value == "FAILED"))

        self.assertEqual(task.error.kind.value, "ACTION_UNAVAILABLE")
        self.assertNotIn("zzz_phase2_missing_field_zzz", str(task.to_dict()))

    def test_an_unknown_tool_through_the_real_registry_is_explicit(self):
        from core.action_loader import discover_actions
        from core.execution import ExecStatus, ExecutionRequest
        from tests.support import make_layer, make_manager, tmp_dir

        registry = discover_actions(REPO_ROOT / "actions", set(), logger=Sink())
        tm = make_manager(tmp_dir())
        layer = make_layer(tm, actions=registry, logger=Sink(), notify=Sink())
        result = layer.execute(ExecutionRequest(action="format_the_hard_drive",
                                               arguments={}, task_id=""))
        self.assertEqual(result.status, ExecStatus.NOT_AVAILABLE)
        self.assertEqual(result.error.kind.value, "UNKNOWN_ACTION")


if __name__ == "__main__":
    unittest.main()
