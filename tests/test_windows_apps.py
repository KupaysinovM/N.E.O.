"""Application resolution: allowlisted, shell-free, and honest about refusal."""
from __future__ import annotations

import unittest

from core.windows import apps
from core.windows.errors import WindowsError, WindowsErrorKind


class TestNameValidation(unittest.TestCase):

    def test_ordinary_names_pass(self):
        self.assertEqual(apps._clean("Notepad"), "Notepad")
        self.assertEqual(apps._clean(" Visual Studio Code "), "Visual Studio Code")

    def test_shell_metacharacters_are_refused(self):
        # Each of these is a command the moment a shell sees it.
        attempts = [
            "calc & del /s c:\\",
            "calc && format c:",
            "notepad | powershell",
            "app; rm -rf /",
            'app" && whoami',
            "app' | net user",
            "app > out.txt",
            "app < in.txt",
            "app`whoami`",
            "app$(whoami)",
            "app%PATH%",
            "app^&calc",
            "app!x",
            "app\ncalc",
        ]
        for attempt in attempts:
            with self.subTest(attempt=attempt):
                with self.assertRaises(WindowsError) as ctx:
                    apps.resolve(attempt)
                self.assertEqual(ctx.exception.kind, WindowsErrorKind.INVALID_ARGUMENT)

    def test_empty_and_overlong_names_are_refused(self):
        with self.assertRaises(WindowsError):
            apps.resolve("   ")
        with self.assertRaises(WindowsError):
            apps.resolve("a" * 300)

    def test_scripts_are_refused_even_when_they_exist(self):
        # A .bat/.cmd path is a program text file, not an executable.
        import pathlib
        import tempfile
        bat = pathlib.Path(tempfile.mkdtemp()) / "helper.bat"
        bat.write_text("@echo off\n", encoding="utf-8")
        with self.assertRaises(WindowsError) as ctx:
            apps.resolve(str(bat))
        self.assertIn("script", str(ctx.exception).lower())

    def test_absolute_executable_paths_are_allowed(self):
        import pathlib
        import tempfile
        exe = pathlib.Path(tempfile.mkdtemp()) / "helper.exe"
        exe.write_bytes(b"MZ")
        resolution = apps.resolve(str(exe))
        self.assertEqual(resolution["kind"], "absolute_path")
        self.assertEqual(resolution["target"], str(exe))


class TestSettingsUris(unittest.TestCase):

    def test_valid_settings_uris(self):
        for uri in ("ms-settings:", "ms-settings:display", "ms-settings:privacy-windows"):
            self.assertTrue(apps.is_settings_uri(uri))

    def test_anything_that_is_not_a_settings_uri_is_not_one(self):
        for uri in ("ms-settings:&calc", "ms-settings:display/../x", "calc",
                    "https://example.com", "ms-settings:display&del c:"):
            self.assertFalse(apps.is_settings_uri(uri))


class TestAliasResolution(unittest.TestCase):

    def test_alias_table_is_normalised_by_spaces_and_case(self):
        self.assertEqual(apps._normalize("File Explorer"), "file explorer")
        self.assertEqual(apps._normalize("  TASK   MANAGER "), "task manager")

    def test_known_aliases_resolve_or_are_reported_not_invented(self):
        try:
            resolution = apps.resolve("calculator")
        except WindowsError as e:
            # Refusing because calc.exe is genuinely absent is honest; inventing
            # a target would not be.
            self.assertIn(e.kind, (WindowsErrorKind.APPLICATION_NOT_FOUND,
                                   WindowsErrorKind.OS_ERROR))
        else:
            self.assertIn(resolution["kind"], ("system_executable", "path_lookup"))
            self.assertTrue(resolution["target"].lower().endswith(".exe"))
            self.assertIn("how", resolution)

    def test_unknown_application_is_reported_as_not_found(self):
        with self.assertRaises(WindowsError) as ctx:
            apps.resolve("some_application_that_does_not_exist_zzz")
        self.assertEqual(ctx.exception.kind, WindowsErrorKind.APPLICATION_NOT_FOUND)


class TestNoShellExecutorExists(unittest.TestCase):

    def test_the_module_exposes_no_command_string_api(self):
        # Phase 3 must not ship a run_command(command: str).
        forbidden = ("run_command", "run_shell", "execute_command", "shell_exec",
                     "run", "eval", "exec", "popen")
        for name in forbidden:
            self.assertFalse(hasattr(apps, name),
                             f"core/windows/apps.py exposes a {name}() shell path")

    def test_no_shell_true_anywhere_in_the_windows_subsystem(self):
        # Parsed rather than grepped: the prose in these modules talks ABOUT
        # shell=True on purpose, so a text scan would flag the explanation.
        import ast
        import pathlib

        import core.windows as boundary
        root = pathlib.Path(boundary.__file__).parent
        for path in root.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    for keyword in node.keywords:
                        self.assertFalse(
                            keyword.arg == "shell" and getattr(keyword.value, "value", None),
                            f"{path.name} enables a shell at line {node.lineno}")

    def test_the_windows_subsystem_has_no_subprocess_string_execution(self):
        import ast
        import pathlib

        import core.windows as boundary
        root = pathlib.Path(boundary.__file__).parent
        for path in root.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    self.assertNotIn(node.func.id, ("eval", "exec", "os.system"),
                                     f"{path.name} calls {node.func.id}()")


if __name__ == "__main__":
    unittest.main()