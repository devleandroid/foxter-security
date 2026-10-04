import unittest
from pathlib import Path

from scripts.build_app import build_command


class BuildAppTests(unittest.TestCase):
    def setUp(self):
        self.project_root = Path(__file__).resolve().parents[1]

    def test_uses_nuitka_standalone_compilation(self):
        command = build_command(self.project_root, "Linux")

        self.assertIn("--mode=standalone", command)
        self.assertIn("--python-flag=no_docstrings", command)
        self.assertIn("--enable-plugin=pyqt5", command)
        self.assertIn("--include-data-files=VERSION=VERSION", command)
        self.assertNotIn("--onefile", command)
        self.assertTrue(command[-1].endswith("gui_main.py"))

    def test_windows_binary_has_gui_subsystem_and_version_metadata(self):
        command = build_command(self.project_root, "Windows")
        version = (self.project_root / "VERSION").read_text(encoding="utf-8").strip()

        self.assertIn("--windows-console-mode=disable", command)
        self.assertIn(f"--product-version={version}", command)
        self.assertIn(f"--file-version={version}", command)
        self.assertFalse(
            any(argument.startswith("--windows-icon-from-ico=") for argument in command)
        )

    def test_macos_build_produces_named_app_bundle(self):
        command = build_command(self.project_root, "Darwin")

        self.assertIn("--mode=app", command)
        self.assertNotIn("--macos-create-app-bundle", command)


if __name__ == "__main__":
    unittest.main()
