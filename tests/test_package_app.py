import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class PackageAppTests(unittest.TestCase):
    def test_packages_build_output_for_current_platform(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            if sys.platform == "darwin":
                build_output_name = "gui_main.app"
                archive_bundle_name = "Foxter Security.app"
            else:
                build_output_name = "gui_main.dist"
                archive_bundle_name = "FoxterSecurity"
            bundle_dir = workspace / "dist" / build_output_name
            executable_name = (
                "FoxterSecurity.exe" if sys.platform == "win32" else "FoxterSecurity"
            )
            executable = bundle_dir / "app" / executable_name
            executable.parent.mkdir(parents=True)
            executable.write_text("standalone application")

            environment = os.environ.copy()
            environment["BUILD_TARGET"] = "test-target"
            subprocess.run(
                [sys.executable, str(PROJECT_ROOT / "scripts" / "package_app.py")],
                cwd=workspace,
                env=environment,
                check=True,
                capture_output=True,
                text=True,
            )

            archive_path = workspace / "dist" / "FoxterSecurity-test-target.zip"
            with zipfile.ZipFile(archive_path) as archive:
                self.assertEqual(
                    archive.read(f"{archive_bundle_name}/app/{executable_name}"),
                    b"standalone application",
                )

    def test_rejects_missing_or_ambiguous_compiler_output(self):
        from scripts.package_app import find_build_output

        with tempfile.TemporaryDirectory() as temporary_directory:
            dist_dir = Path(temporary_directory)
            with self.assertRaises(FileNotFoundError):
                find_build_output(dist_dir, "Linux")

            (dist_dir / "gui_main.dist").mkdir()
            (dist_dir / "other.dist").mkdir()
            with self.assertRaises(FileNotFoundError):
                find_build_output(dist_dir, "Linux")

    def test_finds_nuitka_dist_and_macos_app_output_names(self):
        from scripts.package_app import find_build_output

        with tempfile.TemporaryDirectory() as temporary_directory:
            dist_dir = Path(temporary_directory)
            linux_output = dist_dir / "gui_main.dist"
            linux_output.mkdir()
            self.assertEqual(find_build_output(dist_dir, "Linux"), linux_output)

            linux_output.rmdir()
            macos_output = dist_dir / "gui_main.app"
            macos_output.mkdir()
            self.assertEqual(find_build_output(dist_dir, "Darwin"), macos_output)


if __name__ == "__main__":
    unittest.main()
