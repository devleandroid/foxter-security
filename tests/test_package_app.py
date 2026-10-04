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
                bundle_name = "Foxter Security.app"
                bundle_dir = workspace / "dist" / bundle_name
            else:
                bundle_name = "FoxterSecurity"
                bundle_dir = workspace / "dist" / "FoxterSecurity.dist"
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
                    archive.read(f"{bundle_name}/app/{executable_name}"),
                    b"standalone application",
                )


if __name__ == "__main__":
    unittest.main()
