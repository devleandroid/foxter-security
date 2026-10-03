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
            bundle_name = "Foxter Security.app" if sys.platform == "darwin" else "FoxterSecurity"
            executable = workspace / "dist" / bundle_name / "app" / "FoxterSecurity"
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
                    archive.read(f"{bundle_name}/app/FoxterSecurity"),
                    b"standalone application",
                )


if __name__ == "__main__":
    unittest.main()
