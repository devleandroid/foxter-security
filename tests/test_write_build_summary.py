import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class BuildSummaryTests(unittest.TestCase):
    def test_writes_artifact_name_and_download_instructions(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            summary_path = Path(temporary_directory) / "summary.md"
            environment = os.environ.copy()
            environment["BUILD_TARGET"] = "linux-x64"
            environment["GITHUB_STEP_SUMMARY"] = str(summary_path)
            subprocess.run(
                [sys.executable, str(PROJECT_ROOT / "scripts" / "write_build_summary.py")],
                check=True,
                env=environment,
                capture_output=True,
                text=True,
            )

            summary = summary_path.read_text(encoding="utf-8")
            self.assertIn("FoxterSecurity-linux-x64.zip", summary)
            self.assertIn("GitHub Release", summary)


if __name__ == "__main__":
    unittest.main()
