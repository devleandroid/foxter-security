import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class ReleaseNotesTests(unittest.TestCase):
    def test_release_notes_explain_usage_and_scanner_limits(self):
        notes = (PROJECT_ROOT / "RELEASE_NOTES.md").read_text(encoding="utf-8")

        for section in ("## Como baixar e iniciar", "## Como usar", "## Limitações importantes"):
            with self.subTest(section=section):
                self.assertIn(section, notes)

        self.assertIn("malware", notes)
        self.assertIn("não substitui um antivírus com proteção em tempo real", notes)
        self.assertIn("falsos positivos", notes)

    def test_release_workflow_uses_notes_for_new_and_existing_releases(self):
        workflow = (PROJECT_ROOT / ".github" / "workflows" / "build.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn('gh release edit "$TAG_NAME" --notes-file RELEASE_NOTES.md', workflow)
        self.assertIn(
            'gh release create "$TAG_NAME" release-assets/*.zip --title "$TAG_NAME" '
            "--notes-file RELEASE_NOTES.md",
            workflow,
        )


if __name__ == "__main__":
    unittest.main()
