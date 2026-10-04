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
        self.assertIn("Monitoramento em tempo real", notes)
        self.assertIn("alteração em massa", notes)
        self.assertIn("não substitui uma suíte antivírus comercial", notes)
        self.assertIn("falsos positivos", notes)
        self.assertIn("SHA256SUMS.txt", notes)

    def test_release_workflow_uses_notes_for_new_and_existing_releases(self):
        workflow = (PROJECT_ROOT / ".github" / "workflows" / "build.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn('gh release edit "$TAG_NAME" --notes-file RELEASE_NOTES.md', workflow)
        self.assertIn(
            'gh release create "$TAG_NAME" release-assets/*.zip '
            'release-assets/SHA256SUMS.txt --title "$TAG_NAME" '
            "--notes-file RELEASE_NOTES.md",
            workflow,
        )
        self.assertIn("sha256sum *.zip > SHA256SUMS.txt", workflow)
        self.assertIn("Verify release version", workflow)

    def test_version_file_matches_release_notes(self):
        version = (PROJECT_ROOT / "VERSION").read_text(encoding="utf-8").strip()
        notes = (PROJECT_ROOT / "RELEASE_NOTES.md").read_text(encoding="utf-8")
        readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertEqual(version, "1.0.4")
        self.assertIn(f"**{version}**", notes)
        self.assertIn(f"`v{version}`", readme)

    def test_donation_copy_is_in_readme_and_release_notes(self):
        expected = (
            "Ajude a fortalecer o Foxter Security",
            "contribuição voluntária",
            "803.185.680-04",
            "decidir com confiança.",
        )
        for filename in ("README.md", "RELEASE_NOTES.md"):
            content = (PROJECT_ROOT / filename).read_text(encoding="utf-8")
            for phrase in expected:
                with self.subTest(file=filename, phrase=phrase):
                    self.assertIn(phrase, content)


if __name__ == "__main__":
    unittest.main()
