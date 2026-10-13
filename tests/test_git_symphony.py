import os
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from git_symphony import GitSymphony
from scripts.git_symphony_site import write_site


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class GitSymphonyTests(unittest.TestCase):
    def test_hash_maps_to_diatonic_triad(self):
        symphony = GitSymphony()

        self.assertEqual(("C", [60, 64, 67]), symphony.commit_to_chord("00000000"))
        self.assertEqual(("Bdim", [71, 74, 77]), symphony.commit_to_chord("00000006"))

    def test_generates_midi_svg_and_interactive_player_from_git_history(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir) / "repo"
            repo.mkdir()
            self._run_git(repo, "init", "-q")
            self._run_git(repo, "config", "user.name", "Test Author")
            self._run_git(repo, "config", "user.email", "test@example.com")
            for index, (date, message) in enumerate(
                (
                    ("2026-01-01T10:00:00+00:00", "feat: first commit"),
                    ("2026-01-01T11:00:00+00:00", "fix: second commit"),
                )
            ):
                (repo / "tracked.txt").write_text(str(index), encoding="utf-8")
                self._run_git(repo, "add", "tracked.txt")
                self._run_git(
                    repo,
                    "commit",
                    "-q",
                    "-m",
                    message,
                    env={
                        "GIT_AUTHOR_DATE": date,
                        "GIT_COMMITTER_DATE": date,
                    },
                )

            output = Path(temp_dir) / "site"
            midi_file = output / "symphony.mid"
            html_file = output / "index.html"
            svg_file = output / "symphony.svg"
            symphony = GitSymphony(repo_path=str(repo))
            symphony.generate_symphony(str(midi_file))
            write_site(
                symphony.events,
                html_file,
                svg_file,
                "https://github.com/example/project",
                symphony.tempo,
                str(midi_file),
            )

            self.assertEqual(2, len(symphony.events))
            self.assertEqual("feat: first commit", symphony.events[0]["message"])
            self.assertEqual(3, len(symphony.events[0]["notes"]))
            self.assertTrue(midi_file.read_bytes().startswith(b"MThd"))
            html = html_file.read_text(encoding="utf-8")
            self.assertIn("AudioContext", html)
            self.assertIn("Baixar arquivo MIDI", html)
            self.assertIn("symphony.svg", html)
            root = ET.fromstring(svg_file.read_text(encoding="utf-8"))
            self.assertTrue(root.tag.endswith("svg"))

    def test_player_escapes_commit_content_in_embedded_json(self):
        event = {
            "hash": "0123456789abcdef",
            "author": "Contributor",
            "date": "2026-01-01 10:00:00 +0000",
            "message": "</script><script>alert(1)</script>",
            "chord": "C",
            "notes": [60, 64, 67],
            "velocity": 80,
            "duration": 1,
            "time": 0,
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            html_file = Path(temp_dir) / "index.html"
            svg_file = html_file.with_name("score.svg")
            write_site([event], html_file, svg_file)

            html = html_file.read_text(encoding="utf-8")
            self.assertNotIn("</script><script>alert(1)</script>", html)
            self.assertIn("\\u003c/script\\u003e", html)

    def test_non_git_directory_reports_an_error(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaisesRegex(RuntimeError, "histórico Git"):
                GitSymphony(repo_path=temp_dir).get_git_commits()

    def test_release_workflow_publishes_the_player_to_pages(self):
        workflow = (PROJECT_ROOT / ".github" / "workflows" / "build.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("publish-symphony:", workflow)
        self.assertIn("if: startsWith(github.ref, 'refs/tags/v')", workflow)
        self.assertIn("actions/upload-pages-artifact@", workflow)
        self.assertIn("actions/deploy-pages@", workflow)
        self.assertIn("requirements-git-symphony.txt", workflow)

    @staticmethod
    def _run_git(repo, *args, env=None):
        command_env = None
        if env:
            command_env = os.environ.copy()
            command_env.update(env)
        subprocess.run(
            ["git", *args],
            cwd=repo,
            check=True,
            capture_output=True,
            text=True,
            env=command_env,
        )


if __name__ == "__main__":
    unittest.main()
