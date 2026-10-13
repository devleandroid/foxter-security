#!/usr/bin/env python3
"""Generate Git Symphony files in the checked-out repository for the composite action."""

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from git_symphony import GitSymphony
from scripts.git_symphony_site import write_site


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-directory", default="site")
    args = parser.parse_args(argv)

    workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    output_directory = (workspace / args.output_directory).resolve()
    try:
        output_directory.relative_to(workspace)
    except ValueError:
        parser.error("output-directory must stay inside GITHUB_WORKSPACE")

    repository_url = os.environ.get("GITHUB_SERVER_URL", "").rstrip("/")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if repository_url and repository:
        repository_url = f"{repository_url}/{repository}"
    else:
        repository_url = ""

    midi_path = output_directory / "git_symphony.mid"
    html_path = output_directory / "index.html"
    svg_path = output_directory / "symphony.svg"
    try:
        symphony = GitSymphony(repo_path=str(workspace))
        symphony.generate_symphony(str(midi_path))
        write_site(
            symphony.events,
            html_path,
            svg_path,
            repository_url,
            symphony.tempo,
            str(midi_path),
        )
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Erro: {error}", file=sys.stderr)
        return 1

    print(f"Git Symphony generated in {output_directory}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
