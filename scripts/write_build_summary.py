import os
from pathlib import Path


def main():
    target = os.environ["BUILD_TARGET"]
    summary_path = Path(os.environ["GITHUB_STEP_SUMMARY"])
    summary_path.write_text(
        f"Build package: FoxterSecurity-{target}.zip\n\n"
        "Download it from this workflow run's Artifacts section. "
        "For a permanent download, push a version tag (for example, "
        "v1.0.0) to publish a GitHub Release.\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
