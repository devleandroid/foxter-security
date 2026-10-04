import platform
import subprocess
import sys
from pathlib import Path


def build_command(project_root, system=None):
    system = platform.system() if system is None else system
    version = (project_root / "VERSION").read_text(encoding="utf-8").strip()
    mode = "app" if system == "Darwin" else "standalone"
    command = [
        sys.executable,
        "-m",
        "nuitka",
        f"--mode={mode}",
        "--python-flag=no_docstrings",
        "--enable-plugin=pyqt5",
        "--include-data-files=fox.png=fox.png",
        "--include-data-files=VERSION=VERSION",
        "--output-dir=dist",
        "--output-filename=FoxterSecurity",
        "--product-name=Foxter Security",
    ]
    if system == "Windows":
        command.extend(
            [
                f"--product-version={version}",
                f"--file-version={version}",
                "--windows-console-mode=disable",
            ]
        )
    command.append(str(project_root / "gui_main.py"))
    return command


def main():
    project_root = Path(__file__).resolve().parents[1]
    subprocess.run(build_command(project_root), cwd=project_root, check=True)


if __name__ == "__main__":
    main()
