import platform
import subprocess
import sys
from pathlib import Path


def build_command(project_root, system=None):
    system = platform.system() if system is None else system
    command = [
        sys.executable,
        "-m",
        "nuitka",
        "--mode=standalone",
        "--python-flag=no_docstrings",
        "--enable-plugin=pyqt5",
        "--include-data-files=fox.png=fox.png",
        "--include-data-files=VERSION=VERSION",
        "--output-dir=dist",
        "--output-filename=FoxterSecurity",
        "--product-name=Foxter Security",
    ]
    if system == "Windows":
        command.append("--windows-console-mode=disable")
    elif system == "Darwin":
        command.extend(
            [
                "--macos-create-app-bundle",
                "--macos-app-name=Foxter Security",
            ]
        )
    command.append(str(project_root / "gui_main.py"))
    return command


def main():
    project_root = Path(__file__).resolve().parents[1]
    subprocess.run(build_command(project_root), cwd=project_root, check=True)


if __name__ == "__main__":
    main()
