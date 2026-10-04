import os
import platform
import stat
import sys
import zipfile
from pathlib import Path


def main():
    target = os.environ.get("BUILD_TARGET")
    if not target:
        system = platform.system()
        machine = platform.machine().lower()
        if system == "Linux" and machine in {"x86_64", "amd64"}:
            target = "linux-x64"
        elif system == "Windows" and machine in {"x86_64", "amd64"}:
            target = "windows-x64"
        elif system == "Darwin" and machine in {"x86_64", "amd64"}:
            target = "macos-x64"
        elif system == "Darwin" and machine in {"arm64", "aarch64"}:
            target = "macos-arm64"
        else:
            raise RuntimeError(
                f"Unsupported build target: {system} {machine}; set BUILD_TARGET explicitly"
            )
    dist_dir = Path("dist")
    if platform.system() == "Darwin":
        bundle_name = "Foxter Security.app"
        bundle = dist_dir / bundle_name
    else:
        bundle_name = "FoxterSecurity"
        bundle = dist_dir / "FoxterSecurity.dist"
    if not bundle.exists():
        raise FileNotFoundError(f"Build output not found: {bundle}")

    archive_path = dist_dir / f"FoxterSecurity-{target}.zip"
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for path in bundle.rglob("*"):
            archive_path_in_zip = Path(bundle_name) / path.relative_to(bundle)
            if path.is_symlink():
                info = zipfile.ZipInfo(archive_path_in_zip.as_posix())
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(info, os.readlink(path))
            elif path.is_dir():
                info = zipfile.ZipInfo(archive_path_in_zip.as_posix() + "/")
                info.external_attr = (stat.S_IFDIR | 0o755) << 16
                archive.writestr(info, "")
            else:
                archive.write(path, archive_path_in_zip.as_posix())
    print(f"Created {archive_path}")


if __name__ == "__main__":
    main()
