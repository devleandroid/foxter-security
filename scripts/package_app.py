import os
import platform
import stat
import sys
import zipfile
from pathlib import Path


def main():
    target = os.environ["BUILD_TARGET"]
    dist_dir = Path("dist")
    bundle_name = "Foxter Security.app" if platform.system() == "Darwin" else "FoxterSecurity"
    bundle = dist_dir / bundle_name
    if not bundle.exists():
        raise FileNotFoundError(f"Build output not found: {bundle}")

    archive_path = dist_dir / f"FoxterSecurity-{target}.zip"
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for path in bundle.rglob("*"):
            archive_path_in_zip = Path(bundle.name) / path.relative_to(bundle)
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
