# -*- mode: python ; coding: utf-8 -*-
import os
import sys

project_dir = os.path.abspath(SPECPATH)

a = Analysis(
    [os.path.join(project_dir, "gui_main.py")],
    pathex=[project_dir],
    binaries=[],
    datas=[(os.path.join(project_dir, "fox.png"), ".")],
    hiddenimports=["win32net"] if sys.platform == "win32" else [],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
if sys.platform == "darwin":
    exe = EXE(
        pyz,
        a.scripts,
        a.binaries,
        a.datas,
        [],
        name="FoxterSecurity",
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        console=False,
        disable_windowed_traceback=False,
    )
    app = BUNDLE(
        exe,
        name="Foxter Security.app",
        bundle_identifier="com.foxtersecurity.app",
    )
else:
    exe = EXE(
        pyz,
        a.scripts,
        [],
        exclude_binaries=True,
        name="FoxterSecurity",
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        console=False,
        disable_windowed_traceback=False,
    )
    collected = COLLECT(
        exe,
        a.binaries,
        a.datas,
        strip=False,
        upx=False,
        name="FoxterSecurity",
    )
