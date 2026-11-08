# -*- mode: python ; coding: utf-8 -*-
# Bu spec bu ortamda çalıştırılmadı. Windows'ta PyInstaller kurulduktan sonra
#   pyinstaller packaging/DPIBypassStudio.spec
# WinDivert sürücü dosyaları pydivert paketinin içinde gelmelidir; collect_all
# onları exe yanına alır. Yönetici hakları yine gerekir.

from PyInstaller.utils.hooks import collect_all

datas = []
binaries = []
hiddenimports = ["dns", "dns.message", "dns.query", "h2", "pystray"]

for package in ("pydivert", "customtkinter", "pystray"):
    package_datas, package_binaries, package_hidden = collect_all(package)
    datas += package_datas
    binaries += package_binaries
    hiddenimports += package_hidden

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="DPIBypassStudio",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="DPIBypassStudio",
)
