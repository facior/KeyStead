"""
Budowanie KeyStead Manager dla macOS (plik DMG) i Linuksa (AppImage). Uruchamiane w GitHub Actions
(.github/workflows/build.yml) albo ręcznie na danym systemie. Wersję dla Windows buduje tools/release_app.py.

    python packaging/build_desktop.py <katalog wynikowy>

Pliki NIE są tu podpisywane kluczem wydawcy – robi to tools/release_app.py na komputerze wydawcy
(klucz prywatny nie trafia do GitHub). Na macOS program dostaje tylko podpis „ad hoc” (bez konta Apple Developer).
"""

import os
import plistlib
import shutil
import stat
import subprocess
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.app_update import asset_names  # noqa: E402
from core.version import APP_VERSION, AUTHOR  # noqa: E402

EXE_NAME = "KeyStead Manager"
BUNDLE_ID = "io.github.facior.keystead"
BUILD = os.path.join(ROOT, "build", "desktop")
LICENSES = [("LICENSE", "LICENSE.txt"), ("LICENSE.en.txt", "LICENSE.en.txt")]
APPIMAGETOOL = "https://github.com/AppImage/appimagetool/releases/download/1.9.1/appimagetool-x86_64.AppImage"


def run(cmd, **kw):
    print(">", " ".join(f'"{c}"' if " " in c else c for c in cmd), flush=True)
    subprocess.run(cmd, check=True, **kw)


def fail(msg: str) -> None:
    print(f"!! {msg}")
    sys.exit(1)


def pyinstaller() -> str:
    """Program zbudowany przez PyInstaller (na macOS: paczka .app). Zwraca jego ścieżkę."""
    shutil.rmtree(BUILD, ignore_errors=True)
    sep = os.pathsep
    args = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--windowed", "--name", EXE_NAME,
            "--add-data", f"{os.path.join(ROOT, 'core', 'wordlist_eff.txt')}{sep}core",
            "--add-data", f"{os.path.join(ROOT, 'ui', 'assets')}{sep}ui/assets",
            "--add-data", f"{os.path.join(ROOT, 'core', 'locales')}{sep}core/locales",
            "--collect-data", "customtkinter",
            "--hidden-import", "zxingcpp",
            # YubiKey (wtyczka): moduły USB ładowane zależnie od systemu
            "--collect-submodules", "yubikit", "--collect-submodules", "ykman.hid",
            # pęk kluczy systemu (token serwera): keyring wybiera moduł dla systemu w czasie działania
            "--collect-submodules", "keyring",
            "--exclude-module", "server", "--exclude-module", "tests", "--exclude-module", "fastapi",
            "--exclude-module", "uvicorn", "--exclude-module", "winrt",
            "--distpath", os.path.join(BUILD, "dist"), "--workpath", os.path.join(BUILD, "work"),
            "--specpath", BUILD]
    if sys.platform == "darwin":
        args += ["--icon", os.path.join(ROOT, "ui", "assets", "keystead.icns"), "--osx-bundle-identifier", BUNDLE_ID,
                 "--hidden-import", "fido2.hid.macos"]
    else:
        args += ["--hidden-import", "fido2.hid.linux"]
    run(args + [os.path.join(ROOT, "main.py")], cwd=ROOT)
    dist = os.path.join(BUILD, "dist")
    app = os.path.join(dist, EXE_NAME + ".app") if sys.platform == "darwin" else os.path.join(dist, EXE_NAME)
    if not os.path.exists(app):
        fail("PyInstaller nie utworzył programu.")
    return app


def add_licenses(target_dir: str) -> None:
    for src, dst in LICENSES:
        shutil.copy2(os.path.join(ROOT, src), os.path.join(target_dir, dst))
    run([sys.executable, os.path.join(ROOT, "packaging", "third_party_notices.py"), os.path.join(BUILD, "work", EXE_NAME),
         os.path.join(target_dir, "THIRD-PARTY-NOTICES.txt")])


def selftest(executable: str) -> None:
    out = os.path.join(BUILD, "selftest.json")
    proc = subprocess.run([executable, "--selftest", out], timeout=300)
    with open(out, encoding="utf-8") as f:
        print(f.read())
    if proc.returncode != 0:
        fail("Autotest zbudowanego programu nie przeszedł.")


# --------------------------------------------------------------------- macOS
def build_mac(out_dir: str) -> str:
    app = pyinstaller()
    contents = os.path.join(app, "Contents")
    plist_path = os.path.join(contents, "Info.plist")
    with open(plist_path, "rb") as f:
        info = plistlib.load(f)
    info.update({
        "CFBundleName": EXE_NAME,
        "CFBundleDisplayName": EXE_NAME,
        "CFBundleShortVersionString": APP_VERSION,
        "CFBundleVersion": APP_VERSION,
        "LSMinimumSystemVersion": "11.0",
        "NSHighResolutionCapable": True,
        "NSHumanReadableCopyright": f"© 2026 {AUTHOR}",
        "LSApplicationCategoryType": "public.app-category.utilities",
    })
    with open(plist_path, "wb") as f:
        plistlib.dump(info, f)
    add_licenses(os.path.join(contents, "Resources"))
    # Każda zmiana w paczce unieważnia podpis – podpis „ad hoc” od nowa (bez niego Apple Silicon nie uruchomi programu)
    run(["codesign", "--force", "--deep", "--sign", "-", app])
    run(["codesign", "--verify", "--deep", "--strict", app])
    selftest(os.path.join(contents, "MacOS", EXE_NAME))

    stage = os.path.join(BUILD, "dmg")
    shutil.rmtree(stage, ignore_errors=True)
    os.makedirs(stage)
    run(["ditto", app, os.path.join(stage, EXE_NAME + ".app")])
    os.symlink("/Applications", os.path.join(stage, "Programy (Applications)"))
    dmg = os.path.join(out_dir, asset_names(APP_VERSION)["mac"])
    if os.path.exists(dmg):
        os.remove(dmg)
    run(["hdiutil", "create", "-volname", f"{EXE_NAME} {APP_VERSION}", "-srcfolder", stage, "-fs", "HFS+",
         "-format", "UDZO", "-ov", dmg])
    return dmg


# --------------------------------------------------------------------- Linux
DESKTOP_FILE = """[Desktop Entry]
Type=Application
Name=KeyStead Manager
GenericName=Password Manager
GenericName[pl]=Menedżer haseł
Comment=Zero-knowledge password manager
Comment[pl]=Menedżer haseł z szyfrowaniem po stronie użytkownika
Exec=keystead-manager
Icon=keystead-manager
Categories=Utility;Security;
Terminal=false
StartupWMClass=KeyStead Manager
"""

APPRUN = """#!/bin/sh
HERE="$(dirname "$(readlink -f "$0")")"
exec "$HERE/usr/lib/keystead-manager/KeyStead Manager" "$@"
"""


def build_linux(out_dir: str) -> str:
    program = pyinstaller()
    add_licenses(program)
    selftest(os.path.join(program, EXE_NAME))

    appdir = os.path.join(BUILD, "KeyStead.AppDir")
    shutil.rmtree(appdir, ignore_errors=True)
    shutil.copytree(program, os.path.join(appdir, "usr", "lib", "keystead-manager"), symlinks=True)
    with open(os.path.join(appdir, "keystead-manager.desktop"), "w", encoding="utf-8") as f:
        f.write(DESKTOP_FILE)
    shutil.copy2(os.path.join(ROOT, "ui", "assets", "keystead.png"), os.path.join(appdir, "keystead-manager.png"))
    apprun = os.path.join(appdir, "AppRun")
    with open(apprun, "w", encoding="utf-8", newline="\n") as f:
        f.write(APPRUN)
    os.chmod(apprun, 0o755)

    tool = os.path.join(BUILD, "appimagetool")
    urllib.request.urlretrieve(APPIMAGETOOL, tool)
    os.chmod(tool, os.stat(tool).st_mode | stat.S_IEXEC)
    image = os.path.join(out_dir, asset_names(APP_VERSION)["linux"])
    env = dict(os.environ, ARCH="x86_64", APPIMAGE_EXTRACT_AND_RUN="1")
    run([tool, "--no-appstream", appdir, image], env=env)
    return image


def main() -> None:
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    out_dir = os.path.abspath(sys.argv[1])
    os.makedirs(out_dir, exist_ok=True)
    if sys.platform == "darwin":
        path = build_mac(out_dir)
    elif sys.platform.startswith("linux"):
        path = build_linux(out_dir)
    else:
        fail("Wersję dla Windows buduje tools/release_app.py.")
    print(f"✓ {path} ({os.path.getsize(path) // (1024 * 1024)} MB)")


if __name__ == "__main__":
    main()
