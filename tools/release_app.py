"""
Budowanie i wydawanie aplikacji KeyStead Manager dla Windows.

    python tools/release_app.py 1.0.0 --dry-run   # zbuduj instalator i wersję przenośną w dist/app-v1.0.0
    python tools/release_app.py 1.0.0             # zbuduj, podpisz, wyślij kod i opublikuj w facior/KeyStead (tag v1.0.0)

Wymaga: PyInstaller (pip install pyinstaller), Inno Setup 6, gh (zalogowany), klucz ~/.ssh/keystead_release.
Repozytorium aplikacji (facior/KeyStead) dostaje kod aplikacji bez katalogu server/ – serwer ma własne
repozytorium (facior/KeyStead-Manager, tools/release.py).
"""

import argparse
import glob
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core import sshsig  # noqa: E402
from core.app_update import RELEASE_PUBLIC_KEY, REPOSITORY, SIGNING_NAMESPACE, TAG_PREFIX, asset_names  # noqa: E402

EXE_NAME = "KeyStead Manager"
DEFAULT_KEY = os.path.join(os.path.expanduser("~"), ".ssh", "keystead_release")
BUILD = os.path.join(ROOT, "build", "app")

# Co trafia do repozytorium aplikacji (kod serwera i jego testy mają osobne repozytorium)
SOURCE_DIRS = ["core", "ui", "sync", "backups", "importers", "tests", "tools/installer"]
SOURCE_FILES = ["main.py", "requirements.txt", "uruchom.bat", "README.md", ".gitignore", ".gitattributes",
                "tools/release_app.py", "tools/make_icon.py", "tools/ui_bench.py"]
SERVER_ONLY_TESTS = ["test_admin.py", "test_admin_features.py", "test_server.py", "test_sync.py",
                     "test_updater.py", "test_client_network.py", "test_policy_client.py"]


def find_ssh_keygen() -> str:
    for path in (shutil.which("ssh-keygen"), r"C:\Program Files\Git\usr\bin\ssh-keygen.exe"):
        if path and os.path.exists(path):
            return path
    fail("Brak programu ssh-keygen (Git for Windows lub OpenSSH).")


def fail(msg: str) -> None:
    print(f"!! {msg}")
    sys.exit(1)


def app_version() -> str:
    with open(os.path.join(ROOT, "core", "version.py"), encoding="utf-8") as f:
        return re.search(r'APP_VERSION\s*=\s*"([^"]+)"', f.read()).group(1)


def find_iscc() -> str:
    candidates = [shutil.which("ISCC")] + glob.glob(os.path.expandvars(r"%LOCALAPPDATA%\Programs\Inno Setup*\ISCC.exe")) \
        + glob.glob(r"C:\Program Files*\Inno Setup*\ISCC.exe")
    for c in candidates:
        if c and os.path.isfile(c):
            return c
    fail("Brak Inno Setup 6 (winget install JRSoftware.InnoSetup).")


def run(cmd, **kw):
    print(">", " ".join(f'"{c}"' if " " in c else c for c in cmd))
    subprocess.run(cmd, check=True, **kw)


def build(version: str, out_dir: str) -> dict:
    shutil.rmtree(BUILD, ignore_errors=True)
    os.makedirs(out_dir, exist_ok=True)
    sep = os.pathsep
    run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--windowed", "--name", EXE_NAME,
         "--icon", os.path.join(ROOT, "ui", "assets", "keystead.ico"),
         "--add-data", f"{os.path.join(ROOT, 'core', 'wordlist_eff.txt')}{sep}core",
         "--add-data", f"{os.path.join(ROOT, 'ui', 'assets')}{sep}ui/assets",
         "--collect-data", "customtkinter", "--collect-data", "pykeepass",
         "--exclude-module", "server", "--exclude-module", "tests", "--exclude-module", "fastapi",
         "--exclude-module", "uvicorn",
         "--distpath", os.path.join(BUILD, "dist"), "--workpath", os.path.join(BUILD, "work"),
         "--specpath", BUILD, os.path.join(ROOT, "main.py")], cwd=ROOT)
    app_dir = os.path.join(BUILD, "dist", EXE_NAME)
    if not os.path.isfile(os.path.join(app_dir, EXE_NAME + ".exe")):
        fail("PyInstaller nie utworzył programu.")

    names = asset_names(version)
    # Instalator
    run([find_iscc(), "/Q", f"/DAppVersion={version}", f"/DSourceDir={app_dir}", f"/DOutputDir={out_dir}",
         os.path.join(ROOT, "tools", "installer", "keystead.iss")])
    setup = os.path.join(out_dir, names["setup"])
    if not os.path.isfile(setup):
        fail("Inno Setup nie utworzył instalatora.")

    # Wersja przenośna (plik portable.txt wyłącza automatyczną instalację aktualizacji)
    portable = os.path.join(out_dir, names["portable"])
    with zipfile.ZipFile(portable, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for root, _dirs, files in os.walk(app_dir):
            for name in files:
                full = os.path.join(root, name)
                z.write(full, os.path.join(EXE_NAME, os.path.relpath(full, app_dir)))
        z.writestr(f"{EXE_NAME}/portable.txt",
                   "Wersja przenośna KeyStead Manager – nowe wersje pobierz ze strony wydań.\r\n"
                   "Dane aplikacji są zapisywane w folderze .keystead w katalogu użytkownika.\r\n")
    return {"setup": setup, "portable": portable}


def sign(files: dict, version: str, key: str, out_dir: str) -> dict:
    names = asset_names(version)
    lines = []
    for k in ("setup", "portable"):
        with open(files[k], "rb") as f:
            lines.append(f"{hashlib.sha256(f.read()).hexdigest()}  {names[k]}\n")
    sums_path = os.path.join(out_dir, names["sums"])
    with open(sums_path, "w", encoding="ascii", newline="\n") as f:
        f.writelines(lines)
    sig_path = sums_path + ".sig"
    if os.path.exists(sig_path):
        os.remove(sig_path)
    run([find_ssh_keygen(), "-Y", "sign", "-f", key, "-n", SIGNING_NAMESPACE, sums_path])
    with open(sums_path, "rb") as f, open(sig_path, "rb") as g:
        try:  # kontrola tym samym kodem, którym weryfikuje aplikacja
            sshsig.verify(RELEASE_PUBLIC_KEY, f.read(), g.read(), SIGNING_NAMESPACE)
        except sshsig.SignatureError as e:
            fail(f"Podpis nie przechodzi weryfikacji aplikacji: {e}. Czy klucz pasuje do RELEASE_PUBLIC_KEY?")
    return {**files, "sums": sums_path, "sig": sig_path}


def push_source(version: str, tag: str) -> None:
    """Kod aplikacji do repozytorium facior/KeyStead: commit „KeyStead Manager X.Y.Z” i tag wydania."""
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc", *SERVER_ONLY_TESTS)
    with tempfile.TemporaryDirectory() as tmp:
        repo = os.path.join(tmp, "repo")
        run(["git", "clone", "-q", f"https://github.com/{REPOSITORY}.git", repo])
        if subprocess.run(["git", "-C", repo, "rev-parse", "-q", "--verify", f"refs/tags/{tag}"],
                          capture_output=True).returncode == 0:
            fail(f"Tag {tag} już istnieje w repozytorium {REPOSITORY}.")
        for d in SOURCE_DIRS:
            shutil.rmtree(os.path.join(repo, d), ignore_errors=True)
            shutil.copytree(os.path.join(ROOT, d), os.path.join(repo, d), ignore=ignore)
        for f in SOURCE_FILES:
            os.makedirs(os.path.dirname(os.path.join(repo, f)) or repo, exist_ok=True)
            shutil.copy2(os.path.join(ROOT, f), os.path.join(repo, f))
        assets = os.path.join(repo, "ui", "assets")
        if not os.path.isfile(os.path.join(assets, "keystead.ico")):
            fail("Brak ikony ui/assets/keystead.ico (python tools/make_icon.py).")
        run(["git", "-C", repo, "add", "-A"])
        if subprocess.run(["git", "-C", repo, "diff", "--cached", "--quiet"]).returncode != 0:
            run(["git", "-C", repo, "commit", "-q", "-m", f"KeyStead Manager {version}"])
        run(["git", "-C", repo, "tag", tag])
        run(["git", "-C", repo, "push", "-q", "origin", "HEAD:main", tag])


def publish(version: str, files: dict, notes: str) -> None:
    tag = f"{TAG_PREFIX}{version}"
    if subprocess.run(["gh", "release", "view", tag, "--repo", REPOSITORY], capture_output=True).returncode == 0:
        fail(f"Wydanie {tag} już istnieje.")
    push_source(version, tag)
    run(["gh", "release", "create", tag, "--repo", REPOSITORY, "--verify-tag",
         "--title", f"KeyStead Manager {version}",
         "--notes", notes or f"KeyStead Manager {version}",
         files["setup"], files["portable"], files["sums"], files["sig"]])
    print(f"✓ Opublikowano: https://github.com/{REPOSITORY}/releases/tag/{tag}")


def main() -> None:
    p = argparse.ArgumentParser(description="Wydanie aplikacji KeyStead Manager")
    p.add_argument("version")
    p.add_argument("--key", default=DEFAULT_KEY)
    p.add_argument("--notes", default="")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()
    if app_version() != args.version:
        fail(f"APP_VERSION w core/version.py to {app_version()}, a nie {args.version}.")
    if not os.path.isfile(args.key):
        fail(f"Brak klucza {args.key} (python tools/release.py init-key).")
    out_dir = os.path.join(ROOT, "dist", f"{TAG_PREFIX}{args.version}")
    files = sign(build(args.version, out_dir), args.version, args.key, out_dir)
    for k, path in files.items():
        print(f"  {k:9} {os.path.getsize(path) // 1024:>8} KB  {path}")
    if args.dry_run:
        print("Tryb próbny – nic nie opublikowano.")
        return
    publish(args.version, files, args.notes)


if __name__ == "__main__":
    main()
