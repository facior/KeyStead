"""
Aktualizacje aplikacji KeyStead Manager.

Wydania aplikacji są publikowane w repozytorium facior/KeyStead z tagiem `vX.Y.Z`
(serwer ma osobne repozytorium: facior/KeyStead-Manager).
Instalator jest instalowany WYŁĄCZNIE wtedy, gdy:
  1. plik SHA256SUMS ma poprawny podpis kluczem wydawcy (RELEASE_PUBLIC_KEY – ten sam co dla serwera),
  2. suma SHA-256 pobranego instalatora zgadza się z podpisaną listą.
Podmieniony plik na GitHubie lub w sieci zostanie odrzucony.
"""

import hashlib
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional

import requests

from core import sshsig
from core.i18n import _
from core.version import APP_VERSION

REPOSITORY = "facior/KeyStead"
TAG_PREFIX = "v"
SIGNING_NAMESPACE = "keystead-release"
RELEASE_PUBLIC_KEY = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHg3QpcnJ86n0K1IsosYMDNlj7blzcbjdeRdrAOPcLCr "
                      "KeyStead release signing")
MAX_INSTALLER_BYTES = 300 * 1024 * 1024
CHECK_INTERVAL_HOURS = 12


class UpdateError(Exception):
    pass


def version_tuple(v: str):
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)$", v or "")
    return tuple(int(x) for x in m.groups()) if m else None


def asset_names(version: str) -> Dict[str, str]:
    return {
        "setup": f"KeyStead-Manager-Setup-{version}.exe",
        "portable": f"KeyStead-Manager-{version}-portable.zip",
        "sums": "SHA256SUMS",
        "sig": "SHA256SUMS.sig",
    }


@dataclass
class AppRelease:
    version: str
    page_url: str
    notes: str = ""
    assets: Dict[str, str] = field(default_factory=dict)  # nazwa pliku -> adres pobierania


# --------------------------------------------------------------------- tryb pracy
def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def is_portable() -> bool:
    """Wersja przenośna (ZIP) – obok programu leży plik portable.txt; aktualizuje się ją ręcznie."""
    return is_frozen() and os.path.exists(os.path.join(os.path.dirname(sys.executable), "portable.txt"))


def can_self_install() -> bool:
    """Automatyczna instalacja tylko w wersji zainstalowanej instalatorem na Windows."""
    return sys.platform == "win32" and is_frozen() and not is_portable()


# --------------------------------------------------------------------- sprawdzanie
def check_for_update(current: str = APP_VERSION, repository: str = REPOSITORY, timeout: float = 15,
                     http=requests, public_key: str = RELEASE_PUBLIC_KEY) -> Optional[AppRelease]:
    """Najnowsze wydanie aplikacji, jeśli jest nowsze od `current` – w przeciwnym razie None."""
    # KEYSTEAD_UPDATE_API: inne źródło listy wydań (testy, firmowy serwer lustrzany). Bezpieczne, bo podpis
    # wydawcy jest wymagany niezależnie od źródła.
    api = os.environ.get("KEYSTEAD_UPDATE_API") or f"https://api.github.com/repos/{repository}/releases"
    resp = http.get(api, params={"per_page": 30}, timeout=timeout,
                    headers={"Accept": "application/vnd.github+json", "User-Agent": "KeyStead-Manager"})
    if resp.status_code != 200:
        raise UpdateError(_("GitHub odpowiedział kodem {code}.", code=resp.status_code))
    best = None
    for rel in resp.json():
        tag = rel.get("tag_name") or ""
        if rel.get("draft") or rel.get("prerelease") or not tag.startswith(TAG_PREFIX):
            continue
        ver = tag[len(TAG_PREFIX):]
        if version_tuple(ver) and (best is None or version_tuple(ver) > version_tuple(best.version)):
            best = AppRelease(ver, rel.get("html_url", ""), rel.get("body") or "",
                              {a.get("name"): a.get("browser_download_url") for a in rel.get("assets", [])})
    cur = version_tuple(current) or (0, 0, 0)
    if not best or version_tuple(best.version) <= cur:
        return None
    # Pasek „Dostępna nowa wersja” tylko dla wydania z POPRAWNYM podpisem wydawcy – samo przejęcie konta GitHub
    # (bez klucza) nie wystarczy, by podsunąć użytkownikowi fałszywą aktualizację ani link do niej
    try:
        sums, sig = _fetch_signed_list(best, http)
        verify_sums(sums, sig, public_key)
        expected_hash(sums, asset_names(best.version)["setup"])
    except UpdateError:
        return None
    best.page_url = safe_page_url(best.page_url, repository)
    return best


def safe_page_url(url: str, repository: str = REPOSITORY) -> str:
    """Link „Co nowego / Pobierz” tylko do strony wydań w repozytorium aplikacji (nie z niepodpisanych danych)."""
    prefix = f"https://github.com/{repository}/releases/"
    return url if isinstance(url, str) and url.startswith(prefix) and re.match(r"^[\w:/.\-]+$", url) \
        else f"https://github.com/{repository}/releases/latest"


def _fetch_signed_list(release: "AppRelease", http=requests):
    names = asset_names(release.version)
    out = []
    for key in ("sums", "sig"):
        url = release.assets.get(names[key])
        if not url:
            raise UpdateError(_("Wydanie nie zawiera pliku {name}.", name=names[key]))
        r = http.get(url, timeout=30, headers={"User-Agent": "KeyStead-Manager"})
        if r.status_code != 200 or len(r.content) > 64 * 1024:
            raise UpdateError(_("Nie udało się pobrać {name}.", name=names[key]))
        out.append(r.content)
    return out[0], out[1]


# --------------------------------------------------------------------- pobieranie i weryfikacja
def expected_hash(sums: bytes, filename: str) -> str:
    for line in sums.decode("utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("*") == filename:
            return parts[0].lower()
    raise UpdateError(_("Podpisana lista nie zawiera instalatora."))


def verify_sums(sums: bytes, sig: bytes, public_key: str = RELEASE_PUBLIC_KEY) -> None:
    try:
        sshsig.verify(public_key, sums, sig, SIGNING_NAMESPACE)
    except sshsig.SignatureError as e:
        raise UpdateError(_("NIEPRAWIDŁOWY PODPIS aktualizacji – instalacja odrzucona ({error}).", error=e))


def download_update(release: AppRelease, dest_dir: Optional[str] = None,
                    progress: Optional[Callable[[int, int], None]] = None,
                    public_key: str = RELEASE_PUBLIC_KEY, http=requests) -> str:
    """Pobiera instalator, sprawdza podpis i sumę kontrolną. Zwraca ścieżkę do zweryfikowanego pliku."""
    names = asset_names(release.version)
    missing = [n for k, n in names.items() if k != "portable" and n not in release.assets]
    if missing:
        raise UpdateError(_("Wydanie nie zawiera plików: {files}.", files=', '.join(missing)))

    sums, sig = _fetch_signed_list(release, http)
    verify_sums(sums, sig, public_key)
    want = expected_hash(sums, names["setup"])

    dest_dir = dest_dir or os.path.join(tempfile.gettempdir(), "KeyStead-update")
    os.makedirs(dest_dir, exist_ok=True)
    target = os.path.join(dest_dir, names["setup"])
    part = target + ".part"
    digest = hashlib.sha256()
    done = 0
    with http.get(release.assets[names["setup"]], stream=True, timeout=60,
                  headers={"User-Agent": "KeyStead-Manager"}) as r:
        if r.status_code != 200:
            raise UpdateError(_("Nie udało się pobrać instalatora (kod {code}).", code=r.status_code))
        total = int(r.headers.get("Content-Length") or 0)
        with open(part, "wb") as f:
            for chunk in r.iter_content(256 * 1024):
                done += len(chunk)
                if done > MAX_INSTALLER_BYTES:
                    raise UpdateError(_("Instalator jest zbyt duży."))
                digest.update(chunk)
                f.write(chunk)
                if progress:
                    progress(done, total)
    if digest.hexdigest() != want:
        os.remove(part)
        raise UpdateError(_("Suma kontrolna instalatora nie zgadza się z podpisaną listą – instalacja odrzucona."))
    os.replace(part, target)
    _verified[os.path.abspath(target)] = want
    return target


_verified: Dict[str, str] = {}  # ścieżka zweryfikowanego instalatora -> oczekiwana suma SHA-256


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def launch_installer(path: str) -> None:
    """Uruchamia instalator w trybie cichym; po instalacji uruchamia on aplikację ponownie."""
    # Ponowna kontrola tuż przed uruchomieniem: plik w %TEMP% mógł zostać podmieniony po pobraniu
    want = _verified.get(os.path.abspath(path))
    if not want or _sha256_file(path) != want:
        raise UpdateError(_("Plik instalatora zmienił się po weryfikacji – instalacja przerwana."))
    flags = 0
    if sys.platform == "win32":
        flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    subprocess.Popen([path, "/SILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/CLOSEAPPLICATIONS"],
                     creationflags=flags, close_fds=True)
