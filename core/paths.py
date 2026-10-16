"""
Ścieżki plików aplikacji KeyStead Manager w katalogu użytkownika (~/.keystead).

    config.json         – ustawienia aplikacji (pierwsze uruchomienie, Client ID chmur, profil serwera)
    recent_vaults.json  – ostatnio otwierane sejfy
    cache/              – lokalne, zaszyfrowane kopie sejfów z serwera synchronizacji
    certs/              – przypięte certyfikaty serwerów

Pliki z wcześniejszych wersji (~/.pm_config.json, ~/.pm_recent_vaults.json, ~/.securevault/)
są jednorazowo kopiowane przez migrate_legacy_files().
"""

import os
import shutil

HOME = os.path.expanduser("~")
APP_DIR = os.path.join(HOME, ".keystead")
CONFIG_FILE = os.path.join(APP_DIR, "config.json")
RECENT_VAULTS_FILE = os.path.join(APP_DIR, "recent_vaults.json")
CACHE_DIR = os.path.join(APP_DIR, "cache")
CERTS_DIR = os.path.join(APP_DIR, "certs")

_LEGACY_FILES = {
    os.path.join(HOME, ".pm_config.json"): CONFIG_FILE,
    os.path.join(HOME, ".pm_recent_vaults.json"): RECENT_VAULTS_FILE,
}
# Nazwa katalogu sprzed zmiany nazwy projektu (składana, aby nie objęła jej automatyczna zamiana nazw)
_LEGACY_APP_DIR = os.path.join(HOME, ".secure" + "vault")
_LEGACY_DIRS = {
    os.path.join(_LEGACY_APP_DIR, "cache"): CACHE_DIR,
    os.path.join(_LEGACY_APP_DIR, "certs"): CERTS_DIR,
}


def branding_logo_path(server_id: str) -> str:
    """Lokalna kopia logo firmy pobranego z serwera synchronizacji."""
    safe = "".join(c for c in (server_id or "serwer") if c.isalnum())[:32] or "serwer"
    return os.path.join(APP_DIR, "branding", f"{safe}.png")


def ensure_app_dir() -> str:
    os.makedirs(APP_DIR, exist_ok=True)
    return APP_DIR


def migrate_legacy_files() -> None:
    """Przenosi ustawienia z poprzedniej nazwy aplikacji (Secure Vault Pro). Bezpieczne do wielokrotnego wywołania."""
    for old, new in _LEGACY_FILES.items():
        if os.path.isfile(old) and not os.path.exists(new):
            try:
                ensure_app_dir()
                shutil.copy2(old, new)
            except OSError:
                pass
    for old, new in _LEGACY_DIRS.items():
        if os.path.isdir(old) and not os.path.exists(new):
            try:
                ensure_app_dir()
                shutil.copytree(old, new)
            except OSError:
                pass
