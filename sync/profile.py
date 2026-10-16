"""
Zapamiętany profil serwera (adres + token urządzenia chroniony DPAPI) w ~/.keystead/config.json.
"""

import json
import os
from dataclasses import dataclass
from typing import Optional

from core.paths import CACHE_DIR, CONFIG_FILE, ensure_app_dir
from core.secret_store import protect_secret, unprotect_secret


@dataclass
class ServerProfile:
    url: str
    token: str
    server_id: str = ""
    device_name: str = ""
    ca_file: str = ""          # przypięty certyfikat serwera (samopodpisany / firmowe CA)
    account_name: str = ""     # nazwa konta na serwerze (z kodu aktywacyjnego)
    cache_dir: str = ""        # nadpisywane tylko w testach

    def cache_path(self) -> str:
        """Lokalna, zaszyfrowana kopia sejfu z serwera (praca offline + źródło kopii zapasowych)."""
        # Identyfikator pochodzi z serwera – w nazwie pliku tylko litery i cyfry (bez „..”, „/”, „:”)
        suffix = "".join(c for c in (self.server_id or "") if c.isascii() and c.isalnum())[:12] or "nowy"
        return os.path.join(self.cache_dir or CACHE_DIR, f"SejfSerwer_{suffix}.vault")


def _read() -> dict:
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write(data: dict) -> None:
    ensure_app_dir()
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def load_profile() -> Optional[ServerProfile]:
    raw = _read().get("sync_server")
    if not raw or not raw.get("url"):
        return None
    try:
        token = unprotect_secret(raw.get("token", ""))
    except OSError:
        return None  # profil z innego konta/komputera – trzeba podać token ponownie
    return ServerProfile(url=raw["url"], token=token, server_id=raw.get("server_id", ""),
                         device_name=raw.get("device_name", ""), ca_file=raw.get("ca_file", ""),
                         account_name=raw.get("account_name", ""))


def save_profile(profile: ServerProfile) -> None:
    data = _read()
    data["sync_server"] = {
        "url": profile.url,
        "token": protect_secret(profile.token),
        "server_id": profile.server_id,
        "device_name": profile.device_name,
        "ca_file": profile.ca_file,
        "account_name": profile.account_name,
    }
    _write(data)


def delete_profile() -> None:
    data = _read()
    data.pop("sync_server", None)
    _write(data)
