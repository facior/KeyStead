"""
Wykrywanie serwera KeyStead w sieci Tailscale.

Korzysta z zainstalowanego na tym komputerze Tailscale (`tailscale status --json`), sprawdza
urządzenia online w Twojej sieci i zwraca te, na których odpowiada serwer sejfu
(https://<urządzenie>.<sieć>.ts.net – certyfikat wystawia Tailscale).
"""

import json
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import List, Optional

import requests

_WINDOWS_PATHS = (
    r"C:\Program Files\Tailscale\tailscale.exe",
    r"C:\Program Files (x86)\Tailscale\tailscale.exe",
)


class TailscaleUnavailable(Exception):
    """Tailscale nie jest zainstalowany albo nie jest zalogowany na tym komputerze."""


@dataclass
class DiscoveredServer:
    name: str
    url: str
    server_version: str


def find_tailscale_cli() -> Optional[str]:
    # Najpierw stałe ścieżki instalacji – plik „tailscale.exe” podrzucony w katalogu z PATH nie zostanie użyty
    if sys.platform == "win32":
        for path in _WINDOWS_PATHS:
            if os.path.exists(path):
                return path
    if sys.platform == "darwin" and os.path.exists("/Applications/Tailscale.app/Contents/MacOS/Tailscale"):
        return "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
    return shutil.which("tailscale")


_running_cache = {"at": 0.0, "value": False}


def tailscale_running(max_age: float = 60.0) -> bool:
    """Czy Tailscale na tym komputerze jest połączony (wynik pamiętany przez minutę)."""
    import time
    now = time.monotonic()
    if now - _running_cache["at"] < max_age and _running_cache["at"]:
        return _running_cache["value"]
    try:
        value = _status().get("BackendState") in (None, "Running")
    except TailscaleUnavailable:
        value = False
    _running_cache.update(at=now, value=value)
    return value


def _status() -> dict:
    cli = find_tailscale_cli()
    if not cli:
        raise TailscaleUnavailable("Na tym komputerze nie ma Tailscale. Zainstaluj go z https://tailscale.com/download "
                                   "albo wpisz adres serwera ręcznie.")
    flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    try:
        out = subprocess.run([cli, "status", "--json"], capture_output=True, timeout=10, creationflags=flags)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise TailscaleUnavailable(f"Nie udało się odczytać stanu Tailscale: {e}")
    if out.returncode != 0:
        raise TailscaleUnavailable("Tailscale nie jest połączony – zaloguj się w aplikacji Tailscale.")
    try:
        return json.loads(out.stdout.decode("utf-8", errors="replace"))
    except ValueError:
        raise TailscaleUnavailable("Nieoczekiwana odpowiedź Tailscale.")


def _probe(name: str, dns_name: str, timeout: float) -> Optional[DiscoveredServer]:
    url = f"https://{dns_name}"
    try:
        resp = requests.get(f"{url}/api/v1/health", timeout=timeout)
        data = resp.json() if resp.status_code == 200 else {}
    except (requests.RequestException, ValueError):
        return None
    if data.get("status") == "ok" and data.get("server_id"):
        return DiscoveredServer(name=name, url=url, server_version=data.get("server_version", "?"))
    return None


def discover_servers(timeout: float = 4.0) -> List[DiscoveredServer]:
    status = _status()
    if status.get("BackendState") not in (None, "Running"):
        raise TailscaleUnavailable("Tailscale nie jest połączony – włącz go i spróbuj ponownie.")

    candidates = []
    nodes = list((status.get("Peer") or {}).values()) + [status.get("Self") or {}]
    for node in nodes:
        dns = (node.get("DNSName") or "").rstrip(".")
        if dns and (node.get("Online") or node is status.get("Self")):
            candidates.append((node.get("HostName") or dns.split(".")[0], dns))

    if not candidates:
        return []
    with ThreadPoolExecutor(max_workers=min(16, len(candidates))) as pool:
        results = pool.map(lambda c: _probe(c[0], c[1], timeout), candidates)
    return [r for r in results if r]
