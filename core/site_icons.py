"""
Ikony stron (favicony) przy wpisach.

Prywatność: ikona jest pobierana BEZPOŚREDNIO ze strony wpisu – jak robi to przeglądarka. Nie używamy
pośredników (np. usług ikon Google/DuckDuckGo), które poznałyby pełną listę stron, na których użytkownik ma konta.

Bezpieczeństwo:
- tylko http(s) do adresów publicznych (bez sieci wewnętrznej/localhost – wpis nie może „sondować” sieci firmy),
- limity rozmiaru odpowiedzi i liczby pikseli przed dekodowaniem obrazu (ochrona przed „bombami”),
- obraz jest od razu zmniejszany i zapisywany jako PNG 64×64 w pamięci podręcznej (~/.keystead/icons).
"""

import hashlib
import ipaddress
import os
import socket
import time
from html.parser import HTMLParser
from io import BytesIO
from typing import List, Optional
from urllib.parse import urljoin, urlparse

import requests

from core.paths import APP_DIR

ICON_DIR = os.path.join(APP_DIR, "icons")
ICON_SIZE = 64
MAX_HTML_BYTES = 256 * 1024
MAX_ICON_BYTES = 200 * 1024
MAX_ICON_PIXELS = 1024 * 1024
REFRESH_DAYS = 30
RETRY_MISSING_DAYS = 7
TIMEOUT = 6
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) KeyStead-Manager"


def site_domain(url: str) -> Optional[str]:
    """Domena do ikony: https://www.github.com/login → github.com (None dla adresów spoza internetu)."""
    if not url:
        return None
    parsed = urlparse(url if "://" in url else f"https://{url}")
    if parsed.scheme not in ("http", "https"):
        return None
    host = (parsed.hostname or "").lower().strip(".")
    if not host or "." not in host or len(host) > 253:
        return None
    if host.startswith("www."):
        host = host[4:]
    try:
        ipaddress.ip_address(host)
        return None  # adresy IP (zwykle urządzenia w sieci lokalnej) – bez ikon
    except ValueError:
        pass
    if host.endswith((".local", ".lan", ".internal", ".home.arpa", ".corp", ".localhost")):
        return None
    return host


def _is_public_host(host: str) -> bool:
    """Wszystkie adresy, na które wskazuje nazwa, muszą być publiczne (bez sieci prywatnej i loopback)."""
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except OSError:
        return False
    for info in infos:
        addr = ipaddress.ip_address(info[4][0].split("%")[0])
        if (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
                or addr.is_multicast or addr.is_unspecified):
            return False
    return bool(infos)


class _IconLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: List[tuple] = []

    def handle_starttag(self, tag, attrs):
        if tag != "link":
            return
        a = {k.lower(): (v or "") for k, v in attrs}
        rel = a.get("rel", "").lower()
        if "icon" in rel and a.get("href"):
            # Preferencja: apple-touch-icon (duża, ostra) > icon z rozmiarem > shortcut icon
            score = 3 if "apple-touch-icon" in rel else 2 if a.get("sizes") else 1
            if a.get("type", "").lower() == "image/svg+xml" or a["href"].lower().endswith(".svg"):
                return  # SVG pomijamy (brak bezpiecznego dekodera)
            self.links.append((score, a["href"]))


def _get(session, url: str, limit: int) -> Optional[bytes]:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or not _is_public_host(parsed.hostname):
        return None
    try:
        with session.get(url, timeout=TIMEOUT, stream=True, allow_redirects=True,
                         headers={"User-Agent": USER_AGENT}) as r:
            final = urlparse(r.url)
            if r.status_code != 200 or not final.hostname or not _is_public_host(final.hostname):
                return None
            data = r.raw.read(limit + 1, decode_content=True)
            return data if len(data) <= limit else None
    except (requests.RequestException, OSError, ValueError):
        return None


def _decode_icon(data: bytes):
    from PIL import Image
    try:
        img = Image.open(BytesIO(data))
        if img.width * img.height > MAX_ICON_PIXELS:
            return None
        if getattr(img, "format", "") == "ICO":
            sizes = sorted(img.info.get("sizes") or [], key=lambda s: s[0] * s[1])
            usable = [s for s in sizes if s[0] * s[1] <= MAX_ICON_PIXELS]
            if usable:
                img.size = usable[-1]
        img.load()
        img = img.convert("RGBA")
        if img.width < 8 or img.height < 8:
            return None
        img.thumbnail((ICON_SIZE, ICON_SIZE), Image.LANCZOS)
        return img
    except Exception:
        return None


class IconCache:
    def __init__(self, directory: str = ICON_DIR):
        self.directory = directory

    def _base(self, domain: str) -> str:
        return os.path.join(self.directory, hashlib.sha256(domain.encode()).hexdigest()[:24])

    def cached_path(self, domain: str) -> Optional[str]:
        path = self._base(domain) + ".png"
        return path if os.path.isfile(path) else None

    def needs_fetch(self, domain: str) -> bool:
        now = time.time()
        png, none = self._base(domain) + ".png", self._base(domain) + ".none"
        if os.path.isfile(png):
            return now - os.path.getmtime(png) > REFRESH_DAYS * 86400
        if os.path.isfile(none):
            return now - os.path.getmtime(none) > RETRY_MISSING_DAYS * 86400
        return True

    def fetch(self, domain: str, session=None) -> Optional[str]:
        """Pobiera ikonę strony (wątek roboczy). Zwraca ścieżkę PNG albo None (strona bez ikony)."""
        session = session or requests.Session()
        candidates = []
        page = _get(session, f"https://{domain}/", MAX_HTML_BYTES)
        if page:
            parser = _IconLinks()
            try:
                parser.feed(page.decode("utf-8", errors="replace"))
            except Exception:
                pass
            candidates = [urljoin(f"https://{domain}/", href) for _, href in sorted(parser.links, reverse=True)]
        candidates.append(f"https://{domain}/favicon.ico")
        os.makedirs(self.directory, exist_ok=True)
        for url in candidates[:4]:
            data = _get(session, url, MAX_ICON_BYTES)
            img = _decode_icon(data) if data else None
            if img is not None:
                path = self._base(domain) + ".png"
                img.save(path + ".tmp", "PNG")
                os.replace(path + ".tmp", path)
                try:
                    os.remove(self._base(domain) + ".none")
                except FileNotFoundError:
                    pass
                return path
        with open(self._base(domain) + ".none", "w") as f:
            f.write("")  # zapamiętujemy brak ikony – ponowna próba po kilku dniach
        return None

    def clear(self) -> None:
        import shutil
        shutil.rmtree(self.directory, ignore_errors=True)
