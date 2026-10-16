"""
Ikony stron w interfejsie: pobieranie w tle (najwyżej kilka naraz), obrazy Tk tworzone w wątku okna,
powiadamianie list o nowo pobranych ikonach. Bez ikony – kolorowy kafelek z literą lub ikoną kategorii.
"""

import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Dict, List, Optional, Tuple

from core.site_icons import IconCache, site_domain

AVATAR_COLORS = ["#4f46e5", "#0891b2", "#059669", "#d97706", "#db2777", "#7c3aed", "#2563eb", "#dc2626",
                 "#0d9488", "#9333ea"]


def avatar_for(title: str, url: str, fallback_icon: str = "") -> Tuple[Optional[str], str, str]:
    """(domena do ikony, tekst kafelka, kolor kafelka) dla wpisu."""
    domain = site_domain(url) if url else None
    key = domain or title or "?"
    color = AVATAR_COLORS[int(hashlib.md5(key.encode("utf-8")).hexdigest(), 16) % len(AVATAR_COLORS)]
    if domain:
        letter = domain.split(".")[-2][:1].upper() if domain.count(".") else domain[:1].upper()
    else:
        letter = fallback_icon or (title.strip()[:1].upper() if title.strip() else "?")
    return domain, letter, color


TILE_COLOR = (241, 245, 249, 255)


def _on_tile(path: str, size: int):
    """Ikona na jasnym, zaokrąglonym kafelku – czytelna także, gdy jest ciemna (np. GitHub) na ciemnym tle."""
    from PIL import Image, ImageDraw
    scale = 4  # rysowanie w większej skali i zmniejszenie = gładkie zaokrąglenia
    tile = Image.new("RGBA", (size * scale, size * scale), (0, 0, 0, 0))
    ImageDraw.Draw(tile).rounded_rectangle([0, 0, size * scale - 1, size * scale - 1], radius=size * scale // 4,
                                           fill=TILE_COLOR)
    tile = tile.resize((size, size), Image.LANCZOS)
    inner = max(8, int(size * 0.72))
    with Image.open(path) as img:
        icon = img.convert("RGBA").resize((inner, inner), Image.LANCZOS)
    offset = (size - inner) // 2
    tile.alpha_composite(icon, (offset, offset))
    return tile


class IconProvider:
    def __init__(self, app, cache: Optional[IconCache] = None):
        self.app = app
        self.cache = cache or IconCache()
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="site-icons")
        self._images: Dict[Tuple[str, int], object] = {}
        self._pending = set()
        self._lock = threading.Lock()
        self._listeners: List[Callable[[str], None]] = []

    # --- ustawienia
    def enabled(self) -> bool:
        vault = getattr(self.app, "current_vault", None)
        policy = self.app.current_policy() if hasattr(self.app, "current_policy") else {}
        if (policy or {}).get("allow_site_icons", True) is False:
            return False
        return bool(vault is not None and vault.settings.get("site_icons", True))

    def add_listener(self, fn: Callable[[str], None]) -> None:
        self._listeners.append(fn)

    def remove_listener(self, fn: Callable[[str], None]) -> None:
        if fn in self._listeners:
            self._listeners.remove(fn)

    # --- obrazy (wywoływać w wątku okna)
    def image(self, domain: Optional[str], size: int):
        """PhotoImage dla domeny albo None (wtedy kafelek z literą; ikona pobierze się w tle)."""
        if not domain or not self.enabled():
            return None
        key = (domain, size)
        if key in self._images:
            return self._images[key]
        path = self.cache.cached_path(domain)
        if self.cache.needs_fetch(domain):
            self._schedule(domain)
        if not path:
            return None
        try:
            from PIL import ImageTk
            photo = ImageTk.PhotoImage(_on_tile(path, size))
        except Exception:
            return None
        self._images[key] = photo
        return photo

    def _schedule(self, domain: str) -> None:
        with self._lock:
            if domain in self._pending:
                return
            self._pending.add(domain)

        def _work():
            try:
                self.cache.fetch(domain)
            finally:
                self.app.post_to_ui(lambda: self._loaded(domain))
        self._executor.submit(_work)

    def _loaded(self, domain: str) -> None:
        with self._lock:
            self._pending.discard(domain)
        for key in [k for k in self._images if k[0] == domain]:
            del self._images[key]
        for fn in list(self._listeners):
            try:
                fn(domain)
            except Exception:
                pass

    def clear(self) -> None:
        self._images.clear()
        self.cache.clear()
