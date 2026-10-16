"""
Windows Hello w interfejsie: dostępność (sprawdzana raz, w tle), zapis/odczyt w wątku roboczym,
polityka firmy i zapamiętana odmowa propozycji włączenia.
"""

import hashlib
import json
import os
import threading
from typing import Any, Callable, Dict, Optional

from core.quick_unlock import (DEFAULT_VALID_DAYS, STORE_DIR, QuickUnlockError, QuickUnlockStore, target_id)


def file_target(path: str) -> str:
    return target_id("file", path)


def server_target(url: str, token: str) -> str:
    # Token urządzenia zmienia się przy ponownym dołączeniu – stary zapis wtedy nie pasuje
    return target_id("server", f"{url.rstrip('/')}|{hashlib.sha256(token.encode()).hexdigest()[:16]}")


def policy_allows(policy: Optional[Dict[str, Any]]) -> bool:
    return (policy or {}).get("allow_quick_unlock", True) is not False


def valid_days(policy: Optional[Dict[str, Any]]) -> int:
    try:
        days = int((policy or {}).get("quick_unlock_days") or DEFAULT_VALID_DAYS)
    except (TypeError, ValueError):
        days = DEFAULT_VALID_DAYS
    return max(1, min(days, 90))


class QuickUnlockService:
    def __init__(self, store: Optional[QuickUnlockStore] = None):
        self.store = store or QuickUnlockStore()
        self.available: Optional[bool] = None  # None = jeszcze nie sprawdzono
        self._prefs_path = os.path.join(STORE_DIR, "prefs.json")

    # --- dostępność (WinRT bywa wolne – sprawdzamy raz, w tle)
    def check_availability(self, on_done: Optional[Callable[[bool], None]] = None, widget=None) -> None:
        if self.available is not None:
            if on_done:
                on_done(self.available)
            return

        poster = None
        if widget is not None:
            poster = getattr(widget.winfo_toplevel(), "post_to_ui", None) or (lambda fn: widget.after(0, fn))

        def _work():
            self.available = bool(self.store.available())
            if on_done and poster is not None:
                try:
                    poster(lambda: widget.winfo_exists() and on_done(self.available))
                except Exception:
                    pass
        threading.Thread(target=_work, daemon=True).start()

    def can_use(self, target: Optional[str], policy=None) -> bool:
        return bool(self.available and target and policy_allows(policy) and self.store.is_enrolled(target))

    def can_offer(self, target: Optional[str], policy=None) -> bool:
        return bool(self.available and target and policy_allows(policy) and not self.store.is_enrolled(target)
                    and target not in self._prefs().get("declined", []))

    def needs_renewal(self, target: str, policy=None) -> bool:
        """Po wpisaniu hasła: odnowienie okresu ważności, gdy zbliża się jego koniec (data z pliku – tylko do UI)."""
        import time
        try:
            age_days = (time.time() - os.path.getmtime(self.store._path(target))) / 86400
        except OSError:
            return False
        return age_days > max(0, valid_days(policy) - 3)

    # --- preferencje
    def _prefs(self) -> Dict[str, Any]:
        try:
            with open(self._prefs_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def set_declined(self, target: str, declined: bool = True) -> None:
        prefs = self._prefs()
        items = set(prefs.get("declined", []))
        (items.add if declined else items.discard)(target)
        prefs["declined"] = sorted(items)
        os.makedirs(STORE_DIR, exist_ok=True)
        with open(self._prefs_path, "w", encoding="utf-8") as f:
            json.dump(prefs, f)

    # --- operacje w tle (okno Windows Hello blokuje wątek do potwierdzenia)
    def _bg(self, widget, work, on_done) -> None:
        # Sposób powrotu do wątku okna ustalany TERAZ (w wątku UI): kolejka aplikacji, jeśli jest
        poster = getattr(widget.winfo_toplevel(), "post_to_ui", None) or (lambda fn: widget.after(0, fn))

        def _worker():
            try:
                result = work()
            except Exception as e:
                result = e
            try:
                poster(lambda: widget.winfo_exists() and on_done(result))
            except Exception:
                pass
        threading.Thread(target=_worker, daemon=True).start()

    def enroll_async(self, widget, target: str, password: str, keyfile: Optional[bytes],
                     on_done: Callable[[Optional[Exception]], None]) -> None:
        def _work():
            self.store.enroll(target, password, keyfile)
            self.set_declined(target, False)
            return None
        self._bg(widget, _work, on_done)

    def unlock_async(self, widget, target: str, policy, on_done: Callable[[Any], None]) -> None:
        """on_done dostaje (hasło, plik-klucz) albo wyjątek QuickUnlockError."""
        self._bg(widget, lambda: self.store.unlock(target, valid_days(policy)), on_done)

    def disable(self, target: str) -> None:
        self.store.remove(target)


quick = QuickUnlockService()

__all__ = ["quick", "file_target", "server_target", "policy_allows", "valid_days", "QuickUnlockError"]
