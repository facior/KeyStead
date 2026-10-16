"""
Szybki dostęp z dowolnego programu:
- Ctrl+Shift+Spacja – okienko wyszukiwania: Enter kopiuje hasło, Shift+Enter login, Ctrl+Enter kod 2FA,
- Ctrl+Shift+L – Autotype: wpisuje login, Tab, hasło, Enter w okno, w którym wciśnięto skrót.

Bezpieczeństwo Autotype: okno docelowe jest zapamiętywane w chwili naciśnięcia skrótu i sprawdzane przed
wpisaniem każdego fragmentu – jeśli w międzyczasie aktywne jest inne okno, wpisywanie zostaje przerwane.
"""

import json
import os
import queue
import re
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import customtkinter as ctk

from core import winsys
from core.paths import APP_DIR
from core.totp_service import get_current_totp
from core.vault import Vault, VaultEntry
from ui.entry_list import EntryList
from ui.site_icons_ui import avatar_for
from ui.theme import (COLOR_BORDER, COLOR_PANEL_DARK, COLOR_PRIMARY, COLOR_TEXT_MUTED, FONT_BODY, FONT_SMALL,
                      FONT_SUBTITLE)

PREFS_FILE = os.path.join(APP_DIR, "hotkeys.json")
DEFAULT_PREFS = {"enabled": True, "search": "Ctrl+Shift+Space", "autotype": "Ctrl+Shift+L"}
DEFAULT_SEQUENCE = "{USERNAME}{TAB}{PASSWORD}{ENTER}"
SEQUENCE_FIELD = "Sekwencja autotype"
WINDOW_FIELD = "Autotype okno"


def load_prefs() -> Dict[str, Any]:
    try:
        with open(PREFS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {**DEFAULT_PREFS, **(data if isinstance(data, dict) else {})}
    except (OSError, ValueError):
        return dict(DEFAULT_PREFS)


def save_prefs(prefs: Dict[str, Any]) -> None:
    os.makedirs(APP_DIR, exist_ok=True)
    with open(PREFS_FILE, "w", encoding="utf-8") as f:
        json.dump({k: prefs.get(k, v) for k, v in DEFAULT_PREFS.items()}, f, indent=2)


# --------------------------------------------------------------------- dopasowanie wpisu do okna
_GENERIC_LABELS = {"www", "login", "auth", "app", "my", "online", "secure", "accounts", "account", "portal"}


def _site_label(url: str) -> str:
    """Charakterystyczna część domeny: github.com → github, online.mbank.pl → mbank."""
    host = (urlparse(url if "://" in url else f"https://{url}").hostname or "").lower()
    parts = [p for p in host.split(".") if p]
    if len(parts) >= 2:
        candidates = [p for p in parts[:-1] if p not in _GENERIC_LABELS]
        label = candidates[-1] if candidates else parts[-2]
        if label in ("com", "co", "org", "net", "gov", "edu") and len(parts) >= 3:
            label = parts[-3]
        return label
    return parts[0] if parts else ""


def autotype_matches(vault: Vault, window_title: str) -> List[Tuple[int, VaultEntry]]:
    """Wpisy pasujące do tytułu okna, od najlepiej dopasowanych (wynik, wpis)."""
    title = (window_title or "").lower()
    if not title:
        return []
    scored = []
    for entry in vault.entries.values():
        if not (entry.password or entry.username):
            continue
        score = 0
        pattern = (entry.custom_fields.get(WINDOW_FIELD) or "").strip().lower()
        if pattern and pattern in title:
            score = 100
        label = _site_label(entry.url) if entry.url else ""
        if len(label) >= 3 and label in title:
            score = max(score, 60)
        name = entry.title.strip().lower()
        if len(name) >= 3 and name in title:
            score = max(score, 50)
        if score:
            scored.append((score, entry))
    scored.sort(key=lambda s: (-s[0], s[1].title.lower()))
    return scored


def single_best_match(matches: List[Tuple[int, VaultEntry]]) -> Optional[VaultEntry]:
    if not matches:
        return None
    if len(matches) == 1 or matches[0][0] > matches[1][0]:
        return matches[0][1]
    return None


# --------------------------------------------------------------------- sekwencja Autotype
_TOKEN_RE = re.compile(r"\{(USERNAME|PASSWORD|TAB|ENTER|TOTP|DELAY=\d{1,4})\}", re.IGNORECASE)


def parse_sequence(sequence: str) -> List[Tuple[str, str]]:
    """'{USERNAME}{TAB}{PASSWORD}' → [('field','USERNAME'),('key','TAB'),...]; zwykły tekst → ('text', ...)."""
    out, pos = [], 0
    for m in _TOKEN_RE.finditer(sequence or ""):
        if m.start() > pos:
            out.append(("text", sequence[pos:m.start()]))
        token = m.group(1).upper()
        if token in ("TAB", "ENTER"):
            out.append(("key", token))
        elif token.startswith("DELAY="):
            out.append(("delay", token.split("=", 1)[1]))
        else:
            out.append(("field", token))
        pos = m.end()
    if pos < len(sequence or ""):
        out.append(("text", sequence[pos:]))
    return out


def entry_sequence(entry: VaultEntry) -> str:
    return (entry.custom_fields.get(SEQUENCE_FIELD) or "").strip() or DEFAULT_SEQUENCE


class AutotypeAborted(Exception):
    pass


def perform_autotype(entry: VaultEntry, target_hwnd: int, sequence: Optional[str] = None,
                     typer=None, foreground=None, activate=None) -> None:
    """Wpisuje dane wpisu w okno `target_hwnd`. Wywoływać w wątku roboczym (czeka i wpisuje z opóźnieniami)."""
    typer = typer or winsys
    foreground = foreground or (lambda: winsys.foreground_window()[0])
    activate = activate or winsys.activate_window
    typer.wait_modifiers_released()
    if foreground() != target_hwnd:
        activate(target_hwnd)
        time.sleep(0.25)

    def _check():
        if foreground() != target_hwnd:
            raise AutotypeAborted("Okno docelowe przestało być aktywne – przerwano, aby nie wpisać danych w inne okno.")

    values = {"USERNAME": entry.username, "PASSWORD": entry.password,
              "TOTP": (get_current_totp(entry.totp_secret) or "") if entry.totp_secret else ""}
    for kind, value in parse_sequence(sequence or entry_sequence(entry)):
        _check()
        if kind == "text":
            typer.type_text(value)
        elif kind == "field":
            typer.type_text(values.get(value, ""))
        elif kind == "key":
            typer.press_key(value)
            time.sleep(0.05)
        elif kind == "delay":
            time.sleep(min(int(value), 5000) / 1000)


# --------------------------------------------------------------------- okienko wyszukiwania
class QuickSearchPopup(ctk.CTkToplevel):
    """Małe okno na środku ekranu. mode='copy' (Ctrl+Shift+Spacja) albo 'autotype' (wybór wpisu do wpisania)."""

    def __init__(self, master, vault: Vault, mode: str, on_copy: Callable[[str, str], None],
                 on_autotype: Optional[Callable[[VaultEntry], None]] = None, query: str = ""):
        super().__init__(master, fg_color=COLOR_PANEL_DARK)
        self.vault, self.mode = vault, mode
        self.on_copy, self.on_autotype = on_copy, on_autotype
        self.overrideredirect(True)
        self.attributes("-topmost", True)
        s = self._get_window_scaling()
        w, h = 560, 430
        x = (self.winfo_screenwidth() - int(w * s)) // 2
        y = (self.winfo_screenheight() - int(h * s)) // 3
        self.geometry(f"{w}x{h}+{x}+{y}")

        frame = ctk.CTkFrame(self, fg_color=COLOR_PANEL_DARK, border_width=1, border_color=COLOR_BORDER, corner_radius=0)
        frame.pack(fill="both", expand=True)
        title = "⌨️ Autotype – wybierz wpis do wpisania" if mode == "autotype" else "🔍 Szybkie wyszukiwanie"
        ctk.CTkLabel(frame, text=title, font=FONT_SUBTITLE).pack(anchor="w", padx=14, pady=(10, 4))
        self.entry = ctk.CTkEntry(frame, placeholder_text="Wpisz nazwę, login lub adres...", height=36, font=FONT_BODY)
        self.entry.pack(fill="x", padx=14)
        if query:
            self.entry.insert(0, query)
        self.list = EntryList(frame, bg=COLOR_PANEL_DARK, on_select=self._clicked,
                              icon_provider=getattr(master, "icon_provider", None))
        self.list.pack(fill="both", expand=True, padx=8, pady=8)
        hint = ("Enter – wpisz w okno  ·  ↑↓ – wybór  ·  Esc – zamknij" if mode == "autotype" else
                "Enter – kopiuj hasło  ·  Shift+Enter – login  ·  Ctrl+Enter – kod 2FA  ·  Esc – zamknij")
        ctk.CTkLabel(frame, text=hint, font=FONT_SMALL, text_color=COLOR_TEXT_MUTED).pack(pady=(0, 8))

        self.entry.bind("<KeyRelease>", self._on_key)
        self.entry.bind("<Return>", lambda e: self._activate("password"))
        self.entry.bind("<Shift-Return>", lambda e: self._activate("username"))
        self.entry.bind("<Control-Return>", lambda e: self._activate("totp"))
        self.entry.bind("<Down>", lambda e: self.list.move_selection(1))
        self.entry.bind("<Up>", lambda e: self.list.move_selection(-1))
        self.bind("<Escape>", lambda e: self.close())
        self.bind("<FocusOut>", self._on_focus_out)
        self._last_query = None
        self._refresh()
        self.after(30, self._grab_focus)

    def _grab_focus(self, attempt: int = 0):
        if not self.winfo_exists():
            return
        try:
            self.lift()
            if winsys.IS_WINDOWS:
                winsys.force_foreground(int(self.wm_frame(), 16))
            self.focus_force()
            self.entry.focus_set()
        except Exception:
            pass
        # Okno mogło jeszcze nie być w pełni utworzone – ponawiamy kilka razy
        if attempt < 4 and self.focus_get() is None:
            self.after(60, lambda: self._grab_focus(attempt + 1))

    def _on_focus_out(self, event=None):
        # Zamknięcie po kliknięciu poza okno (z opóźnieniem – fokus mógł przejść do pola wewnątrz okienka)
        self.after(150, lambda: self.winfo_exists() and self.focus_get() is None and self.close())

    def _on_key(self, event=None):
        if event is not None and event.keysym in ("Up", "Down", "Return", "Escape"):
            return
        self._refresh()

    def _refresh(self):
        query = self.entry.get().strip()
        if query == self._last_query:
            return
        self._last_query = query
        results = self.vault.search(query=query) if query else sorted(
            self.vault.entries.values(), key=lambda e: (not e.favorite, e.title.lower()))
        results = results[:200]
        items = []
        for e in results:
            domain, avatar, color = avatar_for(e.title, e.url)
            items.append({"id": e.id, "title": f"{'⭐ ' if e.favorite else ''}{e.title}",
                          "subtitle": e.username or e.url or e.category, "domain": domain, "avatar": avatar,
                          "color": color})
        self.list.set_items(items, empty_text="Brak pasujących wpisów.")
        if items:
            self.list.set_selected(items[0]["id"])

    def _clicked(self, entry_id: str):
        self.list.set_selected(entry_id)
        self._activate("password")

    def _activate(self, what: str):
        entry = self.vault.get_entry(self.list.selected_id) if self.list.selected_id else None
        if not entry:
            return "break"
        self.close()
        if self.mode == "autotype" and self.on_autotype:
            self.on_autotype(entry)
        else:
            self.on_copy(entry.id, what)
        return "break"

    def close(self):
        if self.winfo_exists():
            self.destroy()


# --------------------------------------------------------------------- kontroler
class QuickAccess:
    """Globalne skróty klawiszowe aplikacji. Zdarzenia z wątku skrótów przechodzą do UI przez kolejkę."""

    def __init__(self, app):
        self.app = app
        self.prefs = load_prefs()
        self._events: "queue.Queue[Tuple[str, int, str]]" = queue.Queue()
        self.manager = winsys.HotkeyManager(self._on_hotkey)
        self.registered: Dict[str, bool] = {}
        self.popup: Optional[QuickSearchPopup] = None
        self._poll()

    def start(self) -> Dict[str, bool]:
        self.manager.stop()
        self.registered = {}
        if self.prefs.get("enabled") and winsys.IS_WINDOWS:
            self.registered = self.manager.start({"search": self.prefs["search"], "autotype": self.prefs["autotype"]})
        return self.registered

    def stop(self) -> None:
        self.manager.stop()

    def apply_prefs(self, prefs: Dict[str, Any]) -> Dict[str, bool]:
        for key in ("search", "autotype"):
            winsys.parse_hotkey(prefs[key])  # ValueError dla błędnego skrótu
        self.prefs = {**DEFAULT_PREFS, **prefs}
        save_prefs(self.prefs)
        return self.start()

    # --- wątek skrótów → kolejka (okno docelowe zapamiętane natychmiast, zanim cokolwiek się pojawi)
    def _on_hotkey(self, name: str) -> None:
        hwnd, title = winsys.foreground_window()
        self._events.put((name, hwnd, title))

    def _poll(self) -> None:
        try:
            while True:
                name, hwnd, title = self._events.get_nowait()
                self._handle(name, hwnd, title)
        except queue.Empty:
            pass
        try:
            self.app.after(80, self._poll)
        except Exception:
            pass

    def _handle(self, name: str, hwnd: int, title: str) -> None:
        vault = self.app.current_vault
        if vault is None:
            self.app.bring_to_front(message="Odblokuj sejf, aby skorzystać ze skrótu.")
            return
        if self.popup is not None and self.popup.winfo_exists():
            self.popup.close()
        if name == "search":
            self.popup = QuickSearchPopup(self.app, vault, "copy", on_copy=self.app.quick_copy)
            return
        if name == "autotype":
            if not self.app.autotype_allowed():
                self.app.notify("Autotype jest wyłączony przez politykę Twojej firmy.", error=True)
                return
            if not hwnd or winsys.window_pid(hwnd) == os.getpid():
                self.app.notify("Autotype: najpierw kliknij pole logowania w programie lub na stronie.", error=True)
                return
            matches = autotype_matches(vault, title)
            best = single_best_match(matches)
            if best is not None:
                self.run_autotype(best, hwnd)
                return
            query = matches[0][1].title if matches else ""
            self.popup = QuickSearchPopup(self.app, vault, "autotype", on_copy=self.app.quick_copy,
                                          on_autotype=lambda entry: self.run_autotype(entry, hwnd), query=query)

    def run_autotype(self, entry: VaultEntry, hwnd: int) -> None:
        self.app.on_user_activity()

        def _worker():
            try:
                perform_autotype(entry, hwnd)
            except AutotypeAborted as e:
                msg = str(e)
                self.app.post_to_ui(lambda: self.app.notify(msg, error=True))
            except Exception as e:
                msg = f"Autotype nie powiódł się: {e}"
                self.app.post_to_ui(lambda: self.app.notify(msg, error=True))
        threading.Thread(target=_worker, daemon=True).start()
