"""
„O programie” i „O autorze”: wersja aplikacji i serwera (zgodność linii wersji), bezpieczeństwo, licencja, autor.
Używane w panelu bocznym (Ustawienia → O programie) i w okienku z ekranu logowania.
"""

import os
import platform
import sys
import webbrowser
from typing import Optional

import customtkinter as ctk

from core.desktop import open_path
from core.i18n import N_, _, _n, current_language
from core.version import (APP_NAME, APP_REPOSITORY_URL, APP_VERSION, AUTHOR, AUTHOR_GITHUB,
                          SERVER_REPOSITORY_URL, product_line, server_compatibility)
from ui.theme import (COLOR_CARD_DARK, COLOR_PANEL_DARK, COLOR_PRIMARY, COLOR_SUCCESS, COLOR_TEXT_ACCENT,
                      COLOR_TEXT_MUTED, COLOR_TEXT_PRIMARY, COLOR_WARNING, FONT_BODY, FONT_BODY_BOLD, FONT_SMALL,
                      FONT_SUBTITLE, FONT_TITLE)

COMPATIBILITY = {
    "ok": (_("✅ Zgodna z aplikacją"), COLOR_SUCCESS),
    "server_older": (_("⚠️ Serwer ma starszą wersję – poproś administratora o aktualizację serwera"), COLOR_WARNING),
    "app_older": (_("⚠️ Serwer jest nowszy – zaktualizuj aplikację"), COLOR_WARNING),
    "unknown": (_("serwer nie podał wersji (starsza wersja serwera)"), COLOR_TEXT_MUTED),
}


def program_file(name: str) -> str:
    """Plik dołączony do zainstalowanego programu (obok KeyStead Manager.exe) albo "" (wersja deweloperska)."""
    if getattr(sys, "frozen", False):
        base = os.path.dirname(sys.executable)
    else:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(base, name)
    return path if os.path.isfile(path) else ""


def _line(version: str) -> str:
    major, minor = product_line(version)
    return f"{major}.{minor}"


class AboutView(ctk.CTkFrame):
    def __init__(self, parent, server_url: str = "", server_version: str = ""):
        super().__init__(parent, fg_color="transparent")
        self.pack(fill="both", expand=True)
        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.pack(fill="both", expand=True)

        # --- O programie
        card = self._card(scroll)
        ctk.CTkLabel(card, text=f"🛡️ {APP_NAME}", font=FONT_TITLE, text_color=COLOR_TEXT_PRIMARY).pack(anchor="w", padx=16, pady=(12, 0))
        ctk.CTkLabel(card, text=_("Wersja {version}  ·  KeyStead {line}", version=APP_VERSION, line=_line(APP_VERSION)), font=FONT_BODY,
                     text_color=COLOR_TEXT_ACCENT).pack(anchor="w", padx=16, pady=(0, 6))
        ctk.CTkLabel(card, text=_("Menedżer haseł z szyfrowaniem end-to-end: sejf szyfrowany jest na tym komputerze "
                                  "(AES-256-GCM, klucz z hasła głównego – Argon2id). Serwer firmy przechowuje wyłącznie "
                                  "zaszyfrowane dane i nie zna Twoich haseł."),
                     font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, wraplength=470, justify="left").pack(anchor="w", padx=16, pady=(0, 8))
        rows = [(_("System"), f"{platform.system()} {platform.release()} · Python {platform.python_version()}")]
        if server_url:
            rows.insert(0, (_("Serwer"), server_url))
            text, color = COMPATIBILITY[server_compatibility(server_version)]
            rows.insert(1, (_("Wersja serwera"), f"{server_version or '—'}"))
            self._rows(card, rows[:2])
            ctk.CTkLabel(card, text=text, font=FONT_SMALL, text_color=color, wraplength=470,
                         justify="left").pack(anchor="w", padx=16, pady=(0, 4))
            rows = rows[2:]
        self._rows(card, rows)
        ctk.CTkLabel(card, text=_("Wersjonowanie: aplikacja {line}.x współpracuje z serwerem "
                                  "{line}.x i nowszym. Ostatnia liczba oznacza poprawki.", line=_line(APP_VERSION)),
                     font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, wraplength=470, justify="left").pack(anchor="w", padx=16, pady=(4, 6))
        links = ctk.CTkFrame(card, fg_color="transparent")
        links.pack(anchor="w", padx=16, pady=(2, 12))
        self._link(links, _("Wydania aplikacji"), APP_REPOSITORY_URL + "/releases")
        self._link(links, _("Serwer"), SERVER_REPOSITORY_URL)

        # --- O autorze
        card = self._card(scroll)
        ctk.CTkLabel(card, text=_("👤 O autorze"), font=FONT_SUBTITLE, text_color=COLOR_TEXT_PRIMARY).pack(anchor="w", padx=16, pady=(12, 6))
        self._rows(card, [(_("Autor"), AUTHOR), (_("Rola"), _("twórca i programista KeyStead Manager i KeyStead Server"))])
        links = ctk.CTkFrame(card, fg_color="transparent")
        links.pack(anchor="w", padx=16, pady=(6, 12))
        self._link(links, "GitHub: " + AUTHOR_GITHUB.replace("https://", ""), AUTHOR_GITHUB)

        # --- Licencja
        card = self._card(scroll)
        ctk.CTkLabel(card, text=_("📜 Licencja"), font=FONT_SUBTITLE, text_color=COLOR_TEXT_PRIMARY).pack(anchor="w", padx=16, pady=(12, 4))
        ctk.CTkLabel(card, text=_("© 2026 {author}. Wszelkie prawa zastrzeżone.", author=AUTHOR), font=FONT_BODY_BOLD, text_color=COLOR_TEXT_PRIMARY).pack(anchor="w", padx=16)
        ctk.CTkLabel(card, text=_("Oprogramowanie jest chronione prawem autorskim. Korzystanie, kopiowanie, modyfikowanie "
                                  "i rozpowszechnianie jest dozwolone wyłącznie na podstawie zgody autora lub odrębnej "
                                  "umowy licencyjnej."),
                     font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, wraplength=470, justify="left").pack(anchor="w", padx=16, pady=(4, 6))
        files = ctk.CTkFrame(card, fg_color="transparent")
        files.pack(anchor="w", padx=16, pady=(0, 12))
        license_file = ((program_file("LICENSE.en.txt") if current_language() == "en" else "")
                        or program_file("LICENSE.txt") or program_file("LICENSE"))
        for text, path in ((_("Pełna treść licencji"), license_file),
                           (_("Licencje użytych bibliotek"), program_file("THIRD-PARTY-NOTICES.txt"))):
            if path:
                ctk.CTkButton(files, text=text, height=26, font=FONT_SMALL, fg_color=COLOR_PANEL_DARK,
                              hover_color=COLOR_PRIMARY, command=lambda p=path: open_path(p)).pack(side="left", padx=(0, 6))

    @staticmethod
    def _card(parent) -> ctk.CTkFrame:
        card = ctk.CTkFrame(parent, fg_color=COLOR_CARD_DARK, corner_radius=10)
        card.pack(fill="x", pady=6)
        return card

    @staticmethod
    def _rows(parent, rows):
        for label, value in rows:
            row = ctk.CTkFrame(parent, fg_color="transparent")
            row.pack(fill="x", padx=16, pady=1)
            ctk.CTkLabel(row, text=label, width=120, anchor="w", font=FONT_SMALL, text_color=COLOR_TEXT_MUTED).pack(side="left")
            ctk.CTkLabel(row, text=value, anchor="w", font=FONT_BODY, text_color=COLOR_TEXT_PRIMARY,
                         wraplength=340, justify="left").pack(side="left", fill="x", expand=True)

    @staticmethod
    def _link(parent, text: str, url: str):
        ctk.CTkButton(parent, text=text + " ↗", height=26, font=FONT_SMALL, fg_color=COLOR_PANEL_DARK,
                      hover_color=COLOR_PRIMARY, command=lambda: webbrowser.open(url)).pack(side="left", padx=(0, 6))


def show_about_window(master, server_url: str = "", server_version: str = "") -> Optional[ctk.CTkToplevel]:
    """Okienko „O programie” (np. z ekranu logowania, gdzie nie ma panelu bocznego)."""
    win = ctk.CTkToplevel(master)
    win.title(_("O programie – {app}", app=APP_NAME))
    win.geometry("560x620")
    win.transient(master.winfo_toplevel())
    AboutView(win, server_url=server_url, server_version=server_version).pack(padx=12, pady=12)
    win.after(50, win.lift)
    return win
