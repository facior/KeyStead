"""Wybór języka interfejsu (ekran logowania i Ustawienia). Zmiana działa po ponownym uruchomieniu programu."""

from typing import Callable

import customtkinter as ctk

from core.i18n import LANGUAGES, current_language, save_language
from ui.theme import COLOR_CARD_DARK, COLOR_PANEL_DARK, COLOR_TEXT_MUTED, FONT_SMALL


class LanguageMenu(ctk.CTkOptionMenu):
    """Lista języków podpisanych w ich własnym języku (Polski / English) – czytelna niezależnie od bieżącego."""

    def __init__(self, master, on_change: Callable[[str], None], **kw):
        self._codes = {name: code for code, name in LANGUAGES.items()}
        self._on_change = on_change
        kw.setdefault("width", 120)
        kw.setdefault("height", 24)
        kw.setdefault("font", FONT_SMALL)
        kw.setdefault("fg_color", COLOR_CARD_DARK)
        kw.setdefault("button_color", COLOR_PANEL_DARK)
        kw.setdefault("text_color", COLOR_TEXT_MUTED)
        super().__init__(master, values=list(LANGUAGES.values()), command=self._picked, **kw)
        self.set(LANGUAGES[current_language()])

    def _picked(self, name: str) -> None:
        code = self._codes[name]
        if code == current_language():
            return
        save_language(code)
        self._on_change(code)
