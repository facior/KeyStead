"""
Lekki przycisk wyglądający jak CTkButton (zaokrąglone tło, podświetlenie po najechaniu).

CTkButton to osobne płótno z kilkunastoma elementami rysunku i przeliczaniem kształtu przy każdej zmianie
rozmiaru. W panelu szczegółów wpisu, przebudowywanym przy każdym kliknięciu, kilkanaście takich przycisków
kosztowało większość czasu. Tutaj przycisk to zwykła etykieta Tk z tłem-obrazkiem: obrazek o danym rozmiarze
i kolorze powstaje raz (PIL, wygładzone rogi) i jest współdzielony przez wszystkie przyciski.
"""

import tkinter as tk
import tkinter.font as tkfont
from typing import Callable, Dict, Optional, Tuple

import customtkinter as ctk
from customtkinter.windows.widgets.scaling import ScalingTracker
from PIL import Image, ImageDraw, ImageTk

from core.desktop import ui_font_family



def _root_cache(master, name: str) -> dict:
    """Obrazki i czcionki Tk należą do konkretnego okna głównego – pamięć podręczna znika razem z nim."""
    root = master._root()
    cache = getattr(root, name, None)
    if cache is None:
        cache = {}
        setattr(root, name, cache)
    return cache
SUPERSAMPLE = 3


def _color(value) -> str:
    if isinstance(value, (tuple, list)):
        return value[1] if ctk.get_appearance_mode() == "Dark" else value[0]
    return value


def _shade(hex_color: str, factor: float) -> str:
    """Jaśniejszy (factor > 0) lub ciemniejszy (factor < 0) odcień – kolor podświetlenia."""
    try:
        r, g, b = (int(hex_color[i:i + 2], 16) for i in (1, 3, 5))
    except (ValueError, TypeError):
        return hex_color
    if factor >= 0:
        r, g, b = (int(c + (255 - c) * factor) for c in (r, g, b))
    else:
        r, g, b = (int(c * (1 + factor)) for c in (r, g, b))
    return f"#{r:02x}{g:02x}{b:02x}"


def _rounded(master, width: int, height: int, radius: int, color: str, background: str) -> ImageTk.PhotoImage:
    images = _root_cache(master, "_ks_flat_images")
    key = (width, height, radius, color, background)
    image = images.get(key)
    if image is None:
        s = SUPERSAMPLE
        big = Image.new("RGB", (width * s, height * s), background)
        ImageDraw.Draw(big).rounded_rectangle((0, 0, width * s - 1, height * s - 1), radius=radius * s, fill=color)
        image = ImageTk.PhotoImage(big.resize((width, height), Image.LANCZOS), master=master)
        images[key] = image
    return image


_widths: Dict[Tuple, int] = {}


def _text_width(tk_font: tkfont.Font, font_key: Tuple, text: str) -> int:
    """
    Szerokość tekstu (z pamięcią podręczną). Emoji liczone z góry jako kwadrat o boku wysokości czcionki:
    pierwszy pomiar emoji w Tk na Windows szuka czcionki zastępczej i trwa kilkanaście ms na każdy przycisk.
    """
    cache_key = (font_key, text)
    width = _widths.get(cache_key)
    if width is None:
        plain = "".join(ch for ch in text if ord(ch) < 0x2190 and ch != "Fe0f")
        emoji = sum(1 for ch in text if ord(ch) >= 0x2190 and ch != "Fe0f")
        width = tk_font.measure(plain) + emoji * tk_font.metrics("linespace")
        _widths[cache_key] = width
    return width


class FlatButton(tk.Label):
    def __init__(self, master, text: str = "", width: int = 100, height: int = 28,
                 fg_color=None, hover_color=None, text_color="#ffffff", font=None, corner_radius: int = 6,
                 command: Optional[Callable[[], None]] = None, **_ignored):
        scaling = ScalingTracker.get_widget_scaling(master)
        family, size, *style = font or (ui_font_family(), 13)
        key = (family, size, tuple(style), scaling)
        fonts = _root_cache(master, "_ks_flat_fonts")
        tk_font = fonts.get(key)
        if tk_font is None:
            tk_font = tkfont.Font(master, family=family, size=-int(round(size * scaling)),
                                  weight="bold" if "bold" in style else "normal")
            fonts[key] = tk_font
        fg = _color(fg_color or ctk.ThemeManager.theme["CTkButton"]["fg_color"])
        hover = _color(hover_color) if hover_color else _shade(fg, 0.12)
        background = self._parent_bg(master)
        w = max(int(width * scaling), _text_width(tk_font, key, text) + int(16 * scaling))
        h = int(height * scaling)
        r = int(corner_radius * scaling)
        self._normal = _rounded(master, w, h, r, fg, background)
        self._hover = _rounded(master, w, h, r, hover, background)
        self._command = command
        super().__init__(master, text=text, image=self._normal, compound="center", font=tk_font,
                         fg=_color(text_color), bg=background, bd=0, padx=0, pady=0, cursor="hand2",
                         highlightthickness=0)
        self.bind("<Enter>", lambda _e: self.configure(image=self._hover))
        self.bind("<Leave>", lambda _e: self.configure(image=self._normal))
        self.bind("<ButtonRelease-1>", self._clicked)

    @staticmethod
    def _parent_bg(master) -> str:
        try:
            return master.cget("bg")
        except (ValueError, tk.TclError):
            color = master.cget("fg_color")
            if color == "transparent":
                color = master.cget("bg_color")
            return _color(color)

    def _clicked(self, event):
        # jak zwykły przycisk: akcja tylko, gdy kursor jest nadal nad przyciskiem
        if self._command and 0 <= event.x < self.winfo_width() and 0 <= event.y < self.winfo_height():
            self._command()
