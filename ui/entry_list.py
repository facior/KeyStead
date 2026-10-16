"""
Szybka lista wpisów rysowana na jednym płótnie (tk.Canvas).

Lista z widżetów CustomTkinter (ramka + etykiety na każdy wpis) potrzebowała ok. 25 ms na wiersz
i była przebudowywana przy każdym kliknięciu – przy kilkuset wpisach aplikacja zamierała na kilka sekund.
Tutaj wiersz to trzy elementy płótna: zaznaczenie zmienia tylko kolor dwóch wierszy, wyszukiwanie przerysowuje
listę w milisekundach, a przewijanie kółkiem myszy jest animowane.
"""

import tkinter as tk
import tkinter.font as tkfont
from typing import Callable, Dict, List, Optional

import customtkinter as ctk

from ui.theme import (COLOR_CARD_DARK, COLOR_CARD_HOVER, COLOR_PRIMARY, COLOR_TEXT_MUTED, COLOR_TEXT_PRIMARY,
                      FONT_FAMILY)

ROW_HEIGHT = 50
ROW_GAP = 6
ROW_RADIUS = 8
PAD_X = 10


class EntryList(ctk.CTkFrame):
    def __init__(self, master, bg: str, on_select: Callable[[str], None]):
        super().__init__(master, fg_color="transparent")
        self.on_select = on_select
        self.items: List[Dict[str, str]] = []
        self.selected_id: Optional[str] = None
        self._hover_index: Optional[int] = None
        self._rects: Dict[int, int] = {}  # indeks wiersza -> element tła (tylko narysowane wiersze)
        self._empty_text = ""
        self._last_width = 0
        self._scroll_target: Optional[float] = None
        self._scroll_job = None

        s = self._get_widget_scaling()
        self.s = s
        self.row_h = int(ROW_HEIGHT * s)
        self.gap = int(ROW_GAP * s)
        self.radius = int(ROW_RADIUS * s)
        self.pad = int(PAD_X * s)
        self.font_title = tkfont.Font(family=FONT_FAMILY, size=-int(13 * s), weight="bold")
        self.font_sub = tkfont.Font(family=FONT_FAMILY, size=-int(11 * s))

        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0, bd=0, yscrollincrement=1)
        self.scrollbar = ctk.CTkScrollbar(self, command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self._on_scroll_changed)
        self.canvas.pack(side="left", fill="both", expand=True)

        self.canvas.bind("<Configure>", self._on_resize)
        self.canvas.bind("<Button-1>", self._on_click)
        self.canvas.bind("<Motion>", self._on_motion)
        self.canvas.bind("<Leave>", lambda e: self._set_hover(None))
        self.canvas.bind("<MouseWheel>", self._on_wheel)

    # ------------------------------------------------------------ API
    def set_items(self, items: List[Dict[str, str]], empty_text: str = "", keep_scroll: bool = False) -> None:
        """items: [{"id", "title", "subtitle"}] w kolejności wyświetlania."""
        self.items = items
        self._empty_text = empty_text
        self._hover_index = None
        self._redraw()
        if not keep_scroll:
            self._stop_scroll_animation()
            self.canvas.yview_moveto(0)

    def set_selected(self, entry_id: Optional[str]) -> None:
        old = self.selected_id
        self.selected_id = entry_id
        for eid in {old, entry_id}:
            idx = self._index_of(eid)
            if idx is not None:
                self._paint_row(idx)

    # ------------------------------------------------------------ rysowanie
    def _row_top(self, i: int) -> int:
        return self.gap // 2 + i * (self.row_h + self.gap)

    def _index_of(self, entry_id) -> Optional[int]:
        if entry_id is None:
            return None
        for i, it in enumerate(self.items):
            if it["id"] == entry_id:
                return i
        return None

    def _fit(self, text: str, font: tkfont.Font, max_w: int) -> str:
        if font.measure(text) <= max_w:
            return text
        lo, hi = 0, len(text)
        while lo < hi:  # najdłuższy prefiks mieszczący się z wielokropkiem
            mid = (lo + hi + 1) // 2
            if font.measure(text[:mid] + "…") <= max_w:
                lo = mid
            else:
                hi = mid - 1
        return text[:lo] + "…"

    def _rounded_rect(self, x0, y0, x1, y1, r, **kw) -> int:
        pts = [x0 + r, y0, x1 - r, y0, x1, y0, x1, y0 + r, x1, y1 - r, x1, y1, x1 - r, y1,
               x0 + r, y1, x0, y1, x0, y1 - r, x0, y0 + r, x0, y0]
        return self.canvas.create_polygon(pts, smooth=True, **kw)

    def _redraw(self) -> None:
        """Czyści płótno; wiersze są dorysowywane leniwie – tylko te, które widać (także przy tysiącach wpisów)."""
        c = self.canvas
        c.delete("all")
        self._rects = {}
        width = max(c.winfo_width(), 50)
        self._last_width = width
        if not self.items:
            if self._empty_text:
                c.create_text(width // 2, int(40 * self.s), text=self._empty_text, fill=COLOR_TEXT_MUTED,
                              font=self.font_sub, width=width - 2 * self.pad)
            c.configure(scrollregion=(0, 0, width, 1))
            self._update_scrollbar()
            return
        c.configure(scrollregion=(0, 0, width, self._content_height()))
        self._update_scrollbar()
        self._draw_visible()

    def _draw_visible(self) -> None:
        if not self.items:
            return
        c = self.canvas
        top = c.canvasy(0)
        height = max(c.winfo_height(), self.row_h * 20)
        step = self.row_h + self.gap
        first = max(0, int(top // step) - 3)
        last = min(len(self.items), int((top + height) // step) + 4)
        x0, x1 = 2, self._last_width - 2
        text_w = x1 - x0 - 2 * self.pad
        for i in range(first, last):
            if i in self._rects:
                continue
            it = self.items[i]
            y = self._row_top(i)
            self._rects[i] = self._rounded_rect(x0, y, x1, y + self.row_h, self.radius, width=1)
            c.create_text(x0 + self.pad, y + int(self.row_h * 0.33), anchor="w", fill=COLOR_TEXT_PRIMARY,
                          font=self.font_title, text=self._fit(it["title"], self.font_title, text_w))
            c.create_text(x0 + self.pad, y + int(self.row_h * 0.70), anchor="w", fill=COLOR_TEXT_MUTED,
                          font=self.font_sub, text=self._fit(it["subtitle"], self.font_sub, text_w))
            self._paint_row(i)

    def _paint_row(self, i: int) -> None:
        if i not in self._rects:
            return
        selected = self.items[i]["id"] == self.selected_id
        fill = COLOR_CARD_HOVER if selected or i == self._hover_index else COLOR_CARD_DARK
        self.canvas.itemconfigure(self._rects[i], fill=fill, outline=COLOR_PRIMARY if selected else fill)

    # ------------------------------------------------------------ przewijanie
    def _content_height(self) -> int:
        return self._row_top(len(self.items)) + self.gap // 2 if self.items else 1

    def _update_scrollbar(self) -> None:
        need = self._content_height() > self.canvas.winfo_height()
        if need and not self.scrollbar.winfo_ismapped():
            self.scrollbar.pack(side="right", fill="y", before=self.canvas)
        elif not need and self.scrollbar.winfo_ismapped():
            self.scrollbar.pack_forget()

    def _on_scroll_changed(self, first, last) -> None:
        self.scrollbar.set(first, last)
        self._draw_visible()

    def _on_wheel(self, event) -> None:
        """Płynne przewijanie: każdy obrót kółka przesuwa cel, animacja dojeżdża do niego w kilku klatkach."""
        total = self._content_height()
        view_h = self.canvas.winfo_height()
        if total <= view_h:
            return
        current = self.canvas.canvasy(0)
        base = self._scroll_target if self._scroll_target is not None else current
        step = -event.delta / 120 * self.row_h * 1.6
        self._scroll_target = max(0.0, min(base + step, total - view_h))
        if self._scroll_job is None:
            self._animate_scroll()

    def _animate_scroll(self) -> None:
        self._scroll_job = None
        if self._scroll_target is None or not self.winfo_exists():
            return
        current = self.canvas.canvasy(0)
        diff = self._scroll_target - current
        if abs(diff) < 1:
            self._scroll_target = None
            return
        move = diff * 0.35
        move = int(move) if abs(move) >= 1 else (1 if diff > 0 else -1)
        self.canvas.yview_scroll(move, "units")
        self._scroll_job = self.after(12, self._animate_scroll)

    def _stop_scroll_animation(self) -> None:
        if self._scroll_job is not None:
            self.after_cancel(self._scroll_job)
            self._scroll_job = None
        self._scroll_target = None

    # ------------------------------------------------------------ zdarzenia
    def _row_at(self, event) -> Optional[int]:
        y = self.canvas.canvasy(event.y)
        i = int((y - self.gap // 2) // (self.row_h + self.gap))
        if 0 <= i < len(self.items) and y - self._row_top(i) <= self.row_h:
            return i
        return None

    def _on_click(self, event) -> None:
        i = self._row_at(event)
        if i is not None:
            self.on_select(self.items[i]["id"])

    def _on_motion(self, event) -> None:
        self._set_hover(self._row_at(event))

    def _set_hover(self, i: Optional[int]) -> None:
        if i == self._hover_index:
            return
        old, self._hover_index = self._hover_index, i
        for idx in (old, i):
            if idx is not None and idx < len(self.items):
                self._paint_row(idx)
        self.canvas.configure(cursor="hand2" if i is not None else "")

    def _on_resize(self, event) -> None:
        if abs(event.width - self._last_width) > 1:
            self._redraw()
        else:
            self._update_scrollbar()
            self._draw_visible()  # wyższe okno – dorysuj odsłonięte wiersze

    def destroy(self):
        self._stop_scroll_animation()
        super().destroy()
