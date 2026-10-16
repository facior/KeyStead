"""
Moduł wysuwanego z boku panelu bocznego (Sliding Drawer / Offcanvas Panel).
Zamiast otwierać osobne okna systemowe, panele wyjeżdżają płynnie z prawej strony
wewnątrz tego samego okna aplikacji.
"""

import math
import time
from typing import Optional, Callable
import customtkinter as ctk

from ui.theme import (
    FONT_TITLE, FONT_SUBTITLE, FONT_BODY, FONT_BODY_BOLD, FONT_SMALL,
    COLOR_PANEL_DARK, COLOR_CARD_DARK, COLOR_CARD_HOVER, COLOR_BORDER,
    COLOR_PRIMARY, COLOR_TEXT_PRIMARY, COLOR_TEXT_MUTED
)

SLIDE_IN_MS = 190
SLIDE_OUT_MS = 150
FRAME_MS = 10


class SlidingDrawer:
    def __init__(self, parent_widget):
        self.parent = parent_widget
        self.is_open = False
        self._animating = False
        self._target_rel_width = 0.55
        self._current_x_fraction = 1.0  # 1.0 = całkowicie poza ekranem z prawej
        self._anim_token = 0  # Unieważnia trwające animacje przy kolejnym open/close
        self._escape_root = None
        self._escape_bind_id = None
        self.on_closed: Optional[Callable[[], None]] = None

        # Główny wysuwany panel z cieniem/obramowaniem po lewej stronie
        self.panel = ctk.CTkFrame(
            self.parent,
            fg_color=COLOR_PANEL_DARK,
            corner_radius=0,
            border_width=1,
            border_color=COLOR_BORDER
        )

        # Nagłówek panelu
        self.header_frame = ctk.CTkFrame(self.panel, fg_color=COLOR_CARD_DARK, height=65, corner_radius=0)
        self.header_frame.pack(fill="x", side="top")

        header_inner = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        header_inner.pack(fill="both", expand=True, padx=20, pady=12)

        self.title_col = ctk.CTkFrame(header_inner, fg_color="transparent")
        self.title_col.pack(side="left", fill="x", expand=True)

        self.title_lbl = ctk.CTkLabel(
            self.title_col,
            text="",
            font=FONT_TITLE,
            text_color=COLOR_TEXT_PRIMARY,
            anchor="w"
        )
        self.title_lbl.pack(anchor="w")

        self.subtitle_lbl = ctk.CTkLabel(
            self.title_col,
            text="",
            font=FONT_SMALL,
            text_color=COLOR_TEXT_MUTED,
            anchor="w"
        )
        self.subtitle_lbl.pack(anchor="w")

        # Przycisk zamknięcia panelu (X)
        self.close_btn = ctk.CTkButton(
            header_inner,
            text="✕",
            width=36,
            height=36,
            font=("Segoe UI", 16, "bold"),
            fg_color=COLOR_PANEL_DARK,
            hover_color=COLOR_CARD_HOVER,
            corner_radius=18,
            command=self.close
        )
        self.close_btn.pack(side="right")

        # Kontener na treść panelu
        self.content_container = ctk.CTkFrame(self.panel, fg_color="transparent")
        self.content_container.pack(fill="both", expand=True, padx=15, pady=15)

        # Skrót Escape zamyka panel (przypisany do okna głównego)
        try:
            self._escape_root = self.parent.winfo_toplevel()
            self._escape_bind_id = self._escape_root.bind("<Escape>", self._on_escape_pressed, add="+")
        except Exception:
            self._escape_root = None

    def destroy(self):
        """Odpina globalny skrót Escape (wywoływane przy niszczeniu widoku-rodzica)."""
        self._anim_token += 1
        if self._escape_root is not None and self._escape_bind_id:
            try:
                self._escape_root.unbind("<Escape>", self._escape_bind_id)
            except Exception:
                pass
        self._escape_root = None
        self._escape_bind_id = None

    def _alive(self) -> bool:
        try:
            return bool(self.panel.winfo_exists())
        except Exception:
            return False

    def _on_escape_pressed(self, event=None):
        if self.is_open and self._alive():
            self.close()

    def _calc_drawer_width_fraction(self) -> float:
        """Dynamicznie oblicza responsywną szerokość panelu w zależności od rozmiaru okna."""
        win_w = self.parent.winfo_width()
        if win_w <= 750:
            return 0.96  # Prawie pełny ekran na małych oknach
        elif win_w <= 1050:
            return 0.70  # 70% na średnich oknach
        elif win_w <= 1350:
            return 0.52  # 52% na typowych laptopach
        else:
            # Na dużych ekranach stała optymalna szerokość ~560-600px
            return max(0.38, min(0.48, 620.0 / win_w))

    def open(
        self,
        title: str,
        subtitle: str = "",
        on_closed: Optional[Callable[[], None]] = None
    ) -> ctk.CTkFrame:
        """
        Płynnie wysuwa panel z prawej strony i zwraca pusty kontener `content_container`
        do wypełnienia widokiem.
        """
        self.on_closed = on_closed
        self.title_lbl.configure(text=title)
        self.subtitle_lbl.configure(text=subtitle)

        # Wyczyść poprzednią treść
        for w in self.content_container.winfo_children():
            w.destroy()

        self._target_rel_width = self._calc_drawer_width_fraction()

        self.panel.lift()

        start = self._current_x_fraction if self._animating or self.is_open else 1.0
        self.is_open = True
        self._animating = True
        self._anim_token += 1
        token = self._anim_token
        target = 1.0 - self._target_rel_width
        # Start animacji dopiero po zbudowaniu zawartości przez wywołującego (after_idle) –
        # inaczej pierwsze klatki czekałyby na budowę formularza i panel by „skakał”
        self.parent.after_idle(lambda: self._animate(start, target, token, SLIDE_IN_MS, ease_out=True))

        return self.content_container

    def _animate(self, start: float, target: float, token: int, duration_ms: int, ease_out: bool,
                 t0: Optional[float] = None, on_done: Optional[Callable[[], None]] = None):
        """Animacja zależna od czasu: wolniejsza klatka nie wydłuża ruchu, tylko pomija pośrednią pozycję."""
        if token != self._anim_token or not self._alive():
            return
        now = time.perf_counter()
        if t0 is None:
            t0 = now
        progress = min(1.0, (now - t0) * 1000 / duration_ms)
        ease = 1.0 - math.pow(1.0 - progress, 3) if ease_out else math.pow(progress, 2)
        current = start + (target - start) * ease
        self._current_x_fraction = current
        self.panel.place(relx=current, rely=0, relwidth=self._target_rel_width, relheight=1.0)
        if progress < 1.0:
            self.parent.after(FRAME_MS, lambda: self._animate(start, target, token, duration_ms, ease_out, t0, on_done))
            return
        self._animating = False
        if on_done:
            on_done()

    def close(self):
        """Płynnie chowa panel z powrotem za prawą krawędź okna."""
        if not self.is_open:
            return

        self.is_open = False
        self._animating = True
        self._anim_token += 1
        self._animate(self._current_x_fraction, 1.0, self._anim_token, SLIDE_OUT_MS, ease_out=False,
                      on_done=self._after_closed)

    def _after_closed(self):
        self.panel.place_forget()
        # Zwolnij widok z panelu (np. formularz z hasłem) po schowaniu
        for w in self.content_container.winfo_children():
            w.destroy()
        if self.on_closed:
            self.on_closed()
