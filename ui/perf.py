"""
Poprawki wydajności CustomTkinter (stosowane raz, przy starcie aplikacji).

CTkScrollbar.set() przerysowuje pasek natychmiast i kończy rysowanie wywołaniem update_idletasks(),
czyli wymusza przeliczenie układu całego okna. Przewijana ramka woła set() przy każdej zmianie zawartości,
więc zbudowanie panelu z kilkudziesięciu elementów powodowało dziesiątki pełnych przeliczeń.
Tutaj kolejne wywołania set() w tej samej klatce są łączone w jedno przerysowanie w czasie bezczynności.
"""

import customtkinter as ctk

_applied = False


def apply() -> None:
    global _applied
    if _applied:
        return
    _applied = True
    original_draw = ctk.CTkScrollbar._draw

    def set_coalesced(self, start_value, end_value):
        self._start_value = float(start_value)
        self._end_value = float(end_value)
        if getattr(self, "_ks_draw_pending", False):
            return
        self._ks_draw_pending = True

        def _run():
            self._ks_draw_pending = False
            try:
                if self.winfo_exists():
                    original_draw(self, no_color_updates=True)
            except Exception:
                pass  # pasek zniszczony w międzyczasie

        try:
            self.after_idle(_run)
        except Exception:
            self._ks_draw_pending = False

    ctk.CTkScrollbar.set = set_coalesced
