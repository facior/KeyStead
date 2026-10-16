"""
Poprawki wydajności CustomTkinter (stosowane raz, przy starcie aplikacji).

1. Pasek przewijania. CTkScrollbar kończy każde rysowanie wywołaniem update_idletasks(), czyli przeliczeniem
   układu całego okna – a przewijana ramka woła set() przy każdej zmianie zawartości i każdym kroku przewijania.
   Tutaj pasek rysuje się od razu (suwak nadąża za treścią), ale bez przeliczania całego okna.

2. Kółko myszy. Każda CTkScrollableFrame rejestruje globalną obsługę kółka (bind_all) i nigdy jej nie usuwa.
   Panele boczne i szuflady tworzą takie ramki przy każdym otwarciu, więc po chwili pracy każdy obrót kółka
   wywoływał dziesiątki procedur (także dla dawno zamkniętych paneli). Tutaj jest jedna wspólna obsługa,
   która przekazuje zdarzenie tylko do istniejących ramek.

3. Płynne przewijanie. Na Windows ramka przeskakiwała o 20 px na każdy ząbek kółka; tutaj dojeżdża do celu
   w kilku klatkach – tak jak lista wpisów.
"""

import math
import sys
import time
import weakref

import customtkinter as ctk

_applied = False
_frames: "weakref.WeakSet" = weakref.WeakSet()

WHEEL_STEP_PX = 70      # przesunięcie na jeden ząbek kółka


def apply() -> None:
    global _applied
    if _applied:
        return
    _applied = True
    high_resolution_timer()
    _patch_scrollbar()
    _patch_scrollable_frame()


# --------------------------------------------------------------------- 1. pasek przewijania
def _patch_scrollbar() -> None:
    original_draw = ctk.CTkScrollbar._draw

    def draw_without_full_layout(self, no_color_updates=False):
        canvas = getattr(self, "_canvas", None)
        if canvas is not None and "update_idletasks" not in canvas.__dict__:
            canvas.update_idletasks = lambda: None  # tylko ten pasek – układ okna przeliczy Tk w swoim czasie
        original_draw(self, no_color_updates)

    def set_immediately(self, start_value, end_value):
        start_value, end_value = float(start_value), float(end_value)
        if (start_value, end_value) == (self._start_value, self._end_value):
            return
        self._start_value, self._end_value = start_value, end_value
        try:
            draw_without_full_layout(self, no_color_updates=True)
        except Exception:
            pass  # pasek zniszczony w międzyczasie

    ctk.CTkScrollbar._draw = draw_without_full_layout
    ctk.CTkScrollbar.set = set_immediately


# --------------------------------------------------------------------- 2–3. kółko myszy w przewijanych ramkach
_SHARED_EVENTS = {"<MouseWheel>", "<Button-4>", "<Button-5>", "<KeyPress-Shift_L>", "<KeyPress-Shift_R>",
                  "<KeyRelease-Shift_L>", "<KeyRelease-Shift_R>"}


def _patch_scrollable_frame() -> None:
    cls = ctk.CTkScrollableFrame
    original_bind_all = cls.bind_all

    def bind_all_shared(self, sequence=None, func=None, add=None):
        if sequence not in _SHARED_EVENTS:
            return original_bind_all(self, sequence, func, add)
        _frames.add(self)
        root = self._root()
        if not getattr(root, "_ks_wheel_installed", False):
            root._ks_wheel_installed = True
            for event in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
                root.bind_all(event, _dispatch_wheel, add=True)
            for event in ("<KeyPress-Shift_L>", "<KeyPress-Shift_R>"):
                root.bind_all(event, lambda e: _set_shift(True), add=True)
            for event in ("<KeyRelease-Shift_L>", "<KeyRelease-Shift_R>"):
                root.bind_all(event, lambda e: _set_shift(False), add=True)
        return None

    cls.bind_all = bind_all_shared
    if sys.platform.startswith("win"):
        cls._mouse_wheel_all = _smooth_wheel


def _set_shift(pressed: bool) -> None:
    for frame in list(_frames):
        frame._shift_pressed = pressed


def _dispatch_wheel(event) -> None:
    for frame in list(_frames):
        try:
            if frame.winfo_exists():
                frame._mouse_wheel_all(event)
        except Exception:
            pass


def _smooth_wheel(self, event) -> None:
    if not self._check_if_valid_scroll(event.widget):
        return
    canvas = self._parent_canvas
    horizontal = bool(self._shift_pressed)
    if (canvas.xview() if horizontal else canvas.yview()) == (0.0, 1.0):
        return
    key = "_ks_scroller_x" if horizontal else "_ks_scroller_y"
    scroller = getattr(self, key, None)
    if scroller is None:
        def total(c=canvas, h=horizontal):
            region = c.bbox("all")
            return 0 if not region else (region[2] - region[0]) if h else (region[3] - region[1])
        scroller = SmoothScroller(canvas, total, horizontal=horizontal)
        setattr(self, key, scroller)
    scroller.scroll_by(-event.delta / 120 * WHEEL_STEP_PX)


# --------------------------------------------------------------------- wspólne płynne przewijanie
class SmoothScroller:
    """
    Płynne przewijanie płótna Tk: kolejne obroty kółka przesuwają cel, a widok dojeżdża do niego
    wykładniczo w czasie rzeczywistym (niezależnie od tego, jak równo Tk wywołuje klatki).
    Przy ciągłym kręceniu daje to stałą prędkość zamiast szarpania „szybko–wolno” po każdym ząbku.
    """

    FRAME_MS = 8          # ok. 120 klatek/s (przy zegarze 1 ms – patrz high_resolution_timer)
    TIME_CONSTANT = 0.07  # s – im mniej, tym szybciej widok dogania cel

    def __init__(self, canvas, total_size, horizontal: bool = False, on_frame=None):
        self.canvas = canvas
        self.total_size = total_size        # funkcja: pełna wysokość/szerokość zawartości w px
        self.horizontal = horizontal
        self.on_frame = on_frame
        self._target = None
        self._pos = 0.0
        self._last = 0.0
        self._job = None

    def _visible(self) -> int:
        return self.canvas.winfo_width() if self.horizontal else self.canvas.winfo_height()

    def _current(self) -> float:
        return float(self.canvas.canvasx(0) if self.horizontal else self.canvas.canvasy(0))

    @property
    def active(self) -> bool:
        return self._job is not None

    def scroll_by(self, pixels: float) -> None:
        total, visible = self.total_size(), self._visible()
        if total <= visible:
            return
        if self._job is None:
            self._pos = self._current()  # użytkownik mógł w międzyczasie przeciągnąć pasek
            self._last = time.perf_counter()
        base = self._target if self._target is not None else self._pos
        self._target = max(0.0, min(base + pixels, float(total - visible)))
        if self._job is None:
            self._job = self.canvas.after(self.FRAME_MS, self._frame)

    def stop(self) -> None:
        if self._job is not None:
            try:
                self.canvas.after_cancel(self._job)
            except Exception:
                pass
        self._job = None
        self._target = None

    def _frame(self) -> None:
        self._job = None
        try:
            if self._target is None or not self.canvas.winfo_exists():
                return
            now = time.perf_counter()
            dt = min(0.1, max(0.0, now - self._last))
            self._last = now
            diff = self._target - self._pos
            if abs(diff) < 0.5:
                self._pos = self._target
            else:
                self._pos += diff * (1.0 - math.exp(-dt / self.TIME_CONSTANT))
            total = self.total_size()
            if total > 0:
                (self.canvas.xview_moveto if self.horizontal else self.canvas.yview_moveto)(self._pos / total)
            if self.on_frame is not None:
                self.on_frame()
            if self._pos == self._target:
                self._target = None
                return
            self._job = self.canvas.after(self.FRAME_MS, self._frame)
        except Exception:
            self._target = None


_timer_period_set = False


def high_resolution_timer() -> None:
    """
    Zegar Windows domyślnie tyka co 15,6 ms – zaplanowane „za 8 ms” wykonuje się po 16 albo 31 ms,
    więc animacje (przewijanie, panel boczny) szarpią. Na czas działania aplikacji prosimy o dokładność 1 ms
    (tak robią przeglądarki podczas animacji); system przywraca ją sam po zamknięciu programu.
    """
    global _timer_period_set
    if _timer_period_set or not sys.platform.startswith("win"):
        return
    try:
        import ctypes
        if ctypes.windll.winmm.timeBeginPeriod(1) == 0:
            _timer_period_set = True
            import atexit
            atexit.register(lambda: ctypes.windll.winmm.timeEndPeriod(1))
    except Exception:
        pass
