"""Wspólne dla testów interfejsu: czy jest ekran, na którym można tworzyć okna Tk."""

import os
import sys


def has_display() -> bool:
    """
    Bez tworzenia próbnego okna: na macOS (Tk 9) okno zamknięte, zanim się narysowało, wywracało następne
    okno w tym samym procesie. Windows i macOS mają ekran zawsze, Linux – gdy działa X11 lub Wayland.
    """
    try:
        import customtkinter  # noqa: F401
    except Exception:
        return False
    if sys.platform.startswith("linux"):
        return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    return True


def require_screen_width(test, root, width: int = 1300) -> None:
    """Pomija test układu, gdy ekran jest węższy niż okno testu (np. maszyna macOS w GitHub Actions: 1024 px)."""
    if root.winfo_screenwidth() < width:
        test.skipTest(f"ekran {root.winfo_screenwidth()} px – układ okna sprawdzany od {width} px")
