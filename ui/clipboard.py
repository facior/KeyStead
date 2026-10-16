"""
Bezpieczny schowek systemowy z funkcją automatycznego czyszczenia po upływie zadanego czasu.

Na Windows 10/11 sekrety są dodatkowo oznaczane formatami, które wykluczają je
z historii schowka (Win+V), synchronizacji schowka w chmurze Microsoft oraz z
monitorów schowka (tak samo robią KeePassXC i 1Password).
"""

import sys
import threading
import time
from typing import Optional, Callable
import pyperclip


def _win_copy_excluded(text: str) -> bool:
    """Kopiuje tekst przez WinAPI z flagami wykluczenia z historii/chmury. Zwraca False przy niepowodzeniu."""
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32.OpenClipboard.argtypes = [wintypes.HWND]
    user32.OpenClipboard.restype = wintypes.BOOL
    user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    user32.SetClipboardData.restype = wintypes.HANDLE
    user32.RegisterClipboardFormatW.argtypes = [wintypes.LPCWSTR]
    user32.RegisterClipboardFormatW.restype = wintypes.UINT
    kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
    kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalFree.argtypes = [wintypes.HGLOBAL]

    GMEM_MOVEABLE = 0x0002
    CF_UNICODETEXT = 13

    def _set(fmt: int, payload: bytes) -> bool:
        handle = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(payload))
        if not handle:
            return False
        ptr = kernel32.GlobalLock(handle)
        if not ptr:
            kernel32.GlobalFree(handle)
            return False
        ctypes.memmove(ptr, payload, len(payload))
        kernel32.GlobalUnlock(handle)
        if not user32.SetClipboardData(fmt, handle):
            kernel32.GlobalFree(handle)  # Własność pamięci przechodzi na system tylko przy sukcesie
            return False
        return True

    # Schowek bywa chwilowo zajęty przez inny proces
    for _ in range(10):
        if user32.OpenClipboard(None):
            break
        time.sleep(0.02)
    else:
        return False

    try:
        user32.EmptyClipboard()
        if not _set(CF_UNICODETEXT, (text + "\0").encode("utf-16-le")):
            return False
        zero_dword = (0).to_bytes(4, "little")
        for name in ("ExcludeClipboardContentFromMonitorProcessing", "CanIncludeInClipboardHistory", "CanUploadToCloudClipboard"):
            fmt = user32.RegisterClipboardFormatW(name)
            if fmt:
                _set(fmt, zero_dword)
        return True
    finally:
        user32.CloseClipboard()


def _copy_secret(text: str) -> None:
    if sys.platform == "win32" and text:
        try:
            if _win_copy_excluded(text):
                return
        except Exception:
            pass
    pyperclip.copy(text)


class SecureClipboard:
    _lock = threading.Lock()
    _active_timer: Optional[threading.Timer] = None
    _last_copied_secret: Optional[str] = None

    @classmethod
    def copy(
        cls,
        text: str,
        timeout_seconds: int = 30,
        on_cleared: Optional[Callable[[], None]] = None
    ) -> None:
        """Kopiuje tekst do schowka i planuje jego wyczyszczenie po timeout_seconds."""
        with cls._lock:
            # Anulowanie poprzedniego timera
            if cls._active_timer:
                cls._active_timer.cancel()
                cls._active_timer = None

            _copy_secret(text)
            cls._last_copied_secret = text

            if timeout_seconds > 0:
                def _clear_worker():
                    with cls._lock:
                        try:
                            # Czyść tylko jeśli w schowku nadal znajduje się to samo hasło
                            current = pyperclip.paste()
                            if current == cls._last_copied_secret:
                                pyperclip.copy("")
                                cls._last_copied_secret = None
                                if on_cleared:
                                    on_cleared()
                        except Exception:
                            pass

                cls._active_timer = threading.Timer(timeout_seconds, _clear_worker)
                cls._active_timer.daemon = True
                cls._active_timer.start()

    @classmethod
    def clear(cls) -> None:
        """Natychmiast usuwa ze schowka sekret skopiowany przez aplikację (cudzej zawartości nie rusza)."""
        with cls._lock:
            if cls._active_timer:
                cls._active_timer.cancel()
                cls._active_timer = None
            if cls._last_copied_secret is None:
                return
            try:
                if pyperclip.paste() == cls._last_copied_secret:
                    pyperclip.copy("")
            except Exception:
                pass
            cls._last_copied_secret = None
