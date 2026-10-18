"""
Biblioteka C++ Microsoftu (msvcp140.dll) – wczytywana na starcie, ZANIM zrobi to Windows Hello.

Pakiet winrt (Windows Hello) ma własną, starą kopię msvcp140.dll (14.29). Jeśli wczyta się pierwsza, każdy inny
moduł używa już jej – a zxing-cpp (kody QR we wtyczkach) wymaga wersji 14.40 lub nowszej i kończy się wtedy
błędem ochrony pamięci. Nowsza wersja jest zgodna wstecz, więc wczytujemy najnowszą dostępną jako pierwszą:
kopię dołączoną do programu (tools/release_app.py → vcrt/), a w wersji deweloperskiej – systemową.
"""

import ctypes
import os
import sys

_loaded = None


def _file_version(path: str):
    try:
        size = ctypes.windll.version.GetFileVersionInfoSizeW(path, None)
        if not size:
            return None
        buf = ctypes.create_string_buffer(size)
        if not ctypes.windll.version.GetFileVersionInfoW(path, 0, size, buf):
            return None
        info = ctypes.c_void_p()
        length = ctypes.c_uint()
        if not ctypes.windll.version.VerQueryValueW(buf, "\\", ctypes.byref(info), ctypes.byref(length)):
            return None
        ms, ls = ctypes.cast(info, ctypes.POINTER(ctypes.c_uint32 * 4)).contents[2:4]
        return ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF
    except Exception:
        return None


def candidates():
    paths = []
    base = getattr(sys, "_MEIPASS", None)
    if base:
        paths.append(os.path.join(base, "vcrt", "msvcp140.dll"))
    paths.append(os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "msvcp140.dll"))
    return [p for p in paths if os.path.isfile(p)]


def preload_cpp_runtime():
    """Wczytuje najnowszą dostępną msvcp140.dll. Zwraca jej ścieżkę albo None (np. poza Windows)."""
    global _loaded
    if _loaded is not None or os.name != "nt":
        return _loaded
    found = sorted(((_file_version(p) or (0,), p) for p in candidates()), reverse=True)
    for _version, path in found:
        try:
            ctypes.WinDLL(path)
            _loaded = path
            break
        except OSError:
            continue
    return _loaded
