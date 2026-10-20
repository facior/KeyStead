"""
Drobne funkcje zależne od systemu (Windows / macOS / Linux): otwieranie plików domyślnym programem,
pokazywanie pliku w menedżerze plików, czcionki interfejsu.
"""

import os
import subprocess
import sys

IS_WINDOWS = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")


def open_path(path: str) -> None:
    """Otwiera plik lub folder domyślnym programem systemu. OSError, gdy się nie da."""
    if IS_WINDOWS:
        os.startfile(path)
        return
    tool = "open" if IS_MAC else "xdg-open"
    try:
        subprocess.Popen([tool, path], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True)
    except FileNotFoundError as e:
        raise OSError(e.errno, f"{tool}: {e.strerror}") from e


def ui_font_family() -> str:
    if IS_WINDOWS:
        return "Segoe UI"
    if IS_MAC:
        return "Helvetica Neue"
    return "DejaVu Sans"


def mono_font_family() -> str:
    if IS_WINDOWS:
        return "Consolas"
    if IS_MAC:
        return "Menlo"
    return "DejaVu Sans Mono"


def primary_modifier() -> str:
    """Nazwa klawisza skrótów w zdarzeniach Tk: Command na Macu, Control gdzie indziej."""
    return "Command" if IS_MAC else "Control"
