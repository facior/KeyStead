"""Testy działają zawsze w języku źródłowym (polskim) – niezależnie od języka Windows i wyboru w programie."""

from core import i18n
from core.runtime_dlls import preload_cpp_runtime

preload_cpp_runtime()  # jak w main.py – przed Windows Hello (winrt), inaczej kody QR wywracają proces

i18n.set_language("pl")
