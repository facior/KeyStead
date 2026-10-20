"""
Tłumaczenia interfejsu aplikacji.

Teksty w kodzie są po polsku (język źródłowy) i jednocześnie są kluczami tłumaczeń:

    _("Zapisz")                                   → "Save"
    _("Login „{title}” skopiowany", title=t)      → "Username for “GitHub” copied"
    _n(n, "{n} wpis", "{n} wpisy", "{n} wpisów")  → "1 entry" / "5 entries"
    N_("Loginy")                                  – tylko oznacza tekst do tłumaczenia (tłumaczony przy wyświetleniu)

Tłumaczenia leżą w core/locales/<język>/*.json jako {"tekst polski": "tłumaczenie"}; dla _n wartością jest lista
[liczba pojedyncza, liczba mnoga]. Brak tłumaczenia → tekst polski, więc nic nie znika z ekranu.

Język wybiera użytkownik (Ustawienia lub ekran logowania), domyślnie język Windows. Wybór obowiązuje od
następnego uruchomienia – teksty stałych w modułach są tłumaczone przy ich wczytaniu.
"""

import glob
import json
import os
import sys
from typing import Dict, Optional, Union

from core.paths import APP_DIR

SOURCE_LANGUAGE = "pl"
LANGUAGES = {"pl": "Polski", "en": "English"}
LOCALES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "locales")
PREFS_FILE = os.path.join(APP_DIR, "language.json")

_language: Optional[str] = None
_catalog: Dict[str, Union[str, list]] = {}


def system_language() -> str:
    """Język systemu: polski → 'pl', każdy inny → 'en'."""
    if sys.platform == "win32":
        try:
            import ctypes
            return "pl" if ctypes.windll.kernel32.GetUserDefaultUILanguage() & 0x3FF == 0x15 else "en"
        except Exception:
            pass
    if sys.platform == "darwin":
        # Program uruchomiony z Findera nie dostaje zmiennej LANG – język interfejsu macOS jest w ustawieniach
        try:
            import subprocess
            out = subprocess.run(["defaults", "read", "-g", "AppleLanguages"], capture_output=True, text=True,
                                 timeout=3).stdout
            first = out.replace("(", "").replace('"', "").strip().split(",")[0].strip().lower()
            if first:
                return "pl" if first.startswith("pl") else "en"
        except Exception:
            pass
    for var in ("LC_ALL", "LC_MESSAGES", "LANG"):
        lang = (os.environ.get(var) or "").lower()
        if lang:
            return "pl" if lang.startswith("pl") else "en"
    return "en"


def saved_language() -> Optional[str]:
    try:
        with open(PREFS_FILE, encoding="utf-8") as f:
            lang = json.load(f).get("language")
        return lang if lang in LANGUAGES else None
    except (OSError, ValueError, AttributeError):
        return None


def save_language(lang: str) -> None:
    """Zapisuje wybór języka (obowiązuje od następnego uruchomienia)."""
    if lang not in LANGUAGES:
        raise ValueError(f"Nieznany język: {lang}")
    os.makedirs(APP_DIR, exist_ok=True)
    with open(PREFS_FILE, "w", encoding="utf-8") as f:
        json.dump({"language": lang}, f)


def load_catalog(lang: str, directory: str = LOCALES_DIR) -> Dict[str, Union[str, list]]:
    catalog: Dict[str, Union[str, list]] = {}
    for path in sorted(glob.glob(os.path.join(directory, lang, "*.json"))):
        with open(path, encoding="utf-8") as f:
            catalog.update(json.load(f))
    return catalog


def set_language(lang: str) -> None:
    """Aktywny język bieżącego procesu (wywoływane przy starcie i w testach)."""
    global _language, _catalog
    _language = lang if lang in LANGUAGES else SOURCE_LANGUAGE
    _catalog = load_catalog(_language) if _language != SOURCE_LANGUAGE else {}


def current_language() -> str:
    if _language is None:
        set_language(saved_language() or system_language())
    return _language


def _format(text: str, source: str, kw) -> str:
    if not kw:
        return text
    try:
        return text.format(**kw)
    except (KeyError, IndexError, ValueError):
        return source.format(**kw)  # błędne tłumaczenie nie może zepsuć okna


def _(text: str, /, **kw) -> str:
    if current_language() == SOURCE_LANGUAGE:
        return _format(text, text, kw)
    value = _catalog.get(text)
    return _format(value if isinstance(value, str) else text, text, kw)


def _n(n: int, one: str, few: str, many: str, /, **kw) -> str:
    """Liczba mnoga: polski ma trzy formy (1 wpis, 2 wpisy, 5 wpisów), angielski dwie. Kluczem jest forma `many`."""
    kw = {"n": n, **kw}
    if current_language() == SOURCE_LANGUAGE:
        return _format(polish_plural(n, one, few, many), many, kw)
    value = _catalog.get(many)
    if isinstance(value, list) and len(value) == 2:
        return _format(value[0] if n == 1 else value[1], many, kw)
    return _format(polish_plural(n, one, few, many), many, kw)


def polish_plural(n: int, one: str, few: str, many: str) -> str:
    n = abs(int(n))
    if n == 1:
        return one
    if n % 10 in (2, 3, 4) and n % 100 not in (12, 13, 14):
        return few
    return many


def N_(text: str) -> str:
    """Oznacza tekst do tłumaczenia bez tłumaczenia go teraz (np. wartości zapisywane w sejfie)."""
    return text
