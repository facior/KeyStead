"""
Główny punkt wejściowy aplikacji KeyStead Manager.

    KeyStead Manager.exe --selftest wynik.json   – diagnostyka (wersja, moduły, Windows Hello) bez okna
"""

import sys
import os

# Zapewnienie poprawnej ścieżki do modułów
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


def selftest(out_path: str) -> int:
    """Diagnostyka zbudowanego programu (bez otwierania okna i bez dostępu do sejfu)."""
    import json
    from core.version import APP_VERSION
    result = {"version": APP_VERSION, "frozen": bool(getattr(sys, "frozen", False)), "modules": {}}
    for name in ("customtkinter", "cryptography", "argon2", "pykeepass", "winrt.windows.security.credentials",
                 "winrt.windows.security.cryptography", "core.quick_unlock", "ui.quick_access"):
        try:
            __import__(name)
            result["modules"][name] = "ok"
        except Exception as e:
            result["modules"][name] = f"{type(e).__name__}: {e}"
    try:
        from core.quick_unlock import WindowsHelloProvider
        result["windows_hello_available"] = WindowsHelloProvider().is_available()
    except Exception as e:
        result["windows_hello_available"] = f"{type(e).__name__}: {e}"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    return 0 if all(v == "ok" for v in result["modules"].values()) else 1


def main():
    if len(sys.argv) >= 3 and sys.argv[1] == "--selftest":
        sys.exit(selftest(sys.argv[2]))

    from core.paths import migrate_legacy_files
    # Przeniesienie ustawień z poprzedniej nazwy aplikacji – przed wczytaniem interfejsu
    migrate_legacy_files()

    from ui.app import PasswordManagerApp
    app = PasswordManagerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
