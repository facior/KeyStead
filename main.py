"""
Główny punkt wejściowy aplikacji KeyStead Manager.

    KeyStead Manager.exe --selftest wynik.json   – diagnostyka (wersja, moduły, Windows Hello) bez okna
    (macOS: "KeyStead Manager.app/Contents/MacOS/KeyStead Manager" --selftest wynik.json)
"""

import sys
import os

# Zapewnienie poprawnej ścieżki do modułów
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# Przed czymkolwiek innym: nowsza biblioteka C++ niż stara kopia z pakietu Windows Hello (patrz core/runtime_dlls.py)
from core.runtime_dlls import preload_cpp_runtime  # noqa: E402
preload_cpp_runtime()


def selftest(out_path: str) -> int:
    """Diagnostyka zbudowanego programu (bez otwierania okna i bez dostępu do sejfu)."""
    import json
    from core.version import APP_VERSION
    result = {"version": APP_VERSION, "frozen": bool(getattr(sys, "frozen", False)), "modules": {}}
    modules = ["customtkinter", "cryptography", "bcrypt", "argon2", "importers.kdbx", "core.quick_unlock",
               "ui.quick_access", "zxingcpp", "ui.plugin_dialogs", "ui.plugins_view", "core.ssh_agent", "ykman.hid",
               "yubikit.yubiotp"]
    if sys.platform == "win32":
        modules += ["winrt.windows.security.credentials", "winrt.windows.security.cryptography"]
    else:
        modules += ["keyring"]
    for name in modules:
        try:
            __import__(name)
            result["modules"][name] = "ok"
        except Exception as e:
            result["modules"][name] = f"{type(e).__name__}: {e}"
    if sys.platform == "win32":
        try:
            from core.quick_unlock import WindowsHelloProvider
            result["windows_hello_available"] = WindowsHelloProvider().is_available()
        except Exception as e:
            result["windows_hello_available"] = f"{type(e).__name__}: {e}"
    result["platform"] = sys.platform
    try:
        from core.i18n import load_catalog
        result["translations_en"] = len(load_catalog("en"))  # pliki core/locales trafiły do programu
    except Exception as e:
        result["translations_en"] = f"{type(e).__name__}: {e}"
    try:
        from core import qr
        result["qr_round_trip"] = qr.read_codes(qr.make_image("keystead")) == ["keystead"]  # wtyczki z kodami QR
    except Exception as e:
        result["qr_round_trip"] = f"{type(e).__name__}: {e}"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    ok = isinstance(result["translations_en"], int) and result["translations_en"] > 0 and result["qr_round_trip"] is True
    return 0 if ok and all(v == "ok" for v in result["modules"].values()) else 1


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
