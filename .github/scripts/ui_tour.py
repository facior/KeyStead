"""
Przegląd interfejsu w GitHub Actions (macOS / Linux / Windows): ekran logowania, okno główne i panele boczne
jako zrzuty PNG w katalogu podanym w argumencie. Sejf testowy w tymczasowym katalogu domowym.

    python .github/scripts/ui_tour.py zrzuty [pl|en]
"""

import os
import sys
import tempfile
import time
import traceback

OUT = os.path.abspath(sys.argv[1])
LANG = sys.argv[2] if len(sys.argv) > 2 else "pl"
os.makedirs(OUT, exist_ok=True)
home = tempfile.mkdtemp(prefix="ks-home-")
os.environ.update({"HOME": home, "USERPROFILE": home})
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
log = open(os.path.join(OUT, "log.txt"), "w", encoding="utf-8")


def main() -> int:
    from PIL import ImageGrab
    from core import i18n, paths
    assert paths.APP_DIR.startswith(home), paths.APP_DIR
    i18n.set_language(LANG)
    from tkinter import messagebox
    for name in ("showinfo", "showwarning", "showerror"):
        setattr(messagebox, name, lambda *a, **k: log.write(f"MSGBOX {a}\n"))
    for name in ("askyesno", "askokcancel", "askyesnocancel"):
        setattr(messagebox, name, lambda *a, **k: (log.write(f"ASK {a}\n"), False)[1])
    from ui.onboarding_wizard import mark_first_run_completed
    mark_first_run_completed()
    from ui.app import PasswordManagerApp
    from core.storage import save_vault
    from core.vault import Vault, VaultEntry

    app = PasswordManagerApp()
    app.geometry("1280x820+40+40")

    def pump(sec: float) -> None:
        end = time.time() + sec
        while time.time() < end:
            app.update()
            time.sleep(0.01)

    def capture(name: str) -> None:
        app.lift()
        app.attributes("-topmost", True)
        pump(0.6)
        x, y = app.winfo_rootx(), app.winfo_rooty()
        w, h = app.winfo_width(), app.winfo_height()
        shot = ImageGrab.grab()
        # Ekran Retina: zrzut ma więcej pikseli niż punktów Tk
        scale = shot.width / app.winfo_screenwidth()
        shot.crop((int(x * scale), int(y * scale), int((x + w) * scale), int((y + h) * scale))).save(
            os.path.join(OUT, name + ".png"))
        log.write(f"{name}: {w}x{h} at {x},{y} scale {scale:.2f}\n")

    pump(2)
    capture("01_login")

    vault = Vault("Sejf testowy")
    vault.settings["auto_breach_check"] = False
    vault.settings["breach_watch_consent"] = False
    for i, (title, user, url) in enumerate([("GitHub", "jan", "https://github.com"),
                                            ("mBank", "jan.k", "https://mbank.pl"),
                                            ("Router", "admin", "192.168.0.1")]):
        vault.add_entry(VaultEntry(title=title, username=user, password="Tajne-haslo-123!", url=url,
                                   category="Loginy" if i < 2 else "Serwery / Wi-Fi"))
    path = os.path.join(home, "test.vault")
    save_vault(vault, path, "Haslo-glowne-123!")
    app._on_vault_unlocked(vault, "Haslo-glowne-123!", path, None)
    pump(2)
    view = app._current_view
    view._select_entry(next(iter(vault.entries)))
    pump(1)
    capture("02_main")
    for name, opener in [("03_settings", "_open_settings_dialog"), ("04_generator", "_open_generator_dialog"),
                         ("05_audit", "_open_audit_dialog"), ("06_new_entry", "_open_new_entry_dialog")]:
        try:
            getattr(view, opener)()
            pump(2.5)
            capture(name)
        except Exception:
            log.write(f"{name} FAILED\n{traceback.format_exc()}\n")
    app._on_close()
    return 0


if __name__ == "__main__":
    try:
        code = main()
    except Exception:
        log.write(traceback.format_exc())
        code = 1
    log.close()
    sys.exit(code)
