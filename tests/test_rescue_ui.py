"""
Centrum ratunkowe w prawdziwym oknie (poza ekranem): mapa domina, kreator z odhaczaniem i zmiana hasła,
okno opcji karty awaryjnej.
"""

import os
import shutil
import tempfile
import time
import unittest
from unittest import mock

from core import rescue
from core.storage import background_saver, save_vault
from core.vault import Vault
from tests.test_rescue import home_vault

try:
    import customtkinter as ctk
    _probe = ctk.CTk()
    _probe.destroy()
    HAS_DISPLAY = True
except Exception:
    HAS_DISPLAY = False

PASSWORD = "haslo-testowe-123"
OFFSCREEN = "+-4000+-4000"


def find(widget, cls):
    out = [widget] if isinstance(widget, cls) else []
    for child in widget.winfo_children():
        out += find(child, cls)
    return out


def texts(widget):
    out = []
    for w in find(widget, object):
        try:
            out.append(str(w.cget("text")))
        except Exception:
            pass
    return out


@unittest.skipUnless(HAS_DISPLAY, "brak środowiska graficznego")
class RescueUiTests(unittest.TestCase):
    def setUp(self):
        from ui.main_view import MainView
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "v.vault")
        self.vault = Vault("Dom")
        self.entries = home_vault()
        for e in self.entries:
            self.vault.add_entry(e)
        save_vault(self.vault, self.path, PASSWORD)
        self.copied = []
        self.opened = []
        for p in (mock.patch("ui.clipboard.SecureClipboard.copy",
                             side_effect=lambda text, timeout_seconds=0: self.copied.append(text)),
                  mock.patch("webbrowser.open", side_effect=self.opened.append)):
            p.start()
            self.addCleanup(p.stop)
        self.root = ctk.CTk()
        self.root.geometry("1300x850" + OFFSCREEN)
        self.view = MainView(self.root, self.vault, PASSWORD, self.path)
        self.view.pack(fill="both", expand=True)
        self.pump(0.3)

    def tearDown(self):
        background_saver.flush()
        self.root.destroy()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def pump(self, seconds=0.0):
        end = time.perf_counter() + seconds
        while True:
            self.root.update()
            if time.perf_counter() >= end:
                break
            time.sleep(0.01)

    def open_center(self, entry_id=None):
        from ui.rescue_view import RescueDrawerView
        self.view._open_rescue_dialog(entry_id)
        self.pump(0.8)
        return find(self.root, RescueDrawerView)[0]

    def test_toolbar_button_and_domino_map(self):
        self.assertIn("🚨 Ratunek", texts(self.view.actions_box))
        rv = self.open_center()
        shown = texts(rv)
        self.assertIn("📧 jan@gmail.com", shown)
        self.assertIn("Od tej skrzynki zależy 4 konta", shown)
        self.assertIn("  PILNE  ", shown)
        self.assertTrue(any("Brak weryfikacji dwuetapowej" in t for t in shown))
        self.assertTrue(any("1 wpis ma login" in t for t in shown))  # „Forum” z loginem bez e-maila

    def test_takeover_wizard_progress_and_password(self):
        gmail = self.entries[0]
        old = gmail.password
        rv = self.open_center(gmail.id)
        shown = texts(rv)
        self.assertIn("Zrobione: 0 z 8", shown)
        self.assertTrue(any("To skrzynka e-mail" in t for t in shown))
        # „Wygeneruj i skopiuj” → hasło w schowku → „Zapisz we wpisie” → stare w historii, krok odhaczony
        gen = next(b for b in find(rv, ctk.CTkButton) if b.cget("text") == "⚡ Wygeneruj i skopiuj nowe hasło")
        gen.invoke()
        new = self.copied[-1]
        self.assertEqual(len(new), 20)
        save = next(b for b in find(rv, ctk.CTkButton) if b.cget("text") == "💾 Zapisz nowe hasło we wpisie")
        save.invoke()
        self.pump(0.2)
        self.assertEqual(gmail.password, new)
        self.assertEqual(gmail.password_history[-1]["password"], old)
        self.assertEqual(rescue.progress(self.vault.settings, gmail.id)["done"], ["password"])
        self.assertIn("Zrobione: 1 z 8", texts(rv))
        # zależne konto odhaczone i link do zmiany hasła
        mbank = next(e for e in self.entries if e.title == "mBank")
        box = next(c for c in find(rv, ctk.CTkCheckBox) if c.cget("text") == "mBank  (bank)")
        box.toggle()
        self.assertIn(mbank.id, rescue.progress(self.vault.settings, gmail.id)["entries_done"])
        link = next(b for b in find(rv, ctk.CTkButton) if b.cget("text") == "Zgłoś do CERT Polska ↗")
        link.invoke()
        self.assertEqual(self.opened, [rescue.CERT_URL])
        background_saver.flush()

    def test_picker_and_from_domino(self):
        rv = self.open_center()
        button = next(b for b in find(rv, ctk.CTkButton) if b.cget("text") == "🚨 Co jeśli ją przejmą?")
        button.invoke()
        self.pump(0.3)
        self.assertEqual(rv.tabs.get(), "🚨 Ktoś przejął konto")
        self.assertIn("Zmień hasła w kontach zależnych od tej skrzynki (4)", [t.split("6. ")[-1] for t in texts(rv)])

    def test_emergency_card_dialog_options(self):
        from ui.recovery_ui import EmergencyCardDialog
        d = EmergencyCardDialog(self.root, has_recovery=False)
        d.geometry(OFFSCREEN)
        self.pump(0.2)
        self.assertTrue(d.new_code.get())
        d.password_box.set(False)
        d._ok()
        self.assertEqual(d.result, {"new_code": True, "password_box": False})


if __name__ == "__main__":
    unittest.main()
