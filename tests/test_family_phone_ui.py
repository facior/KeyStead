"""
Okna „Domownicy”, „Udostępnij” i „Hasło na telefon” w prawdziwym interfejsie (poza ekranem; schowek podmieniony,
serwer telefonu tylko na 127.0.0.1).
"""

import os
import queue
import shutil
import tempfile
import time
import unittest
import urllib.request
from unittest import mock

from core import family_share as fs
from core import phone_handoff as ph
from core import plugins
from core.storage import background_saver, save_vault
from core.vault import Vault, VaultEntry

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
class FamilyPhoneUiTests(unittest.TestCase):
    def setUp(self):
        from ui import plugin_dialogs
        from ui.main_view import MainView
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "v.vault")
        self.vault = Vault("Dom")
        self.entry = VaultEntry("Netflix", username="dom@gmail.com", password="Nf!2026", url="netflix.com")
        self.vault.add_entry(self.entry)
        plugins.set_choices(self.vault.settings, {"family_share": True, "phone_handoff": True})
        save_vault(self.vault, self.path, PASSWORD)
        self.copied, self.clipboard = [], {"text": ""}
        patches = [
            mock.patch("ui.clipboard.SecureClipboard.copy",
                       side_effect=lambda text, timeout_seconds=0: self.copied.append(text)),
            mock.patch("ui.family_view._clipboard_text", side_effect=lambda w: self.clipboard["text"]),
            mock.patch.object(plugin_dialogs._Dialog, "center_on",
                              lambda self, master: ctk.CTkToplevel.geometry(self, OFFSCREEN)),
            mock.patch.object(ph, "lan_ip", return_value="127.0.0.1"),   # bez nasłuchu w sieci – bez pytania zapory
            mock.patch("tkinter.messagebox.askyesno", return_value=True),
            mock.patch("tkinter.messagebox.showinfo"), mock.patch("tkinter.messagebox.showerror"),
        ]
        for p in patches:
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

    def family_view(self):
        from ui.family_view import FamilyDrawerView
        self.view._open_family_dialog()
        self.pump(0.8)
        return find(self.root, FamilyDrawerView)[0]

    def test_buttons_visible(self):
        self.assertTrue(self.view.family_btn.winfo_ismapped())
        self.view._select_entry(self.entry.id)
        self.pump(0.2)
        shown = texts(self.view.details_scroll)
        self.assertIn("👪 Udostępnij", shown)
        self.assertIn("📱 Telefon", shown)

    def test_card_contact_send_and_receive(self):
        # Anna (inny sejf) daje wizytówkę → dodajemy ją → wysyłamy wpis → Anna odbiera
        anna = Vault("Anna")
        self.clipboard["text"] = fs.my_card(anna.settings, "Anna")
        fv = self.family_view()
        fv._add_contact("clipboard")
        self.assertEqual([c.name for c in fs.contacts(self.vault.settings)], ["Anna"])
        self.assertIn("👪 Domownicy (1)", texts(fv))
        my_card = fv._my_card()
        self.assertTrue(my_card.startswith(fs.CONTACT_PREFIX))

        from ui.family_view import SendShareDialog
        d = SendShareDialog(self.view, self.vault, self.entry, "Łukasz", copy_text=self.view._copy_share_text,
                            on_sent=lambda: None)
        d._send("copy")
        package = self.copied[-1]
        fs.add_contact(anna.settings, fs.parse_card(my_card))
        got = fs.open_package(anna.settings, package)
        # Anna widzi nadawcę pod nazwą z wizytówki (tu: domyślnie nazwa sejfu), a nie pod deklaracją z paczki
        self.assertEqual((got.known_sender.name, got.payload["password"]), ("Dom", "Nf!2026"))
        self.assertIn("Wysłano już wcześniej", d.hint.cget("text"))
        d.destroy()

        # Odbiór paczki od Anny w tym sejfie
        anna_entry = VaultEntry("Wi-Fi", password="siec-123")
        me = fs.contacts(anna.settings)[0]
        self.clipboard["text"] = fs.seal_package(anna.settings, "Anna", me, fs.entry_payload(anna_entry), "s1")
        fv._receive("clipboard")
        self.pump(0.5)
        added = [e for e in self.vault.entries.values() if e.title == "Wi-Fi"]
        self.assertEqual(len(added), 1)
        self.assertEqual(self.view.selected_entry_id, added[0].id)

    def test_password_change_reminds_to_resend(self):
        fs.add_contact(self.vault.settings, fs.parse_card(fs.my_card(Vault("Anna").settings, "Anna")))
        fs.remember_sent(self.vault.settings, self.entry.id, fs.contacts(self.vault.settings)[0], "s1")
        toasts = []
        with mock.patch.object(self.view, "show_toast", side_effect=lambda m, error=False: toasts.append(m)):
            self.view._open_edit_entry_dialog(self.entry)
            self.pump(0.8)
            from ui.drawer_views import EntryDrawerView
            form = find(self.root, EntryDrawerView)[0]
            form.pwd_entry.delete(0, "end")
            form.pwd_entry.insert(0, "Zmienione!2027")
            form._save_entry()
            self.pump(1.0)
        self.assertTrue(any("Anna" in t and "aktualizację" in t for t in toasts), toasts)

    def test_phone_dialog(self):
        from ui.plugin_dialogs import PhoneHandoffDialog
        calls = queue.Queue()
        d = PhoneHandoffDialog(self.view, self.entry, calls.put)
        self.pump(0.2)
        self.assertTrue(d.server.url.startswith("http://127.0.0.1:"))
        self.assertIn("Czekam na telefon", d.status_lbl.cget("text"))
        base = d.server.url.split("#")[0]
        with urllib.request.urlopen(base + "/data", timeout=5) as r:   # „telefon” pobiera szyfrogram
            self.assertEqual(r.status, 200)
        calls.get(timeout=3)()   # serwer zgłasza odbiór tuż po wysłaniu danych (z własnego wątku)
        while not calls.empty():
            calls.get()()
        self.pump(0.1)
        self.assertEqual(d.status_lbl.cget("text"), "✓ Telefon odebrał hasło")
        server = d.server
        d.destroy()
        self.assertIsNone(server._cipher)


if __name__ == "__main__":
    unittest.main()
