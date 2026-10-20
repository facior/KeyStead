"""
Wtyczki w prawdziwym interfejsie (okna poza ekranem, schowek i uruchamianie programów podmienione):
przycisk „Połącz”, data ważności, kolorowe hasło, kod QR, wybrane znaki, pływający panel, szablony,
kod QR 2FA ze schowka, ekran Ustawienia → Wtyczki i blokada przez firmę.
"""

import functools
import os
import shutil
import uuid
import tempfile
import time
import unittest
from datetime import date, timedelta
from unittest import mock

from core import connect, expiry, plugins, qr, ssh_keys
from core.secure_send import open_sealed as secure_send_open
from core.ssh_agent import AgentService
from core.storage import background_saver, save_vault
from core.vault import Vault, VaultEntry

from tests.gui import has_display

HAS_DISPLAY = has_display()
if HAS_DISPLAY:
    import customtkinter as ctk

PASSWORD = "haslo-testowe-123"
OFFSCREEN = "+-4000+-4000"


def find_widgets(widget, predicate):
    out = []
    for child in widget.winfo_children():
        if predicate(child):
            out.append(child)
        out += find_widgets(child, predicate)
    return out


def texts(widget):
    out = []
    for w in find_widgets(widget, lambda w: True):
        try:
            out.append(str(w.cget("text")))
        except Exception:
            pass
    return out


@unittest.skipUnless(HAS_DISPLAY, "brak środowiska graficznego")
class PluginsUiTests(unittest.TestCase):
    def setUp(self):
        from ui import plugin_dialogs
        from ui.main_view import MainView
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "v.vault")
        self.vault = Vault("Test")
        past = (date.today() - timedelta(days=3)).isoformat()
        self.rdp = VaultEntry("Serwer AD", category="Serwery / Wi-Fi", username="admin", password="Ab1!cd2#",
                              url="rdp://", custom_fields={"Adres IP": "10.0.0.5", expiry.EXPIRY_FIELD: past},
                              favorite=True)
        self.wifi = VaultEntry("Wi-Fi biuro", category="Serwery / Wi-Fi", password="siec-123",
                               custom_fields={"SSID": "Biuro"})
        self.plain = VaultEntry("Poczta", username="jan", password="Haslo123", totp_secret="JBSWY3DPEHPK3PXP")
        for e in (self.rdp, self.wifi, self.plain):
            self.vault.add_entry(e)
        plugins.set_choices(self.vault.settings, {p.id: True for p in plugins.PLUGINS})
        save_vault(self.vault, self.path, PASSWORD)

        self.copied = []
        # Agent SSH pod testowymi nazwami kanałów – prawdziwe „openssh-ssh-agent” i „Pageant” zostają wolne
        self.agent_pipe = rf"\\.\pipe\keystead-ui-{uuid.uuid4().hex[:8]}"
        self.agent_window = f"KeySteadUi{uuid.uuid4().hex[:8]}"
        patches = [
            mock.patch("ui.ssh_agent_ui.AgentService", functools.partial(AgentService, pipe_name=self.agent_pipe,
                                                                         pageant_class=self.agent_window)),
            mock.patch("ui.clipboard.SecureClipboard.copy", side_effect=lambda text, timeout_seconds=0:
                       self.copied.append(text)),
            mock.patch.object(plugin_dialogs._Dialog, "center_on",
                              lambda self, master: ctk.CTkToplevel.geometry(self, OFFSCREEN)),
            mock.patch.object(plugin_dialogs.FloatingPanel, "geometry",
                              lambda self, g=None: ctk.CTkToplevel.geometry(self, OFFSCREEN)),
            mock.patch("tkinter.messagebox.showinfo"), mock.patch("tkinter.messagebox.showwarning"),
            mock.patch("tkinter.messagebox.showerror"),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

        self.root = ctk.CTk()
        self.root.geometry("1300x850" + OFFSCREEN)
        self.view = MainView(self.root, self.vault, PASSWORD, self.path)
        self.view.pack(fill="both", expand=True)
        self.pump()

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

    def details_texts(self):
        """Teksty widocznego panelu szczegółów (bez ukrytych paneli z pamięci podręcznej)."""
        return [self._text(w) for w in find_widgets(self.view.details_scroll, lambda w: w.winfo_ismapped())
                if self._text(w) is not None]

    def visible(self, widget):
        return bool(widget.winfo_manager())

    def button(self, parent, text):
        found = [w for w in find_widgets(parent, lambda w: True)
                 if getattr(w, "cget", None) and self._text(w) == text and w.winfo_ismapped()]
        self.assertTrue(found, f"brak przycisku {text!r}")
        return found[0]

    @staticmethod
    def _text(w):
        try:
            return str(w.cget("text"))
        except Exception:
            return None

    def click(self, flat_button):
        flat_button.event_generate("<Button-1>")
        flat_button.event_generate("<ButtonRelease-1>")
        self.pump()

    def test_connect_button_launches_rdp(self):
        self.view._select_entry(self.rdp.id)
        self.pump()
        btn = self.button(self.view.details_scroll, "🖥️ Połącz")
        with mock.patch.object(connect, "find_program", side_effect=lambda name, _p=None: f"C:\\fake\\{name}.exe"), \
                mock.patch.object(connect, "launch", return_value=[]) as launch:
            self.view._connect(self.view._details_entry)  # to samo, co kliknięcie przycisku
            self.click(btn)
        plan = launch.call_args_list[0].args[0]
        self.assertEqual(plan.argv, ["C:\\fake\\mstsc.exe", "/v:10.0.0.5"])
        self.assertEqual(plan.rdp_credential["username"], "admin")
        self.assertEqual(launch.call_count, 2)

    def test_expiry_filter_badge_and_label(self):
        names = [b.cget("text") for (_kind, name), b in self.view._sidebar_buttons.items() if name == "⏰ Do zmiany"]
        self.assertEqual(names, ["⏰  Do zmiany (1)"])
        self.view._select_category("⏰ Do zmiany")
        self.pump()
        self.assertEqual([i["title"] for i in self.view.entry_list.items], ["⏰ Serwer AD ⭐"])
        self.view._select_entry(self.rdp.id)
        self.pump()
        self.assertTrue(any("Hasło wygasło 3 dni temu" in t for t in self.details_texts()))

    def test_colored_password(self):
        self.view._select_entry(self.plain.id)
        self.pump()
        self.view._toggle_details_password(self.plain.password)
        self.pump()
        txt = self.view.pwd_color_txt
        self.assertTrue(txt.winfo_ismapped())
        self.assertFalse(self.view.pwd_display_lbl.winfo_ismapped())
        self.assertEqual(txt.get("1.0", "end-1c"), "Haslo123")
        self.assertEqual([str(r) for r in txt.tag_ranges("digit")][:2], ["1.5", "1.8"])
        self.view._toggle_details_password(self.plain.password)
        self.pump()
        self.assertFalse(txt.winfo_ismapped())
        self.assertEqual(self.view.pwd_display_lbl.cget("text"), "•" * 8)

    def test_qr_dialog_wifi_and_password(self):
        from ui.plugin_dialogs import QrDialog
        self.view._select_entry(self.wifi.id)
        self.pump()
        self.view._show_password_qr(self.view._details_entry)
        self.pump()
        dialogs = find_widgets(self.root, lambda w: isinstance(w, QrDialog))
        self.assertEqual(len(dialogs), 1)
        d = dialogs[0]
        img = d._image.cget("light_image")
        self.assertEqual(qr.read_codes(img), ["WIFI:T:WPA;S:Biuro;P:siec-123;;"])
        d._show("Samo hasło")
        self.assertEqual(qr.read_codes(d._image.cget("light_image")), ["siec-123"])
        d._remaining = 0
        d._tick()
        self.assertFalse(d.winfo_exists())

    def test_pick_chars(self):
        from ui.plugin_dialogs import PickCharsDialog
        d = PickCharsDialog(self.view, self.plain, on_copy=self.view._copy_to_clipboard)
        self.pump()
        d.numbers_entry.insert(0, "1, 5;8 99")
        d._typed()
        self.assertEqual(d.selected, [0, 4, 7])
        self.assertEqual(d.result_lbl.cget("text"), "H  o  3")
        d._toggle(4)
        d._copy()
        self.assertEqual(self.copied[-1], "H3")
        d.destroy()

    def test_floating_panel(self):
        self.assertTrue(self.view.floating_btn.winfo_ismapped())
        self.view._toggle_floating_panel()
        self.pump()
        panel = self.view._floating_panel
        self.assertEqual(texts(panel.list_frame).count("Serwer AD"), 1)  # tylko ulubione
        panel.search.insert(0, "poczta")
        panel.refresh()
        self.assertIn("Poczta", texts(panel.list_frame))
        panel._copy_field(self.plain.id, "password")
        self.assertEqual(self.copied[-1], "Haslo123")
        self.assertIn("Hasło skopiowane", panel.info_lbl.cget("text"))
        self.view.destroy()  # blokada sejfu zamyka panel
        self.assertFalse(panel.winfo_exists())

    def test_company_policy_hides_blocked_plugins(self):
        self.view._select_entry(self.rdp.id)
        self.pump()
        self.view.policy = {"blocked_plugins": ["connect", "floating_panel", "expiry"]}
        self.view.apply_plugins()
        self.pump()
        self.assertNotIn("🖥️ Połącz", self.details_texts())
        self.assertFalse(self.view.floating_btn.winfo_ismapped())
        self.assertNotIn(("cat", "⏰ Do zmiany"), self.view._sidebar_buttons)
        self.assertEqual([i["title"] for i in self.view.entry_list.items if i["title"].startswith("⏰")], [])

    def test_disabled_plugins_change_nothing(self):
        plugins.set_choices(self.vault.settings, {p.id: False for p in plugins.PLUGINS})
        self.view.apply_plugins()
        self.view._select_entry(self.rdp.id)
        self.pump()
        shown = self.details_texts()
        for text in ("🖥️ Połącz", "🔳 QR", "🔢 Znaki"):
            self.assertNotIn(text, shown)
        self.assertIsNone(self.view.pwd_color_txt)
        self.assertIn("Hasło ważne do:", shown)  # bez wtyczki data to zwykłe pole niestandardowe

    def test_entry_form_template_expiry_and_qr(self):
        from PIL import Image
        from ui.drawer_views import EntryDrawerView
        frame = ctk.CTkFrame(self.root)
        saved = []
        form = EntryDrawerView(frame, categories=self.vault.categories, on_save=saved.append,
                               settings=self.vault.settings, plugin_on=self.view.plugin_on)
        label = next(k for k, t in form._templates.items() if t.id == "ssh_server")
        form._apply_template(label)
        self.assertEqual(form.url_entry.get(), "ssh://")
        self.assertEqual([w["key"].get() for w in form._custom_field_widgets], ["Adres IP", "System"])

        uri = "otpauth://totp/Firma:jan@firma.pl?secret=JBSWY3DPEHPK3PXP&issuer=Firma"
        shot = Image.new("RGB", (700, 500), "white")
        shot.paste(qr.make_image(uri, scale=4).convert("RGB"), (200, 100))
        with mock.patch("PIL.ImageGrab.grabclipboard", return_value=shot):
            form._read_qr("clipboard")
        self.assertEqual(form.totp_entry.get(), uri)
        self.assertEqual((form.title_entry.get(), form.user_entry.get()), ("Firma", "jan@firma.pl"))

        form.expiry_entry.insert(0, "31.02.2027")
        form._save_entry()
        self.assertEqual(saved, [])  # błędna data – nic nie zapisano
        form._set_expiry_in(90)
        form._save_entry()
        entry = saved[0]
        self.assertEqual(entry.totp_secret, "JBSWY3DPEHPK3PXP")
        self.assertEqual(expiry.get_expiry(entry), date.today() + timedelta(days=90))
        self.assertEqual(entry.custom_fields["System"], "Ubuntu")

        # Edycja: data ważności w osobnym polu, nie jako zwykłe pole niestandardowe
        edit = EntryDrawerView(frame, categories=self.vault.categories, entry=entry, on_save=saved.append,
                               settings=self.vault.settings, plugin_on=self.view.plugin_on)
        self.assertNotIn(expiry.EXPIRY_FIELD, [w["key"].get() for w in edit._custom_field_widgets])
        self.assertEqual(edit.expiry_entry.get(), entry.custom_fields[expiry.EXPIRY_FIELD])
        edit.expiry_entry.delete(0, "end")
        edit._save_entry()
        self.assertNotIn(expiry.EXPIRY_FIELD, entry.custom_fields)

    def wait_for(self, condition, seconds=10.0):
        end = time.perf_counter() + seconds
        while time.perf_counter() < end:
            self.root.update()
            if condition():
                return True
            time.sleep(0.02)
        return False

    @unittest.skipUnless(os.name == "nt", "agent SSH poza Windows – etap 3 przenoszenia na macOS i Linuksa")
    def test_ssh_key_card_and_agent_lifecycle(self):
        from core.ssh_agent import pageant_request
        key_text = ssh_keys.generate_ed25519("admin@srv")
        self.rdp.custom_fields[ssh_keys.KEY_FIELD] = key_text
        self.view._save_vault_to_disk()
        self.assertTrue(self.wait_for(lambda: self.view.ssh_agent.key_for(self.rdp.id) is not None))
        key = self.view.ssh_agent.key_for(self.rdp.id)
        self.view._select_entry(self.rdp.id)
        self.pump()
        shown = self.details_texts()
        self.assertTrue(any(key.fingerprint() in t for t in shown))
        self.assertNotIn(f"{ssh_keys.KEY_FIELD}:", shown)  # tekst klucza nie jest pokazywany jako zwykłe pole
        self.view._copy_ssh_public_key(self.rdp)
        self.assertEqual(self.copied[-1], key.public_line())
        self.assertEqual(self.view.ssh_agent.status(), {"openssh": "running", "pageant": "running"})
        self.assertEqual(pageant_request(bytes([11]), self.agent_window)[0], 12)

        # Wyłączenie wtyczki, a potem blokada sejfu: agent przestaje odpowiadać
        plugins.set_choices(self.vault.settings, {"ssh_agent": False})
        self.view.apply_plugins()
        self.assertIsNone(pageant_request(bytes([11]), self.agent_window))
        plugins.set_choices(self.vault.settings, {"ssh_agent": True})
        self.view.apply_plugins()
        self.assertEqual(pageant_request(bytes([11]), self.agent_window)[0], 12)
        self.view.destroy()
        self.assertIsNone(pageant_request(bytes([11]), self.agent_window))

    def test_ssh_agent_asks_for_consent(self):
        import queue
        import threading
        calls = queue.Queue()
        self.root.post_to_ui = calls.put  # jak w aplikacji: wątek agenta → kolejka wątku interfejsu
        self.view.ssh_agent.sync()
        key = ssh_keys.load_key(ssh_keys.generate_ed25519("x"))
        key.entry_title = "Serwer AD"
        controller = self.view.ssh_agent

        def ask(answer):
            result = {}
            worker = threading.Thread(target=lambda: result.setdefault("ok", controller._on_use(key, "ssh.exe")))
            with mock.patch("tkinter.messagebox.askyesno", return_value=answer) as box:
                worker.start()
                while worker.is_alive():
                    try:
                        calls.get(timeout=0.05)()
                    except queue.Empty:
                        pass
                    self.root.update()
            return result["ok"], box

        plugins.set_options(self.vault.settings, "ssh_agent", {"confirm": False})
        ok, box = ask(False)
        self.assertTrue(ok)               # bez opcji: tylko powiadomienie
        box.assert_not_called()
        plugins.set_options(self.vault.settings, "ssh_agent", {"confirm": True})
        ok, box = ask(False)
        self.assertFalse(ok)
        self.assertIn("ssh.exe", box.call_args.args[1])
        ok, _box = ask(True)
        self.assertTrue(ok)

    def test_secure_send_dialog(self):
        from ui.plugin_dialogs import SecureSendDialog

        class FakeClient:
            def __init__(self):
                self.created, self.revoked = [], []

            def create_share(self, ciphertext, iv, proof, hours, has_password):
                self.created.append((ciphertext, iv, proof, hours, has_password))
                return {"id": "abcdEFGH1234", "created": 1, "expires": 2, "has_password": has_password,
                        "state": "active", "public_url": ""}

            def list_shares(self):
                return [{"id": "abcdEFGH1234", "state": "active"}] if self.created and not self.revoked else []

            def revoke_share(self, share_id):
                self.revoked.append(share_id)
                return True

        session = mock.Mock()
        session.client = FakeClient()
        session.profile.url = "https://ks.firma.pl"
        run_now = lambda work, done: done(work())  # noqa: E731 – w teście bez wątków
        saved = []
        d = SecureSendDialog(self.view, self.plain, session, self.vault.settings, run_now, on_sent=lambda: saved.append(1))
        self.pump()
        d.include["title"].set(False)
        d.password.insert(0, "sms-4321")
        d.expiry.set("1 godzina")
        d._create()
        ciphertext, iv, proof, hours, has_password = session.client.created[0]
        self.assertEqual((hours, has_password), (1, True))
        url = d.link_entry.get()
        self.assertTrue(url.startswith("https://ks.firma.pl/s/abcdEFGH1234#"))
        data = secure_send_open(url.split("#")[1], ciphertext, iv, "sms-4321")
        self.assertEqual(data, {"username": "jan", "password": "Haslo123"})  # bez odznaczonej nazwy
        self.assertEqual(saved, [1])
        self.assertEqual(self.vault.settings["secure_send_sent"][0]["title"], "Poczta")
        self.assertIn("ks.firma.pl", d.status_lbl.cget("text"))  # ostrzeżenie: brak publicznego adresu serwera
        d._copy(url)
        self.assertEqual(self.copied[-1], url)
        d._revoke("abcdEFGH1234")
        self.assertEqual(session.client.revoked, ["abcdEFGH1234"])
        d.destroy()

    def test_link_button_in_local_vault(self):
        self.view._select_entry(self.plain.id)
        self.pump()
        self.assertIn("✉ Link", self.details_texts())  # widoczny także w sejfie lokalnym…
        with mock.patch("tkinter.messagebox.showinfo") as info,                 mock.patch("ui.plugin_dialogs.SecureSendDialog") as dialog:
            self.view._secure_send(self.plain)
        info.assert_called_once()                      # …ale wyjaśnia, że link wymaga serwera
        self.assertIn("wymaga serwera", info.call_args.args[1])
        dialog.assert_not_called()

    def test_ssh_key_errors_shown(self):
        self.plain.custom_fields[ssh_keys.KEY_FIELD] = "-----BEGIN OPENSSH PRIVATE KEY-----\nzepsute\n-----END OPENSSH PRIVATE KEY-----"
        self.view._save_vault_to_disk()
        self.assertTrue(self.wait_for(lambda: self.plain.id in self.view.ssh_agent.errors))
        self.view._select_entry(self.plain.id)
        self.pump()
        self.assertIn("⚠️ Klucza nie można użyć", self.details_texts())

    def test_entry_form_ssh_key(self):
        from ui.drawer_views import EntryDrawerView
        frame = ctk.CTkFrame(self.root)
        saved = []
        form = EntryDrawerView(frame, categories=self.vault.categories, on_save=saved.append,
                               settings=self.vault.settings, plugin_on=self.view.plugin_on)
        fixture = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "ppk", "v2-ed25519-aes256-cbc.ppk")
        form.title_entry.insert(0, "Serwer SSH")
        with mock.patch("tkinter.filedialog.askopenfilename", return_value=fixture):
            form._load_ssh_key_file()
        self.assertIn("zabezpieczony hasłem", form.ssh_key_lbl.cget("text"))
        form.pwd_entry.insert(0, "123456")
        with mock.patch("tkinter.filedialog.askopenfilename", return_value=fixture):
            form._load_ssh_key_file()
        self.assertTrue(form.ssh_key_lbl.cget("text").startswith("✓ ED25519 256"))
        form._copy_ssh_public()
        self.assertTrue(self.copied[-1].startswith("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDAdJiRkkBM8yC8seTEoAn2Pfwb"))
        form._save_entry()
        entry = saved[0]
        self.assertIn("PuTTY-User-Key-File-2", entry.custom_fields[ssh_keys.KEY_FIELD])

        # Edycja: klucz w osobnej sekcji, a zły klucz wymaga potwierdzenia
        edit = EntryDrawerView(frame, categories=self.vault.categories, entry=entry, on_save=saved.append,
                               settings=self.vault.settings, plugin_on=self.view.plugin_on)
        self.assertNotIn(ssh_keys.KEY_FIELD, [w["key"].get() for w in edit._custom_field_widgets])
        self.assertTrue(edit.ssh_key_lbl.cget("text").startswith("✓"))
        edit.pwd_entry.delete(0, "end")
        with mock.patch("tkinter.messagebox.askyesno", return_value=False) as ask:
            edit._save_entry()
        ask.assert_called_once()
        self.assertEqual(len(saved), 1)
        edit._set_ssh_key("")
        edit._save_entry()
        self.assertNotIn(ssh_keys.KEY_FIELD, entry.custom_fields)

        new = EntryDrawerView(frame, categories=self.vault.categories, on_save=saved.append,
                              settings=self.vault.settings, plugin_on=self.view.plugin_on)
        new.user_entry.insert(0, "jan")
        new._generate_ssh_key()
        self.assertTrue(new.ssh_key_lbl.cget("text").startswith("✓ ED25519 256"))
        self.assertTrue(new._ssh_public_line.endswith(" jan"))

    def test_plugins_settings_screen(self):
        from ui.plugins_view import PluginsDrawerView
        frame = ctk.CTkFrame(self.root)
        saved = []
        view = PluginsDrawerView(frame, vault=self.vault, policy={"blocked_plugins": ["qr_show"]},
                                 on_saved=lambda: saved.append(1))
        self.assertNotIn("qr_show", view._switches)        # zablokowana przez firmę – bez przełącznika
        self.assertNotIn("passkeys", view._switches)       # w przygotowaniu
        self.assertIn("🏢 zablokowane przez firmę", texts(view))
        view._switches["pick_chars"].deselect()
        with mock.patch.object(connect, "save_prefs") as save_prefs:
            view._save()
        save_prefs.assert_called_once()
        self.assertEqual(saved, [1])
        self.assertFalse(plugins.is_enabled(self.vault.settings, {}, "pick_chars"))
        self.assertTrue(self.vault.settings["plugins"]["qr_show"])  # wybór sprzed blokady zachowany


if __name__ == "__main__":
    unittest.main()
