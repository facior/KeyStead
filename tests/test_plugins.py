"""
Testy wbudowanych wtyczek: rejestr i polityka firmy, data ważności hasła, szablony wpisów,
„Połącz” (bez uruchamiania programów) i kody QR.
"""

import os
import tempfile
import unittest
from datetime import date
from unittest import mock

from core import connect, entry_templates, expiry, plugins, qr, secure_send
from core.vault import Vault, VaultEntry


class PluginRegistryTests(unittest.TestCase):
    def test_all_off_by_default(self):
        settings = Vault().settings
        self.assertEqual(plugins.enabled_set(settings, {}), frozenset())

    def test_user_choice_and_company_block(self):
        settings = Vault().settings
        plugins.set_choices(settings, {"connect": True, "expiry": True})
        self.assertTrue(plugins.is_enabled(settings, {}, "connect"))
        policy = {"blocked_plugins": ["connect"]}
        self.assertFalse(plugins.is_enabled(settings, policy, "connect"))
        self.assertTrue(plugins.is_enabled(settings, policy, "expiry"))

    def test_not_ready_and_unknown_cannot_be_enabled(self):
        settings = {}
        plugins.set_choices(settings, {"passkeys": True, "evil": True})
        self.assertEqual(settings["plugins"], {})
        settings["plugins"] = {"passkeys": True, "evil": True}  # np. z ręcznie zmienionego pliku
        self.assertFalse(plugins.is_enabled(settings, {}, "passkeys"))
        self.assertFalse(plugins.is_enabled(settings, {}, "evil"))

    def test_malformed_values_are_ignored(self):
        self.assertFalse(plugins.is_enabled({"plugins": {"connect": "yes"}}, {}, "connect"))
        self.assertFalse(plugins.is_enabled({"plugins": ["connect"]}, {}, "connect"))
        self.assertFalse(plugins.blocked_by_policy({"blocked_plugins": "connect"}, "connect"))

    def test_choice_survives_vault_round_trip(self):
        vault = Vault()
        plugins.set_choices(vault.settings, {"qr_show": True})
        again = Vault.from_json(vault.to_json())
        self.assertTrue(plugins.is_enabled(again.settings, {}, "qr_show"))

    def test_blocked_plugin_keeps_users_choice(self):
        settings = {"plugins": {"connect": True}}
        plugins.set_choices(settings, {"expiry": True})  # „connect” zablokowany – nie ma go w formularzu
        self.assertEqual(settings["plugins"], {"connect": True, "expiry": True})

    def test_server_and_app_know_the_same_plugins(self):
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "server", "settings.py")
        if not os.path.exists(path):
            self.skipTest("bez katalogu server/ (repozytorium aplikacji)")
        with open(path, encoding="utf-8") as f:
            source = f.read()
        for plugin in plugins.PLUGINS:
            self.assertIn(f'"{plugin.id}":', source)


class ExpiryTests(unittest.TestCase):
    def entry(self, value=None, name=expiry.EXPIRY_FIELD):
        return VaultEntry("Konto", custom_fields={name: value} if value is not None else {})

    def test_parse_formats(self):
        self.assertEqual(expiry.parse_date("2027-03-31"), date(2027, 3, 31))
        self.assertEqual(expiry.parse_date("31.03.2027"), date(2027, 3, 31))
        self.assertEqual(expiry.parse_date(" 1-2-2027 "), date(2027, 2, 1))
        self.assertIsNone(expiry.parse_date("2027-02-30"))
        self.assertIsNone(expiry.parse_date("jutro"))

    def test_status(self):
        today = date(2026, 10, 18)
        self.assertEqual(expiry.status(self.entry("2026-10-10"), today), (expiry.EXPIRED, -8))
        self.assertEqual(expiry.status(self.entry("2026-10-18"), today), (expiry.SOON, 0))
        self.assertEqual(expiry.status(self.entry("2026-11-01"), today), (expiry.SOON, 14))
        self.assertEqual(expiry.status(self.entry("2026-11-02"), today), (expiry.OK, 15))
        self.assertIsNone(expiry.status(self.entry(), today))
        self.assertIsNone(expiry.status(self.entry("nie wiem"), today))

    def test_english_field_name_is_read(self):
        e = self.entry("2026-10-01", name="Password expires")
        self.assertEqual(expiry.get_expiry(e), date(2026, 10, 1))

    def test_attention_sorted_most_urgent_first(self):
        today = date(2026, 10, 18)
        a, b, c = self.entry("2026-10-25"), self.entry("2026-09-01"), self.entry("2027-01-01")
        self.assertEqual([e for e, _s, _d in expiry.attention([a, b, c], today)], [b, a])

    def test_set_field_replaces_aliases(self):
        fields = {"Password expires": "2020-01-01", "PIN": "1234"}
        expiry.set_expiry_field(fields, date(2027, 1, 2))
        self.assertEqual(fields, {"PIN": "1234", expiry.EXPIRY_FIELD: "2027-01-02"})
        expiry.set_expiry_field(fields, None)
        self.assertEqual(fields, {"PIN": "1234"})


class TemplateTests(unittest.TestCase):
    def test_apply_keeps_existing_values(self):
        server = next(t for t in entry_templates.BUILTIN if t.id == "rdp_server")
        fields = entry_templates.apply(server, {"Adres IP": "10.0.0.5", "PIN": "1"})
        self.assertEqual(fields["Adres IP"], "10.0.0.5")
        self.assertEqual(fields["System"], "Windows Server")
        self.assertEqual(fields["PIN"], "1")

    def test_user_template_saves_names_only(self):
        settings = {}
        entry_templates.save_user_template(settings, "Kamera", "Serwery / Wi-Fi", "https://10.0.0.9/login",
                                           ["Adres IP", " ", "Model"])
        saved = settings["entry_templates"][0]
        self.assertEqual(saved, {"name": "Kamera", "category": "Serwery / Wi-Fi", "url": "https://",
                                 "fields": ["Adres IP", "Model"]})
        tpl = entry_templates.user_templates(settings)[0]
        self.assertFalse(tpl.builtin)
        self.assertEqual([n for n, _v in tpl.fields], ["Adres IP", "Model"])

    def test_same_name_replaces_and_delete(self):
        settings = {}
        entry_templates.save_user_template(settings, "A", "Loginy", "", ["X"])
        entry_templates.save_user_template(settings, "A", "Loginy", "", ["Y"])
        self.assertEqual(len(settings["entry_templates"]), 1)
        entry_templates.delete_user_template(settings, "A")
        self.assertEqual(settings["entry_templates"], [])

    def test_malformed_user_templates_are_skipped(self):
        settings = {"entry_templates": ["x", {"name": ""}, {"name": "OK", "fields": "zle"}, {"name": 5}]}
        names = [t.name for t in entry_templates.user_templates(settings)]
        self.assertEqual(names, ["OK", "5"])

    def test_templates_survive_old_client_settings_merge(self):
        # Starsza wersja aplikacji zapisuje ustawienia przez _merge_settings – nieznane klucze muszą zostać
        vault = Vault(settings={"entry_templates": [{"name": "A", "fields": ["X"]}], "plugins": {"templates": True}})
        again = Vault.from_json(vault.to_json())
        self.assertEqual(again.settings["entry_templates"][0]["name"], "A")
        self.assertTrue(again.settings["plugins"]["templates"])


class ConnectTests(unittest.TestCase):
    def target(self, url, **kw):
        e = VaultEntry("Serwer", url=url, username=kw.pop("username", "admin"), password=kw.pop("password", "Tajne1!"),
                       custom_fields=kw.pop("fields", {}))
        return connect.parse_target(e)

    def test_parse(self):
        t = self.target("rdp://srv01.firma.local:3390")
        self.assertEqual((t.protocol, t.host, t.port, t.username), ("rdp", "srv01.firma.local", 3390, "admin"))
        t = self.target("ssh://root@10.0.0.1")
        self.assertEqual((t.protocol, t.host, t.port, t.username), ("ssh", "10.0.0.1", 0, "root"))
        t = self.target("rdp://", fields={"Adres IP": "192.168.1.10", "Domena": "FIRMA"})
        self.assertEqual((t.host, t.domain), ("192.168.1.10", "FIRMA"))
        t = self.target("anydesk://", fields={"Numer ID": "123456789"})
        self.assertEqual(t.host, "123456789")
        t = self.target("ssh://[fe80::1]:2222")
        self.assertEqual((t.host, t.port), ("[fe80::1]", 2222))
        self.assertIsNone(self.target("https://example.com"))
        self.assertIsNone(self.target("file://c:/windows"))

    def test_rejects_option_injection(self):
        for url in ("ssh://-oProxyCommand=calc", "rdp://srv /admin", "winbox://a;b", "ssh://ho\"st",
                    "anydesk://--plain", "teamviewer://12ab"):
            t = self.target(url)
            if t is None:
                continue
            with self.assertRaises(connect.ConnectError, msg=url):
                connect.validate(t)
        with self.assertRaises(connect.ConnectError):
            connect.validate(self.target("ssh://host", username="-oProxyCommand=calc"))
        with self.assertRaises(connect.ConnectError):
            connect.validate(self.target("rdp://", fields={}))  # brak adresu

    def tools(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        paths = {}
        for name in ("putty", "winbox", "anydesk", "teamviewer", "mstsc", "ssh"):
            paths[name] = os.path.join(tmp, f"{name}.exe")
            open(paths[name], "wb").close()
        return paths

    def plan(self, url, prefs=None, **kw):
        paths = self.tools()
        with mock.patch.object(connect, "find_program", side_effect=lambda name, _p=None: paths[name]):
            return connect.build_plan(self.target(url, **kw), prefs or dict(connect.DEFAULT_PREFS)), paths

    def test_rdp_plan_uses_credential_manager_not_command_line(self):
        plan, paths = self.plan("rdp://srv01:3390", fields={"Domena": "FIRMA"})
        self.assertEqual(plan.argv, [paths["mstsc"], "/v:srv01:3390"])
        self.assertEqual(plan.rdp_credential, {"target": "TERMSRV/srv01", "username": "FIRMA\\admin",
                                               "password": "Tajne1!"})
        self.assertNotIn("Tajne1!", " ".join(plan.argv))

    def test_ssh_plan_password_only_in_clipboard(self):
        plan, paths = self.plan("ssh://root@10.0.0.1:2222")
        self.assertEqual(plan.argv, [paths["ssh"], "-p", "2222", "root@10.0.0.1"])
        self.assertTrue(plan.new_console)
        self.assertEqual(plan.clipboard_text, "Tajne1!")
        plan, paths = self.plan("ssh://10.0.0.1", prefs={**connect.DEFAULT_PREFS, "ssh_client": "putty"})
        self.assertEqual(plan.argv, [paths["putty"], "-ssh", "10.0.0.1", "-P", "22", "-l", "admin"])
        self.assertNotIn("Tajne1!", plan.argv)

    def test_anydesk_password_via_stdin(self):
        plan, paths = self.plan("anydesk://123456789")
        self.assertEqual(plan.argv, [paths["anydesk"], "123456789", "--with-password"])
        self.assertEqual(plan.stdin_text, "Tajne1!\n")

    def test_winbox_and_teamviewer(self):
        plan, paths = self.plan("winbox://192.168.88.1")
        self.assertEqual(plan.argv, [paths["winbox"], "192.168.88.1", "admin", "Tajne1!"])
        plan, paths = self.plan("teamviewer://987654321")
        self.assertEqual(plan.argv, [paths["teamviewer"], "-i", "987654321", "--Password", "Tajne1!"])

    def test_missing_program(self):
        with mock.patch.object(connect, "find_program", return_value=""):
            with self.assertRaises(connect.ConnectError):
                connect.build_plan(self.target("winbox://10.0.0.1"), dict(connect.DEFAULT_PREFS))

    def test_launch_skips_existing_rdp_credential(self):
        plan = connect.LaunchPlan(["mstsc.exe", "/v:srv"], rdp_credential={"target": "TERMSRV/srv",
                                                                              "username": "a", "password": "b"})
        with mock.patch.object(connect, "rdp_credential_exists", return_value=True), \
                mock.patch.object(connect, "write_rdp_credential") as write, \
                mock.patch.object(connect.subprocess, "Popen") as popen:
            notes = connect.launch(plan)
        write.assert_not_called()
        popen.assert_called_once()
        self.assertTrue(notes)

    def test_launch_removes_credential_when_start_fails(self):
        plan = connect.LaunchPlan(["brak.exe"], rdp_credential={"target": "TERMSRV/srv", "username": "a",
                                                                 "password": "b"})
        with mock.patch.object(connect, "rdp_credential_exists", return_value=False), \
                mock.patch.object(connect, "write_rdp_credential"), \
                mock.patch.object(connect, "delete_rdp_credential") as delete, \
                mock.patch.object(connect.threading, "Timer"), \
                mock.patch.object(connect.subprocess, "Popen", side_effect=OSError("nie ma")):
            with self.assertRaises(connect.ConnectError):
                connect.launch(plan)
        delete.assert_called_once_with("TERMSRV/srv")

    def test_pending_credential_removed_once_on_exit(self):
        plan = connect.LaunchPlan(["mstsc.exe"], rdp_credential={"target": "TERMSRV/x", "username": "a",
                                                                  "password": "b"})
        with mock.patch.object(connect, "rdp_credential_exists", return_value=False),                 mock.patch.object(connect, "write_rdp_credential"),                 mock.patch.object(connect, "delete_rdp_credential") as delete,                 mock.patch.object(connect.threading, "Timer"),                 mock.patch.object(connect.subprocess, "Popen"):
            connect.launch(plan)
            connect._cleanup_credentials()      # zamknięcie programu przed upływem 30 s
            connect._expire_credential("TERMSRV/x")  # późniejszy timer nie usuwa drugi raz
        delete.assert_called_once_with("TERMSRV/x")

    def test_prefs_round_trip(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        with mock.patch.object(connect, "APP_DIR", tmp), \
                mock.patch.object(connect, "PREFS_FILE", os.path.join(tmp, "connect.json")):
            connect.save_prefs({"ssh_client": "putty", "winbox": r"C:\x\winbox64.exe", "inne": "x"})
            prefs = connect.load_prefs()
        self.assertEqual(prefs["ssh_client"], "putty")
        self.assertNotIn("inne", prefs)

    @unittest.skipUnless(os.name == "nt", "Menedżer poświadczeń Windows")
    def test_credential_manager_round_trip(self):
        target = "TERMSRV/keystead-test.invalid"
        connect.write_rdp_credential(target, "tester", "Haslo123!")
        try:
            self.assertTrue(connect.rdp_credential_exists(target))
        finally:
            connect.delete_rdp_credential(target)
        self.assertFalse(connect.rdp_credential_exists(target))


class SecureSendTests(unittest.TestCase):
    def test_round_trip_and_wrong_password(self):
        payload = {"title": "Bank", "password": "Zażółć 123!"}
        sealed = secure_send.seal(payload, "sms-4321")
        self.assertEqual(len(secure_send._from_b64url(sealed.link_key)), 32)
        self.assertNotIn("=", sealed.link_key)
        self.assertEqual(secure_send.open_sealed(sealed.link_key, sealed.ciphertext, sealed.iv, "sms-4321"), payload)
        with self.assertRaises(Exception):
            secure_send.open_sealed(sealed.link_key, sealed.ciphertext, sealed.iv, "zle")
        _key, proof = secure_send.derive(secure_send._from_b64url(sealed.link_key), "sms-4321")
        self.assertEqual(proof, sealed.proof)
        self.assertNotEqual(secure_send.derive(secure_send._from_b64url(sealed.link_key))[1], sealed.proof)

    def test_payload_only_selected_fields(self):
        e = VaultEntry("Poczta", username="jan", password="x", url="https://p", notes="tajna notatka")
        self.assertEqual(secure_send.payload_from_entry(e, {"username": True, "password": True}),
                         {"username": "jan", "password": "x"})

    def test_link_and_sent_list(self):
        self.assertEqual(secure_send.link("https://ks.firma.pl/", "abc12345", "KEY"), "https://ks.firma.pl/s/abc12345#KEY")
        settings = {}
        for i in range(secure_send.MAX_SENT + 5):
            secure_send.remember_sent(settings, {"id": f"id{i}", "created": i, "expires": i + 1}, f"Wpis {i}")
        sent = secure_send.sent_list(settings)
        self.assertEqual(len(sent), secure_send.MAX_SENT)
        self.assertEqual(sent[0]["title"], f"Wpis {secure_send.MAX_SENT + 4}")


@unittest.skipUnless(qr.available(), "brak zxing-cpp")
class QrTests(unittest.TestCase):
    def test_round_trip(self):
        img = qr.make_image("Zażółć gęślą jaźń 123!")
        self.assertEqual(qr.read_codes(img), ["Zażółć gęślą jaźń 123!"])

    def test_otpauth_found_among_codes(self):
        uri = "otpauth://totp/Firma:jan?secret=JBSWY3DPEHPK3PXP&issuer=Firma"
        self.assertEqual(qr.find_otpauth(["https://x", uri]), uri)
        self.assertIsNone(qr.find_otpauth(["https://x"]))

    def test_read_from_screenshot_like_image(self):
        from PIL import Image
        uri = "otpauth://totp/Test:me?secret=JBSWY3DPEHPK3PXP"
        shot = Image.new("RGBA", (900, 700), (40, 40, 60, 255))
        shot.paste(qr.make_image(uri, scale=5).convert("RGBA"), (300, 200))
        self.assertEqual(qr.find_otpauth(qr.read_codes(shot)), uri)

    def test_wifi_payload(self):
        e = VaultEntry("Biuro", password='p;a"ss', custom_fields={"SSID": "Biuro:5G", "Zabezpieczenia": "WPA2"})
        self.assertEqual(qr.wifi_payload(e), 'WIFI:T:WPA;S:Biuro\\:5G;P:p\\;a\\"ss;;')
        self.assertIsNone(qr.wifi_payload(VaultEntry("Bez SSID", password="x")))
        open_net = VaultEntry("Kawiarnia", custom_fields={"SSID": "Free"})
        self.assertEqual(qr.wifi_payload(open_net), "WIFI:T:nopass;S:Free;;")


if __name__ == "__main__":
    unittest.main()
