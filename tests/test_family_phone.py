"""
Udostępnianie domownikom (paczki między sejfami, bez serwera) i hasło na telefon przez Wi-Fi (serwer lokalny
z jednorazowym, zaszyfrowanym hasłem; strona odszyfrowuje je w przeglądarce – sprawdzane w prawdziwym Edge).
Serwer telefonu słucha w testach tylko na 127.0.0.1 – bez pytania zapory Windows na ekranie użytkownika.
"""

import json
import time
import unittest
import urllib.error
import urllib.request
from unittest import mock

from core import family_share as fs
from core import phone_handoff as ph
from core.vault import Vault, VaultEntry


def pair():
    a, b = Vault("Łukasz"), Vault("Anna")
    fs.add_contact(a.settings, fs.parse_card(fs.my_card(b.settings, "Anna")))
    fs.add_contact(b.settings, fs.parse_card(fs.my_card(a.settings, "Łukasz")))
    return a, b


class FamilyShareTests(unittest.TestCase):
    def setUp(self):
        self.a, self.b = pair()
        self.anna = fs.contacts(self.a.settings)[0]
        self.entry = VaultEntry("Netflix", category="Rozrywka", username="dom@gmail.com", password="Nf!2026",
                                url="netflix.com", notes="tajne", tags=["dom"], custom_fields={"PIN": "1234"})

    def send(self, notes=True):
        sid = fs.share_id_for(self.a.settings, self.entry.id, self.anna)
        pkg = fs.seal_package(self.a.settings, "Łukasz", self.anna, fs.entry_payload(self.entry, notes), sid)
        fs.remember_sent(self.a.settings, self.entry.id, self.anna, sid)
        return pkg

    def test_round_trip_and_update(self):
        received = fs.open_package(self.b.settings, self.send())
        self.assertEqual(received.known_sender.name, "Łukasz")
        got = fs.apply_received(self.b.settings, self.b, received)
        self.assertEqual((got.title, got.password, got.custom_fields, got.tags, got.notes),
                         ("Netflix", "Nf!2026", {"PIN": "1234"}, ["dom"], "tajne"))
        self.assertIn("Rozrywka", self.b.categories)
        self.entry.update(password="Nowe!2027")
        again = fs.apply_received(self.b.settings, self.b, fs.open_package(self.b.settings, self.send(notes=False)))
        self.assertIs(again, got)                       # ten sam wpis – aktualizacja, nie kopia
        self.assertEqual(again.password, "Nowe!2027")
        self.assertEqual(again.password_history[-1]["password"], "Nf!2026")
        self.assertEqual(len(self.b.entries), 1)
        self.assertEqual([i["name"] for i in fs.shared_with(self.a.settings, self.entry.id)], ["Anna"])

    def test_only_recipient_can_open(self):
        pkg = self.send()
        with self.assertRaisesRegex(fs.ShareError, "innej osoby"):
            fs.open_package(self.a.settings, pkg)          # nadawca też nie otworzy
        stranger = Vault("Obcy")
        fs.identity(stranger.settings)
        with self.assertRaises(fs.ShareError):
            fs.open_package(stranger.settings, pkg)

    def test_impostor_is_not_trusted(self):
        # Ktoś obcy podpisuje się jako „Łukasz”, ale ma własny klucz – Anna widzi nieznanego nadawcę
        impostor = Vault("X")
        fs.add_contact(impostor.settings, fs.parse_card(fs.my_card(self.b.settings, "Anna")))
        anna = fs.contacts(impostor.settings)[0]
        pkg = fs.seal_package(impostor.settings, "Łukasz", anna, fs.entry_payload(self.entry), "id1")
        received = fs.open_package(self.b.settings, pkg)
        self.assertIsNone(received.known_sender)
        self.assertEqual(received.sender_name, "Łukasz")    # tylko deklaracja – okno ostrzega

    def test_tampering_detected(self):
        pkg = self.send()
        head, body = pkg[len(fs.PACKAGE_PREFIX):].split(".", 1)
        forged_header = json.loads(fs._unb64(head))
        forged_header["from"] = "Ktoś inny"
        forged = fs.PACKAGE_PREFIX + fs._b64(json.dumps(forged_header).encode()) + "." + body
        with self.assertRaises(fs.ShareError):
            fs.open_package(self.b.settings, forged)       # nagłówek jest w AAD – zmiana nadawcy wykryta
        with self.assertRaises(fs.ShareError):
            fs.open_package(self.b.settings, pkg[:-6] + "AAAAAA")

    def test_cards(self):
        with self.assertRaises(fs.ShareError):
            fs.parse_card("ksfam1:śmieci")
        with self.assertRaises(fs.ShareError):
            fs.parse_card("hello")
        own = fs.parse_card(fs.my_card(self.a.settings, "Łukasz"))
        self.assertFalse(fs.add_contact(self.a.settings, own))
        again = Vault.from_json(self.a.to_json())          # tożsamość i kontakty w zaszyfrowanym sejfie
        self.assertEqual(fs.identity(again.settings)["public"], fs.identity(self.a.settings)["public"])
        self.assertEqual([c.name for c in fs.contacts(again.settings)], ["Anna"])
        self.assertRegex(self.anna.fingerprint, r"^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$")
        fs.remove_contact(self.a.settings, self.anna.public)
        self.assertEqual(fs.contacts(self.a.settings), [])


class PhoneHandoffTests(unittest.TestCase):
    def server(self, **kw):
        s = ph.HandoffServer("Wi-Fi", "Hasło-ąę 123", host="127.0.0.1", **kw).start()
        self.addCleanup(s.close)
        return s

    def get(self, url):
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            with e:
                return e.code, e.read()

    def test_page_and_one_time_data(self):
        fetched = []
        s = self.server(on_fetched=lambda: fetched.append(1))
        base = s.url.split("#")[0]
        status, page = self.get(base)
        self.assertEqual(status, 200)
        self.assertNotIn(s.url.split("#")[1].encode(), page)   # klucz nigdy nie jest wysyłany przez sieć
        status, data = self.get(base + "/data")
        self.assertEqual(status, 200)
        d = json.loads(data)
        import base64
        plain = ph.encrypt(s.key, base64.b64decode(d["n"]), base64.b64decode(d["c"]))
        self.assertEqual(json.loads(plain)["p"], "Hasło-ąę 123")
        self.assertEqual(self.get(base + "/data")[0], 410)       # drugi raz – nic
        self.assertEqual(fetched, [1])

    def test_guessing_and_timeout_close_server(self):
        closed = []
        s = self.server(on_closed=closed.append)
        root = f"http://127.0.0.1:{s.port}/h/"
        for i in range(ph.MAX_BAD_REQUESTS):
            self.get(root + f"zgaduje{i}")
        time.sleep(0.3)
        self.assertEqual(closed, ["attack"])
        closed2 = []
        self.server(lifetime=1, on_closed=closed2.append)
        time.sleep(1.5)
        self.assertEqual(closed2, ["timeout"])

    def test_no_network(self):
        with mock.patch.object(ph.socket.socket, "connect", side_effect=OSError("brak")):
            with self.assertRaises(ph.HandoffError):
                ph.lan_ip()

    def test_phone_browser_decrypts(self):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skipTest("brak Playwright")
        secret = 'Zażółć "gęślą" <jaźń> & 123! </script>' * 3   # kilka bloków ChaCha20, znaki specjalne
        s = ph.HandoffServer("Wi-Fi dom", secret, host="127.0.0.1").start()
        self.addCleanup(s.close)
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(channel="msedge", headless=True)
            except Exception as e:
                self.skipTest(f"brak Edge: {e}")
            page = browser.new_page()
            page.goto(s.url)
            page.wait_for_selector(".p", timeout=10000)
            self.assertEqual(page.inner_text(".p"), secret)
            self.assertNotIn("#", page.url)                   # klucz usunięty z paska adresu
            browser.close()


if __name__ == "__main__":
    unittest.main()
