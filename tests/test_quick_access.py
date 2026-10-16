"""
Szybki dostęp: dopasowanie wpisu do okna, sekwencje Autotype, bezpieczeństwo (zmiana okna przerywa wpisywanie),
skróty klawiszowe i okienko wyszukiwania.
"""

import time
import unittest

from core import winsys
from core.vault import Vault, VaultEntry
from ui.quick_access import (AutotypeAborted, autotype_matches, parse_sequence, perform_autotype, single_best_match,
                             _site_label)


def vault_with(*entries):
    v = Vault("t")
    for e in entries:
        v.add_entry(e)
    return v


class FakeTyper:
    def __init__(self):
        self.out = []

    def wait_modifiers_released(self):
        pass

    def type_text(self, text):
        self.out.append(("text", text))

    def press_key(self, name):
        self.out.append(("key", name))


class TestMatching(unittest.TestCase):
    def test_site_labels(self):
        self.assertEqual(_site_label("https://github.com/login"), "github")
        self.assertEqual(_site_label("https://online.mbank.pl"), "mbank")
        self.assertEqual(_site_label("www.allegro.pl"), "allegro")
        self.assertEqual(_site_label("https://login.microsoftonline.com"), "microsoftonline")

    def test_matches_by_domain_title_and_custom_pattern(self):
        gh = VaultEntry(title="GitHub praca", username="jan", password="p", url="https://github.com")
        bank = VaultEntry(title="Bank", username="u", password="p", url="https://online.mbank.pl")
        vpn = VaultEntry(title="VPN", username="u", password="p", custom_fields={"Autotype okno": "FortiClient"})
        v = vault_with(gh, bank, vpn)
        self.assertEqual(single_best_match(autotype_matches(v, "Sign in to GitHub · GitHub - Google Chrome")), gh)
        self.assertEqual(single_best_match(autotype_matches(v, "mBank – bankowość internetowa")), bank)
        self.assertEqual(single_best_match(autotype_matches(v, "FortiClient -- Zero Trust Fabric Agent")), vpn)
        self.assertEqual(autotype_matches(v, "Notatnik"), [])

    def test_ambiguous_match_needs_choice(self):
        a = VaultEntry(title="Google prywatne", username="a", password="p", url="https://accounts.google.com")
        b = VaultEntry(title="Google firma", username="b", password="p", url="https://accounts.google.com")
        matches = autotype_matches(vault_with(a, b), "Zaloguj się – Konta Google")
        self.assertEqual(len(matches), 2)
        self.assertIsNone(single_best_match(matches))


class TestAutotype(unittest.TestCase):
    def test_sequence_parsing(self):
        self.assertEqual(parse_sequence("{USERNAME}{TAB}{PASSWORD}{ENTER}"),
                         [("field", "USERNAME"), ("key", "TAB"), ("field", "PASSWORD"), ("key", "ENTER")])
        self.assertEqual(parse_sequence("x{DELAY=200}{totp}"), [("text", "x"), ("delay", "200"), ("field", "TOTP")])

    def test_types_into_target_window(self):
        typer = FakeTyper()
        e = VaultEntry(title="X", username="jan@firma.pl", password="Zażółć!1")
        perform_autotype(e, 42, typer=typer, foreground=lambda: 42, activate=lambda h: True)
        self.assertEqual(typer.out, [("text", "jan@firma.pl"), ("key", "TAB"), ("text", "Zażółć!1"), ("key", "ENTER")])

    def test_window_change_aborts_before_password(self):
        typer = FakeTyper()
        windows = iter([42, 42, 42, 99, 99, 99])  # po wpisaniu loginu użytkownik przełączył okno
        e = VaultEntry(title="X", username="jan", password="TAJNE")
        with self.assertRaises(AutotypeAborted):
            perform_autotype(e, 42, typer=typer, foreground=lambda: next(windows), activate=lambda h: True)
        self.assertNotIn(("text", "TAJNE"), typer.out)

    def test_target_not_activatable(self):
        typer = FakeTyper()
        with self.assertRaises(AutotypeAborted):
            perform_autotype(VaultEntry(title="X", username="a", password="b"), 42, typer=typer,
                             foreground=lambda: 7, activate=lambda h: False)
        self.assertEqual(typer.out, [])


@unittest.skipUnless(winsys.IS_WINDOWS, "tylko Windows")
class TestHotkeys(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(winsys.parse_hotkey("Ctrl+Shift+Space"), (winsys.MOD_CONTROL | winsys.MOD_SHIFT, 0x20))
        self.assertEqual(winsys.parse_hotkey("alt+F5"), (winsys.MOD_ALT, 0x74))
        for bad in ("Space", "Ctrl+", "Ctrl+Shift+Ąę"):
            with self.assertRaises(ValueError):
                winsys.parse_hotkey(bad)

    def test_registered_hotkey_fires(self):
        got = []
        mgr = winsys.HotkeyManager(got.append)
        try:
            reg = mgr.start({"test": "Ctrl+Shift+Alt+F9"})
            if not reg.get("test"):
                self.skipTest("skrót zajęty")
            # symulacja naciśnięcia skrótu na poziomie systemu
            seq = [winsys._key(0x11), winsys._key(0x10), winsys._key(0x12), winsys._key(0x78),
                   winsys._key(0x78, True), winsys._key(0x12, True), winsys._key(0x10, True), winsys._key(0x11, True)]
            winsys._send(seq)
            deadline = time.time() + 3
            while not got and time.time() < deadline:
                time.sleep(0.05)
            self.assertEqual(got, ["test"])
        finally:
            mgr.stop()


class TestQuickSearchPopup(unittest.TestCase):
    def test_popup_filters_and_copies(self):
        import customtkinter as ctk
        from ui.quick_access import QuickSearchPopup
        root = ctk.CTk()
        try:
            v = vault_with(VaultEntry(title="GitHub", username="jan", password="p1"),
                           VaultEntry(title="Bank", username="ola", password="p2", totp_secret="JBSWY3DPEHPK3PXP"))
            copied = []
            popup = QuickSearchPopup(root, v, "copy", on_copy=lambda eid, what: copied.append((v.get_entry(eid).title, what)))
            root.update()
            self.assertEqual(len(popup.list.items), 2)
            popup.entry.insert(0, "ban")
            popup._refresh()
            self.assertEqual([i["title"] for i in popup.list.items], ["Bank"])
            popup._activate("totp")
            self.assertEqual(copied, [("Bank", "totp")])
            self.assertFalse(popup.winfo_exists())
        finally:
            root.destroy()


if __name__ == "__main__":
    unittest.main()
