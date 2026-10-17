"""
Szybki dostęp: dopasowanie wpisu do okna, sekwencje Autotype, bezpieczeństwo (zmiana okna przerywa wpisywanie),
skróty klawiszowe i okienko wyszukiwania.
"""

import os
import time
import unittest
from unittest import mock

from core import browser_url, winsys
from core.vault import Vault, VaultEntry
from ui.quick_access import (ADDRESSES_FIELD, AutotypeAborted, QuickAccess, autotype_matches, browser_matches,
                             entry_allowed_on, parse_sequence, perform_autotype, single_best_match, _site_label)


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

    @unittest.skipUnless(os.environ.get("KS_REAL_INPUT_TESTS"), "wysyła prawdziwe klawisze do pulpitu (KS_REAL_INPUT_TESTS=1)")
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


class TestBrowserAddress(unittest.TestCase):
    def test_page_host(self):
        self.assertEqual(browser_url.page_host("https://www.mbank.pl/logowanie"), "mbank.pl")
        self.assertEqual(browser_url.page_host("online.mbank.pl/x?y"), "online.mbank.pl")  # Chrome bez https://
        self.assertEqual(browser_url.page_host("http://192.168.0.1:8080/"), "192.168.0.1")
        self.assertIsNone(browser_url.page_host("jak zalogować się do banku"))  # wpisywana fraza
        self.assertIsNone(browser_url.page_host("file:///C:/x.html"))
        self.assertIsNone(browser_url.page_host(""))

    def test_host_matching_blocks_lookalikes(self):
        m = browser_url.host_matches
        self.assertTrue(m("mbank.pl", "mbank.pl"))
        self.assertTrue(m("online.mbank.pl", "mbank.pl"))
        for fake in ("mbank.pl.evil.com", "evilmbank.pl", "mbank-logowanie.xyz", "mbank.pl.co"):
            self.assertFalse(m(fake, "mbank.pl"), fake)
        self.assertFalse(m("mbank.pl", "online.mbank.pl"))
        self.assertFalse(m("10.192.168.0.1", "192.168.0.1"))
        self.assertFalse(m("evil.pl", "pl"))

    def test_entry_matching_by_address(self):
        bank = VaultEntry(title="Bank", username="u", password="p", url="https://www.mbank.pl")
        ms = VaultEntry(title="Office", username="u", password="p", url="https://outlook.office.com",
                        custom_fields={ADDRESSES_FIELD: "login.microsoftonline.com, account.live.com"})
        nourl = VaultEntry(title="VPN", username="u", password="p")
        v = vault_with(bank, ms, nourl)
        self.assertEqual(single_best_match(browser_matches(v, "online.mbank.pl")), bank)
        self.assertEqual(single_best_match(browser_matches(v, "login.microsoftonline.com")), ms)
        self.assertEqual(browser_matches(v, "mbank-logowanie.xyz"), [])
        self.assertIs(entry_allowed_on(bank, "mbank-logowanie.xyz"), False)
        self.assertIsNone(entry_allowed_on(nourl, "cokolwiek.pl"))

    def test_exact_address_beats_parent_domain(self):
        a = VaultEntry(title="Google", username="a", password="p", url="https://google.com")
        b = VaultEntry(title="Google Ads", username="b", password="p", url="https://ads.google.com")
        self.assertEqual(single_best_match(browser_matches(vault_with(a, b), "ads.google.com")), b)

    def test_verify_runs_before_anything_is_typed(self):
        typer = FakeTyper()

        def _changed():
            raise AutotypeAborted("zmiana strony")
        with self.assertRaises(AutotypeAborted):
            perform_autotype(VaultEntry(title="X", username="a", password="TAJNE"), 42, typer=typer,
                             foreground=lambda: 42, activate=lambda h: True, verify=_changed)
        self.assertEqual(typer.out, [])


class FakeNode:
    def __init__(self, role, value=None, kids=()):
        self.role, self.value, self.kids = role, value, list(kids)


class FakeMSAA(browser_url._MSAA):
    """Drzewo dostępności okna bez COM – sprawdza same reguły wyboru paska adresu."""

    def __init__(self, tree):
        super().__init__()
        self.tree = tree

    def root(self, hwnd):
        return self.tree

    def role(self, acc):
        return acc.role

    def value(self, acc):
        return acc.value

    def children(self, acc):
        return list(acc.kids)


def window_tree(page_fields=(), bar="https://www.mbank.pl/login", toolbar=True):
    document = FakeNode(browser_url.ROLE_DOCUMENT, "https://evil.xyz",
                        [FakeNode(browser_url.ROLE_TEXT, v) for v in page_fields])
    bar_node = FakeNode(browser_url.ROLE_TEXT, bar)
    holder = FakeNode(browser_url.ROLE_TOOLBAR if toolbar else 20, None, [FakeNode(43), bar_node])
    return FakeNode(16, None, [FakeNode(16, None, [holder]), FakeNode(16, None, [document])])


class TestMsaaAddressBar(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(browser_url, "_release", lambda obj: None)
        p.start()
        self.addCleanup(p.stop)
        browser_url._msaa_paths.clear()

    def test_finds_bar_and_ignores_page_fields(self):
        m = FakeMSAA(window_tree(page_fields=["mbank.pl", "https://mbank.pl"]))
        self.assertEqual(m.address_bar_value(1, "opera.exe"), "https://www.mbank.pl/login")
        self.assertEqual(browser_url._msaa_paths["opera.exe"], [0, 0, 1])
        self.assertEqual(m.address_bar_value(1, "opera.exe"), "https://www.mbank.pl/login")  # zapamiętaną drogą

    def test_field_outside_toolbar_is_not_trusted(self):
        self.assertIsNone(FakeMSAA(window_tree(toolbar=False)).address_bar_value(1, "opera.exe"))

    def test_two_candidates_mean_unknown(self):
        tree = window_tree()
        tree.kids[0].kids[0].kids.append(FakeNode(browser_url.ROLE_TEXT, "https://inna.pl"))
        self.assertIsNone(FakeMSAA(tree).address_bar_value(1, "opera.exe"))

    def test_stale_path_into_page_is_rejected(self):
        browser_url._msaa_paths["opera.exe"] = [1, 0, 0]  # prowadzi do pola na stronie
        m = FakeMSAA(window_tree(page_fields=["https://mbank.pl"]))
        self.assertEqual(m.address_bar_value(1, "opera.exe"), "https://www.mbank.pl/login")
        self.assertEqual(browser_url._msaa_paths["opera.exe"], [0, 0, 1])


class FakeApp:
    def __init__(self, vault):
        self.current_vault = vault
        self.remembered, self.notes = [], []

    def after(self, *a):
        pass

    def post_to_ui(self, fn):
        fn()

    def notify(self, text, error=False):
        self.notes.append(text)

    def remember_autotype_host(self, entry_id, host):
        self.remembered.append((entry_id, host))

    quick_copy = on_user_activity = lambda *a, **k: None


class TestBrowserAutotypeFlow(unittest.TestCase):
    """Decyzje po naciśnięciu Ctrl+Shift+L w przeglądarce (okienka i wpisywanie podmienione)."""

    def setUp(self):
        self.bank = VaultEntry(title="mBank", username="jan", password="TAJNE", url="https://www.mbank.pl")
        self.vault = vault_with(self.bank, VaultEntry(title="GitHub", username="g", password="p", url="github.com"))
        self.app = FakeApp(self.vault)
        with mock.patch.object(QuickAccess, "_poll"):
            self.qa = QuickAccess(self.app)
        self.typed = []
        self.qa.run_autotype = lambda entry, hwnd, expected_host=None: self.typed.append((entry, expected_host))
        patches = [mock.patch("ui.quick_access.QuickSearchPopup"), mock.patch("ui.quick_access.AutotypeWarning")]
        self.popup, self.warning = (p.start() for p in patches)
        for p in patches:
            self.addCleanup(p.stop)

    def test_matching_address_types_automatically(self):
        self.qa._autotype_in_browser(self.vault, 1, "Logowanie – Chrome", "online.mbank.pl/login")
        self.assertEqual(self.typed, [(self.bank, "online.mbank.pl")])
        self.popup.assert_not_called()

    def test_fake_page_with_bank_title_is_not_typed(self):
        self.qa._autotype_in_browser(self.vault, 1, "mBank – logowanie - Google Chrome", "https://mbank-logowanie.xyz/")
        self.assertEqual(self.typed, [])
        self.warning.assert_called_once()
        entry, host = self.warning.call_args[0][1:3]
        self.assertEqual((entry, host), (self.bank, "mbank-logowanie.xyz"))
        # dopiero świadome „To moja strona – wpisz” wpisuje i zapamiętuje adres
        self.warning.call_args.kwargs["on_confirm"]()
        self.assertEqual(self.typed, [(self.bank, "mbank-logowanie.xyz")])
        self.assertEqual(self.app.remembered, [(self.bank.id, "mbank-logowanie.xyz")])

    def test_manual_choice_of_other_site_entry_warns(self):
        self.qa._autotype_in_browser(self.vault, 1, "Jakaś strona", "https://inna.pl/")
        on_autotype = self.popup.call_args.kwargs["on_autotype"]
        on_autotype(self.bank)
        self.assertEqual(self.typed, [])
        self.warning.assert_called_once()

    def test_unreadable_address_never_types_automatically(self):
        self.qa._autotype_in_browser(self.vault, 1, "mBank – logowanie", None)
        self.assertEqual(self.typed, [])
        self.assertIn("Nie udało się sprawdzić adresu", self.popup.call_args.kwargs["note"])
        self.popup.call_args.kwargs["on_autotype"](self.bank)  # świadomy wybór z listy
        self.assertEqual(self.typed, [(self.bank, None)])

    def test_locked_meanwhile_does_nothing(self):
        self.app.current_vault = None
        self.qa._autotype_in_browser(self.vault, 1, "mBank", "mbank.pl")
        self.assertEqual(self.typed, [])
        self.popup.assert_not_called()


def offscreen(cls):
    """Okienka testowe poza ekranem i bez wyciągania na wierzch – nie przeszkadzają w pracy przy komputerze."""
    import customtkinter as ctk
    return [mock.patch.object(cls, "geometry", lambda self, g=None: ctk.CTkToplevel.geometry(self, "+-4000+-4000")),
            mock.patch.object(winsys, "force_foreground", lambda hwnd: False)]


class TestQuickSearchPopup(unittest.TestCase):
    def setUp(self):
        from ui.quick_access import AutotypeWarning, QuickSearchPopup
        for p in offscreen(QuickSearchPopup) + offscreen(AutotypeWarning):
            p.start()
            self.addCleanup(p.stop)

    def test_warning_defaults_to_not_typing(self):
        import customtkinter as ctk
        from ui.quick_access import AutotypeWarning
        root = ctk.CTk()
        root.geometry("+-4000+-4000")
        try:
            bank = VaultEntry(title="mBank", username="jan", password="p", url="https://mbank.pl")
            confirmed = []
            w = AutotypeWarning(root, bank, "mbank-logowanie.xyz", on_confirm=lambda: confirmed.append(1))
            root.update()
            w.event_generate("<Return>")
            root.update()
            self.assertFalse(w.winfo_exists())
            self.assertEqual(confirmed, [])
            w = AutotypeWarning(root, bank, "mbank-logowanie.xyz", on_confirm=lambda: confirmed.append(1))
            root.update()
            w.confirm_btn.invoke()
            self.assertEqual(confirmed, [1])
            self.assertFalse(w.winfo_exists())
        finally:
            root.destroy()

    def test_popup_filters_and_copies(self):
        import customtkinter as ctk
        from ui.quick_access import QuickSearchPopup
        root = ctk.CTk()
        root.geometry("+-4000+-4000")
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
