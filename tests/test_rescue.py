"""
Centrum ratunkowe i karta awaryjna: mapa domina kont, kroki kreatora „Ktoś przejął moje konto!”,
zapamiętywany postęp oraz karta awaryjna w PDF.
"""

import os
import tempfile
import unittest

from core import domino, qr, rescue
from core.emergency_card import CardInfo, render, save_pdf
from core.vault import Vault, VaultEntry as E


def home_vault():
    return [
        E("Gmail", username="jan@gmail.com", password="Kot123", url="https://accounts.google.com"),
        E("mBank", username="jan@gmail.com", password="x9!Lkq2#pP0zA", url="https://online.mbank.pl"),
        E("Allegro", username="jan@gmail.com", password="Kot123", url="https://allegro.pl"),
        E("Netflix", username="jan@gmail.com", password="Nf-2026!xyz", url="netflix.com"),
        E("ePUAP", username="Jan@Gmail.com", password="g0v!Haslo#1", url="https://epuap.gov.pl"),
        E("Poczta WP", username="jan.k@wp.pl", password="Bardzo-Dlugie-Haslo-2026!", url="https://poczta.wp.pl",
          totp_secret="JBSWY3DPEHPK3PXP"),
        E("Instagram", username="jan.k@wp.pl", password="Ig-Haslo-2026!", url="instagram.com"),
        E("Forum", username="janek", password="q"),
        E("Sklep", username="sklepowy-login", password="s", url="sklep.pl", custom_fields={"E-mail": "jan.k@wp.pl"}),
    ]


class DominoTests(unittest.TestCase):
    def setUp(self):
        self.entries = home_vault()
        self.keys = domino.analyze(self.entries)
        self.by_email = {k.email: k for k in self.keys}

    def test_mailboxes_and_dependents(self):
        gmail = self.by_email["jan@gmail.com"]
        self.assertEqual(gmail.mailbox.title, "Gmail")
        self.assertEqual(sorted(e.title for e in gmail.dependents), ["Allegro", "Netflix", "ePUAP", "mBank"])
        self.assertEqual(gmail.important, {"bank": 1, "shop": 1, "gov": 1})
        wp = self.by_email["jan.k@wp.pl"]
        self.assertEqual(wp.mailbox.title, "Poczta WP")
        self.assertEqual(sorted(e.title for e in wp.dependents), ["Instagram", "Sklep"])  # także pole „E-mail”

    def test_risk_order_and_problems(self):
        self.assertEqual(self.keys[0].email, "jan@gmail.com")
        gmail = self.by_email["jan@gmail.com"]
        self.assertIn(domino.PROBLEM_NO_2FA, gmail.problems)
        self.assertIn(domino.PROBLEM_REUSED, gmail.problems)
        self.assertIn(domino.PROBLEM_WEAK, gmail.problems)
        self.assertEqual(gmail.risk, 3)
        self.assertEqual(self.by_email["jan.k@wp.pl"].problems, [])
        breached = domino.analyze(self.entries, {self.by_email["jan.k@wp.pl"].mailbox.id})
        self.assertIn(domino.PROBLEM_BREACHED, {k.email: k for k in breached}["jan.k@wp.pl"].problems)

    def test_missing_mailbox_entry(self):
        keys = domino.analyze([E("Allegro", username="ola@outlook.com", password="x", url="allegro.pl")])
        self.assertIsNone(keys[0].mailbox)
        self.assertEqual(keys[0].problems, [domino.PROBLEM_NO_ENTRY])
        self.assertEqual(keys[0].provider_host, "live.com")

    def test_importance_matches_domains_not_fragments(self):
        self.assertIsNone(domino.importance(E("Netflix", url="netflix.com")))  # „x.com” w „netflix.com”
        self.assertEqual(domino.importance(E("X", url="https://x.com")), "social")
        self.assertEqual(domino.importance(E("Mój bank", url="")), "bank")
        self.assertEqual(domino.importance(E("Profil", url="https://pz.gov.pl")), "gov")

    def test_urls(self):
        self.assertEqual(domino.change_password_url(E("A", url="allegro.pl/login")),
                         "https://allegro.pl/.well-known/change-password")
        self.assertEqual(domino.change_password_url(E("A")), "")
        self.assertTrue(domino.security_pages(E("G", url="https://accounts.google.com"))[0].startswith("https://myaccount"))


class RescueStepsTests(unittest.TestCase):
    def setUp(self):
        self.entries = home_vault()
        self.keys = domino.analyze(self.entries)

    def steps(self, title):
        entry = next(e for e in self.entries if e.title == title)
        return entry, rescue.build_steps(entry, self.entries, self.keys)

    def test_mailbox_takeover(self):
        _entry, steps = self.steps("Gmail")
        ids = [s.id for s in steps]
        self.assertEqual(ids[:4], ["password", "sessions", "2fa", "recovery"])
        self.assertIn("mail_rules", ids)
        deps = next(s for s in steps if s.id == "dependents")
        self.assertIn(deps.entries[0].title, ("mBank", "Allegro", "ePUAP"))  # ważne konta najpierw
        self.assertEqual(deps.entries[-1].title, "Netflix")
        reused = next(s for s in steps if s.id == "reused")
        self.assertEqual([e.title for e in reused.entries], ["Allegro"])
        self.assertEqual(ids[-1], "report")

    def test_bank_account(self):
        _entry, steps = self.steps("mBank")
        ids = [s.id for s in steps]
        self.assertIn("mailbox:jan@gmail.com", ids)
        self.assertIn("bank", ids)
        self.assertIn("pesel", ids)
        self.assertIn(rescue.CARD_BLOCK_PHONE, next(s for s in steps if s.id == "bank").text)

    def test_existing_2fa_changes_wording(self):
        _entry, steps = self.steps("Poczta WP")
        self.assertIn("Sprawdź", next(s for s in steps if s.id == "2fa").title)

    def test_progress_persists_in_vault(self):
        vault = Vault()
        for e in self.entries:
            vault.add_entry(e)
        gmail = self.entries[0]
        rescue.set_done(vault.settings, gmail.id, "password", True)
        rescue.set_done(vault.settings, gmail.id, self.entries[1].id, True, "entries_done")
        again = Vault.from_json(vault.to_json())
        state = rescue.progress(again.settings, gmail.id)
        self.assertEqual(state["done"], ["password"])
        self.assertEqual(state["entries_done"], [self.entries[1].id])
        self.assertEqual(rescue.open_cases(again.settings), [gmail.id])
        rescue.clear(again.settings, gmail.id)
        self.assertEqual(rescue.open_cases(again.settings), [])
        self.assertEqual(rescue.progress({"rescue": "zepsute"}, "x")["done"], [])


class EmergencyCardTests(unittest.TestCase):
    def test_render_file_and_server_cards(self):
        for info in (CardInfo("Dom", "file", r"C:\Users\Jan\Sejf.vault", keyfile=True, yubikey=True,
                              recovery_code="ABCDE-FGHJK-LMNPQ-RSTUV-WXYZ2-34567",
                              download_url="https://github.com/facior/KeyStead/releases/latest"),
                     CardInfo("Praca", "server", "https://ks.firma.pl", account="jan", has_recovery=True,
                              org_recovery=True, download_url="https://ks.firma.pl/download", password_box=False)):
            img = render(info)
            self.assertEqual(img.size, (1240, 1754))
            if qr.available():
                self.assertIn(info.download_url, qr.read_codes(img))  # kod QR do pobrania programu działa

    def test_pdf_file(self):
        fd, path = tempfile.mkstemp(suffix=".pdf")
        os.close(fd)
        self.addCleanup(os.remove, path)
        save_pdf(CardInfo("Dom", "file", "C:/sejf.vault", download_url="https://example.com"), path)
        with open(path, "rb") as f:
            self.assertEqual(f.read(5), b"%PDF-")


if __name__ == "__main__":
    unittest.main()
