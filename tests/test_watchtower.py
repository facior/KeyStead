"""Monitorowanie wycieków: powiadomienie tylko o nowych wyciekach, rytm sprawdzania, zgoda użytkownika."""

import shutil
import tempfile
import time
import unittest

from core.security_audit import AuditIssue, AuditReport
from core.vault import VaultEntry
from core.watchtower import Watchtower, attention_count, consent


def report_with(*issues):
    r = AuditReport()
    for entry, kind in issues:
        r.issues.append(AuditIssue(entry, kind, "high", kind, ""))
    return r


class TestWatchtower(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.w = Watchtower("sejf1", directory=self.tmp)
        self.a = VaultEntry(title="Bank", password="x")
        self.b = VaultEntry(title="Poczta", password="y")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_only_new_breaches_reported(self):
        self.assertTrue(self.w.breach_check_due())
        new = self.w.record(report_with((self.a, "breached")), breach_checked=True)
        self.assertEqual(new, [(self.a.id, "Bank")])
        self.assertFalse(self.w.breach_check_due())
        new = self.w.record(report_with((self.a, "breached"), (self.b, "breached")), breach_checked=True)
        self.assertEqual(new, [(self.b.id, "Poczta")])  # „Bank” już zgłoszony

    def test_changed_password_then_breached_again_is_reported(self):
        self.w.record(report_with((self.a, "breached")), True)
        self.w.record(report_with(), True)  # hasło zmienione – brak wycieku
        self.assertEqual(self.w.record(report_with((self.a, "breached")), True), [(self.a.id, "Bank")])

    def test_local_only_audit_does_not_touch_breach_state(self):
        self.w.record(report_with((self.a, "breached")), True)
        self.assertEqual(self.w.record(report_with(), breach_checked=False), [])
        self.assertEqual(self.w.known_breached(), [self.a.id])

    def test_hibp_failure_retries_sooner(self):
        r = report_with()
        r.hibp_failures = 3
        self.w.record(r, True)
        state = self.w._load()
        self.assertLess(state["last_breach_check"], time.time() - 20 * 3600)

    def test_attention_count_and_consent(self):
        r = report_with((self.a, "weak"), (self.a, "reused"), (self.b, "missing_totp"))
        self.assertEqual(attention_count(r), 1)  # jeden wpis; brak 2FA się nie liczy
        self.assertIsNone(consent({}))
        self.assertTrue(consent({"auto_breach_check": True}))
        self.assertIsNone(consent({"auto_breach_check": "tak"}))


if __name__ == "__main__":
    unittest.main()
