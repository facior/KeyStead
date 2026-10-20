"""
Szybkie odblokowanie (Windows Hello) – logika magazynu na atrapie dostawcy (prawdziwy test wymaga PIN/odcisku).
"""

import hashlib
import hmac
import json
import os
import sys
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from core import quick_unlock
from core.quick_unlock import QuickUnlockError, QuickUnlockExpired, QuickUnlockStore, target_id


class FakeHello:
    """Deterministyczny „podpis” jak RSA PKCS#1 – inny klucz TPM = inny podpis."""

    def __init__(self, secret=b"tpm-key-1", available=True, cancel=False):
        self.secret, self._available, self.cancel = secret, available, cancel
        self.created = False
        self.prompts = 0

    def is_available(self):
        return self._available

    def sign(self, challenge, create=False):
        self.prompts += 1
        if self.cancel:
            raise QuickUnlockError("Anulowano potwierdzenie Windows Hello.")
        self.created = self.created or create
        return hmac.new(self.secret, challenge, hashlib.sha256).digest() * 8


class TestQuickUnlock(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.hello = FakeHello()
        self.store = QuickUnlockStore(self.hello, directory=self.tmp)
        self.target = target_id("file", r"C:\Sejfy\moj.vault")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_roundtrip_with_keyfile(self):
        self.store.enroll(self.target, "Hasło-Główne!", b"\x00\x01klucz")
        self.assertTrue(self.store.is_enrolled(self.target))
        self.assertEqual(self.store.unlock(self.target), ("Hasło-Główne!", b"\x00\x01klucz"))
        self.store.enroll(self.target, "inne", None)
        self.assertEqual(self.store.unlock(self.target), ("inne", None))

    def test_file_contains_no_plaintext(self):
        self.store.enroll(self.target, "SuperTajne123", None)
        raw = open(os.path.join(self.tmp, f"{self.target}.json"), encoding="utf-8").read()
        self.assertNotIn("SuperTajne123", raw)
        self.assertNotIn("verified_at", raw)  # data ważności też zaszyfrowana – nie da się jej przedłużyć

    def test_other_tpm_key_cannot_decrypt(self):
        self.store.enroll(self.target, "x", None)
        other = QuickUnlockStore(FakeHello(secret=b"inny-komputer"), directory=self.tmp)
        with self.assertRaises(QuickUnlockError):
            other.unlock(self.target)
        self.assertFalse(self.store.is_enrolled(self.target))  # nieaktualny zapis usunięty

    def test_file_bound_to_target(self):
        self.store.enroll(self.target, "x", None)
        other_target = target_id("file", r"C:\Sejfy\inny.vault")
        shutil.copy(os.path.join(self.tmp, f"{self.target}.json"), os.path.join(self.tmp, f"{other_target}.json"))
        with self.assertRaises(QuickUnlockError):
            self.store.unlock(other_target)

    def test_expires_after_valid_days(self):
        past = datetime.now(timezone.utc) - timedelta(days=15)
        with mock.patch.object(quick_unlock, "_now", return_value=past):
            self.store.enroll(self.target, "x", None)
        with self.assertRaises(QuickUnlockExpired):
            self.store.unlock(self.target, valid_days=14)
        self.assertEqual(self.store.unlock(self.target, valid_days=30), ("x", None))

    def test_cancel_and_missing(self):
        with self.assertRaises(QuickUnlockError):
            self.store.unlock(self.target)
        self.store.enroll(self.target, "x", None)
        self.hello.cancel = True
        with self.assertRaisesRegex(QuickUnlockError, "Anulowano"):
            self.store.unlock(self.target)
        self.assertTrue(self.store.is_enrolled(self.target))  # anulowanie nie kasuje zapisu

    def test_target_ids(self):
        a = target_id("file", r"C:\Sejfy\Moj.vault")
        if sys.platform == "win32":
            self.assertEqual(a, target_id("file", r"c:\sejfy\moj.vault"))  # Windows: wielkość liter bez znaczenia
        self.assertNotEqual(a, target_id("server", r"C:\Sejfy\Moj.vault"))

    def test_remove_all(self):
        self.store.enroll(self.target, "x", None)
        self.store.remove_all()
        self.assertFalse(self.store.is_enrolled(self.target))


if __name__ == "__main__":
    unittest.main()
