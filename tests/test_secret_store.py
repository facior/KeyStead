"""Token urządzenia poza sejfem: DPAPI (Windows), pęk kluczy (macOS / Linux z Secret Service) albo zapis zwykły."""

import sys
import unittest
import uuid

from core import secret_store


class SecretStoreTests(unittest.TestCase):
    def test_round_trip_on_this_system(self):
        name = f"test-{uuid.uuid4().hex[:8]}"
        stored = secret_store.protect_secret("tajny-token-123", name=name)
        self.addCleanup(secret_store.forget_secret, stored)
        self.assertNotIn("tajny-token-123", stored if not stored.startswith("plain:") else "")
        self.assertEqual(secret_store.unprotect_secret(stored), "tajny-token-123")
        if sys.platform == "win32":
            self.assertTrue(stored.startswith("dpapi:"))
        elif sys.platform == "darwin":
            self.assertTrue(stored.startswith("keyring:"), stored)  # pęk kluczy macOS jest zawsze dostępny

    def test_forgotten_keyring_secret_raises(self):
        if secret_store._keyring() is None:
            self.skipTest("brak systemowego pęku kluczy")
        stored = secret_store.protect_secret("x", name=f"test-{uuid.uuid4().hex[:8]}")
        if not stored.startswith("keyring:"):
            self.skipTest("ten system używa innego zabezpieczenia")
        secret_store.forget_secret(stored)
        with self.assertRaises(OSError):
            secret_store.unprotect_secret(stored)

    def test_empty_and_legacy_values(self):
        self.assertEqual(secret_store.protect_secret(""), "")
        self.assertEqual(secret_store.unprotect_secret("plain:abc"), "abc")
        self.assertEqual(secret_store.unprotect_secret("abc"), "abc")  # zapis sprzed ochrony tokenu


if __name__ == "__main__":
    unittest.main()
