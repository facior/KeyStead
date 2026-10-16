"""
Testy regresyjne zabezpieczeń: siła haseł i polityka hasła głównego, generator fraz,
ochrona nagłówka sejfu przed DoS, transport WebDAV oraz bezpieczne usuwanie eksportów.
"""

import os
import shutil
import struct
import tempfile
import unittest

from backups.webdav_backup import WebDAVBackupProvider
from core.crypto import (
    MAGIC_HEADER, CURRENT_VERSION, SALT_LEN, NONCE_LEN,
    InvalidVaultHeaderError, decrypt_payload, encrypt_payload
)
from core.generator import (
    check_master_password, evaluate_password_strength, generate_passphrase,
    generate_password, get_wordlist
)
from importers import is_plaintext_export, secure_delete_file


class TestPasswordStrength(unittest.TestCase):
    def test_common_and_patterned_passwords_are_weak(self):
        for pwd in ["Password123!", "P@ssw0rd2024", "Qwerty2024!!", "aaaaaaaaaaaaaaaa",
                    "Kochamcie1990!", "abcabcabcabc", "Lukasz1999", "zaq1@WSX"]:
            self.assertLessEqual(evaluate_password_strength(pwd)["score"], 1, pwd)

    def test_random_passwords_are_strong(self):
        for _ in range(20):
            self.assertEqual(evaluate_password_strength(generate_password(length=16))["score"], 4)

    def test_passphrase_strength_counts_words(self):
        self.assertLessEqual(evaluate_password_strength(generate_passphrase(word_count=4))["score"], 2)
        self.assertGreaterEqual(evaluate_password_strength(generate_passphrase(word_count=5))["score"], 3)
        self.assertEqual(evaluate_password_strength(generate_passphrase(word_count=6))["score"], 4)

    def test_wordlist_is_full_eff_list(self):
        words = get_wordlist()
        self.assertEqual(len(words), 7776)
        self.assertEqual(len(set(words)), 7776)


class TestMasterPasswordPolicy(unittest.TestCase):
    def test_weak_or_short_master_rejected(self):
        for pwd in ["krotkie", "Password123!", "Kochamcie1990!", "aaaaaaaaaaaaaaaa"]:
            allowed, msg = check_master_password(pwd)
            self.assertFalse(allowed, pwd)
            self.assertTrue(msg)

    def test_strong_master_accepted_without_warning(self):
        allowed, msg = check_master_password(generate_passphrase(word_count=6))
        self.assertTrue(allowed)
        self.assertEqual(msg, "")

    def test_medium_master_requires_confirmation(self):
        allowed, msg = check_master_password(generate_passphrase(word_count=4))
        self.assertTrue(allowed)
        self.assertTrue(msg)


class TestVaultHeaderHardening(unittest.TestCase):
    def _forged_blob(self, t, m, p):
        header = MAGIC_HEADER + struct.pack(">BIII", CURRENT_VERSION, t, m, p) + b"\0" * SALT_LEN + b"\0" * NONCE_LEN
        return header + b"\0" * 32

    def test_absurd_kdf_params_rejected_before_kdf(self):
        for t, m, p in [(1, 65536, 4), (3, 1024, 4), (3, 2 ** 31, 4), (10 ** 6, 65536, 4), (3, 65536, 0)]:
            with self.assertRaises(InvalidVaultHeaderError):
                decrypt_payload(self._forged_blob(t, m, p), "haslo")

    def test_default_params_roundtrip(self):
        blob = encrypt_payload(b"dane", "haslo-glowne")
        self.assertEqual(decrypt_payload(blob, "haslo-glowne"), b"dane")


class TestWebDAVTransport(unittest.TestCase):
    def test_transport_rules(self):
        check = WebDAVBackupProvider.check_transport
        self.assertEqual(check("https://cloud.example.com/dav"), (True, ""))
        self.assertFalse(check("http://cloud.example.com/dav")[0])
        self.assertFalse(check("ftp://nas/dav")[0])
        for local in ["http://192.168.1.10:5005/", "http://nas.local/dav", "http://localhost:8080"]:
            allowed, warning = check(local)
            self.assertTrue(allowed, local)
            self.assertTrue(warning)

    def test_upload_refuses_public_http(self):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, "s.vault")
            with open(path, "wb") as f:
                f.write(b"x")
            status = WebDAVBackupProvider().upload_backup(path, {"url": "http://example.com/dav", "username": "u", "password": "p"})
            self.assertFalse(status.success)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestSecureDelete(unittest.TestCase):
    def test_export_is_overwritten_and_removed(self):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, "export.csv")
            with open(path, "w") as f:
                f.write("name,password\nbank,TajneHaslo\n")
            self.assertTrue(is_plaintext_export(path))
            self.assertFalse(is_plaintext_export(os.path.join(tmp, "baza.kdbx")))
            secure_delete_file(path)
            self.assertFalse(os.path.exists(path))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
