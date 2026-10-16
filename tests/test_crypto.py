"""
Testy jednostkowe modułu kryptograficznego.
"""

import unittest
from core.crypto import (
    encrypt_payload,
    decrypt_payload,
    compute_sha256,
    InvalidPasswordOrCorruptDataError,
    InvalidVaultHeaderError
)


class TestCrypto(unittest.TestCase):
    def test_encrypt_decrypt_cycle(self):
        secret_message = b"Tajna tresc sejfu 123456789!@#$%"
        password = "MojeSuperSilneHaslo123!"

        encrypted = encrypt_payload(secret_message, password)
        self.assertNotEqual(encrypted, secret_message)
        self.assertTrue(encrypted.startswith(b"SECVAULT"))

        decrypted = decrypt_payload(encrypted, password)
        self.assertEqual(decrypted, secret_message)

    def test_wrong_password_fails(self):
        secret_message = b"Dane do ochrony"
        encrypted = encrypt_payload(secret_message, "DobreHaslo")

        with self.assertRaises(InvalidPasswordOrCorruptDataError):
            decrypt_payload(encrypted, "ZleHaslo")

    def test_keyfile_support(self):
        secret_message = b"Dane z kluczem plikowym"
        password = "Haslo"
        keyfile = b"\x01\x02\x03\x04" * 8

        encrypted = encrypt_payload(secret_message, password, keyfile_bytes=keyfile)

        # Bez pliku klucza powinno wyrzucić błąd
        with self.assertRaises(InvalidPasswordOrCorruptDataError):
            decrypt_payload(encrypted, password, keyfile_bytes=None)

        # Z błędnym kluczem powinno wyrzucić błąd
        with self.assertRaises(InvalidPasswordOrCorruptDataError):
            decrypt_payload(encrypted, password, keyfile_bytes=b"zly_klucz")

        # Z poprawnym powinno odszyfrować
        decrypted = decrypt_payload(encrypted, password, keyfile_bytes=keyfile)
        self.assertEqual(decrypted, secret_message)

    def test_tampered_ciphertext_fails(self):
        secret_message = b"Nie modyfikuj mnie"
        encrypted = bytearray(encrypt_payload(secret_message, "Haslo123"))

        # Zmiana jednego bajtu na końcu (w tagu/szyfrogramie)
        encrypted[-1] ^= 0x01

        with self.assertRaises(InvalidPasswordOrCorruptDataError):
            decrypt_payload(bytes(encrypted), "Haslo123")

    def test_invalid_header_fails(self):
        with self.assertRaises(InvalidVaultHeaderError):
            decrypt_payload(b"ZLYNAGLOWEK_I_JAKIES_DANE_ZA_KROTKI", "Haslo")

    def test_sha256(self):
        h = compute_sha256(b"antigravity")
        self.assertEqual(len(h), 64)


if __name__ == "__main__":
    unittest.main()
