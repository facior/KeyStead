"""
Testy jednostkowe modelu sejfu, zapisu/odczytu, generatora i TOTP.
"""

import os
import tempfile
import unittest
from core.vault import Vault, VaultEntry
from core.storage import save_vault, load_vault
from core.generator import generate_password, generate_passphrase, evaluate_password_strength
from core.totp_service import get_current_totp, is_valid_totp_secret, parse_otpauth_uri
import pyotp


class TestVaultAndStorage(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.vault_path = os.path.join(self.temp_dir, "test_vault.vault")

    def tearDown(self):
        if os.path.exists(self.vault_path):
            os.remove(self.vault_path)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)

    def test_vault_entry_and_history(self):
        entry = VaultEntry(title="Test Account", username="user@example.com", password="Pass1")
        self.assertEqual(entry.title, "Test Account")
        self.assertEqual(len(entry.password_history), 0)

        # Zmiana hasła powinna zapisać stare w historii
        entry.update(password="Pass2")
        self.assertEqual(entry.password, "Pass2")
        self.assertEqual(len(entry.password_history), 1)
        self.assertEqual(entry.password_history[0]["password"], "Pass1")

    def test_save_and_load_vault(self):
        vault = Vault(name="Sejf Testowy")
        entry1 = VaultEntry(
            title="GitHub",
            category="Loginy",
            username="dev",
            password="StrongPassword123!",
            url="https://github.com",
            tags=["dev", "git"]
        )
        vault.add_entry(entry1)

        password = "MojeHasloGlowne123"
        size, sha = save_vault(vault, self.vault_path, password)
        self.assertGreater(size, 0)
        self.assertEqual(len(sha), 64)

        loaded_vault = load_vault(self.vault_path, password)
        self.assertEqual(loaded_vault.name, "Sejf Testowy")
        self.assertEqual(len(loaded_vault.entries), 1)
        loaded_entry = loaded_vault.get_entry(entry1.id)
        self.assertIsNotNone(loaded_entry)
        self.assertEqual(loaded_entry.title, "GitHub")
        self.assertEqual(loaded_entry.password, "StrongPassword123!")
        self.assertEqual(loaded_entry.tags, ["dev", "git"])

    def test_search(self):
        vault = Vault()
        e1 = VaultEntry(title="ProtonMail", username="proton@pm.me", tags=["email"])
        e2 = VaultEntry(title="Gmail", username="work@gmail.com", tags=["email"])
        e3 = VaultEntry(title="Bank", username="12345", category="Karty płatnicze")
        vault.add_entry(e1)
        vault.add_entry(e2)
        vault.add_entry(e3)

        results = vault.search(query="mail")
        self.assertEqual(len(results), 2)

        results_cat = vault.search(category="Karty płatnicze")
        self.assertEqual(len(results_cat), 1)
        self.assertEqual(results_cat[0].title, "Bank")

    def test_password_generator(self):
        pwd = generate_password(length=20, avoid_ambiguous=True)
        self.assertEqual(len(pwd), 20)
        eval_res = evaluate_password_strength(pwd)
        self.assertGreaterEqual(eval_res["score"], 3)

        passphrase = generate_passphrase(word_count=5)
        self.assertEqual(len(passphrase.split("-")), 5)

    def test_totp(self):
        secret = pyotp.random_base32()
        self.assertTrue(is_valid_totp_secret(secret))
        code = get_current_totp(secret)
        self.assertIsNotNone(code)
        self.assertEqual(len(code), 6)

        uri = f"otpauth://totp/Google:user@gmail.com?secret={secret}&issuer=Google"
        parsed = parse_otpauth_uri(uri)
        self.assertIsNotNone(parsed)
        p_secret, p_acc, p_iss = parsed
        self.assertEqual(p_secret, secret)
        self.assertEqual(p_iss, "Google")


if __name__ == "__main__":
    unittest.main()
