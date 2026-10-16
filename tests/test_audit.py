"""
Testy jednostkowe audytu bezpieczeństwa i sprawdzania wycieków HIBP.
"""

import unittest
from core.vault import Vault, VaultEntry
from core.security_audit import check_password_breach_hibp, run_vault_audit


class TestSecurityAudit(unittest.TestCase):
    def test_hibp_known_breach(self):
        # Znane wyciekłe hasło "password"
        is_breached, count = check_password_breach_hibp("password")
        self.assertTrue(is_breached)
        self.assertGreater(count, 1000000)

    def test_hibp_unique_password(self):
        # Bardzo unikalne hasło, które z prawdopodobieństwem ~100% nigdy nie wyciekło
        unique_pwd = "X$9qZ#8vL!2mK@7pW&4uT^1sY"
        is_breached, count = check_password_breach_hibp(unique_pwd)
        self.assertFalse(is_breached)
        self.assertEqual(count, 0)

    def test_vault_audit_detects_reused_and_weak(self):
        vault = Vault()
        # Dwa wpisy z tym samym hasłem
        e1 = VaultEntry(title="Serwis A", category="Loginy", username="user@a.com", password="common_pass_123")
        e2 = VaultEntry(title="Serwis B", category="Loginy", username="user@b.com", password="common_pass_123")
        # Jeden wpis ze słabym hasłem
        e3 = VaultEntry(title="Serwis C", category="Loginy", username="user@c.com", password="123")
        # Jeden silny wpis z TOTP
        e4 = VaultEntry(title="Bank", category="Loginy", username="user@bank.com", password="SuperStrongPassword!#9921", totp_secret="JBSWY3DPEHPK3PXP")

        vault.add_entry(e1)
        vault.add_entry(e2)
        vault.add_entry(e3)
        vault.add_entry(e4)

        report = run_vault_audit(vault, check_hibp=False)

        # Powinno wykryć powtórzone hasła dla e1 i e2
        self.assertEqual(len(report.reused_issues), 2)
        # Powinno wykryć słabe hasło dla e3
        self.assertTrue(any(i.entry_title == "Serwis C" for i in report.weak_issues))
        # Powinno wykryć brak 2FA dla e1, e2, e3
        self.assertEqual(len(report.missing_totp_issues), 3)

        # Wynik nie powinien wynosić 100
        self.assertLess(report.score, 100)


if __name__ == "__main__":
    unittest.main()
