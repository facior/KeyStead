"""
Odporność importu na złośliwe pliki: pola niewłaściwego typu, limity, parametry KDF w nagłówku KeePass.
"""

import os
import struct
import tempfile
import unittest

from core.vault import Vault, VaultEntry
from importers import apply_import
from importers.base import ImportItem, ImportResult, MAX_IMPORT_ITEMS
from importers.keepass import check_kdbx_header

try:
    import pykeepass
    BLANK_KDBX = os.path.join(os.path.dirname(pykeepass.__file__), "blank_database.kdbx")
except ImportError:
    BLANK_KDBX = ""


def kdbx4_header(params: dict) -> bytes:
    vd = b"\x00\x01"
    for key, value in params.items():
        k = key.encode()
        vd += bytes([0x05]) + struct.pack("<I", len(k)) + k + struct.pack("<I", 8) + struct.pack("<Q", value)
    vd += b"\x00"
    head = struct.pack("<IIHH", 0x9AA2D903, 0xB54BFB67, 1, 4)
    head += bytes([11]) + struct.pack("<I", len(vd)) + vd
    head += bytes([0]) + struct.pack("<I", 4) + b"\r\n\r\n"
    return head


class TestKdbxHeader(unittest.TestCase):
    def write(self, data: bytes) -> str:
        fd, path = tempfile.mkstemp(suffix=".kdbx")
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        self.addCleanup(os.remove, path)
        return path

    @unittest.skipUnless(BLANK_KDBX and os.path.exists(BLANK_KDBX), "brak pykeepass")
    def test_real_database_accepted(self):
        self.assertEqual(check_kdbx_header(BLANK_KDBX), "")

    def test_huge_argon2_memory_rejected(self):
        path = self.write(kdbx4_header({"M": 64 * 1024 ** 3, "I": 2, "P": 2}))
        self.assertIn("pamięci", check_kdbx_header(path))

    def test_huge_aes_rounds_rejected(self):
        path = self.write(kdbx4_header({"R": 2 ** 40}))
        self.assertIn("rund", check_kdbx_header(path))
        kdbx3 = struct.pack("<IIHH", 0x9AA2D903, 0xB54BFB67, 1, 3) + bytes([6]) + struct.pack("<H", 8) \
            + struct.pack("<Q", 2 ** 50) + bytes([0]) + struct.pack("<H", 0)
        self.assertIn("rund", check_kdbx_header(self.write(kdbx3)))

    def test_sane_params_and_garbage(self):
        self.assertEqual(check_kdbx_header(self.write(kdbx4_header({"M": 64 * 1024 ** 2, "I": 3, "P": 4}))), "")
        self.assertTrue(check_kdbx_header(self.write(b"nie kdbx")))


class TestFieldTypes(unittest.TestCase):
    def test_wrong_types_coerced_and_vault_keeps_working(self):
        vault = Vault("t")
        items = [ImportItem(title=["a"], username={"x": 1}, password=["p"], notes={"n": 1}, url=5,
                            tags="nie-lista", custom_fields=["x"]),
                 ImportItem(title="Bank", password="tajne", tags=["praca", {"x": 1}], custom_fields={"PIN": 1234})]
        stats = apply_import(vault, items)
        self.assertEqual(stats["added"], 2)
        self.assertEqual(len(vault.search("bank")), 1)
        self.assertEqual(vault.search("zzz"), [])  # wcześniej: AttributeError na polu-słowniku
        bank = vault.search("bank")[0]
        self.assertEqual(bank.tags, ["praca"])
        self.assertEqual(bank.custom_fields, {"PIN": "1234"})
        from core.security_audit import run_vault_audit
        run_vault_audit(vault, check_hibp=False)  # wcześniej: TypeError (unhashable list)

    def test_vault_file_with_wrong_types_loads(self):
        v = Vault.from_dict({"entries": [{"title": {"a": 1}, "password": ["x"], "tags": [1, None], "notes": None}]})
        e = next(iter(v.entries.values()))
        self.assertEqual((e.title, e.password, e.tags, e.notes), ("Bez tytułu", "", ["1"], ""))

    def test_field_length_and_item_limits(self):
        self.assertEqual(len(VaultEntry(title="x" * 10_000).title), 500)
        result = ImportResult("test")
        for i in range(MAX_IMPORT_ITEMS + 5):
            result.add_item(ImportItem(title=str(i)))
        self.assertEqual(len(result.items), MAX_IMPORT_ITEMS)
        self.assertEqual(len(result.errors), 1)


class TestTidyLogins(unittest.TestCase):
    def test_site_prefix_removed_only_when_matching_url(self):
        from importers.base import tidy_login
        self.assertEqual(tidy_login("--", "fotka.com, LukaszKubieniec", "https://fotka.com/"),
                         ("fotka.com", "LukaszKubieniec"))
        self.assertEqual(tidy_login("GitHub", "github.com, jan@x.pl", "https://www.github.com/login")[1], "jan@x.pl")
        self.assertEqual(tidy_login("Konto", "accounts.google.com, jan", "https://google.com")[1], "jan")
        # nie ruszamy loginów, które tylko wyglądają podobnie
        self.assertEqual(tidy_login("X", "inna.pl, jan", "https://fotka.com")[1], "inna.pl, jan")
        self.assertEqual(tidy_login("X", "Kowalski, Jan", "https://fotka.com")[1], "Kowalski, Jan")
        self.assertEqual(tidy_login("X", "fotka.com, jan", "")[1], "fotka.com, jan")
        self.assertEqual(tidy_login("--", "jan", ""), ("--", "jan"))
        self.assertEqual(tidy_login("Moja poczta", "jan", "https://poczta.pl"), ("Moja poczta", "jan"))

    def test_import_and_existing_vault_cleanup(self):
        from importers.base import tidy_vault, untidy_entries
        result = ImportResult("test")
        result.add_item(ImportItem(title="--", username="fotka.com, jan", url="https://fotka.com/"))
        self.assertEqual((result.items[0].title, result.items[0].username), ("fotka.com", "jan"))
        v = Vault("x")
        bad = VaultEntry(title="--", username="fotka.com, jan", password="p", url="https://fotka.com/")
        ok = VaultEntry(title="Bank", username="jan", password="p", url="https://bank.pl")
        v.add_entry(bad)
        v.add_entry(ok)
        self.assertEqual(len(untidy_entries(v)), 1)
        self.assertEqual(tidy_vault(v), 1)
        self.assertEqual((bad.title, bad.username, bad.password), ("fotka.com", "jan", "p"))
        self.assertEqual(bad.password_history, [])
        self.assertEqual(untidy_entries(v), [])


if __name__ == "__main__":
    unittest.main()
