"""
Własny odczyt baz KeePass (.kdbx) – na plikach utworzonych przez KeePass/KeePassXC (zestaw testowy keepass-rs,
licencja MIT, patrz tests/fixtures/kdbx/README.md). Oczekiwane wartości pochodzą z testów keepass-rs.
"""

import os
import struct
import tempfile
import unittest

from importers.kdbx import KdbxError, KdbxPasswordError, aes_kdf, keyfile_key, open_kdbx
from importers.keepass import KeePassImporter, check_kdbx_header

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "kdbx")


def read(name: str) -> bytes:
    with open(os.path.join(FIX, name), "rb") as f:
        return f.read()


class KdbxReaderTests(unittest.TestCase):
    def test_kdbx3_salsa20_protected_fields(self):
        db = open_kdbx(read("test_db_with_password.kdbx"), "demopass", None)
        self.assertEqual(db.version, (3, 1))
        self.assertEqual(db.name, "Database Name for Demo Database")
        self.assertEqual(len(db.entries), 6)
        by_title = {e.fields.get("Title"): e for e in db.entries}
        self.assertEqual(by_title["Sample Entry #2"].fields["Password"], "12345")
        self.assertEqual(by_title["test entry"].fields["Password"], "nWuu5AtqsxqNhnYgLwoB")
        self.assertEqual(by_title["test entry"].group, "Subgroup")

    def test_kdbx3_chacha20_protected_fields(self):
        db = open_kdbx(read("test_db_kdbx3_with_chacha20_protected_fields.kdbx"), "password", None)
        self.assertTrue(db.entries)
        self.assertTrue(all(e.fields.get("Password") == "admin" for e in db.entries))

    def test_kdbx4_kdfs_and_ciphers(self):
        for name, count, version in (("test_db_kdbx4_with_password_argon2.kdbx", 2, (4, 0)),
                                     ("test_db_kdbx4_with_password_argon2id.kdbx", 2, (4, 0)),
                                     ("test_db_kdbx4_with_password_aes.kdbx", 1, (4, 1)),
                                     ("test_db_kdbx4_with_password_argon2id_chacha20.kdbx", 1, (4, 0)),
                                     ("test_db_kdbx41_with_password_aes.kdbx", 4, (4, 1))):
            db = open_kdbx(read(name), "demopass", None)
            self.assertEqual((len(db.entries), db.version), (count, version), name)

    def test_keyfiles(self):
        self.assertEqual(len(open_kdbx(read("test_db_with_keyfile.kdbx"), None, read("test_key.key")).entries), 1)
        self.assertEqual(len(open_kdbx(read("test_db_with_keyfile_xml.kdbx"), None, read("test_key_xml.key")).entries), 6)
        db = open_kdbx(read("test_db_kdbx4_with_keyfile_v2.kdbx"), "demopass", read("test_db_kdbx4_with_keyfile_v2.keyx"))
        self.assertEqual(len(db.entries), 1)
        with self.assertRaises(KdbxPasswordError):  # sam plik-klucz bez hasła
            open_kdbx(read("test_db_kdbx4_with_keyfile_v2.kdbx"), None, read("test_db_kdbx4_with_keyfile_v2.keyx"))

    def test_keyfile_formats(self):
        self.assertEqual(keyfile_key(b"\x01" * 32), b"\x01" * 32)
        self.assertEqual(keyfile_key(b"ab" * 32), bytes.fromhex("ab" * 32))
        self.assertEqual(len(keyfile_key(b"dowolny plik")), 32)
        bad = (b'<?xml version="1.0"?><KeyFile><Meta><Version>2.0</Version></Meta>'
               b'<Key><Data Hash="00000000">' + b"AB" * 32 + b"</Data></Key></KeyFile>")
        with self.assertRaises(KdbxError):
            keyfile_key(bad)

    def test_totp_and_recycle_bin(self):
        db = open_kdbx(read("test_db_kdbx4_with_totp_entry.kdbx"), "test", None)
        self.assertEqual(db.entries[0].fields["otp"],
                         "otpauth://totp/KeePassXC:none?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&issuer=KeePassXC")
        db = open_kdbx(read("test_db_kdbx4_with_password_deleted_entry.kdbx"), "demopass", None)
        self.assertEqual(len(db.entries), 2)  # wpis z kosza KeePassa pominięty

    def test_wrong_password_and_bad_files(self):
        for name in ("test_db_with_password.kdbx", "test_db_kdbx4_with_password_argon2.kdbx",
                     "test_db_kdbx4_with_password_aes.kdbx"):
            with self.assertRaises(KdbxPasswordError, msg=name):
                open_kdbx(read(name), "zle haslo", None)
        with self.assertRaisesRegex(KdbxError, "Twofish"):
            open_kdbx(read("test_db_kdbx4_with_password_argon2_twofish.kdbx"), "demopass", None)
        with self.assertRaises(KdbxError):
            open_kdbx(os.urandom(2048), "x", None)
        tampered = bytearray(read("test_db_kdbx4_with_password_aes.kdbx"))
        tampered[-40] ^= 1
        with self.assertRaises(KdbxError):
            open_kdbx(bytes(tampered), "demopass", None)

    def test_aes_kdf_matches_plain_ecb(self):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        import hashlib
        key, seed = os.urandom(32), os.urandom(32)
        enc = Cipher(algorithms.AES(seed), modes.ECB()).encryptor()
        block = key
        for _i in range(1000):
            block = enc.update(block)
        self.assertEqual(aes_kdf(key, seed, 1000), hashlib.sha256(block).digest())


class KeePassImporterTests(unittest.TestCase):
    def test_import_kdbx(self):
        imp = KeePassImporter()
        result = imp.parse(os.path.join(FIX, "test_db_with_password.kdbx"), "demopass")
        self.assertTrue(result.success, result.errors)
        titles = {i.title: i for i in result.items}
        self.assertEqual(titles["test entry"].category, "Subgroup")
        self.assertEqual(titles["Sample Entry"].category, "Loginy")
        self.assertEqual(titles["Sample Entry #2"].password, "12345")

    def test_import_totp_becomes_secret(self):
        result = KeePassImporter().parse(os.path.join(FIX, "test_db_kdbx4_with_totp_entry.kdbx"), "test")
        item = result.items[0]
        self.assertEqual(item.totp_secret, "JBSWY3DPEHPK3PXP")
        self.assertNotIn("otp", item.custom_fields)

    def test_import_errors_are_readable(self):
        result = KeePassImporter().parse(os.path.join(FIX, "test_db_with_password.kdbx"), "zle")
        self.assertFalse(result.success)
        self.assertIn("Błędne hasło", result.errors[0])
        result = KeePassImporter().parse(os.path.join(FIX, "test_db_with_keyfile.kdbx"), None,
                                         os.path.join(FIX, "test_key.key"))
        self.assertTrue(result.success, result.errors)

    def test_header_limits_on_real_file(self):
        self.assertEqual(check_kdbx_header(os.path.join(FIX, "test_db_kdbx4_with_password_argon2.kdbx")), "")

    def test_gzip_bomb_rejected(self):
        from importers import kdbx
        import zlib
        packer = zlib.compressobj(9, zlib.DEFLATED, 31)
        bomb = packer.compress(b"\0" * (4 * 1024 * 1024)) + packer.flush()
        self.assertLess(len(bomb), 10_000)
        with unittest.mock.patch.object(kdbx, "MAX_XML_BYTES", 1024 * 1024):
            with self.assertRaisesRegex(KdbxError, "zbyt duża"):
                kdbx._gunzip(bomb)
        with self.assertRaises(KdbxError):
            kdbx._gunzip(b"\x1f\x8b" + os.urandom(100))


import unittest.mock  # noqa: E402

if __name__ == "__main__":
    unittest.main()
