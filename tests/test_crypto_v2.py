"""
Format sejfu v2: klucz danych + klucze dostępu (hasło, kod odzyskiwania, klucz firmy), zgodność z v1,
odporność na podmianę nagłówka.
"""

import json
import struct
import unittest

from core.crypto import (InvalidPasswordOrCorruptDataError, InvalidVaultHeaderError, Keyring, MAGIC_HEADER,
                         blob_version, decrypt_payload, encrypt_payload, generate_org_keypair, load_org_private_key,
                         org_key_id, parse_org_public_key, seal, unseal, unseal_with_org_key, unseal_with_recovery_code)

DATA = "{\"name\": \"Mój sejf\", \"entries\": []}".encode("utf-8")


class TestV2Basics(unittest.TestCase):
    def test_v1_unchanged_without_keyring(self):
        blob = seal(DATA, "haslo-123")
        self.assertEqual(blob_version(blob), 1)
        plain, ring = unseal(blob, "haslo-123")
        self.assertEqual(plain, DATA)
        self.assertIsNone(ring)

    def test_v2_roundtrip_and_legacy_api(self):
        ring = Keyring.new("haslo-123", b"klucz")
        blob = seal(DATA, "haslo-123", b"klucz", ring)
        self.assertEqual(blob_version(blob), 2)
        self.assertEqual(decrypt_payload(blob, "haslo-123", b"klucz"), DATA)  # stare wywołania działają
        with self.assertRaises(InvalidPasswordOrCorruptDataError):
            decrypt_payload(blob, "haslo-123")  # bez pliku-klucza
        with self.assertRaises(InvalidPasswordOrCorruptDataError):
            unseal(blob, "zle", b"klucz")

    def test_stable_dek_and_fast_resave(self):
        ring = Keyring.new("haslo-123")
        _, ring2 = unseal(seal(DATA, "haslo-123", None, ring), "haslo-123")
        self.assertEqual(ring.dek, ring2.dek)
        slots_before = json.dumps(ring2.slots)
        seal(DATA + b" ", "haslo-123", None, ring2)  # to samo hasło – klucz dostępu bez zmian (bez Argon2)
        self.assertEqual(json.dumps(ring2.slots), slots_before)

    def test_password_change_rewraps_only_password_slot(self):
        ring = Keyring.new("stare-haslo-1")
        code = ring.add_recovery_code()
        recovery_slot = [s for s in ring.slots if s["type"] == "recovery"][0]
        blob = seal(DATA, "nowe-haslo-2", None, ring)
        self.assertEqual(unseal(blob, "nowe-haslo-2")[0], DATA)
        with self.assertRaises(InvalidPasswordOrCorruptDataError):
            unseal(blob, "stare-haslo-1")
        self.assertIn(recovery_slot, ring.slots)
        self.assertEqual(unseal_with_recovery_code(blob, code)[0], DATA)  # kod nadal działa


class TestRecoveryCode(unittest.TestCase):
    def test_recovery_code_unlocks_and_allows_new_password(self):
        ring = Keyring.new("zapomniane-haslo")
        code = ring.add_recovery_code()
        self.assertRegex(code, r"^([A-Z2-9]{5}-){5}[A-Z2-9]{5}$")
        blob = seal(DATA, "zapomniane-haslo", None, ring)
        plain, recovered = unseal_with_recovery_code(blob, code.lower().replace("-", " "))  # wpis bez myślników, małymi
        self.assertEqual(plain, DATA)
        new_blob = seal(plain, "nowe-haslo-XYZ", None, recovered)
        self.assertEqual(unseal(new_blob, "nowe-haslo-XYZ")[0], DATA)
        with self.assertRaises(InvalidPasswordOrCorruptDataError):
            unseal_with_recovery_code(blob, "AAAAA-AAAAA-AAAAA-AAAAA-AAAAA-AAAAA")

    def test_removed_recovery_code_stops_working(self):
        ring = Keyring.new("h-123456")
        code = ring.add_recovery_code()
        ring.remove_recovery_code()
        with self.assertRaises(InvalidPasswordOrCorruptDataError):
            unseal_with_recovery_code(seal(DATA, "h-123456", None, ring), code)


class TestOrgRecovery(unittest.TestCase):
    def test_org_key_roundtrip(self):
        public, key_file = generate_org_keypair("haslo-klucza-firmy")
        ring = Keyring.new("haslo-uzytkownika")
        key_id = ring.set_org_key(public)
        self.assertEqual(key_id, key_file["key_id"])
        self.assertEqual(key_id, org_key_id(parse_org_public_key(public)))
        blob = seal(DATA, "haslo-uzytkownika", None, ring)
        private = load_org_private_key(json.loads(json.dumps(key_file)), "haslo-klucza-firmy")
        plain, recovered = unseal_with_org_key(blob, private)
        self.assertEqual(plain, DATA)
        temp = seal(plain, "Tymczasowe-1234", None, recovered)
        self.assertEqual(unseal(temp, "Tymczasowe-1234")[0], DATA)

    def test_wrong_passphrase_and_other_org(self):
        public, key_file = generate_org_keypair("haslo-klucza-firmy")
        with self.assertRaises(InvalidPasswordOrCorruptDataError):
            load_org_private_key(key_file, "zle-haslo-klucza")
        ring = Keyring.new("u-123456")
        ring.set_org_key(public)
        _, other_file = generate_org_keypair("inna-firma-haslo")
        with self.assertRaisesRegex(InvalidPasswordOrCorruptDataError, "innym kluczem"):
            unseal_with_org_key(seal(DATA, "u-123456", None, ring), load_org_private_key(other_file, "inna-firma-haslo"))

    def test_private_key_file_has_no_plain_key(self):
        _, key_file = generate_org_keypair("haslo-klucza-firmy")
        self.assertNotIn("haslo-klucza-firmy", json.dumps(key_file))
        with self.assertRaises(Exception):
            generate_org_keypair("krotkie")


class TestTampering(unittest.TestCase):
    def _blob(self):
        ring = Keyring.new("h-123456")
        ring.add_recovery_code()
        return seal(DATA, "h-123456", None, ring)

    def test_header_cannot_be_modified(self):
        blob = self._blob()
        off = len(MAGIC_HEADER) + 1
        (hlen,) = struct.unpack(">I", blob[off:off + 4])
        header = json.loads(blob[off + 4:off + 4 + hlen])
        header["slots"] = [s for s in header["slots"] if s["type"] != "recovery"]  # serwer usuwa kod odzyskiwania
        new_header = json.dumps(header, separators=(",", ":")).encode()
        forged = blob[:off] + struct.pack(">I", len(new_header)) + new_header + blob[off + 4 + hlen:]
        with self.assertRaises(InvalidPasswordOrCorruptDataError):
            unseal(forged, "h-123456")

    def test_weak_kdf_params_rejected(self):
        blob = self._blob()
        weak = blob.replace(b'"m":65536', b'"m":8')
        with self.assertRaises(InvalidVaultHeaderError):
            unseal(weak, "h-123456")

    def test_huge_header_rejected(self):
        bad = MAGIC_HEADER + struct.pack(">BI", 2, 10 ** 9) + b"x" * 100
        with self.assertRaises(InvalidVaultHeaderError):
            unseal(bad, "x")


if __name__ == "__main__":
    unittest.main()
