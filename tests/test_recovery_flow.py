"""
Odzyskiwanie dostępu od początku do końca (bez interfejsu): kod osobisty, klucz firmy przez pakiet z panelu,
wymuszona zmiana hasła, licznik zapisów (inne urządzenia przyjmą odzyskaną wersję).
"""

import base64
import json
import os
import shutil
import tempfile
import unittest

from fastapi.testclient import TestClient

from core.crypto import Keyring, generate_org_keypair, seal, unseal, unseal_with_recovery_code
from core.storage import load_vault, save_vault
from core.vault import Vault, VaultEntry
from tests.test_admin import _csrf
from tests.test_admin_features import FeatureBase
from ui.recovery_ui import FORCE_CHANGE_KEY, build_recovery_result


class TestPersonalRecoveryCode(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "s.vault")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_save_load_keeps_keyring_and_code_works(self):
        v = Vault("Mój")
        v.add_entry(VaultEntry(title="Bank", password="tajne"))
        v.keyring = Keyring.new("stare-haslo-1")
        code = v.keyring.add_recovery_code()
        save_vault(v, self.path, "stare-haslo-1")
        loaded = load_vault(self.path, "stare-haslo-1")
        self.assertTrue(loaded.keyring.has_recovery_code)
        save_vault(loaded, self.path, "stare-haslo-1")  # zwykły zapis nie gubi kodu
        blob = open(self.path, "rb").read()
        plain, ring = unseal_with_recovery_code(blob, code)
        save = seal(plain, "nowe-haslo-2", None, ring)
        self.assertEqual(Vault.from_json(unseal(save, "nowe-haslo-2")[0].decode()).search("bank")[0].password, "tajne")


class TestOrgRecoveryThroughPanel(FeatureBase):
    def test_full_admin_recovery(self):
        public, key_file = generate_org_keypair("haslo-klucza-firmy")
        r = self.client.post("/admin/settings/recovery", data={"csrf": self.csrf, "public_key": public, "enabled": "1"})
        self.assertIn(key_file["key_id"], r.text)
        tok = self.enroll(self.new_user()).json()["token"]
        auth = {"Authorization": f"Bearer {tok}"}
        policy = self.client.get("/api/v1/policy", headers=auth).json()
        self.assertEqual(policy["recovery_public_key"], public)

        # aplikacja użytkownika: sejf z kluczem firmy (format v2), revision 5
        v = Vault("Jan")
        v.revision = 5
        v.add_entry(VaultEntry(title="Poczta", password="haslo-poczty"))
        ring = Keyring.new("zapomniane-haslo")
        ring.set_org_key(policy["recovery_public_key"])
        blob = seal(v.to_json().encode(), "zapomniane-haslo", None, ring)
        self.assertEqual(self.client.put("/api/v1/vault", content=blob, headers={**auth, "If-Match": '"0"'}).status_code, 200)

        page = self.client.get("/admin/users/jan").text
        self.assertIn("Pobierz pakiet odzyskiwania", page)
        package = self.client.get("/admin/users/jan/recovery-package").json()
        self.assertEqual(package["expected_key_id"], key_file["key_id"])

        result, temp = build_recovery_result(package, key_file, "haslo-klucza-firmy")
        r = self.client.post("/admin/users/jan/recovery-result", data={"csrf": self.csrf},
                             files={"result": ("wynik.ksreset", json.dumps(result).encode(), "application/json")})
        self.assertIn("Dostęp przywrócony", r.text)

        new_blob = self.client.get("/api/v1/vault", headers=auth).content
        plain, ring2 = unseal(new_blob, temp)
        recovered = Vault.from_json(plain.decode())
        self.assertTrue(recovered.settings[FORCE_CHANGE_KEY])
        self.assertEqual(recovered.revision, 6)
        self.assertEqual(recovered.search("poczta")[0].password, "haslo-poczty")
        self.assertEqual(ring2.org_key_id, key_file["key_id"])  # klucz firmy zostaje
        self.assertTrue(any(e["event"] == "vault_recovered_by_admin" for e in self.app.state.audit.search()))

    def test_stale_package_and_wrong_user_rejected(self):
        public, key_file = generate_org_keypair("haslo-klucza-firmy")
        self.client.post("/admin/settings/recovery", data={"csrf": self.csrf, "public_key": public, "enabled": "1"})
        tok = self.enroll(self.new_user()).json()["token"]
        auth = {"Authorization": f"Bearer {tok}"}
        ring = Keyring.new("h-123456")
        ring.set_org_key(public)
        self.client.put("/api/v1/vault", content=seal(Vault("x").to_json().encode(), "h-123456", None, ring),
                        headers={**auth, "If-Match": '"0"'})
        package = self.client.get("/admin/users/jan/recovery-package").json()
        result, _ = build_recovery_result(package, key_file, "haslo-klucza-firmy")
        # w międzyczasie użytkownik zapisał nową wersję
        self.client.put("/api/v1/vault", content=seal(Vault("y").to_json().encode(), "h-123456", None, ring),
                        headers={**auth, "If-Match": '"1"'})
        r = self.client.post("/admin/users/jan/recovery-result", data={"csrf": self.csrf},
                             files={"result": ("w.ksreset", json.dumps(result).encode(), "application/json")})
        self.assertIn("zmienił się", r.text)
        result["user"] = "ktos-inny"
        r = self.client.post("/admin/users/jan/recovery-result", data={"csrf": self.csrf},
                             files={"result": ("w.ksreset", json.dumps(result).encode(), "application/json")})
        self.assertIn("Nieprawidłowy plik", r.text)

    def test_invalid_key_rejected_and_disabled_policy_hides_key(self):
        r = self.client.post("/admin/settings/recovery", data={"csrf": self.csrf, "public_key": "ksrec1:xyz", "enabled": "1"})
        self.assertIn("nie jest prawidłowy klucz", r.text)
        public, _ = generate_org_keypair("haslo-klucza-firmy")
        self.client.post("/admin/settings/recovery", data={"csrf": self.csrf, "public_key": public})
        tok = self.enroll(self.new_user()).json()["token"]
        policy = self.client.get("/api/v1/policy", headers={"Authorization": f"Bearer {tok}"}).json()
        self.assertEqual(policy["recovery_public_key"], "")  # zapisany, ale wyłączony


class TestAttachmentsApi(FeatureBase):
    def test_upload_download_quota_and_isolation(self):
        from core.attachments import encrypt_attachment
        tok = self.enroll(self.new_user()).json()["token"]
        auth = {"Authorization": f"Bearer {tok}"}
        att_id = "a" * 32
        blob, _key = encrypt_attachment(att_id, b"skan dowodu" * 100)
        self.assertEqual(self.client.put(f"/api/v1/attachments/{att_id}", content=blob, headers=auth).status_code, 200)
        self.assertEqual(self.client.get(f"/api/v1/attachments/{att_id}", headers=auth).content, blob)
        info = self.client.get("/api/v1/attachments", headers=auth).json()
        self.assertEqual(info["items"], [{"id": att_id, "size": len(blob)}])
        # inny użytkownik nie widzi pliku
        tok2 = self.enroll(self.new_user("ola")).json()["token"]
        self.assertEqual(self.client.get(f"/api/v1/attachments/{att_id}",
                                         headers={"Authorization": f"Bearer {tok2}"}).status_code, 404)
        # zły identyfikator / niezaszyfrowane dane / limit
        self.assertIn(self.client.put("/api/v1/attachments/..%2Fx", content=blob, headers=auth).status_code, (400, 404))
        self.assertEqual(self.client.put("/api/v1/attachments/ZLY-ID", content=blob, headers=auth).status_code, 400)
        self.assertEqual(self.client.put(f"/api/v1/attachments/{'b' * 32}", content=b"jawny tekst" * 10,
                                         headers=auth).status_code, 422)
        self.policy(max_attachment_mb=1, attachment_quota_mb=1)
        big = b"KSATT1" + os.urandom(2 * 1024 * 1024)
        self.assertEqual(self.client.put(f"/api/v1/attachments/{'c' * 32}", content=big, headers=auth).status_code, 413)
        self.assertEqual(self.client.delete(f"/api/v1/attachments/{att_id}", headers=auth).json(), {"deleted": True})

    def test_attachments_disabled_by_policy(self):
        tok = self.enroll(self.new_user()).json()["token"]
        self.policy(allow_attachments=None)
        from core.attachments import encrypt_attachment
        blob, _ = encrypt_attachment("d" * 32, b"x")
        r = self.client.put(f"/api/v1/attachments/{'d' * 32}", content=blob, headers={"Authorization": f"Bearer {tok}"})
        self.assertEqual(r.status_code, 403)


class TestClientAttachments(unittest.TestCase):
    def test_local_store_roundtrip_and_tamper(self):
        from core.attachments import AttachmentError, LocalAttachmentStore, decrypt_attachment, new_attachment
        tmp = tempfile.mkdtemp()
        try:
            src = os.path.join(tmp, "dowód osobisty.pdf")
            open(src, "wb").write(b"%PDF-1.4 tresc")
            meta, blob = new_attachment(src, 10 * 1024 * 1024)
            self.assertEqual(meta["name"], "dowód osobisty.pdf")
            self.assertNotIn(b"tresc", blob)
            store = LocalAttachmentStore(os.path.join(tmp, "s.vault.files"))
            store.put(meta["id"], blob)
            self.assertEqual(decrypt_attachment(meta, store.get(meta["id"])), b"%PDF-1.4 tresc")
            tampered = bytearray(blob)
            tampered[-1] ^= 1
            with self.assertRaises(AttachmentError):
                decrypt_attachment(meta, bytes(tampered))
            with self.assertRaises(AttachmentError):
                new_attachment(src, 5)  # limit rozmiaru
            # metadane przetrwają zapis sejfu, śmieci są odrzucane
            e = VaultEntry(title="Dowód", attachments=[meta, {"id": "zly"}, "x"])
            self.assertEqual(VaultEntry.from_dict(json.loads(json.dumps(e.to_dict()))).attachments, [meta])
            v = Vault("t")
            v.add_entry(e)
            self.assertTrue(v.attachment_in_use(meta["id"]))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
