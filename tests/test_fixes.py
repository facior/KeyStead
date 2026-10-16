"""
Testy regresyjne poprawek: scalanie ustawień sejfu, import z duplikatami,
format .1pux, CSV z BOM, wiek hasła w audycie oraz migawka pliku do backupu.
"""

import json
import os
import shutil
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta, timezone

from backups import vault_snapshot
from core.security_audit import run_vault_audit
from core.storage import load_vault, save_vault
from core.vault import Vault, VaultEntry
from importers import (
    run_import, apply_import, STRATEGY_SKIP, STRATEGY_ADD_ALL, STRATEGY_UPDATE
)
from importers.base import ImportItem


class TestVaultSettings(unittest.TestCase):
    def test_missing_settings_are_filled_with_defaults(self):
        vault = Vault.from_dict({"name": "Stary", "settings": {"auto_lock_minutes": 10}})
        self.assertEqual(vault.settings["auto_lock_minutes"], 10)
        self.assertEqual(vault.settings["clipboard_clear_seconds"], 30)
        self.assertIn("local", vault.settings["backup_destinations"])
        self.assertIn("webdav", vault.settings["backup_destinations"])

    def test_legacy_local_dir_is_migrated(self):
        vault = Vault.from_dict({
            "settings": {"backup_destinations": {"local_dir": "D:\\Kopie", "webdav": {"url": "https://x"}}}
        })
        dest = vault.settings["backup_destinations"]
        self.assertNotIn("local_dir", dest)
        self.assertEqual(dest["local"]["folder_path"], "D:\\Kopie")
        self.assertEqual(dest["webdav"]["url"], "https://x")
        self.assertIn("username", dest["webdav"])

    def test_default_settings_are_not_shared_between_vaults(self):
        a, b = Vault(), Vault()
        a.settings["backup_destinations"]["local"]["folder_path"] = "X"
        self.assertEqual(b.settings["backup_destinations"]["local"]["folder_path"], "")


class TestApplyImport(unittest.TestCase):
    def setUp(self):
        self.vault = Vault()
        self.existing = VaultEntry(title="GitHub", username="jan", password="old", url="https://github.com", tags=["dev"])
        self.vault.add_entry(self.existing)
        self.items = [
            ImportItem(title="github", username="JAN", password="new", url="https://github.com/", tags=["work"]),
            ImportItem(title="Bank", category="Finanse", username="jan", password="b")
        ]

    def test_skip_strategy(self):
        stats = apply_import(self.vault, self.items, STRATEGY_SKIP)
        self.assertEqual(stats, {"added": 1, "updated": 0, "skipped": 1})
        self.assertEqual(self.existing.password, "old")
        self.assertIn("Finanse", self.vault.categories)

    def test_update_strategy(self):
        stats = apply_import(self.vault, self.items, STRATEGY_UPDATE)
        self.assertEqual(stats, {"added": 1, "updated": 1, "skipped": 0})
        self.assertEqual(self.existing.password, "new")
        self.assertEqual(self.existing.password_history[-1]["password"], "old")
        self.assertEqual(sorted(self.existing.tags), ["dev", "work"])

    def test_add_all_strategy(self):
        stats = apply_import(self.vault, self.items, STRATEGY_ADD_ALL)
        self.assertEqual(stats["added"], 2)
        self.assertEqual(len(self.vault.entries), 3)


class TestImporterFormats(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_1pux_real_structure(self):
        export = {
            "accounts": [{
                "vaults": [{
                    "items": [{
                        "categoryUuid": "001",
                        "overview": {"title": "Dropbox", "urls": [{"url": "https://dropbox.com"}], "tags": ["chmura"]},
                        "details": {
                            "loginFields": [
                                {"value": "jan@example.com", "designation": "username", "fieldType": "E"},
                                {"value": "Tajne123!", "designation": "password", "fieldType": "P"}
                            ],
                            "notesPlain": "notatka",
                            "sections": [{
                                "fields": [
                                    {"title": "one-time password", "value": {"totp": "otpauth://totp/Dropbox:jan?secret=JBSWY3DPEHPK3PXP"}},
                                    {"title": "PIN", "value": {"concealed": "1234"}}
                                ]
                            }]
                        }
                    }]
                }]
            }]
        }
        path = os.path.join(self.temp_dir, "export.1pux")
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("export.data", json.dumps(export))

        res = run_import(path)
        self.assertTrue(res.success, res.errors)
        item = res.items[0]
        self.assertEqual(item.username, "jan@example.com")
        self.assertEqual(item.password, "Tajne123!")
        self.assertEqual(item.url, "https://dropbox.com")
        self.assertEqual(item.totp_secret, "JBSWY3DPEHPK3PXP")
        self.assertEqual(item.custom_fields.get("PIN"), "1234")

    def test_browser_csv_with_bom(self):
        path = os.path.join(self.temp_dir, "chrome.csv")
        with open(path, "w", encoding="utf-8-sig", newline="") as f:
            f.write("name,url,username,password,note\r\nGoogle,https://google.com,jan,haslo123,\r\n")

        res = run_import(path)
        self.assertTrue(res.success, res.errors)
        self.assertEqual(res.items[0].title, "Google")
        self.assertEqual(res.items[0].password, "haslo123")


class TestAuditPasswordAge(unittest.TestCase):
    def test_stale_uses_password_change_date_not_last_edit(self):
        old = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
        entry = VaultEntry(title="Stare", username="u", password="Xy7#mK9!pQ2$wL5@", totp_secret="JBSWY3DPEHPK3PXP", created_at=old)
        entry.update(notes="tylko edycja notatki")  # nie zmienia hasła
        vault = Vault()
        vault.add_entry(entry)

        report = run_vault_audit(vault, check_hibp=False)
        self.assertEqual(len(report.stale_issues), 1)

        entry.update(password="Nowe#Haslo9!Silne2$")
        report = run_vault_audit(vault, check_hibp=False)
        self.assertEqual(len(report.stale_issues), 0)


class TestVaultSnapshot(unittest.TestCase):
    def test_snapshot_keeps_name_and_allows_atomic_save(self):
        temp_dir = tempfile.mkdtemp()
        try:
            path = os.path.join(temp_dir, "MojSejf.vault")
            vault = Vault()
            save_vault(vault, path, "haslo-glowne-123")
            with vault_snapshot(path) as snap:
                self.assertEqual(os.path.basename(snap), "MojSejf.vault")
                self.assertNotEqual(os.path.dirname(snap), temp_dir)
                # Zapis sejfu w trakcie backupu nie może się wywrócić
                vault.add_entry(VaultEntry(title="Nowy"))
                save_vault(vault, path, "haslo-glowne-123")
            self.assertFalse(os.path.exists(snap))
            self.assertEqual(len(load_vault(path, "haslo-glowne-123").entries), 1)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
