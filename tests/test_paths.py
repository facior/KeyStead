"""
Test migracji ustawień z poprzedniej nazwy aplikacji (Secure Vault Pro → KeyStead Manager).
"""

import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from core import paths


class TestLegacyMigration(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        app_dir = os.path.join(self.home, ".keystead")
        legacy_dir = os.path.join(self.home, ".secure" + "vault")
        self.patches = [
            mock.patch.object(paths, "APP_DIR", app_dir),
            mock.patch.object(paths, "_LEGACY_FILES", {
                os.path.join(self.home, ".pm_config.json"): os.path.join(app_dir, "config.json"),
                os.path.join(self.home, ".pm_recent_vaults.json"): os.path.join(app_dir, "recent_vaults.json"),
            }),
            mock.patch.object(paths, "_LEGACY_DIRS", {
                os.path.join(legacy_dir, "cache"): os.path.join(app_dir, "cache"),
            }),
        ]
        for p in self.patches:
            p.start()
        self.legacy_dir = legacy_dir
        self.app_dir = app_dir

    def tearDown(self):
        for p in self.patches:
            p.stop()
        shutil.rmtree(self.home, ignore_errors=True)

    def test_old_settings_are_copied_once(self):
        with open(os.path.join(self.home, ".pm_config.json"), "w") as f:
            json.dump({"first_run_completed": True}, f)
        os.makedirs(os.path.join(self.legacy_dir, "cache"))
        with open(os.path.join(self.legacy_dir, "cache", "SejfSerwer_abc.vault"), "wb") as f:
            f.write(b"SECVAULT")

        paths.migrate_legacy_files()
        with open(os.path.join(self.app_dir, "config.json")) as f:
            self.assertTrue(json.load(f)["first_run_completed"])
        self.assertTrue(os.path.exists(os.path.join(self.app_dir, "cache", "SejfSerwer_abc.vault")))

        # Ponowne uruchomienie nie nadpisuje nowszych ustawień
        with open(os.path.join(self.app_dir, "config.json"), "w") as f:
            json.dump({"first_run_completed": True, "nowe": 1}, f)
        paths.migrate_legacy_files()
        with open(os.path.join(self.app_dir, "config.json")) as f:
            self.assertEqual(json.load(f).get("nowe"), 1)

    def test_nothing_to_migrate(self):
        paths.migrate_legacy_files()
        self.assertFalse(os.path.exists(self.app_dir))


if __name__ == "__main__":
    unittest.main()
