"""
Testy jednostkowe systemu kopii zapasowych (Backup Manager i LocalBackupProvider).
"""

import os
import tempfile
import unittest
from backups import BackupManager, LocalBackupProvider
from core.crypto import compute_sha256


class TestBackups(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.vault_file = os.path.join(self.temp_dir, "test.vault")
        with open(self.vault_file, "wb") as f:
            f.write(b"SECVAULT_MOCK_ENCRYPTED_DATA_FOR_BACKUP")

        self.backup_dir = os.path.join(self.temp_dir, "backups")
        os.makedirs(self.backup_dir, exist_ok=True)

    def tearDown(self):
        for root, dirs, files in os.walk(self.temp_dir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(self.temp_dir)

    def test_local_backup_creation_and_checksum(self):
        provider = LocalBackupProvider()
        config = {"folder_path": self.backup_dir, "max_backups": 5}

        self.assertTrue(provider.is_configured(config))
        ok, msg = provider.test_connection(config)
        self.assertTrue(ok)

        status = provider.upload_backup(self.vault_file, config)
        self.assertTrue(status.success)
        self.assertTrue(os.path.exists(status.destination_path))

        # Weryfikacja sumy kontrolnej
        with open(self.vault_file, "rb") as f:
            expected_sha = compute_sha256(f.read())
        self.assertEqual(status.checksum, expected_sha)

    def test_local_backup_rotation(self):
        provider = LocalBackupProvider()
        config = {"folder_path": self.backup_dir, "max_backups": 3}

        # 4 starsze kopie w formacie nadawanym przez aplikację (<sejf>_backup_RRRRMMDD_GGMMSS.vault)
        base = os.path.splitext(os.path.basename(self.vault_file))[0]
        os.makedirs(self.backup_dir, exist_ok=True)
        for i in range(4):
            path = os.path.join(self.backup_dir, f"{base}_backup_2024010{i + 1}_120000.vault")
            with open(path, "wb") as f:
                f.write(b"stara kopia")
            os.utime(path, (1_700_000_000 + i, 1_700_000_000 + i))
        provider.upload_backup(self.vault_file, config)  # piąta, nowa kopia

        # Z powodu rotacji powinno zostać maksymalnie 3
        vault_files = [f for f in os.listdir(self.backup_dir) if f.endswith(".vault")]
        self.assertLessEqual(len(vault_files), 3)

    def test_backup_manager_orchestration(self):
        manager = BackupManager()
        self.assertIsNotNone(manager.get_provider("local"))
        self.assertIsNotNone(manager.get_provider("webdav"))
        self.assertIsNotNone(manager.get_provider("google_drive"))
        self.assertIsNotNone(manager.get_provider("onedrive"))
        self.assertIsNotNone(manager.get_provider("dropbox"))

        settings = {
            "local": {"folder_path": self.backup_dir, "max_backups": 5}
        }
        results = manager.backup_to_all_configured(self.vault_file, settings)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].success)


if __name__ == "__main__":
    unittest.main()
