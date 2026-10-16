"""
Główny menedżer orkiestracji kopii zapasowych.
Koordynuje tworzenie kopii w chmurach i na dyskach lokalnych.
"""

import os
import shutil
import tempfile
from contextlib import contextmanager
from typing import Dict, Any, Iterator, List, Optional, Tuple
from backups.base import BaseBackupProvider, BackupStatus
from backups.local_backup import LocalBackupProvider
from backups.webdav_backup import WebDAVBackupProvider
from backups.google_drive import GoogleDriveBackupProvider
from backups.onedrive_backup import OneDriveBackupProvider
from backups.dropbox_backup import DropboxBackupProvider


@contextmanager
def vault_snapshot(vault_file_path: str) -> Iterator[str]:
    """
    Tworzy tymczasową kopię pliku sejfu (o tej samej nazwie) na czas wysyłki kopii zapasowej.
    Dzięki temu długotrwały upload w tle nie blokuje atomowego zapisu sejfu (os.replace na Windows).
    """
    temp_dir = tempfile.mkdtemp(prefix="keystead_backup_")
    snapshot_path = os.path.join(temp_dir, os.path.basename(vault_file_path))
    try:
        shutil.copy2(vault_file_path, snapshot_path)
        yield snapshot_path
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


CLOUD_KEYS = ("google_drive", "onedrive", "dropbox")
_RUNTIME_STATE_KEYS = ("oauth", "folder_id")


def merge_runtime_state(target: Dict[str, Any], source: Dict[str, Any]) -> bool:
    """
    Przenosi stan zmieniony podczas backupu (odświeżone tokeny OAuth, ID folderu w chmurze)
    z kopii ustawień użytej w wątku roboczym do ustawień sejfu. Zwraca True, jeśli coś się zmieniło.
    """
    changed = False
    for key in CLOUD_KEYS:
        src, dst = source.get(key) or {}, target.get(key)
        if dst is None:
            continue
        # Nie przywracaj tokenów, jeśli użytkownik w międzyczasie się wylogował
        if not (dst.get("oauth") or {}).get("refresh_token") and (src.get("oauth") or {}).get("refresh_token"):
            continue
        for field in _RUNTIME_STATE_KEYS:
            if field in src and src[field] != dst.get(field):
                dst[field] = src[field]
                changed = True
    return changed


class BackupManager:
    def __init__(self):
        self.providers: Dict[str, BaseBackupProvider] = {
            "local": LocalBackupProvider(),
            "webdav": WebDAVBackupProvider(),
            "google_drive": GoogleDriveBackupProvider(),
            "onedrive": OneDriveBackupProvider(),
            "dropbox": DropboxBackupProvider()
        }

    def get_provider(self, key: str) -> Optional[BaseBackupProvider]:
        return self.providers.get(key)

    def get_all_providers(self) -> List[BaseBackupProvider]:
        return list(self.providers.values())

    def test_provider(self, key: str, config: Dict[str, Any]) -> Tuple[bool, str]:
        provider = self.get_provider(key)
        if not provider:
            return False, f"Nieznany dostawca kopii: {key}"
        return provider.test_connection(config)

    def backup_to_provider(
        self,
        key: str,
        vault_file_path: str,
        config: Dict[str, Any],
        custom_filename: Optional[str] = None
    ) -> BackupStatus:
        provider = self.get_provider(key)
        if not provider:
            return BackupStatus(key, False, error_message=f"Nieznany dostawca: {key}")
        return provider.upload_backup(vault_file_path, config, custom_filename)

    def backup_to_all_configured(
        self,
        vault_file_path: str,
        backup_settings: Dict[str, Any]
    ) -> List[BackupStatus]:
        """
        Wykonuje kopie zapasowe na wszystkich skonfigurowanych i włączonych platformach.
        """
        results: List[BackupStatus] = []

        # 1. Kopia lokalna / USB
        local_cfg = backup_settings.get("local") or {"folder_path": backup_settings.get("local_dir", "")}
        if self.providers["local"].is_configured(local_cfg):
            res = self.providers["local"].upload_backup(vault_file_path, local_cfg)
            results.append(res)

        # 2. WebDAV
        webdav_cfg = backup_settings.get("webdav", {})
        if webdav_cfg.get("enabled", False) and self.providers["webdav"].is_configured(webdav_cfg):
            res = self.providers["webdav"].upload_backup(vault_file_path, webdav_cfg)
            results.append(res)

        # 3. Google Drive
        gdrive_cfg = backup_settings.get("google_drive", {})
        if gdrive_cfg.get("enabled", False) and self.providers["google_drive"].is_configured(gdrive_cfg):
            res = self.providers["google_drive"].upload_backup(vault_file_path, gdrive_cfg)
            results.append(res)

        # 4. OneDrive
        onedrive_cfg = backup_settings.get("onedrive", {})
        if onedrive_cfg.get("enabled", False) and self.providers["onedrive"].is_configured(onedrive_cfg):
            res = self.providers["onedrive"].upload_backup(vault_file_path, onedrive_cfg)
            results.append(res)

        # 5. Dropbox
        dropbox_cfg = backup_settings.get("dropbox", {})
        if dropbox_cfg.get("enabled", False) and self.providers["dropbox"].is_configured(dropbox_cfg):
            res = self.providers["dropbox"].upload_backup(vault_file_path, dropbox_cfg)
            results.append(res)

        return results
