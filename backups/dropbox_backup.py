"""
Dostawca kopii zapasowej na Dropbox.
Obsługuje wysyłanie przez Dropbox API v2 (logowanie kontem Dropbox – OAuth)
oraz lokalny folder synchronizacji Dropbox.
"""

import json
import os
from datetime import datetime
from typing import Dict, Any, Optional, Tuple
import requests
from backups.base import BaseBackupProvider, BackupStatus
from backups import oauth
from core.crypto import compute_sha256
from core.i18n import _

REMOTE_FOLDER = "KeyStead-Backups"


class DropboxBackupProvider(BaseBackupProvider):
    @property
    def name(self) -> str:
        return "Dropbox"

    @property
    def key(self) -> str:
        return "dropbox"

    def is_configured(self, config: Dict[str, Any]) -> bool:
        return oauth.is_connected(config) or bool(config.get("folder_path", "").strip())

    def fetch_account_name(self, token: str) -> str:
        resp = requests.post(
            "https://api.dropboxapi.com/2/users/get_current_account",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10
        )
        if resp.status_code == 200:
            acc = resp.json()
            return acc.get("email") or acc.get("name", {}).get("display_name") or _("Konto Dropbox")
        return _("Konto Dropbox")

    def test_connection(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        folder = config.get("folder_path", "").strip()
        try:
            token = oauth.get_access_token(self.key, config)
        except oauth.OAuthError as e:
            return False, str(e)

        if token:
            try:
                resp = requests.post(
                    "https://api.dropboxapi.com/2/users/get_current_account",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=10
                )
                if resp.status_code == 200:
                    return True, _("Połączono z Dropbox ({account}).", account=resp.json().get('email') or _('konto Dropbox'))
                if resp.status_code == 401:
                    return False, _("Sesja Dropbox wygasła – zaloguj się ponownie.")
                return False, _("Błąd Dropbox API: {code}", code=resp.status_code)
            except requests.RequestException as e:
                return False, _("Błąd połączenia z Dropbox API: {error}", error=e)

        if folder:
            if os.path.isdir(folder):
                return True, _("Folder Dropbox dostępny: {folder}", folder=folder)
            return False, _("Folder Dropbox nie istnieje: {folder}", folder=folder)

        return False, _("Zaloguj się kontem Dropbox lub wybierz folder Dropbox.")

    def upload_backup(
        self,
        vault_file_path: str,
        config: Dict[str, Any],
        custom_filename: Optional[str] = None
    ) -> BackupStatus:
        if not os.path.exists(vault_file_path):
            return BackupStatus(self.name, False, error_message=_("Plik źródłowy sejfu nie istnieje."))

        with open(vault_file_path, "rb") as f:
            data = f.read()

        sha256_sum = compute_sha256(data)
        base_name = os.path.splitext(os.path.basename(vault_file_path))[0]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = custom_filename or f"{base_name}_backup_{timestamp}.vault"
        folder = config.get("folder_path", "").strip()

        try:
            token = oauth.get_access_token(self.key, config)
        except oauth.OAuthError as e:
            return BackupStatus(self.name, False, error_message=str(e))

        if token:
            try:
                remote_folder = (config.get("remote_path") or f"/{REMOTE_FOLDER}").rstrip("/")
                dest_path = f"{remote_folder}/{filename}"
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Dropbox-API-Arg": json.dumps({"path": dest_path, "mode": "overwrite", "autorename": False, "mute": True}),
                    "Content-Type": "application/octet-stream"
                }
                resp = requests.post("https://content.dropboxapi.com/2/files/upload", headers=headers, data=data, timeout=60)
                if resp.status_code == 200:
                    return BackupStatus(self.name, True, destination_path=f"Dropbox: {dest_path}", checksum=sha256_sum, size_bytes=len(data))
                return BackupStatus(self.name, False, error_message=_("Błąd Dropbox API ({code}): {details}", code=resp.status_code, details=resp.text[:300]))
            except requests.RequestException as e:
                return BackupStatus(self.name, False, error_message=_("Błąd wysyłania do Dropbox: {error}", error=e))

        if folder:
            try:
                dest_dir = os.path.join(folder, REMOTE_FOLDER)
                os.makedirs(dest_dir, exist_ok=True)
                target = os.path.join(dest_dir, filename)
                with open(target, "wb") as f:
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())
                return BackupStatus(self.name, True, destination_path=target, checksum=sha256_sum, size_bytes=len(data))
            except OSError as e:
                return BackupStatus(self.name, False, error_message=_("Błąd zapisu do folderu Dropbox: {error}", error=e))

        return BackupStatus(self.name, False, error_message=_("Brak konfiguracji Dropbox."))
