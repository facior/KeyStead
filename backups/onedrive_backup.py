"""
Dostawca kopii zapasowej na Microsoft OneDrive.
Obsługuje wysyłanie przez Microsoft Graph API (logowanie kontem Microsoft – OAuth)
oraz lokalny folder synchronizacji OneDrive (np. %USERPROFILE%\\OneDrive).
"""

import os
from datetime import datetime
from typing import Dict, Any, Optional, Tuple
from urllib.parse import quote
import requests
from backups.base import BaseBackupProvider, BackupStatus
from backups import oauth
from core.crypto import compute_sha256
from core.i18n import _

GRAPH = "https://graph.microsoft.com/v1.0"
REMOTE_FOLDER = "KeyStead-Backups"


class OneDriveBackupProvider(BaseBackupProvider):
    @property
    def name(self) -> str:
        return "Microsoft OneDrive"

    @property
    def key(self) -> str:
        return "onedrive"

    def is_configured(self, config: Dict[str, Any]) -> bool:
        return oauth.is_connected(config) or bool(config.get("folder_path", "").strip())

    def fetch_account_name(self, token: str) -> str:
        resp = requests.get(f"{GRAPH}/me", headers={"Authorization": f"Bearer {token}"}, timeout=10)
        if resp.status_code == 200:
            me = resp.json()
            return me.get("userPrincipalName") or me.get("mail") or me.get("displayName") or _("Konto Microsoft")
        return _("Konto Microsoft")

    def test_connection(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        folder = config.get("folder_path", "").strip()
        try:
            token = oauth.get_access_token(self.key, config)
        except oauth.OAuthError as e:
            return False, str(e)

        if token:
            try:
                resp = requests.get(f"{GRAPH}/me/drive", headers={"Authorization": f"Bearer {token}"}, timeout=10)
                if resp.status_code == 200:
                    quota = resp.json().get("quota", {})
                    free_gb = quota.get("remaining", 0) / 1024 ** 3
                    return True, _("Połączono z OneDrive ({free_gb:.1f} GB wolnego miejsca).", free_gb=free_gb)
                if resp.status_code == 401:
                    return False, _("Sesja OneDrive wygasła – zaloguj się ponownie.")
                return False, _("Błąd OneDrive API: {code}", code=resp.status_code)
            except requests.RequestException as e:
                return False, _("Błąd połączenia z OneDrive: {error}", error=e)

        if folder:
            if os.path.isdir(folder):
                return True, _("Folder OneDrive dostępny: {folder}", folder=folder)
            return False, _("Folder OneDrive nie istnieje: {folder}", folder=folder)

        return False, _("Zaloguj się kontem Microsoft lub wybierz folder OneDrive.")

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
                path = quote(f"{REMOTE_FOLDER}/{filename}")
                resp = requests.put(
                    f"{GRAPH}/me/drive/root:/{path}:/content",
                    headers={"Authorization": f"Bearer {token}", "Content-Type": "application/octet-stream"},
                    data=data,
                    timeout=60
                )
                if resp.status_code in (200, 201):
                    return BackupStatus(
                        self.name, True,
                        destination_path=f"OneDrive: /{REMOTE_FOLDER}/{filename}",
                        checksum=sha256_sum, size_bytes=len(data)
                    )
                return BackupStatus(self.name, False, error_message=_("Błąd Microsoft Graph API ({code}): {details}", code=resp.status_code, details=resp.text[:300]))
            except requests.RequestException as e:
                return BackupStatus(self.name, False, error_message=_("Błąd wysyłania do OneDrive: {error}", error=e))

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
                return BackupStatus(self.name, False, error_message=_("Błąd zapisu do folderu OneDrive: {error}", error=e))

        return BackupStatus(self.name, False, error_message=_("Brak konfiguracji OneDrive."))
