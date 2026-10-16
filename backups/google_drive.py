"""
Dostawca kopii zapasowej na Dysk Google (Google Drive).
Obsługuje wysyłanie przez Google Drive REST API (logowanie kontem Google – OAuth)
oraz lokalny folder synchronizacji aplikacji Google Drive for Desktop.
"""

import json
import os
from datetime import datetime
from typing import Dict, Any, Optional, Tuple
import requests
from backups.base import BaseBackupProvider, BackupStatus
from backups import oauth
from core.crypto import compute_sha256

DRIVE = "https://www.googleapis.com/drive/v3"
UPLOAD = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id"
REMOTE_FOLDER = "KeyStead-Backups"
FOLDER_MIME = "application/vnd.google-apps.folder"


class GoogleDriveBackupProvider(BaseBackupProvider):
    @property
    def name(self) -> str:
        return "Dysk Google"

    @property
    def key(self) -> str:
        return "google_drive"

    def is_configured(self, config: Dict[str, Any]) -> bool:
        return oauth.is_connected(config) or bool(config.get("folder_path", "").strip())

    def fetch_account_name(self, token: str) -> str:
        resp = requests.get(f"{DRIVE}/about?fields=user", headers={"Authorization": f"Bearer {token}"}, timeout=10)
        if resp.status_code == 200:
            user = resp.json().get("user", {})
            return user.get("emailAddress") or user.get("displayName") or "Konto Google"
        return "Konto Google"

    def test_connection(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        folder_path = config.get("folder_path", "").strip()
        try:
            token = oauth.get_access_token(self.key, config)
        except oauth.OAuthError as e:
            return False, str(e)

        if token:
            try:
                resp = requests.get(f"{DRIVE}/about?fields=user", headers={"Authorization": f"Bearer {token}"}, timeout=10)
                if resp.status_code == 200:
                    user = resp.json().get("user", {})
                    return True, f"Połączono z Dyskiem Google ({user.get('emailAddress', 'konto Google')})."
                if resp.status_code == 401:
                    return False, "Sesja Google wygasła – zaloguj się ponownie."
                return False, f"Błąd Google Drive API: {resp.status_code}"
            except requests.RequestException as e:
                return False, f"Błąd połączenia z Google Drive API: {e}"

        if folder_path:
            if os.path.isdir(folder_path):
                return True, f"Folder Google Drive dostępny: {folder_path}"
            return False, f"Ścieżka do folderu Google Drive nie istnieje: {folder_path}"

        return False, "Zaloguj się kontem Google lub wybierz folder Google Drive."

    def upload_backup(
        self,
        vault_file_path: str,
        config: Dict[str, Any],
        custom_filename: Optional[str] = None
    ) -> BackupStatus:
        if not os.path.exists(vault_file_path):
            return BackupStatus(self.name, False, error_message="Plik źródłowy sejfu nie istnieje.")

        with open(vault_file_path, "rb") as f:
            data = f.read()

        sha256_sum = compute_sha256(data)
        base_name = os.path.splitext(os.path.basename(vault_file_path))[0]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = custom_filename or f"{base_name}_backup_{timestamp}.vault"
        folder_path = config.get("folder_path", "").strip()

        try:
            token = oauth.get_access_token(self.key, config)
        except oauth.OAuthError as e:
            return BackupStatus(self.name, False, error_message=str(e))

        if token:
            return self._upload_via_api(data, filename, token, sha256_sum, config)
        if folder_path:
            return self._upload_via_folder(data, filename, folder_path, sha256_sum)
        return BackupStatus(self.name, False, error_message="Brak konfiguracji Google Drive.")

    def _get_or_create_folder(self, token: str, config: Dict[str, Any]) -> Optional[str]:
        """Zwraca ID folderu kopii na Dysku (tworzy go przy pierwszym użyciu)."""
        headers = {"Authorization": f"Bearer {token}"}
        cached = config.get("folder_id")
        if cached:
            resp = requests.get(f"{DRIVE}/files/{cached}?fields=id,trashed", headers=headers, timeout=10)
            if resp.status_code == 200 and not resp.json().get("trashed"):
                return cached

        query = f"name='{REMOTE_FOLDER}' and mimeType='{FOLDER_MIME}' and trashed=false"
        resp = requests.get(f"{DRIVE}/files", headers=headers, params={"q": query, "fields": "files(id)"}, timeout=10)
        if resp.status_code == 200 and resp.json().get("files"):
            config["folder_id"] = resp.json()["files"][0]["id"]
            return config["folder_id"]

        resp = requests.post(
            f"{DRIVE}/files?fields=id",
            headers=headers,
            json={"name": REMOTE_FOLDER, "mimeType": FOLDER_MIME},
            timeout=10
        )
        if resp.status_code in (200, 201):
            config["folder_id"] = resp.json()["id"]
            return config["folder_id"]
        return None

    def _upload_via_api(self, data: bytes, filename: str, token: str, sha256_sum: str, config: Dict[str, Any]) -> BackupStatus:
        try:
            metadata = {"name": filename, "mimeType": "application/octet-stream"}
            folder_id = self._get_or_create_folder(token, config)
            if folder_id:
                metadata["parents"] = [folder_id]
            files = {
                "metadata": ("metadata", json.dumps(metadata), "application/json; charset=UTF-8"),
                "file": (filename, data, "application/octet-stream")
            }
            resp = requests.post(UPLOAD, headers={"Authorization": f"Bearer {token}"}, files=files, timeout=60)

            if resp.status_code in (200, 201):
                where = f"/{REMOTE_FOLDER}/{filename}" if folder_id else filename
                return BackupStatus(self.name, True, destination_path=f"Dysk Google: {where}", checksum=sha256_sum, size_bytes=len(data))
            return BackupStatus(self.name, False, error_message=f"Błąd Google Drive API ({resp.status_code}): {resp.text[:300]}")
        except requests.RequestException as e:
            return BackupStatus(self.name, False, error_message=f"Błąd wysyłania do Google Drive API: {e}")

    def _upload_via_folder(self, data: bytes, filename: str, folder_path: str, sha256_sum: str) -> BackupStatus:
        try:
            dest_dir = os.path.join(folder_path, REMOTE_FOLDER)
            os.makedirs(dest_dir, exist_ok=True)
            target = os.path.join(dest_dir, filename)
            with open(target, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            return BackupStatus(self.name, True, destination_path=target, checksum=sha256_sum, size_bytes=len(data))
        except OSError as e:
            return BackupStatus(self.name, False, error_message=f"Błąd zapisu do folderu Google Drive: {e}")
