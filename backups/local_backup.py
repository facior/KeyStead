"""
Dostawca kopii zapasowej na dysk lokalny, nośnik USB lub udział sieciowy.
Automatycznie dodaje znacznik czasu oraz rotuje stare kopie.
"""

import os
import re
import shutil
from datetime import datetime
from typing import Dict, Any, Optional, Tuple
from backups.base import BaseBackupProvider, BackupStatus
from core.crypto import compute_sha256


class LocalBackupProvider(BaseBackupProvider):
    @property
    def name(self) -> str:
        return "Dysk lokalny / USB / Udział sieciowy"

    @property
    def key(self) -> str:
        return "local"

    def is_configured(self, config: Dict[str, Any]) -> bool:
        path = config.get("folder_path") or config.get("local_dir") or ""
        return bool(path.strip())

    def test_connection(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        path = config.get("folder_path") or config.get("local_dir") or ""
        if not path:
            return False, "Ścieżka do katalogu kopii nie została podana."

        try:
            os.makedirs(path, exist_ok=True)
            test_file = os.path.join(path, f".keystead_write_test_{os.getpid()}")
            with open(test_file, "w") as f:
                f.write("test")
            os.remove(test_file)
            return True, f"Katalog jest dostępny i zapisywalny: {path}"
        except Exception as e:
            return False, f"Błąd zapisu w wybranym katalogu: {str(e)}"

    def upload_backup(
        self,
        vault_file_path: str,
        config: Dict[str, Any],
        custom_filename: Optional[str] = None
    ) -> BackupStatus:
        if not os.path.exists(vault_file_path):
            return BackupStatus(self.name, False, error_message="Plik źródłowy sejfu nie istnieje.")

        dest_dir = config.get("folder_path") or config.get("local_dir") or ""
        if not dest_dir:
            return BackupStatus(self.name, False, error_message="Brak skonfigurowanego katalogu docelowego.")

        try:
            os.makedirs(dest_dir, exist_ok=True)
            base_name = os.path.splitext(os.path.basename(vault_file_path))[0]
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = custom_filename or f"{base_name}_backup_{timestamp}.vault"
            dest_file = os.path.join(dest_dir, filename)

            # Odczyt i weryfikacja SHA-256
            with open(vault_file_path, "rb") as f:
                src_data = f.read()
            src_sha = compute_sha256(src_data)

            with open(dest_file, "wb") as f:
                f.write(src_data)
                f.flush()
                os.fsync(f.fileno())

            # Weryfikacja zapisu
            with open(dest_file, "rb") as f:
                dest_data = f.read()
            dest_sha = compute_sha256(dest_data)

            if src_sha != dest_sha:
                return BackupStatus(
                    self.name,
                    False,
                    destination_path=dest_file,
                    error_message="Niezgodność sumy kontrolnej SHA-256 po zapisie kopii lokalnej!"
                )

            # Opcjonalna rotacja starych kopii (np. zachowaj ostatnie 15)
            max_backups = int(config.get("max_backups", 15))
            if max_backups > 0:
                self._rotate_backups(dest_dir, base_name, max_backups)

            return BackupStatus(
                self.name,
                True,
                destination_path=dest_file,
                checksum=dest_sha,
                size_bytes=len(dest_data)
            )
        except Exception as e:
            return BackupStatus(self.name, False, error_message=f"Błąd tworzenia kopii lokalnej: {str(e)}")

    def _rotate_backups(self, dest_dir: str, base_name: str, keep_count: int) -> None:
        try:
            # Dokładnie „<nazwa>_backup_RRRRMMDD_GGMMSS.vault” – rotacja nie usunie kopii innego sejfu
            # o podobnej nazwie (np. „a_backup_X”) zapisanych w tym samym folderze
            pattern = re.compile(rf"^{re.escape(base_name)}_backup_\d{{8}}_\d{{6}}\.vault$")
            files = [os.path.join(dest_dir, f) for f in os.listdir(dest_dir) if pattern.match(f)]
            files.sort(key=os.path.getmtime, reverse=True)
            if len(files) > keep_count:
                for old_file in files[keep_count:]:
                    try:
                        os.remove(old_file)
                    except Exception:
                        pass
        except Exception:
            pass
