"""
Klasa bazowa oraz struktury statusu dla dostawców kopii zapasowych (Backup Providers).
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple


class BackupStatus:
    def __init__(
        self,
        provider_name: str,
        success: bool,
        destination_path: str = "",
        checksum: str = "",
        size_bytes: int = 0,
        error_message: Optional[str] = None
    ):
        self.provider_name = provider_name
        self.success = success
        self.destination_path = destination_path
        self.checksum = checksum
        self.size_bytes = size_bytes
        self.error_message = error_message
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider_name": self.provider_name,
            "success": self.success,
            "destination_path": self.destination_path,
            "checksum": self.checksum,
            "size_bytes": self.size_bytes,
            "error_message": self.error_message,
            "timestamp": self.timestamp
        }


class BaseBackupProvider(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Nazwa czytelna dla człowieka (np. 'WebDAV (Nextcloud)')."""
        pass

    @property
    @abstractmethod
    def key(self) -> str:
        """Identyfikator techniczny, np. 'webdav', 'local', 'gdrive'."""
        pass

    @abstractmethod
    def is_configured(self, config: Dict[str, Any]) -> bool:
        """Zwraca True, jeśli konfiguracja posiada wymagane parametry."""
        pass

    @abstractmethod
    def test_connection(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        """Testuje łączność z usługą kopii zapasowej."""
        pass

    @abstractmethod
    def upload_backup(
        self,
        vault_file_path: str,
        config: Dict[str, Any],
        custom_filename: Optional[str] = None
    ) -> BackupStatus:
        """Wysyła zaszyfrowany plik sejfu do miejsca docelowego."""
        pass
