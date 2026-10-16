"""
Bazowy interfejs i struktury danych dla importerów menedżerów haseł.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Any
from core.vault import VaultEntry, Vault


class ImportItem:
    def __init__(
        self,
        title: str,
        category: str = "Loginy",
        username: str = "",
        password: str = "",
        url: str = "",
        totp_secret: str = "",
        notes: str = "",
        tags: Optional[List[str]] = None,
        custom_fields: Optional[Dict[str, str]] = None,
        favorite: bool = False
    ):
        self.title = title or "Bez tytułu"
        self.category = category or "Loginy"
        self.username = username or ""
        self.password = password or ""
        self.url = url or ""
        self.totp_secret = totp_secret or ""
        self.notes = notes or ""
        self.tags = tags or []
        self.custom_fields = custom_fields or {}
        self.favorite = favorite

    def to_vault_entry(self) -> VaultEntry:
        return VaultEntry(
            title=self.title,
            category=self.category,
            username=self.username,
            password=self.password,
            url=self.url,
            totp_secret=self.totp_secret,
            notes=self.notes,
            tags=self.tags,
            custom_fields=self.custom_fields,
            favorite=self.favorite
        )


class ImportResult:
    def __init__(self, source_format: str):
        self.source_format = source_format
        self.success = False
        self.items: List[ImportItem] = []
        self.errors: List[str] = []
        self.categories_found: List[str] = []

    def add_item(self, item: ImportItem) -> None:
        self.items.append(item)
        if item.category and item.category not in self.categories_found:
            self.categories_found.append(item.category)

    def add_error(self, message: str) -> None:
        self.errors.append(message)


class BaseImporter(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Nazwa czytelna dla człowieka (np. 'Bitwarden (JSON / CSV)')."""
        pass

    @property
    @abstractmethod
    def supported_extensions(self) -> List[str]:
        """Rozszerzenia plików, np. ['.json', '.csv']."""
        pass

    @abstractmethod
    def can_handle(self, file_path: str, preview_header: bytes) -> bool:
        """Sprawdza czy dany importer potrafi rozpoznać i przetworzyć ten plik."""
        pass

    @abstractmethod
    def parse(
        self,
        file_path: str,
        password: Optional[str] = None,
        keyfile_path: Optional[str] = None
    ) -> ImportResult:
        """Parsuje plik i zwraca ImportResult."""
        pass
