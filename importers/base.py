"""
Bazowy interfejs i struktury danych dla importerów menedżerów haseł.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Any
from core.vault import VaultEntry, Vault, as_fields, as_tags, as_text

MAX_IMPORT_ITEMS = 50_000  # ochrona przed plikami „bombami” – realne eksporty mają setki/tysiące wpisów


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
        # Plik importu to niezaufane dane: każde pole sprowadzane do właściwego typu (lista/słownik w miejscu
        # tekstu psułaby wyszukiwanie i audyt sejfu), z limitem długości
        self.title = as_text(title, 500) or "Bez tytułu"
        self.category = as_text(category, 200) or "Loginy"
        self.username = as_text(username, 1000)
        self.password = as_text(password, 10_000)
        self.url = as_text(url, 4000)
        self.totp_secret = as_text(totp_secret, 1000)
        self.notes = as_text(notes)
        self.tags = as_tags(tags)
        self.custom_fields = as_fields(custom_fields)
        self.favorite = bool(favorite) if isinstance(favorite, (bool, int)) else False

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
        if len(self.items) >= MAX_IMPORT_ITEMS:
            if not any("limit" in e for e in self.errors):
                self.add_error(f"Plik zawiera więcej niż {MAX_IMPORT_ITEMS} wpisów – zaimportowano tylko pierwsze "
                               f"{MAX_IMPORT_ITEMS} (limit chroniący przed uszkodzonymi lub złośliwymi plikami).")
            return
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
