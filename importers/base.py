"""
Bazowy interfejs i struktury danych dla importerów menedżerów haseł.
"""

import re
from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Any
from urllib.parse import urlparse
from core.i18n import _
from core.vault import VaultEntry, Vault, as_fields, as_tags, as_text

MAX_IMPORT_ITEMS = 50_000  # ochrona przed plikami „bombami” – realne eksporty mają setki/tysiące wpisów
PLACEHOLDER_TITLES = {"", "-", "--", "---", "bez tytułu", "bez nazwy", "untitled", "no name"}  # i18n: data
_SITE_PREFIX = re.compile(r"^([^\s,]+\.[^\s,]+),\s*(\S.*)$")


def _host(url: str) -> str:
    try:
        host = (urlparse(url if "://" in url else "https://" + url).hostname or "").lower()
    except ValueError:
        return ""
    return host[4:] if host.startswith("www.") else host


def tidy_login(title: str, username: str, url: str):
    """
    Porządkuje typowe śmieci z eksportów: login „strona.pl, jan” (część menedżerów i przeglądarek dokleja
    domenę do loginu) oraz tytuł „--” / pusty. Domena z loginu jest usuwana tylko, gdy zgadza się z adresem wpisu.
    """
    host = _host(url)
    match = _SITE_PREFIX.match(username or "")
    if match and host:
        prefix = _host(match.group(1))
        if prefix and (prefix == host or host.endswith("." + prefix) or prefix.endswith("." + host)):
            username = match.group(2).strip()
    if (title or "").strip().lower() in PLACEHOLDER_TITLES and host:
        title = host
    return title, username


def untidy_entries(vault: Vault) -> List[tuple]:
    """Wpisy sejfu (także w koszu), które tidy_login by poprawił: [(wpis, nowy_tytuł, nowy_login)]."""
    changes = []
    for entry in list(vault.entries.values()) + list(vault.trash.values()):
        title, username = tidy_login(entry.title, entry.username, entry.url)
        if (title, username) != (entry.title, entry.username):
            changes.append((entry, title, username))
    return changes


def tidy_vault(vault: Vault) -> int:
    """Poprawia loginy „strona.pl, jan” i tytuły „--” w istniejących wpisach. Zwraca liczbę zmienionych wpisów."""
    changes = untidy_entries(vault)
    for entry, title, username in changes:
        entry.update(title=title, username=username)
    return len(changes)


class ImportItem:
    def __init__(
        self,
        title: str,
        category: str = "Loginy",  # i18n: data
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
        self.title = as_text(title, 500) or _("Bez tytułu")
        self.category = as_text(category, 200) or "Loginy"  # i18n: data
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
                # tłumaczenie musi zawierać słowo „limit” (sprawdzane wyżej)
                self.add_error(_("Plik zawiera więcej niż {limit} wpisów – zaimportowano tylko pierwsze "
                                 "{limit} (limit chroniący przed uszkodzonymi lub złośliwymi plikami).",
                                 limit=MAX_IMPORT_ITEMS))
            return
        item.title, item.username = tidy_login(item.title, item.username, item.url)
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
