"""
Menedżer importerów zewnętrznych baz haseł.
Automatycznie wykrywa format pliku lub pozwala na ręczny wybór parsera.
"""

import os
from typing import Dict, List, Optional
from core.vault import Vault, VaultEntry
from importers.base import BaseImporter, ImportResult, ImportItem
from importers.bitwarden import BitwardenImporter
from importers.keepass import KeePassImporter
from importers.onepassword import OnePasswordImporter
from importers.lastpass import LastPassImporter
from importers.browser import BrowserImporter


REGISTERED_IMPORTERS: List[BaseImporter] = [
    BitwardenImporter(),
    KeePassImporter(),
    OnePasswordImporter(),
    LastPassImporter(),
    BrowserImporter()
]


def get_available_importers() -> List[BaseImporter]:
    """Zwraca listę zarejestrowanych importerów."""
    return list(REGISTERED_IMPORTERS)


def detect_importer(file_path: str) -> Optional[BaseImporter]:
    """Wykrywa odpowiedni importer na podstawie rozszerzenia i nagłówka pliku."""
    if not os.path.exists(file_path):
        return None

    try:
        with open(file_path, "rb") as f:
            header = f.read(2048)
    except Exception:
        header = b""

    for importer in REGISTERED_IMPORTERS:
        if importer.can_handle(file_path, header):
            return importer

    # Fallback po samym rozszerzeniu
    ext = os.path.splitext(file_path)[1].lower()
    for importer in REGISTERED_IMPORTERS:
        if ext in importer.supported_extensions:
            return importer

    return None


def run_import(
    file_path: str,
    importer_name: Optional[str] = None,
    password: Optional[str] = None,
    keyfile_path: Optional[str] = None
) -> ImportResult:
    """Uruchamia import ze wskazanego pliku."""
    importer = None
    if importer_name:
        for imp in REGISTERED_IMPORTERS:
            if imp.name == importer_name:
                importer = imp
                break

    if not importer:
        importer = detect_importer(file_path)

    if not importer:
        res = ImportResult("Nieznany format")
        res.add_error("Nie udało się rozpoznać formatu pliku ani dopasować importera.")
        return res

    return importer.parse(file_path, password=password, keyfile_path=keyfile_path)


def is_plaintext_export(file_path: str) -> bool:
    """Czy plik to niezaszyfrowany eksport haseł (wszystko poza bazą KeePass .kdbx)."""
    return os.path.splitext(file_path)[1].lower() in (".csv", ".json", ".xml", ".1pux", ".zip")


def secure_delete_file(file_path: str) -> None:
    """
    Nadpisuje zawartość pliku losowymi danymi, a następnie go usuwa.
    Uwaga: na dyskach SSD i w folderach synchronizowanych z chmurą nadpisanie nie
    gwarantuje usunięcia wszystkich kopii – to ograniczenie sprzętowe, nie aplikacji.
    """
    size = os.path.getsize(file_path)
    with open(file_path, "r+b") as f:
        remaining = size
        while remaining > 0:
            chunk = min(remaining, 1024 * 1024)
            f.write(os.urandom(chunk))
            remaining -= chunk
        f.flush()
        os.fsync(f.fileno())
    os.remove(file_path)


# Strategie rozwiązywania konfliktów (duplikatów) podczas importu
STRATEGY_SKIP = "skip"        # Pomiń wpisy, które już istnieją w sejfie
STRATEGY_ADD_ALL = "add_all"  # Dodaj wszystkie jako nowe wpisy
STRATEGY_UPDATE = "update"    # Zaktualizuj istniejące wpisy danymi z importu


def _duplicate_key(title: str, username: str, url: str) -> tuple:
    return (title.strip().lower(), username.strip().lower(), url.strip().lower().rstrip("/"))


def apply_import(
    vault: Vault,
    items: List[ImportItem],
    strategy: str = STRATEGY_SKIP
) -> Dict[str, int]:
    """
    Wstawia zaimportowane elementy do sejfu zgodnie z wybraną strategią duplikatów.
    Nieznane kategorie są dopisywane do listy kategorii sejfu.
    Zwraca statystyki: {"added": n, "updated": n, "skipped": n}.
    """
    stats = {"added": 0, "updated": 0, "skipped": 0}
    existing: Dict[tuple, VaultEntry] = {
        _duplicate_key(e.title, e.username, e.url): e for e in vault.entries.values()
    }

    for item in items:
        key = _duplicate_key(item.title, item.username, item.url)
        current = existing.get(key)

        if current is not None and strategy == STRATEGY_SKIP:
            stats["skipped"] += 1
            continue

        vault.add_category(item.category)

        if current is not None and strategy == STRATEGY_UPDATE:
            merged_fields = dict(current.custom_fields)
            merged_fields.update(item.custom_fields)
            current.update(
                category=item.category,
                password=item.password or current.password,
                totp_secret=item.totp_secret or current.totp_secret,
                notes=item.notes or current.notes,
                tags=sorted(set(current.tags) | set(item.tags)),
                custom_fields=merged_fields,
                favorite=current.favorite or item.favorite
            )
            stats["updated"] += 1
            continue

        entry = item.to_vault_entry()
        vault.add_entry(entry)
        existing[key] = entry
        stats["added"] += 1

    return stats
