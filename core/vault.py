"""
Model danych sejfu haseł: pojedyncze wpisy, kategorie, historia haseł,
ustawienia oraz operacje wyszukiwania i serializacji.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any


DEFAULT_CATEGORIES = [
    "Wszystkie",
    "Loginy",
    "Karty płatnicze",
    "Bezpieczne notatki",
    "Serwery / Wi-Fi",
    "Tożsamości"
]


def default_settings() -> Dict[str, Any]:
    """Zwraca świeżą kopię domyślnych ustawień sejfu."""
    return {
        "auto_lock_minutes": 5,
        "clipboard_clear_seconds": 30,
        "theme": "dark",
        "auto_backup_on_save": True,
        "backup_destinations": {
            "local": {
                "folder_path": "",
                "max_backups": 15
            },
            "webdav": {
                "enabled": False,
                "url": "",
                "username": "",
                "password": "",
                "remote_folder": "KeyStead-Backups"
            },
            # "oauth": tokeny z logowania w przeglądarce (przechowywane wyłącznie w zaszyfrowanym sejfie)
            "google_drive": {
                "enabled": False,
                "folder_path": "",
                "oauth": {}
            },
            "onedrive": {
                "enabled": False,
                "folder_path": "",
                "oauth": {}
            },
            "dropbox": {
                "enabled": False,
                "folder_path": "",
                "oauth": {},
                "remote_path": "/KeyStead-Backups"
            }
        }
    }


def _merge_settings(defaults: Dict[str, Any], loaded: Dict[str, Any]) -> Dict[str, Any]:
    """Uzupełnia wczytane ustawienia brakującymi kluczami domyślnymi (rekurencyjnie)."""
    merged = dict(defaults)
    for key, value in loaded.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_settings(merged[key], value)
        else:
            merged[key] = value

    # Migracja starego formatu: 'local_dir' -> 'local.folder_path'
    dest = merged.get("backup_destinations")
    if isinstance(dest, dict) and "local_dir" in dest:
        legacy_dir = dest.pop("local_dir") or ""
        if legacy_dir and not dest["local"].get("folder_path"):
            dest["local"]["folder_path"] = legacy_dir
    return merged


class VaultEntry:
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
        favorite: bool = False,
        entry_id: Optional[str] = None,
        created_at: Optional[str] = None,
        updated_at: Optional[str] = None,
        password_history: Optional[List[Dict[str, str]]] = None
    ):
        now_iso = datetime.now(timezone.utc).isoformat()
        self.id = entry_id or str(uuid.uuid4())
        self.title = title or "Bez tytułu"
        self.category = category or "Loginy"
        self.username = username
        self.password = password
        self.url = url
        self.totp_secret = totp_secret
        self.notes = notes
        self.tags = tags or []
        self.custom_fields = custom_fields or {}
        self.favorite = bool(favorite)
        self.created_at = created_at or now_iso
        self.updated_at = updated_at or now_iso
        self.password_history = password_history or []

    def update(
        self,
        title: Optional[str] = None,
        category: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        url: Optional[str] = None,
        totp_secret: Optional[str] = None,
        notes: Optional[str] = None,
        tags: Optional[List[str]] = None,
        custom_fields: Optional[Dict[str, str]] = None,
        favorite: Optional[bool] = None
    ) -> None:
        """Aktualizuje wpis. Jeśli hasło się zmieniło, zachowuje stare hasło w historii."""
        now_iso = datetime.now(timezone.utc).isoformat()

        if password is not None and password != self.password:
            if self.password:
                self.password_history.append({
                    "password": self.password,
                    "archived_at": now_iso
                })
            self.password = password

        if title is not None:
            self.title = title
        if category is not None:
            self.category = category
        if username is not None:
            self.username = username
        if url is not None:
            self.url = url
        if totp_secret is not None:
            self.totp_secret = totp_secret
        if notes is not None:
            self.notes = notes
        if tags is not None:
            self.tags = tags
        if custom_fields is not None:
            self.custom_fields = custom_fields
        if favorite is not None:
            self.favorite = favorite

        self.updated_at = now_iso

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "username": self.username,
            "password": self.password,
            "url": self.url,
            "totp_secret": self.totp_secret,
            "notes": self.notes,
            "tags": self.tags,
            "custom_fields": self.custom_fields,
            "favorite": self.favorite,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "password_history": self.password_history
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VaultEntry":
        return cls(
            entry_id=data.get("id"),
            title=data.get("title", "Bez nazwy"),
            category=data.get("category", "Loginy"),
            username=data.get("username", ""),
            password=data.get("password", ""),
            url=data.get("url", ""),
            totp_secret=data.get("totp_secret", ""),
            notes=data.get("notes", ""),
            tags=data.get("tags", []),
            custom_fields=data.get("custom_fields", {}),
            favorite=data.get("favorite", False),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
            password_history=data.get("password_history", [])
        )


class Vault:
    def __init__(
        self,
        name: str = "Główny Sejf",
        categories: Optional[List[str]] = None,
        settings: Optional[Dict[str, Any]] = None
    ):
        self.version = 1
        self.name = name
        self.categories = categories or list(DEFAULT_CATEGORIES[1:])  # bez 'Wszystkie'
        self.settings = _merge_settings(default_settings(), settings or {})
        self.entries: Dict[str, VaultEntry] = {}
        self.trash: Dict[str, VaultEntry] = {}

    def add_entry(self, entry: VaultEntry) -> None:
        self.entries[entry.id] = entry
        if entry.id in self.trash:
            del self.trash[entry.id]

    def get_entry(self, entry_id: str) -> Optional[VaultEntry]:
        return self.entries.get(entry_id) or self.trash.get(entry_id)

    def delete_entry(self, entry_id: str) -> bool:
        """Przenosi wpis do kosza."""
        if entry_id in self.entries:
            entry = self.entries.pop(entry_id)
            self.trash[entry_id] = entry
            return True
        return False

    def restore_from_trash(self, entry_id: str) -> bool:
        """Przywraca wpis z kosza do aktywnych wpisów."""
        if entry_id in self.trash:
            entry = self.trash.pop(entry_id)
            self.entries[entry_id] = entry
            return True
        return False

    def empty_trash(self, entry_id: Optional[str] = None) -> None:
        """Trwale usuwa wpis z kosza lub opróżnia cały kosz."""
        if entry_id:
            self.trash.pop(entry_id, None)
        else:
            self.trash.clear()

    def add_category(self, category_name: str) -> bool:
        category_name = category_name.strip()
        if category_name and category_name not in self.categories:
            self.categories.append(category_name)
            return True
        return False

    def search(
        self,
        query: str = "",
        category: Optional[str] = None,
        tag: Optional[str] = None,
        favorite_only: bool = False,
        in_trash: bool = False
    ) -> List[VaultEntry]:
        """Filtruje wpisy na podstawie frazy wyszukiwania, kategorii, tagu i ulubionych."""
        query_norm = (query or "").lower().strip()
        results = []
        source = self.trash if in_trash else self.entries

        for entry in source.values():
            if favorite_only and not entry.favorite:
                continue

            if category and category != "Wszystkie" and entry.category != category:
                continue

            if tag and tag not in entry.tags:
                continue

            if query_norm:
                match = (
                    query_norm in entry.title.lower() or
                    query_norm in entry.username.lower() or
                    query_norm in entry.url.lower() or
                    query_norm in entry.notes.lower() or
                    any(query_norm in t.lower() for t in entry.tags) or
                    any(query_norm in str(v).lower() for v in entry.custom_fields.values())
                )
                if not match:
                    continue

            results.append(entry)

        # Sortowanie: Ulubione na górze, następnie alfabetycznie wg tytułu
        results.sort(key=lambda x: (not x.favorite, x.title.lower()))
        return results

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "name": self.name,
            "categories": self.categories,
            "settings": self.settings,
            "entries": [entry.to_dict() for entry in self.entries.values()],
            "trash": [entry.to_dict() for entry in self.trash.values()]
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Vault":
        vault = cls(
            name=data.get("name", "Mój Sejf"),
            categories=data.get("categories"),
            settings=data.get("settings")
        )
        vault.version = data.get("version", 1)

        for entry_dict in data.get("entries", []):
            entry = VaultEntry.from_dict(entry_dict)
            vault.add_entry(entry)

        for trash_dict in data.get("trash", []):
            trash_entry = VaultEntry.from_dict(trash_dict)
            vault.trash[trash_entry.id] = trash_entry

        return vault

    @classmethod
    def from_json(cls, json_str: str) -> "Vault":
        data = json.loads(json_str)
        return cls.from_dict(data)
