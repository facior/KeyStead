"""
Model danych sejfu haseł: pojedyncze wpisy, kategorie, historia haseł,
ustawienia oraz operacje wyszukiwania i serializacji.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

from core.i18n import _


DEFAULT_CATEGORIES = [
    "Wszystkie",  # i18n: data
    "Loginy",  # i18n: data
    "Karty płatnicze",  # i18n: data
    "Bezpieczne notatki",  # i18n: data
    "Serwery / Wi-Fi",  # i18n: data
    "Tożsamości"  # i18n: data
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


MAX_FIELD_CHARS = 100_000  # notatki itp. – rozsądny limit chroniący przed „bombami” w importowanych plikach


def as_text(value: Any, limit: int = MAX_FIELD_CHARS) -> str:
    """Pole tekstowe z niezaufanego źródła (import, starszy/obcy plik): tylko tekst, z limitem długości."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return ""
    if isinstance(value, (str, int, float)):
        return str(value)[:limit]
    return ""


def as_tags(value: Any) -> List[str]:
    if not isinstance(value, (list, tuple)):
        return []
    return [t for t in (as_text(v, 100).strip() for v in value[:200]) if t]


def as_fields(value: Any) -> Dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {as_text(k, 200): as_text(v) for k, v in list(value.items())[:200] if as_text(k, 200)}


class VaultEntry:
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
        favorite: bool = False,
        entry_id: Optional[str] = None,
        created_at: Optional[str] = None,
        updated_at: Optional[str] = None,
        password_history: Optional[List[Dict[str, str]]] = None,
        attachments: Optional[List[Dict[str, Any]]] = None
    ):
        now_iso = datetime.now(timezone.utc).isoformat()
        self.id = as_text(entry_id, 64) or str(uuid.uuid4())
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
        self.created_at = as_text(created_at, 64) or now_iso
        self.updated_at = as_text(updated_at, 64) or now_iso
        self.password_history = [h for h in (password_history or []) if isinstance(h, dict)] \
            if isinstance(password_history, list) else []
        from core.attachments import clean_meta
        self.attachments = [m for m in (clean_meta(a) for a in (attachments or [])[:100]) if m] \
            if isinstance(attachments, list) else []

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
            "password_history": self.password_history,
            "attachments": self.attachments
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VaultEntry":
        return cls(
            entry_id=data.get("id"),
            title=data.get("title", _("Bez nazwy")),
            category=data.get("category", "Loginy"),  # i18n: data
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
            password_history=data.get("password_history", []),
            attachments=data.get("attachments", [])
        )


class Vault:
    def __init__(
        self,
        name: str = "Główny Sejf",  # i18n: data
        categories: Optional[List[str]] = None,
        settings: Optional[Dict[str, Any]] = None
    ):
        self.version = 1
        # Licznik zapisów wewnątrz zaszyfrowanej treści: serwer synchronizacji nie może go zmienić bez hasła,
        # więc aplikacja rozpozna podsuniętą starą wersję sejfu (np. z hasłem sprzed zmiany)
        self.revision = 0
        # Pęk kluczy formatu v2 (klucz danych + kod odzyskiwania / klucz firmy) – tylko w pamięci, nie w JSON
        self.keyring = None
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

    def attachment_in_use(self, att_id: str) -> bool:
        """Czy plik jest jeszcze używany przez jakikolwiek wpis (także w koszu, np. po duplikacji wpisu)."""
        return any(a.get("id") == att_id for e in list(self.entries.values()) + list(self.trash.values())
                   for a in e.attachments)

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

            if category and category != "Wszystkie" and entry.category != category:  # i18n: data
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
            "revision": self.revision,
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
            name=data.get("name", "Mój Sejf"),  # i18n: data
            categories=data.get("categories"),
            settings=data.get("settings")
        )
        vault.version = data.get("version", 1)
        try:
            vault.revision = max(0, int(data.get("revision", 0) or 0))
        except (TypeError, ValueError):
            vault.revision = 0

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
