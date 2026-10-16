"""
Sesja synchronizacji sejfu z serwerem.

Model ("prosta synchronizacja", etap 1):
- Lokalnie trzymana jest zaszyfrowana kopia sejfu (cache) – działa też offline.
- Każdy zapis trafia najpierw do cache, a potem jest wysyłany na serwer z numerem wersji,
  z której pochodzi ("wersja bazowa"). Jeśli w międzyczasie ktoś zmienił sejf na innym
  urządzeniu, serwer odrzuca zapis (konflikt) i użytkownik decyduje, którą wersję zachować.
  Nic nie ginie po cichu – serwer przechowuje historię wersji.
- Nowsze wersje z serwera są pobierane automatycznie, gdy lokalnie nie ma niewysłanych zmian.

Wszystkie operacje zmieniające lokalną kopię lub stan wykonuje JEDEN wątek roboczy (kolejka),
dzięki czemu zapisy, wysyłki i pobrania nigdy się nie przeplatają, a wątek interfejsu
nie czeka na sieć.
"""

import json
import os
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from core.crypto import CryptoError, compute_sha256, seal
from core.storage import vault_from_blob, write_encrypted_file
from core.vault import Vault
from sync.client import AuthError, ConflictError, NetworkError, RemoteVaultClient, SyncError
from sync.profile import ServerProfile

# Stany widoczne w interfejsie
SYNCED = "synced"
SYNCING = "syncing"
PENDING = "pending"
OFFLINE = "offline"
CONFLICT = "conflict"
ERROR = "error"
REVOKED = "revoked"  # administrator odebrał dostęp (urządzenie odcięte / konto zablokowane)


class EmptyServerError(SyncError):
    """Na serwerze nie ma jeszcze sejfu – trzeba go wysłać lub utworzyć."""


@dataclass
class SyncStatus:
    state: str
    message: str
    local_version: int
    pending: bool
    last_sync: Optional[float]
    remote_meta: Optional[Dict[str, Any]] = field(default=None)
    policy: Dict[str, Any] = field(default_factory=dict)      # polityki bezpieczeństwa firmy
    branding: Dict[str, Any] = field(default_factory=dict)    # nazwa / kolor / logo firmy


def read_cached_branding(profile: ServerProfile) -> Dict[str, Any]:
    """Wygląd firmy zapamiętany przy ostatniej synchronizacji (ekran logowania, przed połączeniem)."""
    try:
        with open(profile.cache_path() + ".sync.json", "r", encoding="utf-8") as f:
            return json.load(f).get("branding") or {}
    except (OSError, ValueError):
        return {}


def read_cached_policy(profile: ServerProfile) -> Dict[str, Any]:
    """Polityki firmy zapamiętane przy ostatniej synchronizacji (np. czy wolno używać Windows Hello)."""
    try:
        with open(profile.cache_path() + ".sync.json", "r", encoding="utf-8") as f:
            policy = json.load(f).get("policy")
            return policy if isinstance(policy, dict) else {}
    except (OSError, ValueError):
        return {}


class OfflineExpiredError(SyncError):
    """Przekroczono dozwolony przez firmę czas pracy bez połączenia z serwerem."""


@dataclass
class RemoteUpdate:
    """Nowsza wersja pobrana z serwera – zatwierdzana przez adopt() dopiero, gdy UI ją wczyta."""
    vault: Vault
    blob: bytes
    version: int
    updated_by: str


class SyncSession:
    def __init__(self, profile: ServerProfile, client: Optional[RemoteVaultClient] = None):
        self.profile = profile
        self.client = client or RemoteVaultClient(profile.url, profile.token, ca_file=profile.ca_file)
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="vault-sync")
        self._listeners: List[Callable[[SyncStatus], None]] = []
        self._password: Optional[str] = None
        self._keyfile: Optional[bytes] = None
        self._queued_saves = 0
        self._queued_lock = threading.Lock()

        # base_version: wersja serwera, z której wywodzi się zawartość lokalnej kopii
        self.base_version = 0
        self.pending = False
        self.revoked = False
        self.remote_meta: Optional[Dict[str, Any]] = None
        self.last_sync: Optional[float] = None
        self.last_contact: Optional[float] = None  # ostatnie potwierdzenie dostępu przez serwer
        self.last_report_at: Optional[float] = None
        self.policy: Dict[str, Any] = {}
        self.branding: Dict[str, Any] = {}
        self.max_revision = 0  # najwyższy licznik zapisów sejfu widziany na tym urządzeniu (ochrona przed cofnięciem)
        self._rejected_version: Optional[int] = None  # wersja serwera odrzucona jako podsunięta starsza treść
        self.state = SYNCING
        self.message = "Łączenie z serwerem..."

    # ------------------------------------------------------------ kolejka
    def _submit(self, fn, *args) -> Future:
        return self._executor.submit(fn, *args)

    def _run(self, fn, *args):
        """Wykonuje operację w wątku synchronizacji i czeka na wynik (wywoływać poza wątkiem UI)."""
        return self._submit(fn, *args).result()

    @property
    def has_unsent_changes(self) -> bool:
        with self._queued_lock:
            return self._queued_saves > 0 or self.pending

    # ------------------------------------------------------------ stan i powiadomienia
    @property
    def known_version(self) -> int:
        return self.base_version

    @property
    def cache_path(self) -> str:
        return self.profile.cache_path()

    @property
    def _state_path(self) -> str:
        return self.cache_path + ".sync.json"

    def _load_state(self) -> None:
        try:
            with open(self._state_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            data = {}
        if not os.path.exists(self.cache_path):
            data = {}
        self.base_version = int(data.get("base_version", data.get("known_version", 0)))
        self.pending = bool(data.get("pending", False))
        self.last_sync = data.get("last_sync")
        self.last_contact = data.get("last_contact")
        self.policy = data.get("policy") or {}
        self.branding = data.get("branding") or {}
        self.last_report_at = data.get("last_report_at")
        try:
            self.max_revision = max(self.max_revision, int(data.get("max_revision", 0) or 0))
        except (TypeError, ValueError):
            pass

    def _save_state(self) -> None:
        os.makedirs(os.path.dirname(self._state_path), exist_ok=True)
        with open(self._state_path, "w", encoding="utf-8") as f:
            json.dump({"base_version": self.base_version, "pending": self.pending, "last_sync": self.last_sync,
                       "last_contact": self.last_contact, "policy": self.policy, "branding": self.branding,
                       "last_report_at": self.last_report_at, "max_revision": self.max_revision}, f)

    def _seen_revision(self, revision: int) -> None:
        self.max_revision = max(self.max_revision, int(revision or 0))

    def next_revision(self, current: int) -> int:
        """Licznik dla nowego zapisu – zawsze wyższy od wszystkiego, co to urządzenie widziało."""
        return max(int(current or 0), self.max_revision) + 1

    def _is_rollback(self, vault: Vault) -> bool:
        """Czy pobrana zawartość jest STARSZA niż już widziana (serwer podsunął wcześniejszą wersję)."""
        return self.max_revision > 0 and int(getattr(vault, "revision", 0) or 0) < self.max_revision

    ROLLBACK_MESSAGE = ("Serwer przesłał STARSZĄ zawartość sejfu niż ta, którą to urządzenie już widziało – nie została "
                        "wczytana. Jeśli administrator na Twoją prośbę przywrócił poprzednią wersję, wybierz w panelu "
                        "synchronizacji „Pobierz wersję z serwera”. W przeciwnym razie zgłoś to administratorowi.")

    def report_due(self, interval_hours: int = 24) -> bool:
        if not (self.policy or {}).get("security_report"):
            return False
        return not self.last_report_at or time.time() - float(self.last_report_at) > interval_hours * 3600

    def send_security_report(self, report: Dict[str, Any]) -> bool:
        """Wysyła zbiorczy wynik audytu (wywoływać w wątku roboczym)."""
        try:
            ok = self.client.send_report(report)
        except SyncError:
            return False
        if ok:
            self.last_report_at = time.time()
            if os.path.exists(self.cache_path):
                self._submit(self._save_state)
        return ok

    def _apply_server_info(self, info: Dict[str, Any]) -> None:
        """Polityki i wygląd firmy z odpowiedzi serwera (zapamiętywane na czas pracy offline)."""
        if isinstance(info.get("policy"), dict):
            self.policy = info["policy"]
        if isinstance(info.get("branding"), dict):
            self.branding = info["branding"]
        self.last_contact = time.time()
        if os.path.exists(self.cache_path):
            self._save_state()

    def _check_offline_allowed(self) -> None:
        max_hours = int((self.policy or {}).get("max_offline_hours") or 0)
        if max_hours and self.last_contact and time.time() - float(self.last_contact) > max_hours * 3600:
            raise OfflineExpiredError(
                f"Polityka firmy pozwala pracować bez połączenia z serwerem najwyżej {max_hours} h. "
                "Połącz się z siecią firmy / VPN, aby odblokować sejf.")

    def add_listener(self, callback: Callable[[SyncStatus], None]) -> None:
        self._listeners.append(callback)

    def status(self) -> SyncStatus:
        return SyncStatus(self.state, self.message, self.base_version, self.pending, self.last_sync, self.remote_meta,
                          dict(self.policy), dict(self.branding))

    def _set(self, state: str, message: str) -> None:
        self.state, self.message = state, message
        status = self.status()
        for cb in list(self._listeners):
            try:
                cb(status)
            except Exception:
                pass

    def _mark_synced(self, version: int, message: str = "Zsynchronizowano") -> None:
        self.base_version = version
        self.pending = False
        self.last_sync = time.time()
        self._save_state()
        self._set(SYNCED, message)

    def _decrypt(self, blob: bytes) -> Vault:
        return vault_from_blob(blob, self._password, self._keyfile)

    def _read_cache(self) -> bytes:
        with open(self.cache_path, "rb") as f:
            return f.read()

    # ------------------------------------------------------------ odebranie dostępu
    def wipe_local_data(self) -> None:
        """Usuwa z dysku lokalną (zaszyfrowaną) kopię sejfu i stan synchronizacji tego serwera."""
        for path in (self.cache_path, self._state_path):
            try:
                os.remove(path)
            except FileNotFoundError:
                pass
            except OSError:
                pass

    def _revoke(self, reason: str) -> None:
        """Serwer odrzucił urządzenie: koniec synchronizacji, usunięcie lokalnej kopii, powiadomienie UI."""
        if self.revoked:
            return
        self.revoked = True
        self.pending = False
        self.wipe_local_data()
        self._set(REVOKED, reason or "Administrator odebrał temu urządzeniu dostęp do sejfu.")

    # ------------------------------------------------------------ otwieranie
    def open(self, password: str, keyfile: Optional[bytes] = None) -> Vault:
        """
        Łączy się z serwerem i zwraca odszyfrowany sejf (pobierając nowszą wersję, jeśli jest).
        Gdy serwer jest nieosiągalny – otwiera lokalną kopię (tryb offline).
        Rzuca EmptyServerError, gdy na serwerze nie ma jeszcze sejfu.
        """
        return self._run(self._open, password, keyfile)

    def _open(self, password: str, keyfile: Optional[bytes]) -> Vault:
        self._password, self._keyfile = password, keyfile
        try:
            info = self.client.meta()
        except AuthError:
            # Urządzenie odcięte / konto zablokowane – lokalna kopia nie może dalej służyć do pracy offline
            self.revoked = True
            self.wipe_local_data()
            raise
        except NetworkError as e:
            self._load_state()
            if not os.path.exists(self.cache_path):
                raise NetworkError(f"{e}\nBrak lokalnej kopii – pierwsze połączenie wymaga dostępu do serwera.")
            self._check_offline_allowed()
            vault = self._decrypt(self._read_cache())
            self._set(OFFLINE, "Serwer niedostępny – pracujesz na lokalnej kopii")
            return vault

        self.profile.server_id = info.get("server_id", "")
        self.profile.device_name = info.get("device", "")
        self._load_state()
        self._apply_server_info(info)
        if not info.get("exists"):
            raise EmptyServerError("Na serwerze nie ma jeszcze sejfu.")

        remote = info["meta"]
        self.remote_meta = remote
        has_cache = os.path.exists(self.cache_path)

        if has_cache and remote["version"] == self.base_version:
            vault = self._decrypt(self._read_cache())
            self._seen_revision(vault.revision)
            if self.pending:
                self._push()  # niewysłane zmiany z poprzedniej sesji
            else:
                self.last_sync = time.time()
                self._save_state()
                self._set(SYNCED, "Zsynchronizowano")
            return vault

        if has_cache and self.pending and remote["version"] > self.base_version:
            vault = self._decrypt(self._read_cache())
            self._set(CONFLICT, f"Sejf zmieniono na urządzeniu „{remote.get('updated_by')}”, a tu są niewysłane zmiany")
            return vault

        if has_cache and remote["version"] < self.base_version:
            vault = self._decrypt(self._read_cache())
            self._set(ERROR, f"Serwer ma starszą wersję (v{remote['version']}) niż ostatnio widziana (v{self.base_version}). "
                             "Możliwe przywrócenie serwera z kopii – zdecyduj w panelu synchronizacji.")
            return vault

        blob, version = self.client.download()
        vault = self._decrypt(blob)  # najpierw weryfikacja hasła, potem nadpisanie lokalnej kopii
        if has_cache:
            cached = self._decrypt(self._read_cache())
            self._seen_revision(cached.revision)
            if self._is_rollback(vault):
                self._set(ERROR, self.ROLLBACK_MESSAGE)
                return cached  # pracujemy na własnej, nowszej kopii
        write_encrypted_file(self.cache_path, blob)
        self._seen_revision(vault.revision)
        self._mark_synced(version)
        return vault

    def create_on_server(self, encrypted_blob: bytes) -> Dict[str, Any]:
        """Wysyła pierwszy sejf na pusty serwer."""
        return self._run(self._create_on_server, encrypted_blob)

    def _create_on_server(self, encrypted_blob: bytes) -> Dict[str, Any]:
        meta = self.client.upload(encrypted_blob, 0)
        write_encrypted_file(self.cache_path, encrypted_blob)
        self.remote_meta = meta
        self._mark_synced(meta["version"], "Sejf wysłany na serwer")
        return meta

    # ------------------------------------------------------------ zapis i wysyłanie
    def queue_save(self, encrypted_blob, revision: Optional[int] = None) -> Future:
        """
        Zapisuje zaszyfrowany sejf do lokalnej kopii i wysyła go na serwer – w tle, w kolejności zapisów.
        Wywoływane z wątku UI (nie blokuje). `encrypted_blob` to gotowe bajty albo funkcja, która je
        utworzy – wtedy kosztowne szyfrowanie też odbywa się w tle. `revision` – licznik zapisu z treści sejfu.
        """
        with self._queued_lock:
            self._queued_saves += 1
        if revision:
            self._seen_revision(revision)
        if self.state not in (CONFLICT, OFFLINE, REVOKED):
            self._set(PENDING, "Zapisywanie zmian...")
        return self._submit(self._save_and_push, encrypted_blob)

    def _save_and_push(self, encrypted_blob: bytes) -> None:
        if self.revoked:
            # Dostęp odebrany – nie odtwarzamy na dysku usuniętej lokalnej kopii
            with self._queued_lock:
                self._queued_saves -= 1
            return
        try:
            if callable(encrypted_blob):
                encrypted_blob = encrypted_blob()
            write_encrypted_file(self.cache_path, encrypted_blob)
            self.pending = True
            self._save_state()
        finally:
            with self._queued_lock:
                self._queued_saves -= 1
        self._push()

    def push(self) -> None:
        self._run(self._push)

    def _push(self) -> None:
        if not self.pending or self.state in (CONFLICT, REVOKED):
            return
        blob = self._read_cache()
        self._set(SYNCING, "Wysyłanie zmian na serwer...")
        try:
            meta = self.client.upload(blob, self.base_version)
        except AuthError as e:
            self._revoke(str(e))
            return
        except ConflictError as e:
            self.remote_meta = e.remote_meta
            self._set(CONFLICT, f"Sejf zmieniono na urządzeniu „{e.remote_meta.get('updated_by', '?')}” – wybierz, którą wersję zachować")
            return
        except NetworkError:
            self._set(OFFLINE, "Serwer niedostępny – zmiany zapisane lokalnie, zostaną wysłane później")
            return
        except SyncError as e:
            self._set(ERROR, str(e))
            return
        self.remote_meta = meta
        self._mark_synced(meta["version"], "Zmiany wysłane na serwer")

    # ------------------------------------------------------------ sprawdzanie aktualizacji
    def poll(self) -> Optional[RemoteUpdate]:
        """
        Sprawdza serwer (wywoływać poza wątkiem UI). Zwraca RemoteUpdate, jeśli na serwerze jest
        nowsza wersja z innego urządzenia – UI wczytuje ją i potwierdza przez adopt().
        """
        return self._run(self._poll)

    def _poll(self) -> Optional[RemoteUpdate]:
        if self.revoked:
            return None
        try:
            info = self.client.meta()
        except AuthError as e:
            self._revoke(str(e))
            return None
        except NetworkError:
            if self.state != CONFLICT:
                self._set(OFFLINE, "Serwer niedostępny – zmiany są zapisywane lokalnie" if self.pending
                          else "Serwer niedostępny – pracujesz na lokalnej kopii")
            return None
        except SyncError as e:
            self._set(ERROR, str(e))
            return None

        self._apply_server_info(info)
        remote = info.get("meta")
        self.remote_meta = remote
        if self.state == CONFLICT:
            self._set(CONFLICT, self.message)
            return None
        if self.pending:
            self._push()
            return None
        if not remote:
            self._set(ERROR, "Sejf zniknął z serwera – wyślij go ponownie z panelu synchronizacji.")
            return None
        if remote["version"] < self.base_version:
            self._set(ERROR, f"Serwer ma starszą wersję (v{remote['version']}) niż ostatnio widziana (v{self.base_version}).")
            return None
        if remote["version"] == self.base_version:
            self.last_sync = time.time()
            self._set(SYNCED, "Zsynchronizowano")
            return None
        if remote["version"] == self._rejected_version:
            self._set(ERROR, self.ROLLBACK_MESSAGE)  # ta sama podsunięta wersja – bez ponownego pobierania
            return None

        self._set(SYNCING, "Pobieranie zmian z serwera...")
        try:
            blob, version = self.client.download()
            vault = self._decrypt(blob)
        except NetworkError:
            self._set(OFFLINE, "Serwer niedostępny")
            return None
        except CryptoError:
            self._set(ERROR, "Nie można odszyfrować nowej wersji – hasło główne zostało zmienione na innym "
                             "urządzeniu. Zablokuj sejf i odblokuj go nowym hasłem.")
            return None
        if self._is_rollback(vault):
            self._rejected_version = version
            self._set(ERROR, self.ROLLBACK_MESSAGE)
            return None
        self._set(SYNCING, "Wczytywanie zmian...")
        return RemoteUpdate(vault, blob, version, remote.get("updated_by", "?"))

    def adopt(self, update: RemoteUpdate) -> Future:
        """Zatwierdza wczytaną przez UI wersję z serwera jako nową lokalną kopię."""
        return self._submit(self._adopt, update)

    def _adopt(self, update: RemoteUpdate) -> None:
        # Zapis, który zdążył się pojawić w międzyczasie, ma pierwszeństwo – skończy się konfliktem, nie utratą danych
        if self.pending or self.state == CONFLICT:
            return
        write_encrypted_file(self.cache_path, update.blob)
        self._seen_revision(update.vault.revision)
        self._mark_synced(update.version, f"Pobrano zmiany z urządzenia „{update.updated_by}”")

    # ------------------------------------------------------------ konflikty i historia
    def resolve_use_server(self) -> Vault:
        """Odrzuca lokalne niewysłane zmiany i pobiera wersję z serwera."""
        return self._run(self._resolve_use_server)

    def _resolve_use_server(self) -> Vault:
        """Świadoma decyzja użytkownika – przyjmuje wersję z serwera, także starszą (np. przywróconą przez administratora)."""
        blob, version = self.client.download()
        vault = self._decrypt(blob)
        write_encrypted_file(self.cache_path, blob)
        self.max_revision = int(vault.revision or 0)
        self._mark_synced(version, "Pobrano wersję z serwera")
        return vault

    def resolve_keep_local(self) -> None:
        """Nadpisuje serwer lokalną wersją (poprzednia zostaje w historii serwera)."""
        self._run(self._resolve_keep_local)

    def _resolve_keep_local(self) -> None:
        info = self.client.meta()
        base = info["meta"]["version"] if info.get("meta") else 0
        meta = self.client.upload(self._read_cache(), base)
        self.remote_meta = meta
        self._mark_synced(meta["version"], "Twoja wersja została wysłana na serwer")

    def history(self) -> List[Dict[str, Any]]:
        return self.client.history()

    def restore_version(self, version: int) -> Vault:
        """Przywraca wybraną wersję z historii jako nową, najnowszą wersję na serwerze."""
        return self._run(self._restore_version, version)

    def _restore_version(self, version: int) -> Vault:
        blob, _ = self.client.download(version)
        vault = self._decrypt(blob)
        # Przywrócona treść dostaje nowy, najwyższy licznik – inne urządzenia przyjmą ją jako zwykłą zmianę
        vault.revision = self.next_revision(vault.revision)
        blob = seal(vault.to_json().encode("utf-8"), self._password, self._keyfile, vault.keyring)
        self._seen_revision(vault.revision)
        info = self.client.meta()
        base = info["meta"]["version"] if info.get("meta") else 0
        meta = self.client.upload(blob, base)
        write_encrypted_file(self.cache_path, blob)
        self.remote_meta = meta
        self._mark_synced(meta["version"], f"Przywrócono wersję v{version} (jako v{meta['version']})")
        return vault

    def update_credentials(self, password: str, keyfile: Optional[bytes]) -> None:
        """Po zmianie hasła głównego – kolejne pobrania odszyfrowujemy nowym hasłem."""
        self._password, self._keyfile = password, keyfile

    def close(self) -> None:
        """Blokada sejfu: dokończ zaległe zapisy w tle i usuń dane uwierzytelniające z pamięci."""
        self._listeners.clear()

        def _wipe():
            self._password = None
            self._keyfile = None
        self._submit(_wipe)
        self._executor.shutdown(wait=False)
