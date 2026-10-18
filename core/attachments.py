"""
Załączniki wpisów (np. skan dowodu, licencja, klucz SSH) – szyfrowane osobno, każdy własnym kluczem.

- Klucz pliku (AES-256-GCM) jest zapisany w metadanych wpisu, czyli wewnątrz zaszyfrowanego sejfu.
  Sam plik leży obok sejfu (tryb lokalny: <sejf>.files/) lub na serwerze synchronizacji – w obu miejscach
  wyłącznie zaszyfrowany. Bez sejfu (i hasła głównego) jest bezużyteczny.
- Edycja wpisu nie wysyła ponownie załączników: na serwer trafiają tylko raz, przy dodaniu.
"""

import base64
import os
import re
import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.i18n import _

MAGIC = b"KSATT1"
ID_RE = re.compile(r"^[0-9a-f]{32}$")
DEFAULT_MAX_MB = 10
OPEN_DIR = os.path.join(tempfile.gettempdir(), "KeyStead-open")


class AttachmentError(Exception):
    pass


def _aad(att_id: str) -> bytes:
    return MAGIC + att_id.encode("ascii")


def encrypt_attachment(att_id: str, data: bytes) -> Tuple[bytes, str]:
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    return MAGIC + nonce + AESGCM(key).encrypt(nonce, data, _aad(att_id)), base64.b64encode(key).decode("ascii")


def decrypt_attachment(meta: Dict[str, Any], blob: bytes) -> bytes:
    att_id = meta.get("id", "")
    if not blob.startswith(MAGIC) or len(blob) < len(MAGIC) + 12 + 16:
        raise AttachmentError(_("Plik załącznika jest uszkodzony."))
    try:
        key = base64.b64decode(meta["key"], validate=True)
        nonce = blob[len(MAGIC):len(MAGIC) + 12]
        return AESGCM(key).decrypt(nonce, blob[len(MAGIC) + 12:], _aad(att_id))
    except Exception:
        raise AttachmentError(_("Nie udało się odszyfrować załącznika (plik uszkodzony lub podmieniony)."))


def safe_filename(name: str) -> str:
    name = os.path.basename((name or "").replace("\\", "/")).strip()
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name)[:200].strip(". ")
    return name or "załącznik"  # i18n: data (nazwa pliku)


def new_attachment(path: str, max_bytes: int) -> Tuple[Dict[str, Any], bytes]:
    """Czyta plik z dysku i przygotowuje (metadane do wpisu, zaszyfrowane bajty)."""
    size = os.path.getsize(path)
    if size > max_bytes:
        raise AttachmentError(_("Plik jest za duży – limit to {mb} MB.", mb=max_bytes // (1024 * 1024)))
    with open(path, "rb") as f:
        data = f.read()
    att_id = uuid.uuid4().hex
    blob, key = encrypt_attachment(att_id, data)
    meta = {"id": att_id, "name": safe_filename(path), "size": len(data), "key": key,
            "added_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    return meta, blob


def clean_meta(value: Any) -> Optional[Dict[str, Any]]:
    """Metadane załącznika z niezaufanego źródła (plik sejfu, import) – tylko poprawne pola."""
    if not isinstance(value, dict) or not ID_RE.match(str(value.get("id", ""))):
        return None
    key = str(value.get("key", ""))
    try:
        if len(base64.b64decode(key, validate=True)) != 32:
            return None
    except ValueError:
        return None
    try:
        size = max(0, int(value.get("size", 0)))
    except (TypeError, ValueError):
        size = 0
    return {"id": value["id"], "name": safe_filename(str(value.get("name", ""))), "size": size, "key": key,
            "added_at": str(value.get("added_at", ""))[:40]}


# --------------------------------------------------------------------- magazyny
class LocalAttachmentStore:
    """Tryb lokalny: zaszyfrowane pliki w folderze obok pliku sejfu."""

    def __init__(self, directory: str):
        self.directory = directory

    def _path(self, att_id: str) -> str:
        if not ID_RE.match(att_id or ""):
            raise AttachmentError(_("Nieprawidłowy identyfikator załącznika."))
        return os.path.join(self.directory, f"{att_id}.bin")

    def put(self, att_id: str, blob: bytes) -> None:
        os.makedirs(self.directory, exist_ok=True)
        tmp = self._path(att_id) + ".tmp"
        with open(tmp, "wb") as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._path(att_id))

    def get(self, att_id: str) -> bytes:
        try:
            with open(self._path(att_id), "rb") as f:
                return f.read()
        except FileNotFoundError:
            raise AttachmentError(_("Brak pliku załącznika na tym komputerze."))

    def delete(self, att_id: str) -> None:
        try:
            os.remove(self._path(att_id))
        except FileNotFoundError:
            pass


class RemoteAttachmentStore(LocalAttachmentStore):
    """Tryb serwerowy: serwer synchronizacji + lokalna kopia podręczna (zaszyfrowana)."""

    def __init__(self, client, cache_dir: str):
        super().__init__(cache_dir)
        self.client = client

    def put(self, att_id: str, blob: bytes) -> None:
        self.client.upload_attachment(att_id, blob)  # najpierw serwer – inne urządzenia muszą móc go pobrać
        super().put(att_id, blob)

    def get(self, att_id: str) -> bytes:
        try:
            return super().get(att_id)
        except AttachmentError:
            blob = self.client.download_attachment(att_id)
            super().put(att_id, blob)
            return blob

    def delete(self, att_id: str) -> None:
        super().delete(att_id)
        self.client.delete_attachment(att_id)


def store_for(vault_file_path: str, sync_session=None):
    if sync_session is not None:
        return RemoteAttachmentStore(sync_session.client, sync_session.cache_path + ".files")
    return LocalAttachmentStore(vault_file_path + ".files")


# --------------------------------------------------------------------- otwieranie (kopia tymczasowa)
def write_temp_copy(meta: Dict[str, Any], data: bytes) -> str:
    """Odszyfrowana kopia do otwarcia w innym programie – w prywatnym folderze, usuwana przy blokadzie sejfu."""
    folder = tempfile.mkdtemp(prefix="ks-", dir=_ensure_open_dir())
    path = os.path.join(folder, safe_filename(meta.get("name", "")))
    with open(path, "wb") as f:
        f.write(data)
    return path


def _ensure_open_dir() -> str:
    os.makedirs(OPEN_DIR, exist_ok=True)
    return OPEN_DIR


def cleanup_temp_copies() -> None:
    """Usuwa odszyfrowane kopie tymczasowe (blokada sejfu, zamknięcie i start aplikacji)."""
    shutil.rmtree(OPEN_DIR, ignore_errors=True)
