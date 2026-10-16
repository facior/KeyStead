"""
Bezpieczny zapis i odczyt sejfu na dysku z gwarancją atomowości zapisu
(zapis do pliku tymczasowego + atomic rename).
"""

import os
import threading
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple
from core.crypto import encrypt_payload, decrypt_payload, compute_sha256
from core.vault import Vault


VAULT_FILE_EXTENSION = ".vault"


def save_vault(
    vault: Vault,
    file_path: str,
    master_password: str,
    keyfile_bytes: Optional[bytes] = None
) -> Tuple[int, str]:
    """
    Szyfruje i bezpiecznie (atomowo) zapisuje sejf do pliku.
    Zwraca (rozmiar_bajtow, sha256_checksum).
    """
    # Zapisy z kolejki w tle (np. starym hasłem) nie mogą nadpisać tego zapisu po nim
    background_saver.flush()
    json_bytes = vault.to_json().encode("utf-8")
    encrypted_blob = encrypt_payload(
        plaintext_bytes=json_bytes,
        password=master_password,
        keyfile_bytes=keyfile_bytes
    )
    write_encrypted_file(file_path, encrypted_blob)
    return len(encrypted_blob), compute_sha256(encrypted_blob)


class BackgroundSaver:
    """
    Zapis sejfu w tle: szyfrowanie (Argon2id – celowo kosztowne) i zapis na dysk poza wątkiem interfejsu.

    Zapisy wykonują się po kolei w jednym wątku. Jeśli w kolejce czeka już nowszy zapis tego samego pliku,
    starszy jest pomijany (szybka seria edycji = jedno szyfrowanie). Wątki puli są dołączane przy zamknięciu
    programu, więc zlecony zapis zawsze zostaje dokończony.
    """

    def __init__(self):
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="vault-save")
        self._lock = threading.Lock()
        self._latest: Dict[str, int] = {}
        self._generation = 0
        self._pending: List[Future] = []

    def submit(self, json_bytes: bytes, file_path: str, master_password: str,
               keyfile_bytes: Optional[bytes] = None) -> Future:
        key = os.path.abspath(file_path)
        with self._lock:
            self._generation += 1
            gen = self._generation
            self._latest[key] = gen

        def _work() -> bool:
            with self._lock:
                if self._latest.get(key) != gen:
                    return False  # nowszy zapis już czeka – ten jest nieaktualny
            blob = encrypt_payload(plaintext_bytes=json_bytes, password=master_password, keyfile_bytes=keyfile_bytes)
            write_encrypted_file(file_path, blob)
            return True

        future = self._executor.submit(_work)
        with self._lock:
            self._pending = [f for f in self._pending if not f.done()] + [future]
        return future

    def flush(self, timeout: Optional[float] = 120) -> None:
        """Czeka na zakończenie wszystkich zleconych zapisów (zamknięcie programu, zmiana hasła)."""
        if threading.current_thread().name.startswith("vault-save"):
            return
        with self._lock:
            pending = list(self._pending)
        for f in pending:
            try:
                f.result(timeout=timeout)
            except Exception:
                pass  # błąd zgłasza ten, kto zlecił zapis

    @property
    def busy(self) -> bool:
        with self._lock:
            return any(not f.done() for f in self._pending)


background_saver = BackgroundSaver()


def write_encrypted_file(file_path: str, encrypted_blob: bytes) -> None:
    """Atomowo zapisuje gotowy (już zaszyfrowany) plik sejfu."""
    folder = os.path.dirname(os.path.abspath(file_path))
    if folder:
        os.makedirs(folder, exist_ok=True)

    # Zapis atomowy: do pliku .tmp, a następnie natychmiastowa podmiana
    temp_path = f"{file_path}.tmp_{os.getpid()}_{uuid.uuid4().hex[:8]}"
    try:
        with open(temp_path, "wb") as f:
            f.write(encrypted_blob)
            f.flush()
            os.fsync(f.fileno())

        # Atomowa zamiana na systemach Windows i POSIX
        os.replace(temp_path, file_path)
    except BaseException:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise


def vault_from_blob(
    encrypted_blob: bytes,
    master_password: str,
    keyfile_bytes: Optional[bytes] = None
) -> Vault:
    """Odszyfrowuje sejf z bajtów (np. pobranych z serwera synchronizacji)."""
    decrypted = decrypt_payload(encrypted_blob, master_password, keyfile_bytes)
    return Vault.from_json(decrypted.decode("utf-8"))


def load_vault(
    file_path: str,
    master_password: str,
    keyfile_bytes: Optional[bytes] = None
) -> Vault:
    """
    Wczytuje, deszyfruje i deserializuje sejf z pliku.
    Rzuca wyjątek w razie złego hasła lub uszkodzonego pliku.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Plik sejfu nie istnieje: {file_path}")

    with open(file_path, "rb") as f:
        encrypted_blob = f.read()

    decrypted_bytes = decrypt_payload(
        encrypted_blob=encrypted_blob,
        password=master_password,
        keyfile_bytes=keyfile_bytes
    )

    json_str = decrypted_bytes.decode("utf-8")
    return Vault.from_json(json_str)


def change_vault_credentials(
    file_path: str,
    old_password: str,
    new_password: str,
    old_keyfile: Optional[bytes] = None,
    new_keyfile: Optional[bytes] = None
) -> Vault:
    """Zmienia hasło główne lub plik klucza dla istniejącego sejfu."""
    vault = load_vault(file_path, old_password, old_keyfile)
    save_vault(vault, file_path, new_password, new_keyfile)
    return vault
