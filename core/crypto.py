"""
Moduł kryptograficzny menedżera haseł.
Wykorzystuje Argon2id do derywacji klucza oraz AES-256-GCM do uwierzytelnionego szyfrowania.
"""

import os
import struct
import hashlib
from typing import Optional, Tuple
import argon2.low_level as argon_low
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC_HEADER = b"SECVAULT"
CURRENT_VERSION = 1

# Domyślne zalecane parametry Argon2id dla ochrony sejfu haseł (RFC 9106)
DEFAULT_TIME_COST = 3       # Liczba iteracji
DEFAULT_MEMORY_COST = 65536 # 64 MB RAM
DEFAULT_PARALLELISM = 4     # Liczba wątków
SALT_LEN = 32               # 256-bitowa sól

# Dopuszczalny zakres parametrów odczytywanych z pliku (ochrona przed DoS i osłabieniem KDF)
MIN_TIME_COST, MAX_TIME_COST = 2, 64
MIN_MEMORY_COST, MAX_MEMORY_COST = 19456, 4 * 1024 * 1024   # 19 MiB (min. OWASP) .. 4 GiB
MAX_PARALLELISM = 64
NONCE_LEN = 12              # 96-bitowy wektor inicjalizacyjny dla AES-GCM
KEY_LEN = 32                # 256-bitowy klucz AES


class CryptoError(Exception):
    """Bazowy błąd kryptografii."""
    pass


class InvalidVaultHeaderError(CryptoError):
    """Błąd nagłówka pliku sejfu (nieprawidłowy format lub uszkodzony plik)."""
    pass


class InvalidPasswordOrCorruptDataError(CryptoError):
    """Błędne hasło główne lub uszkodzone/zmodyfikowane dane sejfu."""
    pass


def compute_sha256(data: bytes) -> str:
    """Zwraca skrót SHA-256 w postaci szesnastkowej."""
    return hashlib.sha256(data).hexdigest()


def derive_key(
    password: str,
    salt: bytes,
    keyfile_bytes: Optional[bytes] = None,
    time_cost: int = DEFAULT_TIME_COST,
    memory_cost: int = DEFAULT_MEMORY_COST,
    parallelism: int = DEFAULT_PARALLELISM
) -> bytes:
    """
    Derywacja klucza 256-bitowego za pomocą algorytmu Argon2id.
    Opcjonalnie łączy hasło główne z zawartością pliku-klucza (Keyfile).
    """
    secret = password.encode("utf-8")
    if keyfile_bytes:
        # Połączenie hasła z hashem pliku klucza
        keyfile_hash = hashlib.sha256(keyfile_bytes).digest()
        secret = secret + keyfile_hash

    return argon_low.hash_secret_raw(
        secret=secret,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=KEY_LEN,
        type=argon_low.Type.ID
    )


def encrypt_payload(
    plaintext_bytes: bytes,
    password: str,
    keyfile_bytes: Optional[bytes] = None,
    time_cost: int = DEFAULT_TIME_COST,
    memory_cost: int = DEFAULT_MEMORY_COST,
    parallelism: int = DEFAULT_PARALLELISM
) -> bytes:
    """
    Szyfruje dane za pomocą AES-256-GCM z kluczem wyznaczonym przez Argon2id.
    
    Układ pliku binarnego:
    [8B: MAGIC "SECVAULT"]
    [1B: Wersja = 1]
    [4B: time_cost (uint32)]
    [4B: memory_cost (uint32)]
    [4B: parallelism (uint32)]
    [32B: sól]
    [12B: nonce]
    [NB: szyfrogram + tag GCM]
    """
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)

    key = derive_key(
        password=password,
        salt=salt,
        keyfile_bytes=keyfile_bytes,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism
    )

    header_aad = (
        MAGIC_HEADER +
        struct.pack(">BIII", CURRENT_VERSION, time_cost, memory_cost, parallelism) +
        salt +
        nonce
    )

    aesgcm = AESGCM(key)
    # Wykorzystujemy nagłówek jako Associated Data (AAD), co uniemożliwia podmianę parametrów KDF
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, header_aad)

    return header_aad + ciphertext


def decrypt_payload(
    encrypted_blob: bytes,
    password: str,
    keyfile_bytes: Optional[bytes] = None
) -> bytes:
    """
    Deszyfruje dane i weryfikuje ich integralność za pomocą tagu uwierzytelniającego AES-GCM.
    Rzuca InvalidPasswordOrCorruptDataError jeśli hasło jest niepoprawne lub dane zostały zmodyfikowane.
    """
    min_header_len = len(MAGIC_HEADER) + 1 + 12 + SALT_LEN + NONCE_LEN
    if len(encrypted_blob) < min_header_len + 16:  # 16 bajtów to minimalny tag GCM
        raise InvalidVaultHeaderError("Plik jest za mały lub uszkodzony.")

    magic = encrypted_blob[:len(MAGIC_HEADER)]
    if magic != MAGIC_HEADER:
        raise InvalidVaultHeaderError("Nieprawidłowy nagłówek pliku sejfu (brak podpisu SECVAULT).")

    offset = len(MAGIC_HEADER)
    version, time_cost, memory_cost, parallelism = struct.unpack(">BIII", encrypted_blob[offset:offset + 13])
    offset += 13

    if version != CURRENT_VERSION:
        raise InvalidVaultHeaderError(f"Nieobsługiwana wersja sejfu: {version}")

    # Parametry KDF są czytane PRZED weryfikacją tagu GCM – spreparowany plik mógłby
    # zażądać gigabajtów RAM lub miliardów iteracji (DoS) albo osłabionych parametrów.
    if not (MIN_TIME_COST <= time_cost <= MAX_TIME_COST
            and MIN_MEMORY_COST <= memory_cost <= MAX_MEMORY_COST
            and 1 <= parallelism <= MAX_PARALLELISM):
        raise InvalidVaultHeaderError(
            f"Nieprawidłowe parametry Argon2 w nagłówku (t={time_cost}, m={memory_cost} KiB, p={parallelism}). "
            "Plik jest uszkodzony lub został zmodyfikowany."
        )

    salt = encrypted_blob[offset:offset + SALT_LEN]
    offset += SALT_LEN

    nonce = encrypted_blob[offset:offset + NONCE_LEN]
    offset += NONCE_LEN

    header_aad = encrypted_blob[:offset]
    ciphertext = encrypted_blob[offset:]

    key = derive_key(
        password=password,
        salt=salt,
        keyfile_bytes=keyfile_bytes,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism
    )

    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, header_aad)
        return plaintext
    except Exception as e:
        raise InvalidPasswordOrCorruptDataError("Nieprawidłowe hasło główne (bądź klucz) lub plik został uszkodzony.") from e
