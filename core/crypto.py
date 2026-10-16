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
    if keyfile_bytes is not None and len(keyfile_bytes) == 0:
        # Pusty plik-klucz nic nie dodaje do bezpieczeństwa – użytkownik myślałby, że ma drugi składnik
        raise CryptoError("Wybrany plik-klucz jest pusty – wybierz inny plik (np. wygeneruj nowy plik-klucz).")
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
    Obsługuje format v1 (klucz z hasła) i v2 (klucz danych zabezpieczony kluczami dostępu).
    Rzuca InvalidPasswordOrCorruptDataError jeśli hasło jest niepoprawne lub dane zostały zmodyfikowane.
    """
    if blob_version(encrypted_blob) == 2:
        return unseal(encrypted_blob, password, keyfile_bytes)[0]
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


# =====================================================================================================
# Format v2: losowy klucz danych (DEK) zabezpieczony „kluczami dostępu” – hasło, kod odzyskiwania, klucz firmy
# =====================================================================================================
#
#   [8B MAGIC "SECVAULT"][1B wersja = 2][4B długość nagłówka][nagłówek JSON][12B nonce][szyfrogram + tag GCM]
#
# Nagłówek (lista kluczy dostępu) wchodzi do AAD szyfrowania danych: bez klucza danych nie da się dodać,
# usunąć ani podmienić żadnego klucza dostępu (np. przez serwer synchronizacji).
# Klucz danych jest stały między zapisami, więc kod odzyskiwania i klucz firmy nie wymagają ponownego
# podawania przy każdym zapisie, a zapis nie liczy już Argon2 (szybciej). Zmiana hasła głównego
# zmienia tylko klucz dostępu „hasło”.

import base64 as _b64
import hmac as _hmac
import json as _json
import secrets as _secrets
from typing import Any, Dict, List

from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.hazmat.primitives import serialization as _ser
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _HKDF

VERSION_V2 = 2
MAX_HEADER_BYTES = 64 * 1024
RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # bez mylących 0/O, 1/I
RECOVERY_GROUPS, RECOVERY_GROUP_LEN = 6, 5                  # 30 znaków × 5 bitów = 150 bitów
ORG_PUBLIC_PREFIX = "ksrec1:"
ORG_SLOT_INFO = b"KeyStead org recovery v1"


def _e(data: bytes) -> str:
    return _b64.b64encode(data).decode("ascii")


def _d(text: str) -> bytes:
    return _b64.b64decode(text.encode("ascii"), validate=True)


def blob_version(blob: bytes) -> int:
    if len(blob) > len(MAGIC_HEADER) and blob[:len(MAGIC_HEADER)] == MAGIC_HEADER:
        return blob[len(MAGIC_HEADER)]
    return 0


def _wrap(kek: bytes, dek: bytes, label: str) -> Dict[str, str]:
    nonce = os.urandom(NONCE_LEN)
    return {"nonce": _e(nonce), "wrapped": _e(AESGCM(kek).encrypt(nonce, dek, f"keystead-slot:{label}".encode()))}


def _unwrap(kek: bytes, slot: Dict[str, Any], label: str) -> bytes:
    dek = AESGCM(kek).decrypt(_d(slot["nonce"]), _d(slot["wrapped"]), f"keystead-slot:{label}".encode())
    if len(dek) != KEY_LEN:
        raise InvalidPasswordOrCorruptDataError("Nieprawidłowy klucz danych.")
    return dek


def _kdf_slot(secret: str, keyfile: Optional[bytes]) -> Dict[str, Any]:
    salt = os.urandom(SALT_LEN)
    kek = derive_key(secret, salt, keyfile, DEFAULT_TIME_COST, DEFAULT_MEMORY_COST, DEFAULT_PARALLELISM)
    return {"kdf": {"t": DEFAULT_TIME_COST, "m": DEFAULT_MEMORY_COST, "p": DEFAULT_PARALLELISM, "salt": _e(salt)}}, kek


def _kdf_from_slot(slot: Dict[str, Any], secret: str, keyfile: Optional[bytes]) -> bytes:
    kdf = slot.get("kdf") or {}
    t, m, p = int(kdf.get("t", 0)), int(kdf.get("m", 0)), int(kdf.get("p", 0))
    if not (MIN_TIME_COST <= t <= MAX_TIME_COST and MIN_MEMORY_COST <= m <= MAX_MEMORY_COST and 1 <= p <= MAX_PARALLELISM):
        raise InvalidVaultHeaderError("Nieprawidłowe parametry Argon2 w kluczu dostępu – plik uszkodzony lub zmodyfikowany.")
    salt = _d(kdf["salt"])
    if len(salt) != SALT_LEN:
        raise InvalidVaultHeaderError("Nieprawidłowa sól klucza dostępu.")
    return derive_key(secret, salt, keyfile, t, m, p)


def normalize_recovery_code(code: str) -> str:
    return "".join(c for c in (code or "").upper() if c in RECOVERY_ALPHABET)


def generate_recovery_code() -> str:
    raw = "".join(_secrets.choice(RECOVERY_ALPHABET) for _ in range(RECOVERY_GROUPS * RECOVERY_GROUP_LEN))
    return "-".join(raw[i:i + RECOVERY_GROUP_LEN] for i in range(0, len(raw), RECOVERY_GROUP_LEN))


# --------------------------------------------------------------------- klucz firmy (X25519)
def org_key_id(public_raw: bytes) -> str:
    """Odcisk klucza firmy – do porównania z panelem administratora (np. 'A1B2-C3D4-E5F6-0718')."""
    digest = hashlib.sha256(b"keystead-org-key" + public_raw).hexdigest()[:16].upper()
    return "-".join(digest[i:i + 4] for i in range(0, 16, 4))


def parse_org_public_key(text: str) -> bytes:
    text = (text or "").strip()
    if not text.startswith(ORG_PUBLIC_PREFIX):
        raise CryptoError("To nie jest klucz publiczny odzyskiwania KeyStead (powinien zaczynać się od 'ksrec1:').")
    try:
        raw = _d(text[len(ORG_PUBLIC_PREFIX):])
    except ValueError:
        raise CryptoError("Uszkodzony klucz publiczny odzyskiwania.")
    if len(raw) != 32:
        raise CryptoError("Uszkodzony klucz publiczny odzyskiwania.")
    return raw


def generate_org_keypair(passphrase: str) -> Tuple[str, Dict[str, Any]]:
    """
    Nowa para kluczy odzyskiwania firmy. Zwraca (klucz publiczny 'ksrec1:…' do panelu,
    plik klucza prywatnego zabezpieczony hasłem – przechowywany przez administratora poza serwerem).
    """
    if len(passphrase or "") < 12:
        raise CryptoError("Hasło do klucza odzyskiwania firmy musi mieć co najmniej 12 znaków.")
    private = X25519PrivateKey.generate()
    priv_raw = private.private_bytes(_ser.Encoding.Raw, _ser.PrivateFormat.Raw, _ser.NoEncryption())
    pub_raw = private.public_key().public_bytes(_ser.Encoding.Raw, _ser.PublicFormat.Raw)
    slot, kek = _kdf_slot(passphrase, None)
    nonce = os.urandom(NONCE_LEN)
    key_file = {
        "type": "keystead-org-recovery-key", "version": 1, "key_id": org_key_id(pub_raw),
        "public": ORG_PUBLIC_PREFIX + _e(pub_raw), **slot, "nonce": _e(nonce),
        "private": _e(AESGCM(kek).encrypt(nonce, priv_raw, b"keystead-org-private")),
    }
    return ORG_PUBLIC_PREFIX + _e(pub_raw), key_file


def load_org_private_key(key_file: Dict[str, Any], passphrase: str) -> X25519PrivateKey:
    if key_file.get("type") != "keystead-org-recovery-key":
        raise CryptoError("To nie jest plik klucza odzyskiwania firmy KeyStead.")
    kek = _kdf_from_slot(key_file, passphrase, None)
    try:
        raw = AESGCM(kek).decrypt(_d(key_file["nonce"]), _d(key_file["private"]), b"keystead-org-private")
    except Exception:
        raise InvalidPasswordOrCorruptDataError("Nieprawidłowe hasło do klucza odzyskiwania firmy.")
    return X25519PrivateKey.from_private_bytes(raw)


def _org_kek(shared: bytes, eph_pub: bytes, recipient_pub: bytes) -> bytes:
    return _HKDF(algorithm=_hashes.SHA256(), length=KEY_LEN, salt=eph_pub + recipient_pub,
                 info=ORG_SLOT_INFO).derive(shared)


# --------------------------------------------------------------------- pęk kluczy sejfu
class Keyring:
    """Klucz danych sejfu (tylko w pamięci) i jego klucze dostępu zapisane w nagłówku pliku."""

    def __init__(self, dek: bytes, slots: List[Dict[str, Any]], password_marker: Optional[bytes] = None):
        self.dek = dek
        self.slots = slots
        self._marker = password_marker

    # --- znacznik hasła: wykrycie zmiany hasła bez ponownego liczenia Argon2
    def _password_marker(self, password: str, keyfile: Optional[bytes]) -> bytes:
        kf = hashlib.sha256(keyfile).digest() if keyfile else b""
        return _hmac.new(self.dek, b"pw-marker" + password.encode("utf-8") + kf, hashlib.sha256).digest()

    def matches_password(self, password: str, keyfile: Optional[bytes]) -> bool:
        return self._marker is not None and _hmac.compare_digest(self._marker, self._password_marker(password, keyfile))

    @classmethod
    def new(cls, password: str, keyfile: Optional[bytes] = None) -> "Keyring":
        ring = cls(os.urandom(KEY_LEN), [])
        ring.set_password(password, keyfile)
        return ring

    def _replace(self, slot_type: str, slot: Optional[Dict[str, Any]]) -> None:
        self.slots = [s for s in self.slots if s.get("type") != slot_type]
        if slot is not None:
            self.slots.append(slot)

    def set_password(self, password: str, keyfile: Optional[bytes] = None) -> None:
        if keyfile is not None and len(keyfile) == 0:
            raise CryptoError("Wybrany plik-klucz jest pusty – wybierz inny plik.")
        meta, kek = _kdf_slot(password, keyfile)
        self._replace("password", {"type": "password", **meta, **_wrap(kek, self.dek, "password")})
        self._marker = self._password_marker(password, keyfile)

    def add_recovery_code(self) -> str:
        code = generate_recovery_code()
        meta, kek = _kdf_slot(normalize_recovery_code(code), None)
        self._replace("recovery", {"type": "recovery", **meta, **_wrap(kek, self.dek, "recovery")})
        return code

    def remove_recovery_code(self) -> None:
        self._replace("recovery", None)

    @property
    def has_recovery_code(self) -> bool:
        return any(s.get("type") == "recovery" for s in self.slots)

    def set_org_key(self, public_text: str) -> str:
        """Dodaje (lub wymienia) klucz odzyskiwania firmy. Zwraca jego odcisk."""
        recipient = parse_org_public_key(public_text)
        eph = X25519PrivateKey.generate()
        eph_pub = eph.public_key().public_bytes(_ser.Encoding.Raw, _ser.PublicFormat.Raw)
        kek = _org_kek(eph.exchange(X25519PublicKey.from_public_bytes(recipient)), eph_pub, recipient)
        key_id = org_key_id(recipient)
        self._replace("org", {"type": "org", "key_id": key_id, "eph": _e(eph_pub), **_wrap(kek, self.dek, "org")})
        return key_id

    def remove_org_key(self) -> None:
        self._replace("org", None)

    @property
    def org_key_id(self) -> Optional[str]:
        return next((s.get("key_id") for s in self.slots if s.get("type") == "org"), None)

    def encrypt(self, plaintext: bytes) -> bytes:
        if not any(s.get("type") == "password" for s in self.slots):
            raise CryptoError("Brak klucza dostępu „hasło” – nie można zapisać sejfu.")
        header = _json.dumps({"slots": self.slots}, separators=(",", ":")).encode("utf-8")
        nonce = os.urandom(NONCE_LEN)
        prefix = MAGIC_HEADER + struct.pack(">BI", VERSION_V2, len(header)) + header + nonce
        return prefix + AESGCM(self.dek).encrypt(nonce, plaintext, prefix)


def _parse_v2(blob: bytes):
    offset = len(MAGIC_HEADER)
    if len(blob) < offset + 5:
        raise InvalidVaultHeaderError("Plik jest za mały lub uszkodzony.")
    version, header_len = struct.unpack(">BI", blob[offset:offset + 5])
    offset += 5
    if version != VERSION_V2 or header_len > MAX_HEADER_BYTES or len(blob) < offset + header_len + NONCE_LEN + 16:
        raise InvalidVaultHeaderError("Nieprawidłowy nagłówek sejfu (v2).")
    try:
        header = _json.loads(blob[offset:offset + header_len].decode("utf-8"))
        slots = header["slots"]
        if not isinstance(slots, list) or not all(isinstance(s, dict) for s in slots):
            raise ValueError
    except (ValueError, KeyError, UnicodeDecodeError):
        raise InvalidVaultHeaderError("Uszkodzony nagłówek sejfu (v2).")
    offset += header_len
    nonce = blob[offset:offset + NONCE_LEN]
    offset += NONCE_LEN
    return slots, blob[:offset], nonce, blob[offset:]


def _open_v2(blob: bytes, dek_from_slots) -> Tuple[bytes, Keyring]:
    slots, aad, nonce, ciphertext = _parse_v2(blob)
    dek = dek_from_slots(slots)
    try:
        plaintext = AESGCM(dek).decrypt(nonce, ciphertext, aad)
    except Exception as e:
        raise InvalidPasswordOrCorruptDataError("Plik sejfu jest uszkodzony lub został zmodyfikowany.") from e
    return plaintext, Keyring(dek, slots)


def _slot(slots, slot_type: str) -> Dict[str, Any]:
    slot = next((s for s in slots if s.get("type") == slot_type), None)
    if slot is None:
        raise InvalidPasswordOrCorruptDataError({
            "password": "Plik sejfu nie zawiera klucza dostępu hasłem.",
            "recovery": "Ten sejf nie ma ustawionego kodu odzyskiwania.",
            "org": "Ten sejf nie ma włączonego odzyskiwania przez firmę.",
        }.get(slot_type, "Brak klucza dostępu."))
    return slot


def unseal(blob: bytes, password: str, keyfile: Optional[bytes] = None) -> Tuple[bytes, Optional[Keyring]]:
    """Odszyfrowanie hasłem. Zwraca (dane, pęk kluczy) – dla starego formatu v1 pęk kluczy to None."""
    if blob_version(blob) != VERSION_V2:
        return decrypt_payload(blob, password, keyfile), None

    def _dek(slots):
        slot = _slot(slots, "password")
        kek = _kdf_from_slot(slot, password, keyfile)
        try:
            return _unwrap(kek, slot, "password")
        except InvalidPasswordOrCorruptDataError:
            raise
        except Exception as e:
            raise InvalidPasswordOrCorruptDataError("Nieprawidłowe hasło główne (bądź klucz) lub plik został uszkodzony.") from e

    plaintext, ring = _open_v2(blob, _dek)
    ring._marker = ring._password_marker(password, keyfile)
    return plaintext, ring


def unseal_with_recovery_code(blob: bytes, code: str) -> Tuple[bytes, Keyring]:
    if blob_version(blob) != VERSION_V2:
        raise InvalidPasswordOrCorruptDataError("Ten sejf nie ma ustawionego kodu odzyskiwania.")

    def _dek(slots):
        slot = _slot(slots, "recovery")
        try:
            return _unwrap(_kdf_from_slot(slot, normalize_recovery_code(code), None), slot, "recovery")
        except InvalidPasswordOrCorruptDataError:
            raise
        except Exception as e:
            raise InvalidPasswordOrCorruptDataError("Nieprawidłowy kod odzyskiwania.") from e
    return _open_v2(blob, _dek)


def unseal_with_org_key(blob: bytes, private_key: X25519PrivateKey) -> Tuple[bytes, Keyring]:
    if blob_version(blob) != VERSION_V2:
        raise InvalidPasswordOrCorruptDataError("Ten sejf nie ma włączonego odzyskiwania przez firmę.")
    pub = private_key.public_key().public_bytes(_ser.Encoding.Raw, _ser.PublicFormat.Raw)

    def _dek(slots):
        slot = _slot(slots, "org")
        if slot.get("key_id") != org_key_id(pub):
            raise InvalidPasswordOrCorruptDataError(
                f"Sejf jest zabezpieczony innym kluczem firmy ({slot.get('key_id')}) niż wczytany ({org_key_id(pub)}).")
        eph_pub = _d(slot["eph"])
        kek = _org_kek(private_key.exchange(X25519PublicKey.from_public_bytes(eph_pub)), eph_pub, pub)
        try:
            return _unwrap(kek, slot, "org")
        except Exception as e:
            raise InvalidPasswordOrCorruptDataError("Nie udało się odszyfrować klucza danych kluczem firmy.") from e
    return _open_v2(blob, _dek)


def seal(plaintext: bytes, password: str, keyfile: Optional[bytes] = None,
         keyring: Optional[Keyring] = None) -> bytes:
    """
    Zaszyfrowanie sejfu. Bez pęku kluczy – format v1 (zgodny ze starszymi aplikacjami).
    Z pękiem kluczy – format v2; jeśli hasło główne się zmieniło, klucz dostępu „hasło” jest odnawiany.
    """
    if keyring is None:
        return encrypt_payload(plaintext, password, keyfile)
    if not keyring.matches_password(password, keyfile):
        keyring.set_password(password, keyfile)
    return keyring.encrypt(plaintext)
