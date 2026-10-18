"""
Szybkie odblokowanie sejfu przez Windows Hello (odcisk palca / twarz / PIN Windows).

Jak to działa:
- Windows tworzy w module bezpieczeństwa komputera (TPM) klucz „KeyStead Manager”, którego użycie
  wymaga potwierdzenia przez Windows Hello. Klucz prywatny nigdy nie opuszcza TPM.
- Aplikacja podpisuje tym kluczem losowe wyzwanie zapisane w pliku. Podpis RSA (PKCS#1 v1.5) jest
  deterministyczny, więc z podpisu wyprowadzamy ten sam klucz AES przy każdym potwierdzeniu.
- Tym kluczem (AES-256-GCM) szyfrowane jest hasło główne (+ plik-klucz) i data jego ostatniego wpisania.
- Bez TPM tego komputera i potwierdzenia Windows Hello plik w %USERPROFILE%\\.keystead\\quick_unlock jest
  bezużyteczny. Po upływie okresu ważności (domyślnie 14 dni) trzeba wpisać hasło główne.
"""

import asyncio
import base64
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from core.i18n import _
from core.paths import APP_DIR

KEY_NAME = "KeyStead Manager"
DEFAULT_VALID_DAYS = 14
STORE_DIR = os.path.join(APP_DIR, "quick_unlock")


class QuickUnlockError(Exception):
    """Szybkie odblokowanie niedostępne (komunikat dla użytkownika)."""


class QuickUnlockExpired(QuickUnlockError):
    """Minął okres ważności – trzeba wpisać hasło główne."""


# --------------------------------------------------------------------- dostawca Windows Hello
class WindowsHelloProvider:
    """Podpis wyzwania kluczem Windows Hello (z potwierdzeniem użytkownika). Wywoływać poza wątkiem UI."""

    def is_available(self) -> bool:
        try:
            from winrt.windows.security.credentials import KeyCredentialManager
            return bool(asyncio.run(KeyCredentialManager.is_supported_async()))
        except Exception:
            return False

    def sign(self, challenge: bytes, create: bool = False) -> bytes:
        try:
            return asyncio.run(self._sign(challenge, create))
        except QuickUnlockError:
            raise
        except Exception as e:
            raise QuickUnlockError(_("Windows Hello zgłosiło błąd: {error}", error=e))

    async def _sign(self, challenge: bytes, create: bool) -> bytes:
        from winrt.windows.security.credentials import (KeyCredentialCreationOption, KeyCredentialManager,
                                                        KeyCredentialStatus)
        from winrt.windows.security.cryptography import CryptographicBuffer

        result = await KeyCredentialManager.open_async(KEY_NAME)
        if result.status == KeyCredentialStatus.NOT_FOUND and create:
            result = await KeyCredentialManager.request_create_async(KEY_NAME, KeyCredentialCreationOption.FAIL_IF_EXISTS)
        _check_status(result.status, KeyCredentialStatus)
        op = await result.credential.request_sign_async(CryptographicBuffer.create_from_byte_array(challenge))
        _check_status(op.status, KeyCredentialStatus)
        return bytes(CryptographicBuffer.copy_to_byte_array(op.result))

    def delete_key(self) -> None:
        try:
            from winrt.windows.security.credentials import KeyCredentialManager
            asyncio.run(KeyCredentialManager.delete_async(KEY_NAME))
        except Exception:
            pass


def _check_status(status, enum) -> None:
    if status == enum.SUCCESS:
        return
    messages = {
        enum.USER_CANCELED: _("Anulowano potwierdzenie Windows Hello."),
        enum.USER_PREFERS_PASSWORD: _("Wybrano logowanie hasłem."),
        enum.NOT_FOUND: _("Klucz Windows Hello nie istnieje – włącz szybkie odblokowanie ponownie."),
        enum.SECURITY_DEVICE_LOCKED: _("Windows Hello jest tymczasowo zablokowane (zbyt wiele prób). Użyj hasła."),
    }
    raise QuickUnlockError(messages.get(status, _("Windows Hello jest niedostępne – użyj hasła głównego.")))


# --------------------------------------------------------------------- magazyn
def target_id(kind: str, value: str) -> str:
    """Identyfikator sejfu: plik lokalny (ścieżka) albo konto na serwerze (adres + urządzenie)."""
    if kind == "file":
        value = os.path.normcase(os.path.abspath(value))
    return hashlib.sha256(f"{kind}:{value}".encode("utf-8")).hexdigest()[:32]


def _kdf(signature: bytes, challenge: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=challenge,
                info=b"KeyStead quick unlock v1").derive(signature)


def _now() -> datetime:
    return datetime.now(timezone.utc)


class QuickUnlockStore:
    def __init__(self, provider=None, directory: str = STORE_DIR):
        self.provider = provider or WindowsHelloProvider()
        self.directory = directory

    def _path(self, target: str) -> str:
        return os.path.join(self.directory, f"{target}.json")

    def is_enrolled(self, target: str) -> bool:
        return os.path.isfile(self._path(target))

    def available(self) -> bool:
        return self.provider.is_available()

    def enroll(self, target: str, password: str, keyfile: Optional[bytes]) -> None:
        """Zapamiętuje hasło (zaszyfrowane kluczem Windows Hello). Wymaga potwierdzenia przez użytkownika."""
        challenge = os.urandom(32)
        key = _kdf(self.provider.sign(challenge, create=True), challenge)
        secret = json.dumps({
            "password": password,
            "keyfile": base64.b64encode(keyfile).decode() if keyfile is not None else None,
            "verified_at": _now().isoformat(timespec="seconds"),
        }).encode("utf-8")
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(nonce, secret, target.encode())
        record = {"version": 1, "challenge": base64.b64encode(challenge).decode(),
                  "nonce": base64.b64encode(nonce).decode(), "ciphertext": base64.b64encode(ciphertext).decode()}
        os.makedirs(self.directory, exist_ok=True)
        tmp = self._path(target) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(record, f)
        os.replace(tmp, self._path(target))

    def unlock(self, target: str, valid_days: int = DEFAULT_VALID_DAYS) -> Tuple[str, Optional[bytes]]:
        """Zwraca (hasło, plik-klucz) po potwierdzeniu Windows Hello."""
        try:
            with open(self._path(target), "r", encoding="utf-8") as f:
                record = json.load(f)
            challenge = base64.b64decode(record["challenge"])
            nonce = base64.b64decode(record["nonce"])
            ciphertext = base64.b64decode(record["ciphertext"])
        except (OSError, ValueError, KeyError):
            raise QuickUnlockError(_("Brak zapisanego szybkiego odblokowania dla tego sejfu."))
        key = _kdf(self.provider.sign(challenge), challenge)
        try:
            secret = json.loads(AESGCM(key).decrypt(nonce, ciphertext, target.encode()).decode("utf-8"))
        except Exception:
            self.remove(target)
            raise QuickUnlockError(_("Zapis szybkiego odblokowania jest nieaktualny (np. klucz Windows Hello został "
                                     "zmieniony). Odblokuj sejf hasłem – zostanie utworzony na nowo."))
        verified = datetime.fromisoformat(secret["verified_at"])
        if valid_days and _now() - verified > timedelta(days=valid_days):
            raise QuickUnlockExpired(_("Minęło {days} dni od ostatniego wpisania hasła głównego – wpisz je, "
                                       "żeby go nie zapomnieć. Potem znów wystarczy Windows Hello.", days=valid_days))
        keyfile = base64.b64decode(secret["keyfile"]) if secret.get("keyfile") else None
        return secret["password"], keyfile

    def remove(self, target: str) -> None:
        try:
            os.remove(self._path(target))
        except FileNotFoundError:
            pass

    def remove_all(self) -> None:
        if os.path.isdir(self.directory):
            for name in os.listdir(self.directory):
                if name.endswith(".json"):
                    try:
                        os.remove(os.path.join(self.directory, name))
                    except OSError:
                        pass
