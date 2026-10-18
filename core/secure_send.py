"""
Bezpieczny link do hasła (wtyczka „Bezpieczny link do hasła”): szyfrowanie po stronie aplikacji.

Schemat (ten sam liczy strona odbiorcy w przeglądarce – server/templates/share.html, WebCrypto):
    k        = 32 losowe bajty – tylko w linku, po „#” (przeglądarka nie wysyła tej części do serwera)
    pw       = PBKDF2-SHA256(hasło do linku, sól = k, 310 000 powtórzeń, 32 bajty)   – pusty, gdy bez hasła
    master   = SHA-256("keystead-share-v1" || k || pw)
    klucz    = SHA-256("enc" || master)            → AES-256-GCM (losowy 12-bajtowy IV)
    dowód    = hex(SHA-256("proof" || master))     → serwer wydaje szyfrogram tylko za poprawny dowód
Treść: JSON z polami title, username, password, url, notes (tylko te, które wybrał nadawca).
"""

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.i18n import N_
from core.vault import VaultEntry

PBKDF2_ITERATIONS = 310_000
EXPIRY_CHOICES = ((1, N_("1 godzina")), (24, N_("1 dzień")), (72, N_("3 dni")), (168, N_("7 dni")))
SENT_KEY = "secure_send_sent"   # vault.settings: wysłane linki (id, nazwa wpisu, daty) – zaszyfrowane razem z sejfem
MAX_SENT = 100
FIELDS = ("title", "username", "password", "url", "notes")


@dataclass
class SealedShare:
    link_key: str          # część linku po „#” (base64url bez „=”)
    ciphertext: str        # base64
    iv: str                # base64
    proof: str             # hex


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _from_b64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def derive(link_key: bytes, password: str = "") -> Tuple[bytes, str]:
    """(klucz AES, dowód) z klucza linku i opcjonalnego hasła do linku."""
    pw = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), link_key, PBKDF2_ITERATIONS, 32) if password else b""
    master = hashlib.sha256(b"keystead-share-v1" + link_key + pw).digest()
    return hashlib.sha256(b"enc" + master).digest(), hashlib.sha256(b"proof" + master).hexdigest()


def payload_from_entry(entry: VaultEntry, include: Dict[str, bool]) -> Dict[str, str]:
    values = {"title": entry.title, "username": entry.username, "password": entry.password, "url": entry.url,
              "notes": entry.notes}
    return {k: v for k, v in values.items() if include.get(k) and v}


def seal(payload: Dict[str, Any], password: str = "") -> SealedShare:
    link_key = os.urandom(32)
    key, proof = derive(link_key, password)
    iv = os.urandom(12)
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(iv, data, None)
    return SealedShare(_b64url(link_key), base64.b64encode(ciphertext).decode(), base64.b64encode(iv).decode(), proof)


def open_sealed(link_key: str, ciphertext: str, iv: str, password: str = "") -> Dict[str, Any]:
    """Odszyfrowanie (jak w przeglądarce odbiorcy) – do testów i diagnostyki."""
    key, _proof = derive(_from_b64url(link_key), password)
    plain = AESGCM(key).decrypt(base64.b64decode(iv), base64.b64decode(ciphertext), None)
    return json.loads(plain.decode("utf-8"))


def link(base_url: str, share_id: str, link_key: str) -> str:
    return f"{base_url.rstrip('/')}/s/{share_id}#{link_key}"


def remember_sent(settings: Dict[str, Any], share: Dict[str, Any], title: str) -> None:
    sent = [s for s in (settings.get(SENT_KEY) or []) if isinstance(s, dict) and s.get("id") != share.get("id")]
    sent.insert(0, {"id": share["id"], "title": title[:200], "created": share.get("created"),
                    "expires": share.get("expires"), "has_password": bool(share.get("has_password"))})
    settings[SENT_KEY] = sent[:MAX_SENT]


def sent_list(settings: Optional[Dict[str, Any]]):
    return [s for s in ((settings or {}).get(SENT_KEY) or []) if isinstance(s, dict) and s.get("id")]
