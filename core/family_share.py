"""
Udostępnianie domownikom bez serwera (wtyczka „Udostępnianie domownikom”).

Każdy sejf ma parę kluczy X25519 („tożsamość”, w zaszyfrowanych ustawieniach sejfu). Klucz publiczny to
„wizytówka” (tekst ksfam1:… albo kod QR), którą domownicy wymieniają się raz. Wpis wysyłany jest jako paczka
(tekst ksshare1:… lub plik), którą otworzy tylko sejf adresata:

    klucz = HKDF-SHA256( X25519(efemeryczny, adresat) || X25519(nadawca, adresat),
                         sól = pub_efemeryczny || pub_nadawcy || pub_adresata, info = "keystead-family-share-v1" )
    treść = AES-256-GCM(klucz, JSON wpisu), AAD = nagłówek paczki

Drugi składnik (statyczny klucz nadawcy) uwierzytelnia nadawcę: paczkę z kluczem „Anny” mógł utworzyć tylko sejf
Anny. Odbiorca widzi więc „od: Anna ✓”, jeśli ma jej wizytówkę – a podrobionej paczki nie odszyfruje jako od Anny.
Ponowne wysłanie tego samego wpisu (to samo share_id) aktualizuje wpis u odbiorcy.
"""

import base64
import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from core.i18n import _
from core.vault import VaultEntry, as_fields, as_tags, as_text

CONTACT_PREFIX = "ksfam1:"
PACKAGE_PREFIX = "ksshare1:"
IDENTITY_KEY = "family_identity"   # vault.settings: {"private", "public", "name"}
CONTACTS_KEY = "family_contacts"   # vault.settings: [{"name", "public", "added"}]
RECEIVED_KEY = "family_received"   # vault.settings: {share_id: entry_id}
SENT_KEY = "family_sent"           # vault.settings: {entry_id: [{"public", "share_id", "sent"}]}
MAX_PACKAGE_CHARS = 200_000
INFO = b"keystead-family-share-v1"


class ShareError(Exception):
    pass


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    text = "".join((text or "").split())
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _raw_public(key) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def fingerprint(public_raw: bytes) -> str:
    """Odcisk do porównania na głos lub przez telefon (np. „7F3A-91C2-0B4D”)."""
    digest = hashlib.sha256(b"keystead-family-key" + public_raw).hexdigest()[:12].upper()
    return "-".join(digest[i:i + 4] for i in range(0, 12, 4))


# --------------------------------------------------------------------- tożsamość i wizytówki
def identity(settings: Dict[str, Any], default_name: str = "") -> Dict[str, str]:
    """Para kluczy tego sejfu – tworzona przy pierwszym użyciu."""
    ident = settings.get(IDENTITY_KEY)
    if not isinstance(ident, dict) or not ident.get("private"):
        private = X25519PrivateKey.generate()
        ident = {"private": _b64(private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                                       serialization.NoEncryption())),
                 "public": _b64(_raw_public(private.public_key())), "name": default_name[:80]}
        settings[IDENTITY_KEY] = ident
    return ident


def _private(settings: Dict[str, Any]) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(_unb64(identity(settings)["private"]))


def my_card(settings: Dict[str, Any], name: str) -> str:
    ident = identity(settings, name)
    if name and ident.get("name") != name:
        ident["name"] = name[:80]
    return CONTACT_PREFIX + _b64(json.dumps({"n": ident["name"], "k": ident["public"]}, ensure_ascii=False).encode())


@dataclass
class Contact:
    name: str
    public: str           # base64url klucza X25519

    @property
    def fingerprint(self) -> str:
        return fingerprint(_unb64(self.public))


def parse_card(text: str) -> Contact:
    text = (text or "").strip()
    if not text.startswith(CONTACT_PREFIX):
        raise ShareError(_("To nie jest wizytówka KeyStead (powinna zaczynać się od „{prefix}”).", prefix=CONTACT_PREFIX))
    try:
        data = json.loads(_unb64(text[len(CONTACT_PREFIX):]).decode("utf-8"))
        public = data["k"]
        if len(_unb64(public)) != 32:
            raise ValueError
    except Exception:
        raise ShareError(_("Uszkodzona wizytówka KeyStead."))
    return Contact(as_text(data.get("n"), 80).strip() or _("Bez nazwy"), public)


def contacts(settings: Dict[str, Any]) -> List[Contact]:
    out = []
    for c in settings.get(CONTACTS_KEY) or []:
        if isinstance(c, dict) and c.get("public"):
            out.append(Contact(as_text(c.get("name"), 80), c["public"]))
    return out


def add_contact(settings: Dict[str, Any], contact: Contact) -> bool:
    """Dodaje (albo zmienia nazwę). Zwraca False, gdy to własna wizytówka."""
    if contact.public == identity(settings).get("public"):
        return False
    items = [c for c in (settings.get(CONTACTS_KEY) or []) if isinstance(c, dict) and c.get("public") != contact.public]
    items.append({"name": contact.name, "public": contact.public, "added": datetime.now(timezone.utc).isoformat()})
    settings[CONTACTS_KEY] = items
    return True


def remove_contact(settings: Dict[str, Any], public: str) -> None:
    settings[CONTACTS_KEY] = [c for c in (settings.get(CONTACTS_KEY) or [])
                              if isinstance(c, dict) and c.get("public") != public]


# --------------------------------------------------------------------- paczki
def _key(shared_eph: bytes, shared_static: bytes, eph_pub: bytes, sender_pub: bytes, recipient_pub: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=eph_pub + sender_pub + recipient_pub,
                info=INFO).derive(shared_eph + shared_static)


def entry_payload(entry: VaultEntry, include_notes: bool = True) -> Dict[str, Any]:
    return {"title": entry.title, "category": entry.category, "username": entry.username, "password": entry.password,
            "url": entry.url, "totp_secret": entry.totp_secret, "notes": entry.notes if include_notes else "",
            "tags": list(entry.tags), "custom_fields": dict(entry.custom_fields)}


def seal_package(settings: Dict[str, Any], sender_name: str, contact: Contact, payload: Dict[str, Any],
                 share_id: str) -> str:
    sender = _private(settings)
    sender_pub = _raw_public(sender.public_key())
    recipient_pub = _unb64(contact.public)
    recipient = X25519PublicKey.from_public_bytes(recipient_pub)
    eph = X25519PrivateKey.generate()
    eph_pub = _raw_public(eph.public_key())
    key = _key(eph.exchange(recipient), sender.exchange(recipient), eph_pub, sender_pub, recipient_pub)
    header = {"v": 1, "e": _b64(eph_pub), "s": _b64(sender_pub), "r": _b64(recipient_pub), "id": share_id,
              "from": sender_name[:80], "t": datetime.now(timezone.utc).isoformat()}
    header_raw = json.dumps(header, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    nonce = os.urandom(12)
    body = AESGCM(key).encrypt(nonce, json.dumps(payload, ensure_ascii=False).encode("utf-8"), header_raw)
    return PACKAGE_PREFIX + _b64(header_raw) + "." + _b64(nonce + body)


@dataclass
class Received:
    share_id: str
    sender_name: str
    sender_public: str
    known_sender: Optional[Contact]
    payload: Dict[str, Any]
    sent_at: str


def open_package(settings: Dict[str, Any], text: str) -> Received:
    text = "".join((text or "").split())
    if not text.startswith(PACKAGE_PREFIX) or len(text) > MAX_PACKAGE_CHARS or "." not in text:
        raise ShareError(_("To nie jest paczka KeyStead (powinna zaczynać się od „{prefix}”).", prefix=PACKAGE_PREFIX))
    head_text, body_text = text[len(PACKAGE_PREFIX):].split(".", 1)
    try:
        header_raw = _unb64(head_text)
        header = json.loads(header_raw.decode("utf-8"))
        eph_pub, sender_pub, recipient_pub = _unb64(header["e"]), _unb64(header["s"]), _unb64(header["r"])
        blob = _unb64(body_text)
    except Exception:
        raise ShareError(_("Uszkodzona paczka KeyStead."))
    me = _private(settings)
    if _raw_public(me.public_key()) != recipient_pub:
        raise ShareError(_("Ta paczka jest przeznaczona dla innej osoby (innego sejfu)."))
    try:
        key = _key(me.exchange(X25519PublicKey.from_public_bytes(eph_pub)),
                   me.exchange(X25519PublicKey.from_public_bytes(sender_pub)), eph_pub, sender_pub, recipient_pub)
        payload = json.loads(AESGCM(key).decrypt(blob[:12], blob[12:], header_raw).decode("utf-8"))
    except Exception:
        raise ShareError(_("Nie udało się otworzyć paczki – jest uszkodzona albo zmieniona."))
    sender_public = _b64(sender_pub)
    known = next((c for c in contacts(settings) if c.public == sender_public), None)
    return Received(as_text(header.get("id"), 64), as_text(header.get("from"), 80), sender_public, known,
                    payload if isinstance(payload, dict) else {}, as_text(header.get("t"), 40))


def apply_received(settings: Dict[str, Any], vault, received: Received) -> VaultEntry:
    """Nowy wpis albo aktualizacja wpisu z wcześniejszej paczki o tym samym share_id."""
    p = received.payload
    fields = dict(title=as_text(p.get("title"), 500) or _("Bez tytułu"), category=as_text(p.get("category"), 200),
                  username=as_text(p.get("username"), 1000), password=as_text(p.get("password"), 10_000),
                  url=as_text(p.get("url"), 4000), totp_secret=as_text(p.get("totp_secret"), 1000),
                  notes=as_text(p.get("notes")), tags=as_tags(p.get("tags")), custom_fields=as_fields(p.get("custom_fields")))
    received_map = settings.get(RECEIVED_KEY) if isinstance(settings.get(RECEIVED_KEY), dict) else {}
    existing = vault.get_entry(received_map.get(received.share_id, "")) if received.share_id else None
    if existing is not None and existing.id in vault.entries:
        existing.update(**fields)
        entry = existing
    else:
        entry = VaultEntry(**{**fields, "category": fields["category"] or "Loginy"})  # i18n: data
        vault.add_entry(entry)
    if fields["category"]:
        vault.add_category(fields["category"])
    received_map = dict(received_map)
    received_map[received.share_id or entry.id] = entry.id
    settings[RECEIVED_KEY] = received_map
    return entry


def share_id_for(settings: Dict[str, Any], entry_id: str, contact: Contact) -> str:
    """To samo share_id dla tego wpisu i tej osoby – kolejne wysłanie aktualizuje jej wpis."""
    sent = settings.get(SENT_KEY) if isinstance(settings.get(SENT_KEY), dict) else {}
    for item in sent.get(entry_id) or []:
        if isinstance(item, dict) and item.get("public") == contact.public and item.get("share_id"):
            return item["share_id"]
    return uuid.uuid4().hex


def remember_sent(settings: Dict[str, Any], entry_id: str, contact: Contact, share_id: str) -> None:
    sent = dict(settings.get(SENT_KEY)) if isinstance(settings.get(SENT_KEY), dict) else {}
    items = [i for i in sent.get(entry_id) or [] if isinstance(i, dict) and i.get("public") != contact.public]
    items.append({"public": contact.public, "name": contact.name, "share_id": share_id,
                  "sent": datetime.now(timezone.utc).isoformat()})
    sent[entry_id] = items
    settings[SENT_KEY] = sent


def shared_with(settings: Dict[str, Any], entry_id: str) -> List[Dict[str, str]]:
    sent = settings.get(SENT_KEY) if isinstance(settings.get(SENT_KEY), dict) else {}
    return [i for i in sent.get(entry_id) or [] if isinstance(i, dict)]
