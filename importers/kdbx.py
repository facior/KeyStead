"""
Odczyt baz KeePass (.kdbx 3.1 i 4.x) – własna implementacja formatu (bez bibliotek na licencji GPL).

Obsługiwane:
    szyfrowanie bazy:     AES-256-CBC, ChaCha20                (Twofish – czytelny komunikat zamiast importu)
    klucz z hasła:        AES-KDF, Argon2d, Argon2id
    klucz złożony:        hasło i/lub plik-klucz (XML 1.0 i 2.0, 32 bajty, 64 znaki hex, dowolny plik)
    pola chronione:       Salsa20 (KDBX 3) i ChaCha20 (KDBX 4)
    kompresja:            gzip (z limitem rozmiaru – ochrona przed „bombą”)

Odczyt jest tylko do importu: zwraca grupy i wpisy (pola tekstowe, tagi, kosz), bez historii i załączników.
Parametry KDF są sprawdzane PRZED liczeniem klucza (importers/keepass.py: check_kdbx_header).
"""

import base64
import hashlib
import hmac
import io
import struct
import xml.etree.ElementTree as ET
import zlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from core.i18n import _

SIGNATURE = (0x9AA2D903, 0xB54BFB67)
CIPHER_AES256 = bytes.fromhex("31c1f2e6bf714350be5805216afc5aff")
CIPHER_CHACHA20 = bytes.fromhex("d6038a2b8b6f4cb5a524339a31dbb59a")
CIPHER_TWOFISH = bytes.fromhex("ad68f29f576f4bb9a36ad47af965346c")
KDF_AES = bytes.fromhex("c9d9f39a628a4460bf740d08c18a4fea")
KDF_AES_KDBX4 = bytes.fromhex("7c02bb8279a74ac0927d114a00648238")
KDF_ARGON2D = bytes.fromhex("ef636ddf8c29444b91f7a9a403e30a0c")
KDF_ARGON2ID = bytes.fromhex("9e298b1956db4773b23dfc3ec6f0a1e6")
STREAM_SALSA20, STREAM_CHACHA20 = 2, 3
SALSA20_NONCE = bytes.fromhex("e830094b97205d2a")
MAX_XML_BYTES = 256 * 1024 * 1024


class KdbxError(Exception):
    pass


class KdbxPasswordError(KdbxError):
    pass


@dataclass
class KdbxEntry:
    fields: Dict[str, str]
    tags: List[str]
    group: str            # nazwa grupy, w której jest wpis ("" = grupa główna)
    uuid: str = ""


@dataclass
class KdbxDatabase:
    version: tuple
    name: str
    entries: List[KdbxEntry] = field(default_factory=list)


# --------------------------------------------------------------------- klucz złożony
def keyfile_key(data: bytes) -> bytes:
    """32-bajtowy składnik klucza z pliku-klucza (te same reguły co KeePass)."""
    text = data.strip()
    if text.startswith(b"<?xml") or text.startswith(b"<KeyFile"):
        try:
            root = ET.fromstring(data)
            version = (root.findtext("Meta/Version") or "").strip()
            key_el = root.find("Key/Data")
            if key_el is not None and key_el.text:
                if version.startswith("2"):
                    raw = bytes.fromhex("".join(key_el.text.split()))
                    expected = (key_el.get("Hash") or "").strip().lower()
                    if expected and hashlib.sha256(raw).hexdigest()[:8] != expected:
                        raise KdbxError(_("Plik-klucz KeePass jest uszkodzony (niezgodna suma kontrolna)."))
                    return raw
                return base64.b64decode(key_el.text.strip())
        except ET.ParseError:
            pass
    if len(data) == 32:
        return data
    if len(data) == 64:
        try:
            return bytes.fromhex(data.decode("ascii"))
        except (UnicodeDecodeError, ValueError):
            pass
    return hashlib.sha256(data).digest()


def composite_key(password: Optional[str], keyfile: Optional[bytes]) -> bytes:
    parts = b""
    if password:
        parts += hashlib.sha256(password.encode("utf-8")).digest()
    if keyfile is not None:
        parts += keyfile_key(keyfile)
    if not parts:
        raise KdbxError(_("Do otwarcia bazy KeePass (.kdbx) wymagane jest hasło lub plik klucza."))
    return hashlib.sha256(parts).digest()


def aes_kdf(key: bytes, seed: bytes, rounds: int) -> bytes:
    """AES-KDF: `rounds` razy AES-ECB na każdej połowie klucza. Liczone jako CBC na zerach (IV = blok) –
    to samo, a jednym wywołaniem biblioteki zamiast milionów wywołań w Pythonie."""
    out = b""
    for half in (key[:16], key[16:]):
        block, left = half, rounds
        while left:
            n = min(left, 1 << 20)
            enc = Cipher(algorithms.AES(seed), modes.CBC(block)).encryptor()
            block = (enc.update(b"\0" * (16 * n)) + enc.finalize())[-16:]
            left -= n
        out += block
    return hashlib.sha256(out).digest()


def argon2_kdf(key: bytes, params: Dict[str, object], kind: bytes) -> bytes:
    from argon2.low_level import Type, hash_secret_raw
    return hash_secret_raw(secret=key, salt=params["S"], time_cost=int(params["I"]),
                           memory_cost=int(params["M"]) // 1024, parallelism=int(params["P"]), hash_len=32,
                           type=Type.D if kind == KDF_ARGON2D else Type.ID, version=int(params.get("V", 0x13)))


# --------------------------------------------------------------------- nagłówek
def _variant_dict(data: bytes) -> Dict[str, object]:
    out, pos = {}, 2
    while pos < len(data):
        vtype = data[pos]
        pos += 1
        if vtype == 0:
            break
        (klen,) = struct.unpack_from("<I", data, pos)
        key = data[pos + 4:pos + 4 + klen].decode("utf-8", "replace")
        pos += 4 + klen
        (vlen,) = struct.unpack_from("<I", data, pos)
        raw = data[pos + 4:pos + 4 + vlen]
        pos += 4 + vlen
        out[key] = int.from_bytes(raw, "little") if vtype in (0x04, 0x05) else raw
    return out


def _read_header(data: bytes):
    if len(data) < 12:
        raise KdbxError(_("To nie jest baza KeePass (.kdbx)."))
    sig1, sig2, minor, major = struct.unpack_from("<IIHH", data, 0)
    if (sig1, sig2) != SIGNATURE:
        raise KdbxError(_("To nie jest baza KeePass (.kdbx)."))
    if major not in (3, 4):
        raise KdbxError(_("Nieobsługiwana wersja bazy KeePass ({version}).", version=f"{major}.{minor}"))
    fields, pos = {}, 12
    while True:
        if pos >= len(data):
            raise KdbxError(_("Uszkodzony nagłówek bazy KeePass."))
        fid = data[pos]
        if major >= 4:
            (size,) = struct.unpack_from("<I", data, pos + 1)
            pos += 5
        else:
            (size,) = struct.unpack_from("<H", data, pos + 1)
            pos += 3
        fields[fid] = data[pos:pos + size]
        pos += size
        if fid == 0:
            break
    return (major, minor), fields, pos


# --------------------------------------------------------------------- strumienie
def _salsa20_keystream(key: bytes, nonce: bytes):
    """Salsa20/20 (dla pól chronionych KDBX 3) – generator bloków po 64 bajty."""
    def rotl(v, c):
        return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))

    k = struct.unpack("<8I", key)
    n = struct.unpack("<2I", nonce)
    const = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
    counter = 0
    while True:
        state = [const[0], k[0], k[1], k[2], k[3], const[1], n[0], n[1],
                 counter & 0xFFFFFFFF, counter >> 32, const[2], k[4], k[5], k[6], k[7], const[3]]
        x = list(state)
        for _i in range(10):
            for a, b, c, d in ((0, 4, 8, 12), (5, 9, 13, 1), (10, 14, 2, 6), (15, 3, 7, 11),
                               (0, 1, 2, 3), (5, 6, 7, 4), (10, 11, 8, 9), (15, 12, 13, 14)):
                x[b] ^= rotl((x[a] + x[d]) & 0xFFFFFFFF, 7)
                x[c] ^= rotl((x[b] + x[a]) & 0xFFFFFFFF, 9)
                x[d] ^= rotl((x[c] + x[b]) & 0xFFFFFFFF, 13)
                x[a] ^= rotl((x[d] + x[c]) & 0xFFFFFFFF, 18)
        yield struct.pack("<16I", *((x[i] + state[i]) & 0xFFFFFFFF for i in range(16)))
        counter += 1


class _ProtectedStream:
    """Klucz pól chronionych (hasła w XML) – XOR z kolejnymi bajtami strumienia w kolejności dokumentu."""

    def __init__(self, stream_id: int, key: bytes):
        self._buffer = b""
        if stream_id == STREAM_CHACHA20:
            digest = hashlib.sha512(key).digest()
            enc = Cipher(algorithms.ChaCha20(digest[:32], b"\0\0\0\0" + digest[32:44]), None).encryptor()
            self._next = lambda: enc.update(b"\0" * 64)
        elif stream_id == STREAM_SALSA20:
            gen = _salsa20_keystream(hashlib.sha256(key).digest(), SALSA20_NONCE)
            self._next = lambda: next(gen)
        else:
            raise KdbxError(_("Nieobsługiwane szyfrowanie pól chronionych w bazie KeePass."))

    def xor(self, data: bytes) -> bytes:
        while len(self._buffer) < len(data):
            self._buffer += self._next()
        stream, self._buffer = self._buffer[:len(data)], self._buffer[len(data):]
        return bytes(a ^ b for a, b in zip(data, stream))


def _decrypt_payload(cipher_id: bytes, key: bytes, iv: bytes, data: bytes) -> bytes:
    if cipher_id == CIPHER_AES256:
        if len(data) % 16:
            raise KdbxPasswordError(_("Błędne hasło lub plik-klucz."))
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        plain = dec.update(data) + dec.finalize()
        unpad = padding.PKCS7(128).unpadder()
        try:
            return unpad.update(plain) + unpad.finalize()
        except ValueError:
            raise KdbxPasswordError(_("Błędne hasło lub plik-klucz."))
    if cipher_id == CIPHER_CHACHA20:
        return Cipher(algorithms.ChaCha20(key, b"\0\0\0\0" + iv), None).decryptor().update(data)
    if cipher_id == CIPHER_TWOFISH:
        raise KdbxError(_("Baza KeePass jest zaszyfrowana algorytmem Twofish, którego KeyStead nie obsługuje. "
                          "Zmień w KeePass szyfrowanie na AES lub ChaCha20 (Plik → Ustawienia bazy → Zabezpieczenia) "
                          "albo wyeksportuj bazę do XML."))
    raise KdbxError(_("Nieznany algorytm szyfrowania bazy KeePass."))


def _gunzip(data: bytes) -> bytes:
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        out = d.decompress(data, MAX_XML_BYTES + 1)
    except zlib.error:
        raise KdbxError(_("Baza KeePass jest uszkodzona (błąd rozpakowania)."))
    if len(out) > MAX_XML_BYTES or d.unconsumed_tail:
        raise KdbxError(_("Baza KeePass po rozpakowaniu jest zbyt duża – plik odrzucony."))
    return out


# --------------------------------------------------------------------- odczyt
def _transformed_key(version, fields, key: bytes) -> bytes:
    if version[0] >= 4:
        params = _variant_dict(fields.get(11, b""))
        kdf = params.get("$UUID")
        if kdf in (KDF_AES, KDF_AES_KDBX4):
            return aes_kdf(key, params["S"], int(params["R"]))
        if kdf in (KDF_ARGON2D, KDF_ARGON2ID):
            return argon2_kdf(key, params, kdf)
        raise KdbxError(_("Nieznana metoda zabezpieczenia hasła w bazie KeePass."))
    return aes_kdf(key, fields[5], int.from_bytes(fields[6], "little"))


def open_kdbx(data: bytes, password: Optional[str], keyfile: Optional[bytes]) -> KdbxDatabase:
    version, fields, header_end = _read_header(data)
    try:
        cipher_id, master_seed, iv = fields[2], fields[4], fields[7]
        compressed = int.from_bytes(fields.get(3, b"\0\0\0\0"), "little") == 1
    except KeyError:
        raise KdbxError(_("Uszkodzony nagłówek bazy KeePass."))
    transformed = _transformed_key(version, fields, composite_key(password, keyfile))
    master_key = hashlib.sha256(master_seed + transformed).digest()

    if version[0] >= 4:
        header = data[:header_end]
        pos = header_end
        if hashlib.sha256(header).digest() != data[pos:pos + 32]:
            raise KdbxError(_("Uszkodzony nagłówek bazy KeePass."))
        hmac_base = hashlib.sha512(master_seed + transformed + b"\x01").digest()

        def block_key(index: int) -> bytes:
            return hashlib.sha512(struct.pack("<Q", index) + hmac_base).digest()

        if not hmac.compare_digest(hmac.new(block_key(0xFFFFFFFFFFFFFFFF), header, hashlib.sha256).digest(),
                                   data[pos + 32:pos + 64]):
            raise KdbxPasswordError(_("Błędne hasło lub plik-klucz."))
        pos += 64
        payload, index = io.BytesIO(), 0
        while True:
            mac, (size,) = data[pos:pos + 32], struct.unpack_from("<I", data, pos + 32)
            block = data[pos + 36:pos + 36 + size]
            expected = hmac.new(block_key(index), struct.pack("<QI", index, size) + block, hashlib.sha256).digest()
            if not hmac.compare_digest(mac, expected):
                raise KdbxError(_("Baza KeePass jest uszkodzona (niezgodna suma kontrolna bloku)."))
            pos += 36 + size
            if size == 0:
                break
            payload.write(block)
            index += 1
        plain = _decrypt_payload(cipher_id, master_key, iv, payload.getvalue())
        if compressed:
            plain = _gunzip(plain)
        # Nagłówek wewnętrzny: strumień pól chronionych (i załączniki – pomijane)
        pos, stream_id, stream_key = 0, None, None
        while True:
            fid, (size,) = plain[pos], struct.unpack_from("<I", plain, pos + 1)
            value = plain[pos + 5:pos + 5 + size]
            pos += 5 + size
            if fid == 0:
                break
            if fid == 1:
                stream_id = int.from_bytes(value, "little")
            elif fid == 2:
                stream_key = value
        xml = plain[pos:]
    else:
        plain = _decrypt_payload(cipher_id, master_key, iv, data[header_end:])
        if plain[:32] != fields.get(9):
            raise KdbxPasswordError(_("Błędne hasło lub plik-klucz."))
        pos, chunks = 32, io.BytesIO()
        while True:
            (_index,) = struct.unpack_from("<I", plain, pos)
            digest = plain[pos + 4:pos + 36]
            (size,) = struct.unpack_from("<I", plain, pos + 36)
            block = plain[pos + 40:pos + 40 + size]
            pos += 40 + size
            if size == 0:
                break
            if hashlib.sha256(block).digest() != digest:
                raise KdbxError(_("Baza KeePass jest uszkodzona (niezgodna suma kontrolna bloku)."))
            chunks.write(block)
        xml = chunks.getvalue()
        if compressed:
            xml = _gunzip(xml)
        stream_id = int.from_bytes(fields.get(10, b"\0\0\0\0"), "little")
        stream_key = fields.get(8)
    return _parse_xml(version, xml, _ProtectedStream(stream_id, stream_key) if stream_key else None)


def _parse_xml(version, xml: bytes, stream: Optional[_ProtectedStream]) -> KdbxDatabase:
    if b"<!DOCTYPE" in xml[:4096] or b"<!ENTITY" in xml[:4096]:
        raise KdbxError(_("Baza KeePass zawiera niedozwolone deklaracje XML – plik odrzucony."))
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as e:
        raise KdbxError(_("Uszkodzona zawartość bazy KeePass: {error}", error=e))
    # Pola chronione odszyfrowujemy w kolejności dokumentu (także w historii) – strumień musi się zgadzać
    for value in root.iter("Value"):
        if (value.get("Protected") or "").lower() == "true":
            raw = base64.b64decode(value.text or "")
            value.text = stream.xor(raw).decode("utf-8", "replace") if stream else ""
            value.attrib.pop("Protected", None)

    meta = root.find("Meta")
    recycle_uuid = ""
    if meta is not None and (meta.findtext("RecycleBinEnabled") or "True").strip().lower() == "true":
        recycle_uuid = (meta.findtext("RecycleBinUUID") or "").strip()
    db = KdbxDatabase(version=version, name=(meta.findtext("DatabaseName") if meta is not None else "") or "")
    top = root.find("Root/Group")
    if top is None:
        return db

    def walk(group, name: str, depth: int):
        if depth > 64:
            return
        for entry in group.findall("Entry"):
            fields = {}
            for s in entry.findall("String"):
                key = s.findtext("Key")
                if key:
                    fields[key] = s.findtext("Value") or ""
            tags = [t.strip() for t in (entry.findtext("Tags") or "").replace(",", ";").split(";") if t.strip()]
            db.entries.append(KdbxEntry(fields, tags, name, (entry.findtext("UUID") or "").strip()))
        for child in group.findall("Group"):
            if recycle_uuid and (child.findtext("UUID") or "").strip() == recycle_uuid:
                continue  # kosz KeePassa – usunięte wpisy nie są importowane
            walk(child, child.findtext("Name") or "", depth + 1)

    walk(top, "", 0)
    return db
