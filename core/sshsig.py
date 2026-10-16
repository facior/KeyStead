"""
Weryfikacja podpisów SSH (format SSHSIG, `ssh-keygen -Y sign`) bez zewnętrznych programów.

Aplikacja sprawdza nim aktualizacje: plik SHA256SUMS musi być podpisany kluczem Ed25519 wydawcy.
Format opisany w OpenSSH PROTOCOL.sshsig.
"""

import base64
import hashlib
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAGIC = b"SSHSIG"
ARMOR_BEGIN = "-----BEGIN SSH SIGNATURE-----"
ARMOR_END = "-----END SSH SIGNATURE-----"


class SignatureError(Exception):
    pass


def _read_string(buf: bytes, pos: int):
    if pos + 4 > len(buf):
        raise SignatureError("Uszkodzony podpis.")
    (length,) = struct.unpack(">I", buf[pos:pos + 4])
    pos += 4
    if pos + length > len(buf):
        raise SignatureError("Uszkodzony podpis.")
    return buf[pos:pos + length], pos + length


def _string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def parse_public_key(line: str) -> bytes:
    """`ssh-ed25519 AAAA... komentarz` (opcjonalnie poprzedzone nazwą podpisującego) → blob klucza."""
    parts = line.split()
    if "ssh-ed25519" not in parts:
        raise SignatureError("Obsługiwane są tylko klucze Ed25519.")
    idx = parts.index("ssh-ed25519")
    try:
        blob = base64.b64decode(parts[idx + 1], validate=True)
    except (IndexError, ValueError):
        raise SignatureError("Nieprawidłowy klucz publiczny.")
    key_type, pos = _read_string(blob, 0)
    raw, _ = _read_string(blob, pos)
    if key_type != b"ssh-ed25519" or len(raw) != 32:
        raise SignatureError("Nieprawidłowy klucz publiczny.")
    return blob


def verify(public_key_line: str, message: bytes, armored_signature: bytes, namespace: str) -> None:
    """Rzuca SignatureError, jeśli podpis nie jest poprawnym podpisem `message` zaufanym kluczem."""
    trusted_blob = parse_public_key(public_key_line)
    text = armored_signature.decode("ascii", errors="replace").strip()
    if not (text.startswith(ARMOR_BEGIN) and text.endswith(ARMOR_END)):
        raise SignatureError("Nieprawidłowy format podpisu.")
    try:
        sig = base64.b64decode("".join(text[len(ARMOR_BEGIN):-len(ARMOR_END)].split()), validate=True)
    except ValueError:
        raise SignatureError("Nieprawidłowy format podpisu.")

    if sig[:6] != MAGIC or len(sig) < 10 or struct.unpack(">I", sig[6:10])[0] != 1:
        raise SignatureError("Nieobsługiwana wersja podpisu.")
    pos = 10
    key_blob, pos = _read_string(sig, pos)
    sig_namespace, pos = _read_string(sig, pos)
    reserved, pos = _read_string(sig, pos)
    hash_alg, pos = _read_string(sig, pos)
    signature, pos = _read_string(sig, pos)

    if key_blob != trusted_blob:
        raise SignatureError("Podpis złożony innym kluczem niż klucz wydawcy.")
    if sig_namespace != namespace.encode():
        raise SignatureError("Podpis przeznaczony do innego celu.")
    if hash_alg == b"sha512":
        digest = hashlib.sha512(message).digest()
    elif hash_alg == b"sha256":
        digest = hashlib.sha256(message).digest()
    else:
        raise SignatureError("Nieobsługiwany algorytm skrótu.")

    sig_type, p = _read_string(signature, 0)
    raw_sig, _ = _read_string(signature, p)
    if sig_type != b"ssh-ed25519":
        raise SignatureError("Nieobsługiwany typ podpisu.")

    signed = MAGIC + _string(sig_namespace) + _string(reserved) + _string(hash_alg) + _string(digest)
    _, p = _read_string(trusted_blob, 0)
    raw_key, _ = _read_string(trusted_blob, p)
    try:
        Ed25519PublicKey.from_public_bytes(raw_key).verify(raw_sig, signed)
    except InvalidSignature:
        raise SignatureError("Nieprawidłowy podpis.")
