"""
Klucze SSH w sejfie (wtyczka „Klucze SSH w sejfie”): odczyt, podpisywanie i generowanie.

Klucz prywatny jest w polu wpisu „Klucz SSH” (tekst pliku klucza) – zaszyfrowany razem z sejfem. Jeśli plik klucza
ma własne hasło, jest nim hasło wpisu (jak w KeeAgent). Obsługiwane formaty:
    OpenSSH  (-----BEGIN OPENSSH PRIVATE KEY-----)      ssh-keygen, Windows OpenSSH, Git
    PEM      (-----BEGIN RSA/EC/PRIVATE KEY-----)        starsze ssh-keygen, OpenSSL
    PuTTY    (PuTTY-User-Key-File-2/-3, plik .ppk)       PuTTYgen, WinSCP
Rodzaje: Ed25519, RSA (podpisy rsa-sha2-256/512 i ssh-rsa), ECDSA P-256/384/521.
"""

import base64
import hashlib
import hmac
import re
import struct
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from core.i18n import _
from core.vault import VaultEntry

KEY_FIELD = "Klucz SSH"  # i18n: data – tekst pliku klucza prywatnego (pole wpisu)
KEY_ALIASES = ("SSH key",)
MAX_KEY_CHARS = 20_000

# Flagi żądania podpisu (OpenSSH PROTOCOL.agent)
SSH_AGENT_RSA_SHA2_256 = 2
SSH_AGENT_RSA_SHA2_512 = 4

_CURVES = {
    "nistp256": (ec.SECP256R1, hashes.SHA256),
    "nistp384": (ec.SECP384R1, hashes.SHA384),
    "nistp521": (ec.SECP521R1, hashes.SHA512),
}


class SshKeyError(Exception):
    """Klucza nie da się użyć (zły format, złe hasło, nieobsługiwany rodzaj)."""


# --------------------------------------------------------------------- format przewodowy SSH
def ssh_string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def ssh_mpint(n: int) -> bytes:
    if n == 0:
        return ssh_string(b"")
    raw = n.to_bytes((n.bit_length() + 8) // 8, "big")  # z bajtem zerowym, gdy najwyższy bit ustawiony
    return ssh_string(raw)


class Reader:
    def __init__(self, data: bytes):
        self.data, self.pos = data, 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise SshKeyError(_("Uszkodzony klucz SSH."))
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def uint32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def byte(self) -> int:
        return self.take(1)[0]

    def string(self) -> bytes:
        return self.take(self.uint32())

    def mpint(self) -> int:
        return int.from_bytes(self.string(), "big", signed=True)

    def done(self) -> bool:
        return self.pos >= len(self.data)


# --------------------------------------------------------------------- klucz gotowy do podpisywania
@dataclass
class AgentKey:
    private: object
    comment: str
    entry_id: str = ""
    entry_title: str = ""

    @property
    def algorithm(self) -> str:
        k = self.private
        if isinstance(k, ed25519.Ed25519PrivateKey):
            return "ssh-ed25519"
        if isinstance(k, rsa.RSAPrivateKey):
            return "ssh-rsa"
        if isinstance(k, ec.EllipticCurvePrivateKey):
            return f"ecdsa-sha2-{_curve_name(k.curve)}"
        raise SshKeyError(_("Nieobsługiwany rodzaj klucza SSH."))

    @property
    def public_blob(self) -> bytes:
        line = self.private.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                                      serialization.PublicFormat.OpenSSH)
        return base64.b64decode(line.split()[1])

    def public_line(self) -> str:
        line = f"{self.algorithm} {base64.b64encode(self.public_blob).decode()}"
        return f"{line} {self.comment}" if self.comment else line

    def fingerprint(self) -> str:
        digest = hashlib.sha256(self.public_blob).digest()
        return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")

    def description(self) -> str:
        k = self.private
        bits = k.key_size if isinstance(k, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)) else 256
        kind = {"ssh-ed25519": "ED25519", "ssh-rsa": "RSA"}.get(self.algorithm, "ECDSA")
        return f"{kind} {bits}"

    def sign(self, data: bytes, flags: int = 0) -> bytes:
        """Podpis w formacie agenta SSH: string(nazwa algorytmu) + string(podpis)."""
        k = self.private
        if isinstance(k, ed25519.Ed25519PrivateKey):
            return ssh_string(b"ssh-ed25519") + ssh_string(k.sign(data))
        if isinstance(k, rsa.RSAPrivateKey):
            if flags & SSH_AGENT_RSA_SHA2_512:
                name, algo = b"rsa-sha2-512", hashes.SHA512()
            elif flags & SSH_AGENT_RSA_SHA2_256:
                name, algo = b"rsa-sha2-256", hashes.SHA256()
            else:
                name, algo = b"ssh-rsa", hashes.SHA1()
            return ssh_string(name) + ssh_string(k.sign(data, padding.PKCS1v15(), algo))
        if isinstance(k, ec.EllipticCurvePrivateKey):
            curve = _curve_name(k.curve)
            r, s = decode_dss_signature(k.sign(data, ec.ECDSA(_CURVES[curve][1]())))
            return ssh_string(f"ecdsa-sha2-{curve}".encode()) + ssh_string(ssh_mpint(r) + ssh_mpint(s))
        raise SshKeyError(_("Nieobsługiwany rodzaj klucza SSH."))


def _curve_name(curve) -> str:
    for name, (cls, _hash) in _CURVES.items():
        if isinstance(curve, cls):
            return name
    raise SshKeyError(_("Nieobsługiwana krzywa klucza ECDSA."))


def _check_supported(private) -> None:
    if isinstance(private, rsa.RSAPrivateKey) and private.key_size < 2048:
        raise SshKeyError(_("Klucz RSA krótszy niż 2048 bitów jest niebezpieczny – wygeneruj nowy klucz."))
    if not isinstance(private, (ed25519.Ed25519PrivateKey, rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise SshKeyError(_("Nieobsługiwany rodzaj klucza SSH (obsługiwane: Ed25519, RSA, ECDSA)."))
    if isinstance(private, ec.EllipticCurvePrivateKey):
        _curve_name(private.curve)


# --------------------------------------------------------------------- odczyt plików kluczy
def key_format(text: str) -> str:
    t = (text or "").lstrip()
    if t.startswith("PuTTY-User-Key-File-"):
        return "ppk"
    if "-----BEGIN OPENSSH PRIVATE KEY-----" in t:
        return "openssh"
    if re.search(r"-----BEGIN (RSA |EC |ENCRYPTED )?PRIVATE KEY-----", t):
        return "pem"
    if t.startswith(("ssh-", "ecdsa-")):
        return "public"
    return ""


def load_key(text: str, passphrase: str = "", comment: str = "") -> AgentKey:
    """Klucz prywatny z tekstu pliku. SshKeyError z czytelnym komunikatem przy złym haśle lub formacie."""
    text = (text or "").strip()
    if len(text) > MAX_KEY_CHARS:
        raise SshKeyError(_("To nie wygląda na plik klucza SSH (za długi)."))
    fmt = key_format(text)
    if fmt == "public":
        raise SshKeyError(_("To jest klucz PUBLICZNY. Wczytaj plik klucza prywatnego (np. id_ed25519, bez .pub)."))
    if fmt == "ppk":
        private, ppk_comment = _load_ppk(text, passphrase)
        _check_supported(private)
        return AgentKey(private, comment or ppk_comment)
    if fmt not in ("openssh", "pem"):
        raise SshKeyError(_("Nieznany format klucza. Obsługiwane: OpenSSH, PEM i PuTTY (.ppk)."))
    data = text.encode()
    password = passphrase.encode() if passphrase else None
    loader = serialization.load_ssh_private_key if fmt == "openssh" else serialization.load_pem_private_key
    try:
        try:
            private = loader(data, password=password)
        except TypeError as e:
            # Klucz bez hasła, a podano hasło wpisu (hasło wpisu to zwykle hasło do serwera) – spróbuj bez
            if password is not None and "not encrypted" in str(e).lower():
                private = loader(data, password=None)
            elif password is None:
                raise SshKeyError(_("Klucz jest zabezpieczony hasłem – wpisz je w polu „Hasło” tego wpisu.")) from e
            else:
                raise
    except SshKeyError:
        raise
    except UnsupportedAlgorithm as e:
        raise SshKeyError(_("Nieobsługiwany rodzaj klucza SSH (obsługiwane: Ed25519, RSA, ECDSA).")) from e
    except (ValueError, TypeError) as e:
        if password is not None:
            raise SshKeyError(_("Złe hasło klucza SSH (hasło klucza to pole „Hasło” wpisu).")) from e
        raise SshKeyError(_("Nie udało się odczytać klucza SSH: {error}", error=e)) from e
    _check_supported(private)
    return AgentKey(private, comment or _openssh_comment(text))


def _openssh_comment(text: str) -> str:
    """Komentarz zapisany w kluczu OpenSSH (zwykle użytkownik@komputer) – tylko dla kluczy bez hasła."""
    try:
        body = "".join(text.strip().splitlines()[1:-1])
        r = Reader(base64.b64decode(body))
        if r.take(15) != b"openssh-key-v1\0":
            return ""
        cipher, _kdf, _opts = r.string(), r.string(), r.string()
        if cipher != b"none" or r.uint32() != 1:
            return ""
        r.string()  # klucz publiczny
        priv = Reader(r.string())
        priv.uint32(), priv.uint32()
        key_type = priv.string().decode()
        fields = {"ssh-ed25519": 2, "ssh-rsa": 6}.get(key_type, 3 if key_type.startswith("ecdsa") else None)
        if fields is None:
            return ""
        for _i in range(fields):
            priv.string()
        return priv.string().decode("utf-8", "replace")[:200]
    except Exception:
        return ""


def _ppk_fields(text: str):
    lines = text.replace("\r\n", "\n").split("\n")
    fields, i = {}, 0
    version = None
    while i < len(lines):
        line = lines[i]
        i += 1
        if not line.strip():
            continue
        if ":" not in line:
            raise SshKeyError(_("Uszkodzony plik klucza PuTTY."))
        name, value = line.split(":", 1)
        value = value.strip()
        if name.startswith("PuTTY-User-Key-File-"):
            version = int(name.rsplit("-", 1)[1])
            fields["algorithm"] = value
        elif name in ("Public-Lines", "Private-Lines"):
            count = int(value)
            if count > 400:
                raise SshKeyError(_("Uszkodzony plik klucza PuTTY."))
            fields[name] = base64.b64decode("".join(lines[i:i + count]))
            i += count
        else:
            fields[name] = value
    if version not in (2, 3):
        raise SshKeyError(_("Nieobsługiwana wersja pliku klucza PuTTY."))
    return version, fields


def _load_ppk(text: str, passphrase: str) -> Tuple[object, str]:
    version, f = _ppk_fields(text)
    algorithm, encryption = f.get("algorithm", ""), f.get("Encryption", "")
    comment = f.get("Comment", "")
    public, private = f.get("Public-Lines", b""), f.get("Private-Lines", b"")
    if encryption not in ("none", "aes256-cbc"):
        raise SshKeyError(_("Nieobsługiwane szyfrowanie pliku klucza PuTTY."))
    encrypted = encryption == "aes256-cbc"
    if encrypted and not passphrase:
        raise SshKeyError(_("Klucz jest zabezpieczony hasłem – wpisz je w polu „Hasło” tego wpisu."))
    pw = passphrase.encode() if encrypted else b""

    if version == 3:
        if encrypted:
            from argon2.low_level import Type, hash_secret_raw
            kinds = {"Argon2id": Type.ID, "Argon2i": Type.I, "Argon2d": Type.D}
            if f.get("Key-Derivation") not in kinds:
                raise SshKeyError(_("Nieobsługiwane szyfrowanie pliku klucza PuTTY."))
            memory, passes, par = int(f["Argon2-Memory"]), int(f["Argon2-Passes"]), int(f["Argon2-Parallelism"])
            if memory > 1024 * 1024 or passes > 1000 or par > 64:
                raise SshKeyError(_("Uszkodzony plik klucza PuTTY."))
            material = hash_secret_raw(pw, bytes.fromhex(f["Argon2-Salt"]), time_cost=passes, memory_cost=memory,
                                       parallelism=par, hash_len=80, type=kinds[f["Key-Derivation"]])
            cipher_key, iv, mac_key = material[:32], material[32:48], material[48:]
        else:
            cipher_key, iv, mac_key = b"", b"", b""
        mac_algo = hashlib.sha256
    else:
        cipher_key = (hashlib.sha1(b"\0\0\0\0" + pw).digest() + hashlib.sha1(b"\0\0\0\1" + pw).digest())[:32]
        iv = b"\0" * 16
        mac_key = hashlib.sha1(b"putty-private-key-file-mac-key" + pw).digest()
        mac_algo = hashlib.sha1

    if encrypted:
        if len(private) % 16:
            raise SshKeyError(_("Uszkodzony plik klucza PuTTY."))
        dec = Cipher(algorithms.AES(cipher_key), modes.CBC(iv)).decryptor()
        private = dec.update(private) + dec.finalize()
    mac_data = b"".join(ssh_string(x) for x in (algorithm.encode(), encryption.encode(), comment.encode(),
                                                 public, private))
    expected = hmac.new(mac_key, mac_data, mac_algo).hexdigest()
    if not hmac.compare_digest(expected, f.get("Private-MAC", "").lower()):
        if encrypted:
            raise SshKeyError(_("Złe hasło klucza SSH (hasło klucza to pole „Hasło” wpisu)."))
        raise SshKeyError(_("Uszkodzony plik klucza PuTTY."))

    pub, priv = Reader(public), Reader(private)
    if pub.string().decode() != algorithm:
        raise SshKeyError(_("Uszkodzony plik klucza PuTTY."))
    if algorithm == "ssh-ed25519":
        pub.string()
        return ed25519.Ed25519PrivateKey.from_private_bytes(priv.string()), comment
    if algorithm == "ssh-rsa":
        e, n = pub.mpint(), pub.mpint()
        d, p, q, iqmp = priv.mpint(), priv.mpint(), priv.mpint(), priv.mpint()
        numbers = rsa.RSAPrivateNumbers(p, q, d, d % (p - 1), d % (q - 1), iqmp, rsa.RSAPublicNumbers(e, n))
        return numbers.private_key(), comment
    if algorithm.startswith("ecdsa-sha2-"):
        curve = algorithm[len("ecdsa-sha2-"):]
        if curve not in _CURVES:
            raise SshKeyError(_("Nieobsługiwana krzywa klucza ECDSA."))
        return ec.derive_private_key(priv.mpint(), _CURVES[curve][0]()), comment
    raise SshKeyError(_("Nieobsługiwany rodzaj klucza SSH (obsługiwane: Ed25519, RSA, ECDSA)."))


# --------------------------------------------------------------------- wpisy sejfu
def field_name(entry: VaultEntry) -> Optional[str]:
    for name in (KEY_FIELD, *KEY_ALIASES):
        if (entry.custom_fields.get(name) or "").strip():
            return name
    return None


def entry_key_text(entry: VaultEntry) -> str:
    name = field_name(entry)
    return entry.custom_fields.get(name, "") if name else ""


def key_from_entry(entry: VaultEntry) -> AgentKey:
    key = load_key(entry_key_text(entry), entry.password, "")
    key.comment = key.comment or entry.title
    key.entry_id, key.entry_title = entry.id, entry.title
    return key


def generate_ed25519(comment: str) -> str:
    """Nowy klucz Ed25519 w formacie OpenSSH (bez własnego hasła – chroni go szyfrowanie sejfu)."""
    private = ed25519.Ed25519PrivateKey.generate()
    pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                serialization.NoEncryption()).decode()
    return _with_comment(pem, comment)


def _with_comment(openssh_pem: str, comment: str) -> str:
    """Wpisuje komentarz do klucza OpenSSH bez hasła (cryptography zapisuje pusty)."""
    lines = openssh_pem.strip().splitlines()
    r = Reader(base64.b64decode("".join(lines[1:-1])))
    head = r.take(15)
    cipher, kdf, opts, count, pub = r.string(), r.string(), r.string(), r.uint32(), r.string()
    priv = Reader(r.string())
    check1, check2, key_type = priv.uint32(), priv.uint32(), priv.string()
    pub_part, priv_part, _old_comment = priv.string(), priv.string(), priv.string()
    body = struct.pack(">II", check1, check2) + ssh_string(key_type) + ssh_string(pub_part) + \
        ssh_string(priv_part) + ssh_string(comment.encode()[:200])
    body += bytes(range(1, 1 + (-len(body)) % 8))
    blob = head + ssh_string(cipher) + ssh_string(kdf) + ssh_string(opts) + struct.pack(">I", count) + \
        ssh_string(pub) + ssh_string(body)
    b64 = base64.b64encode(blob).decode()
    return "\n".join([lines[0], *[b64[i:i + 70] for i in range(0, len(b64), 70)], lines[-1]]) + "\n"
