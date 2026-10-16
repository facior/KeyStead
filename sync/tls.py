"""
Zaufanie do certyfikatu serwera, którego nie zna system (certyfikat samopodpisany albo
wystawiony przez wewnętrzne CA firmy, np. serwer dostępny tylko w firmowym VPN).

Model "zaufaj przy pierwszym użyciu" z weryfikacją odcisku: aplikacja pokazuje odcisk SHA-256
certyfikatu, użytkownik porównuje go z odciskiem podanym przez administratora (instalator / panel),
a po akceptacji certyfikat jest przypinany – jego podmiana zostanie wykryta.
"""

import hashlib
import os
import re
import socket
import ssl
from typing import Tuple
from urllib.parse import urlparse

from core.paths import CERTS_DIR  # noqa: E402


def fingerprint_of_pem(pem: str) -> str:
    der = ssl.PEM_cert_to_DER_cert(pem)
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def fetch_server_certificate(url: str, timeout: float = 8.0) -> Tuple[str, str]:
    """Pobiera certyfikat prezentowany przez serwer (bez weryfikacji) – zwraca (PEM, odcisk SHA-256)."""
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or 443
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    pem = ssl.DER_cert_to_PEM_cert(der)
    return pem, fingerprint_of_pem(pem)


def save_pinned_certificate(url: str, pem: str, certs_dir: str = "") -> str:
    """Zapisuje zaakceptowany certyfikat i zwraca ścieżkę do użycia jako zaufany (verify=...)."""
    parsed = urlparse(url)
    safe = re.sub(r"[^A-Za-z0-9.-]", "_", f"{parsed.hostname}_{parsed.port or 443}")
    folder = certs_dir or CERTS_DIR
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, f"{safe}.pem")
    with open(path, "w", encoding="ascii") as f:
        f.write(pem)
    return path
