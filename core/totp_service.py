"""
Obsługa jednorazowych kodów dwuskładnikowych TOTP (RFC 6238).
Umożliwia generowanie kodów 2FA, sprawdzanie czasu ważności oraz parsowanie linków otpauth://.
"""

import time
import re
from typing import Optional, Tuple
from urllib.parse import urlparse, parse_qs, unquote
import pyotp


def sanitize_secret(secret: str) -> str:
    """Oczyszcza klucz TOTP (usuwa spacje, myślniki, zamienia na wielkie litery)."""
    return re.sub(r"[\s\-_]", "", secret or "").upper()


def is_valid_totp_secret(secret: str) -> bool:
    """Sprawdza czy ciąg jest poprawnym kluczem Base32 dla TOTP."""
    clean = sanitize_secret(secret)
    if not clean:
        return False
    try:
        totp = pyotp.TOTP(clean)
        totp.now()
        return True
    except Exception:
        return False


def get_current_totp(secret: str) -> Optional[str]:
    """Generuje aktualny 6-cyfrowy kod TOTP."""
    clean = sanitize_secret(secret)
    if not clean:
        return None
    try:
        totp = pyotp.TOTP(clean)
        return totp.now()
    except Exception:
        return None


def get_totp_remaining_seconds(interval: int = 30) -> int:
    """Zwraca liczbę sekund pozostałych do wygaśnięcia obecnego kodu TOTP (0-30s)."""
    current_time = int(time.time())
    return interval - (current_time % interval)


def parse_otpauth_uri(uri: str) -> Optional[Tuple[str, str, str]]:
    """
    Parsuje adres otpauth://totp/Issuer:account?secret=...&issuer=...
    Zwraca (secret, account, issuer).
    """
    if not uri or not uri.startswith("otpauth://"):
        return None

    try:
        parsed = urlparse(uri)
        if parsed.netloc.lower() != "totp":
            return None

        path = unquote(parsed.path.lstrip("/"))
        issuer_label = ""
        account_label = path
        if ":" in path:
            parts = path.split(":", 1)
            issuer_label = parts[0].strip()
            account_label = parts[1].strip()

        query_params = parse_qs(parsed.query)
        secret = query_params.get("secret", [""])[0]
        query_issuer = query_params.get("issuer", [""])[0]

        final_issuer = query_issuer or issuer_label
        return sanitize_secret(secret), account_label, final_issuer
    except Exception:
        return None
