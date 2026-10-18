"""
Data ważności hasła (wtyczka „Data ważności hasła”).

Data jest zapisana w polu niestandardowym wpisu, a nie w nowym polu modelu: starsze wersje aplikacji
(i inne urządzenia przed aktualizacją) zachowują ją wtedy przy zapisie i po prostu pokazują jako zwykłe pole.
Format: RRRR-MM-DD. Odczytywane są też formaty DD.MM.RRRR i DD-MM-RRRR (wpisane ręcznie).
"""

import re
from datetime import date, timedelta
from typing import Iterable, List, Optional, Tuple

from core.vault import VaultEntry

EXPIRY_FIELD = "Hasło ważne do"  # i18n: data – nazwa pola w sejfie, taka sama w każdym języku
EXPIRY_ALIASES = ("Password expires",)  # pole nazwane po angielsku (wpis uzupełniony ręcznie)
SOON_DAYS = 14  # „wkrótce wygasa” – tyle dni przed datą

EXPIRED, SOON, OK = "expired", "soon", "ok"

_ISO = re.compile(r"^\s*(\d{4})-(\d{1,2})-(\d{1,2})\s*$")
_EU = re.compile(r"^\s*(\d{1,2})[.\-/](\d{1,2})[.\-/](\d{4})\s*$")


def parse_date(text: str) -> Optional[date]:
    text = (text or "").strip()
    m = _ISO.match(text)
    try:
        if m:
            return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        m = _EU.match(text)
        if m:
            return date(int(m.group(3)), int(m.group(2)), int(m.group(1)))
    except ValueError:
        return None
    return None


def field_name(entry: VaultEntry) -> Optional[str]:
    """Nazwa pola z datą, które ma wpis (polska albo angielska), lub None."""
    for name in (EXPIRY_FIELD, *EXPIRY_ALIASES):
        if name in entry.custom_fields:
            return name
    return None


def get_expiry(entry: VaultEntry) -> Optional[date]:
    name = field_name(entry)
    return parse_date(entry.custom_fields.get(name, "")) if name else None


def set_expiry_field(fields: dict, value: Optional[date]) -> dict:
    """Ustawia (albo usuwa przy None) datę w słowniku pól niestandardowych; zwraca ten sam słownik."""
    for name in (EXPIRY_FIELD, *EXPIRY_ALIASES):
        fields.pop(name, None)
    if value is not None:
        fields[EXPIRY_FIELD] = value.isoformat()
    return fields


def status(entry: VaultEntry, today: Optional[date] = None) -> Optional[Tuple[str, int]]:
    """(stan, liczba dni do wygaśnięcia – ujemna po terminie) albo None, gdy wpis nie ma daty."""
    expires = get_expiry(entry)
    if expires is None:
        return None
    days = (expires - (today or date.today())).days
    if days < 0:
        return EXPIRED, days
    if days <= SOON_DAYS:
        return SOON, days
    return OK, days


def attention(entries: Iterable[VaultEntry], today: Optional[date] = None) -> List[Tuple[VaultEntry, str, int]]:
    """Wpisy z hasłem wygasłym lub wkrótce wygasającym – najpilniejsze najpierw."""
    out = []
    for e in entries:
        st = status(e, today)
        if st and st[0] != OK:
            out.append((e, st[0], st[1]))
    out.sort(key=lambda item: item[2])
    return out


def in_days(days: int, today: Optional[date] = None) -> date:
    return (today or date.today()) + timedelta(days=days)
