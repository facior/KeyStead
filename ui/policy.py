"""
Stosowanie polityk bezpieczeństwa firmy (z serwera KeyStead) w aplikacji.

Użytkownik może ustawić coś bezpieczniej niż wymaga polityka, ale nie mniej bezpiecznie:
krótszy czas blokady, szybsze czyszczenie schowka, silniejsze hasło główne.
"""

from typing import Any, Dict, List, Tuple

from core.i18n import _, _n

# Etykiety tłumaczone raz przy wczytaniu modułu (język aplikacji nie zmienia się w trakcie działania);
# formularze mapują je z powrotem na liczby przez te same listy, więc działa to w każdym języku.
NEVER = _("Nigdy")


def _minutes(n: int) -> str:
    return _n(n, "{n} minuta", "{n} minuty", "{n} minut")


def _seconds(n: int) -> str:
    return _n(n, "{n} sekunda", "{n} sekundy", "{n} sekund")


LOCK_CHOICES: List[Tuple[str, int]] = [(_minutes(m), m) for m in (1, 5, 10, 15, 30)] + [(NEVER, 0)]
CLIPBOARD_CHOICES: List[Tuple[str, int]] = [(_seconds(s), s) for s in (10, 30, 60)] + [(NEVER, 0)]
SCORE_LABELS = {0: _("bez wymagań"), 1: _("słabe"), 2: _("średnie"), 3: _("silne"), 4: _("bardzo silne")}


# Sensowne zakresy limitów z serwera. Wartość spoza zakresu (np. ujemna) znaczy „bez limitu” – inaczej
# złośliwy serwer mógłby ustawić -1 i wyłączyć tym automatyczną blokadę oraz czyszczenie schowka.
_LIMIT_RANGES = {"max_auto_lock_minutes": (1, 1440), "max_clipboard_seconds": (5, 600)}


def _limit(policy: Dict[str, Any], key: str) -> int:
    try:
        value = int((policy or {}).get(key) or 0)
    except (TypeError, ValueError, OverflowError):
        return 0
    low, high = _LIMIT_RANGES.get(key, (1, 10 ** 6))
    return value if low <= value <= high else 0


def effective_auto_lock(user_minutes: int, policy: Dict[str, Any]) -> int:
    """Czas blokady w minutach (0 = nigdy) po zastosowaniu polityki."""
    limit = _limit(policy, "max_auto_lock_minutes")
    if not limit:
        return user_minutes
    if user_minutes == 0:
        return 0 if (policy or {}).get("allow_never_lock") else limit
    return min(user_minutes, limit)


def effective_clipboard(user_seconds: int, policy: Dict[str, Any]) -> int:
    limit = _limit(policy, "max_clipboard_seconds")
    if not limit:
        return user_seconds
    return limit if user_seconds == 0 else min(user_seconds, limit)


def lock_choices(policy: Dict[str, Any]) -> List[Tuple[str, int]]:
    limit = _limit(policy, "max_auto_lock_minutes")
    if not limit:
        return list(LOCK_CHOICES)
    allowed = [(label, m) for label, m in LOCK_CHOICES if 0 < m <= limit]
    if (policy or {}).get("allow_never_lock"):
        allowed.append((NEVER, 0))
    if not any(m == limit for _unused, m in allowed):
        allowed.insert(0, (_("{n} min", n=limit), limit))
    return allowed


def clipboard_choices(policy: Dict[str, Any]) -> List[Tuple[str, int]]:
    limit = _limit(policy, "max_clipboard_seconds")
    if not limit:
        return list(CLIPBOARD_CHOICES)
    allowed = [(label, s) for label, s in CLIPBOARD_CHOICES if 0 < s <= limit]
    if not any(s == limit for _unused, s in allowed):
        allowed.append((_seconds(limit), limit))
    return allowed


def min_master_score(policy: Dict[str, Any]) -> int:
    return max(0, min(_limit(policy, "min_master_score"), 4))


def personal_backups_allowed(policy: Dict[str, Any]) -> bool:
    return bool((policy or {}).get("allow_personal_backups", True))


def build_security_report(report) -> Dict[str, Any]:
    """Zamienia wynik audytu na zbiorcze liczby wysyłane na serwer (bez żadnych danych z sejfu)."""
    return {
        "score": int(report.score),
        "total": int(report.total_entries),
        "breached": len(report.breached_issues),
        "reused": len({i.entry_id for i in report.reused_issues}),
        "weak": len(report.weak_issues),
        "missing_totp": len(report.missing_totp_issues),
        "stale": len(report.stale_issues),
        "hibp_checked": report.hibp_failures < max(report.total_entries, 1),
    }
