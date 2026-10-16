"""
Monitorowanie haseł w tle: plakietka z liczbą problemów i powiadomienie o NOWYCH wyciekach.

- Lokalny audyt (słabe, powtórzone, stare hasła) – bez sieci, przy każdym sprawdzeniu.
- Sprawdzanie wycieków (Have I Been Pwned, k-anonimowość: wysyłane jest tylko 5 znaków skrótu SHA-1)
  najwyżej raz na dobę i tylko za zgodą użytkownika (ustawienie sejfu „auto_breach_check”).
- Stan „już zgłoszonych” wycieków jest zapisywany lokalnie na tym komputerze (identyfikatory wpisów, bez haseł),
  dzięki czemu użytkownik dostaje powiadomienie tylko o nowych problemach.
"""

import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple

from core.paths import APP_DIR
from core.security_audit import AuditReport

STATE_DIR = os.path.join(APP_DIR, "watch")
CHECK_INTERVAL_HOURS = 24
CONSENT_KEY = "auto_breach_check"  # None = nie pytano, True/False = decyzja użytkownika


def consent(settings: Dict[str, Any]) -> Optional[bool]:
    value = (settings or {}).get(CONSENT_KEY)
    return value if isinstance(value, bool) else None


def attention_count(report: AuditReport) -> int:
    """Liczba wpisów wymagających uwagi (bez „brak 2FA” – to zalecenie, nie zagrożenie)."""
    ids = {i.entry_id for i in report.issues if i.issue_type in ("breached", "reused", "weak", "stale")}
    return len(ids)


class Watchtower:
    def __init__(self, target: str, directory: str = STATE_DIR):
        self.path = os.path.join(directory, f"{target}.json")

    def _load(self) -> Dict[str, Any]:
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self, data: Dict[str, Any]) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp, self.path)

    def breach_check_due(self, hours: float = CHECK_INTERVAL_HOURS) -> bool:
        return time.time() - float(self._load().get("last_breach_check", 0)) > hours * 3600

    def known_breached(self) -> List[str]:
        return list(self._load().get("known_breached", []))

    def record(self, report: AuditReport, breach_checked: bool) -> List[Tuple[str, str]]:
        """Zapisuje wynik i zwraca NOWE wycieki [(id_wpisu, tytuł)] – tylko gdy faktycznie sprawdzano wycieki."""
        state = self._load()
        if not breach_checked:
            return []
        current = {i.entry_id: i.entry_title for i in report.breached_issues}
        known = set(state.get("known_breached", []))
        new = [(eid, title) for eid, title in current.items() if eid not in known]
        # Zapamiętujemy bieżący stan: zmienione hasło znika z listy, a ponowny wyciek zostanie zgłoszony od nowa
        state["known_breached"] = sorted(current)
        state["last_breach_check"] = time.time()
        if report.hibp_failures and not current:
            state["last_breach_check"] = time.time() - (CHECK_INTERVAL_HOURS - 1) * 3600  # ponów za godzinę
        self._save(state)
        return new
