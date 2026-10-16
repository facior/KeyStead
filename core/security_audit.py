"""
Moduł audytu bezpieczeństwa sejfu haseł (Security Audit & Watchtower).
Sprawdza wycieki haseł (Have I Been Pwned z k-Anonymity), powtórzone hasła,
słabe hasła, brak uwierzytelniania dwuskładnikowego (2FA) oraz stare hasła.
"""

import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any, Callable
import requests

from core.vault import Vault, VaultEntry
from core.generator import evaluate_password_strength

HIBP_API_URL = "https://api.pwnedpasswords.com/range/"

# Podręczna pamięć podręczna wyników HIBP, aby nie odpytywać API wielokrotnie o ten sam prefiks
_HIBP_CACHE: Dict[str, Dict[str, int]] = {}


def check_password_breach_hibp(password: str, timeout: int = 6) -> Tuple[bool, int]:
    """
    Sprawdza czy hasło wyciekło w znanych bazach danych za pomocą Have I Been Pwned API.
    
    ZASADA ZERO-KNOWLEDGE (k-Anonymity):
    - Hasło NIE jest wysyłane przez sieć.
    - Tworzony jest skrót SHA-1 z hasła.
    - Tylko pierwsze 5 znaków skrótu (prefix) jest wysyłane do serwera API.
    - Serwer zwraca listę końcówek skrótów pasujących do tego prefiksu.
    - Klient lokalnie porównuje resztę skrótu z otrzymaną listą.
    
    Zwraca (czy_wycieklo, liczba_wyciekow). Gdy API jest niedostępne: (False, -1).
    """
    if not password:
        return False, 0

    # Obliczenie SHA-1
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    if prefix in _HIBP_CACHE:
        suffix_map = _HIBP_CACHE[prefix]
        count = suffix_map.get(suffix, 0)
        return count > 0, count

    try:
        url = f"{HIBP_API_URL}{prefix}"
        headers = {
            "Add-Padding": "true",  # Ochrona przed atakami czasowymi i analizą rozmiaru pakietu
            "User-Agent": "KeyStead-Manager"
        }
        resp = requests.get(url, headers=headers, timeout=timeout)
        if resp.status_code != 200:
            return False, -1

        suffix_map = {}
        for line in resp.text.splitlines():
            line = line.strip()
            if ":" in line:
                s_part, c_part = line.split(":", 1)
                try:
                    suffix_map[s_part.strip().upper()] = int(c_part.strip())
                except ValueError:
                    pass

        _HIBP_CACHE[prefix] = suffix_map
        count = suffix_map.get(suffix, 0)
        return count > 0, count

    except Exception:
        # W przypadku braku internetu lub timeoutu nie blokujemy aplikacji
        return False, -1


class AuditIssue:
    def __init__(
        self,
        entry: VaultEntry,
        issue_type: str,  # 'breached' | 'reused' | 'weak' | 'missing_totp' | 'stale'
        severity: str,    # 'critical' | 'high' | 'medium' | 'low'
        title: str,
        description: str,
        leak_count: int = 0,
        shared_with: Optional[List[str]] = None
    ):
        self.entry_id = entry.id
        self.entry_title = entry.title
        self.entry_username = entry.username
        self.entry_category = entry.category
        self.issue_type = issue_type
        self.severity = severity
        self.title = title
        self.description = description
        self.leak_count = leak_count
        self.shared_with = shared_with or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "entry_title": self.entry_title,
            "entry_username": self.entry_username,
            "entry_category": self.entry_category,
            "issue_type": self.issue_type,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "leak_count": self.leak_count,
            "shared_with": self.shared_with
        }


class AuditReport:
    def __init__(self):
        self.total_entries: int = 0
        self.score: int = 100
        self.rating_label: str = "Doskonały"
        self.rating_color: str = "#10b981"
        self.issues: List[AuditIssue] = []
        self.hibp_failures: int = 0  # Liczba haseł, których nie udało się sprawdzić w HIBP

    @property
    def breached_issues(self) -> List[AuditIssue]:
        return [i for i in self.issues if i.issue_type == "breached"]

    @property
    def reused_issues(self) -> List[AuditIssue]:
        return [i for i in self.issues if i.issue_type == "reused"]

    @property
    def weak_issues(self) -> List[AuditIssue]:
        return [i for i in self.issues if i.issue_type == "weak"]

    @property
    def missing_totp_issues(self) -> List[AuditIssue]:
        return [i for i in self.issues if i.issue_type == "missing_totp"]

    @property
    def stale_issues(self) -> List[AuditIssue]:
        return [i for i in self.issues if i.issue_type == "stale"]

    def calculate_score(self):
        """Wylicza ogólny wynik bezpieczeństwa sejfu w skali 0-100."""
        if self.total_entries == 0:
            self.score = 100
            self.rating_label = "Pusty sejf"
            self.rating_color = "#9ca3af"
            return

        penalty = 0
        # Kary punktowe
        penalty += len(self.breached_issues) * 25      # Wyciekłe hasło to krytyczne zagrożenie
        penalty += len(self.reused_issues) * 10        # Powtórzone hasła
        penalty += len(self.weak_issues) * 8           # Słabe hasła
        penalty += len(self.missing_totp_issues) * 3   # Brak 2FA na kontach loginowych
        penalty += len(self.stale_issues) * 2          # Hasła > 1 roku

        self.score = max(0, min(100, 100 - penalty))

        if self.score >= 85:
            self.rating_label = "Doskonały (Wysoki poziom ochrony)"
            self.rating_color = "#10b981"
        elif self.score >= 65:
            self.rating_label = "Dobry (Zalecane drobne poprawki)"
            self.rating_color = "#f59e0b"
        elif self.score >= 40:
            self.rating_label = "Średni (Wykryto zagrożenia)"
            self.rating_color = "#f97316"
        else:
            self.rating_label = "Krytyczny (Pilnie zmień wyciekłe hasła!)"
            self.rating_color = "#ef4444"


def _parse_iso(value: str) -> Optional[datetime]:
    try:
        dt = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _password_changed_at(entry: VaultEntry) -> Optional[datetime]:
    """Data ustawienia bieżącego hasła: archiwizacja poprzedniego hasła lub utworzenie wpisu."""
    if entry.password_history:
        archived = _parse_iso(entry.password_history[-1].get("archived_at", ""))
        if archived:
            return archived
    return _parse_iso(entry.created_at)


def run_vault_audit(
    vault: Vault,
    check_hibp: bool = True,
    progress_callback: Optional[Callable[[int, int, str], None]] = None
) -> AuditReport:
    """
    Przeprowadza całościowy audyt bezpieczeństwa sejfu:
    1. Wycieki haseł (Have I Been Pwned z k-Anonymity)
    2. Powtórzone hasła pomiędzy różnymi kontami
    3. Słabe hasła (niska entropia / proste wzorce)
    4. Brak 2FA (TOTP)
    5. Hasła niezmieniane od ponad 180 dni
    """
    report = AuditReport()
    entries = list(vault.entries.values())
    report.total_entries = len(entries)

    if not entries:
        report.calculate_score()
        return report

    # 1. Mapa do wykrywania powtórzonych haseł
    password_map: Dict[str, List[VaultEntry]] = {}
    for entry in entries:
        if entry.password:
            password_map.setdefault(entry.password, []).append(entry)

    # 2. Analiza każdego wpisu
    total = len(entries)
    now = datetime.now(timezone.utc)

    for idx, entry in enumerate(entries):
        if progress_callback:
            progress_callback(idx + 1, total, entry.title)

        pwd = entry.password

        # 2.1 Sprawdzenie wycieku w Have I Been Pwned
        if check_hibp and pwd:
            is_breached, leak_count = check_password_breach_hibp(pwd)
            if leak_count < 0:
                report.hibp_failures += 1
            if is_breached:
                report.issues.append(AuditIssue(
                    entry=entry,
                    issue_type="breached",
                    severity="critical",
                    title="Hasło znalezione w wyciekach danych!",
                    description=f"To hasło pojawiło się w znanych wyciekach danych {leak_count:,} razy. Hakerzy posiadają je w swoich słownikach ataku.",
                    leak_count=leak_count
                ))

        # 2.2 Słabe hasła
        if pwd:
            eval_res = evaluate_password_strength(pwd)
            if eval_res["score"] <= 2 or eval_res["entropy"] < 45:
                report.issues.append(AuditIssue(
                    entry=entry,
                    issue_type="weak",
                    severity="high" if eval_res["score"] <= 1 else "medium",
                    title=f"Słabe hasło ({eval_res['label']})",
                    description=f"Hasło ma niską entropię ({eval_res['entropy']} bitów). {', '.join(eval_res['feedback'])}"
                ))
        elif entry.category == "Loginy":
            report.issues.append(AuditIssue(
                entry=entry,
                issue_type="weak",
                severity="critical",
                title="Brak hasła we wpisie logowania",
                description="Ten wpis nie posiada zapisanego hasła."
            ))

        # 2.3 Brak 2FA / TOTP (dla kategorii Loginy)
        if entry.category in ["Loginy", "Konta internetowe"] and not entry.totp_secret:
            report.issues.append(AuditIssue(
                entry=entry,
                issue_type="missing_totp",
                severity="low",
                title="Brak skonfigurowanego 2FA (TOTP)",
                description="Dla tego konta nie skonfigurowano jednorazowych kodów dwuskładnikowych."
            ))

        # 2.4 Stare hasła (> 180 dni od ostatniej zmiany hasła)
        if pwd:
            changed_at = _password_changed_at(entry)
            if changed_at:
                age_days = (now - changed_at).days
                if age_days > 180:
                    report.issues.append(AuditIssue(
                        entry=entry,
                        issue_type="stale",
                        severity="low",
                        title=f"Hasło niezmieniane od {age_days} dni",
                        description=f"Ostatnia zmiana hasła miała miejsce {age_days} dni temu ({changed_at.date().isoformat()})."
                    ))

    # 3. Dodanie problemów z powtórzonymi hasłami
    for pwd, matched_entries in password_map.items():
        if len(matched_entries) > 1:
            for entry in matched_entries:
                other_titles = [e.title for e in matched_entries if e.id != entry.id]
                report.issues.append(AuditIssue(
                    entry=entry,
                    issue_type="reused",
                    severity="high",
                    title=f"Hasło używane na {len(matched_entries)} różnych kontach!",
                    description=f"Identyczne hasło jest współdzielone z kontami: {', '.join(other_titles)}.",
                    shared_with=other_titles
                ))

    report.calculate_score()
    return report
