"""
Mapa domina kont (Centrum ratunkowe): które skrzynki e-mail „otwierają” które konta.

Większość serwisów pozwala zresetować hasło przez e-mail – kto przejmie skrzynkę, przejmie też wszystkie konta
założone na ten adres. Analiza działa tylko na danych z sejfu (bez internetu):
    adres e-mail konta  = login wpisu (jeśli wygląda jak e-mail) albo pole „E-mail” / „E-mail odzyskiwania”
    wpis skrzynki       = wpis z tym samym adresem na stronie dostawcy poczty (gmail.com → google.com itd.)
Dla każdej skrzynki: ile kont od niej zależy (w tym ważnych – bank, zakupy, administracja), jak dobrze jest
zabezpieczona (2FA, siła i powtórzenia hasła, wycieki) i co poprawić najpierw.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set
from urllib.parse import urlparse

from core.i18n import N_
from core.vault import VaultEntry

EMAIL = re.compile(r"^[A-Za-z0-9._%+'-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,}$")
EMAIL_FIELDS = ("E-mail", "Email", "E-mail odzyskiwania", "Recovery e-mail", "Adres e-mail")  # i18n: data

# Dostawcy poczty: domena adresu → domeny stron logowania do skrzynki
PROVIDERS: Dict[str, tuple] = {
    "gmail.com": ("google.com", "gmail.com"), "googlemail.com": ("google.com", "gmail.com"),
    "outlook.com": ("live.com", "microsoft.com", "outlook.com", "office.com"),
    "hotmail.com": ("live.com", "microsoft.com", "outlook.com"), "live.com": ("live.com", "microsoft.com"),
    "msn.com": ("live.com", "microsoft.com"), "icloud.com": ("apple.com", "icloud.com"),
    "me.com": ("apple.com", "icloud.com"), "yahoo.com": ("yahoo.com",), "proton.me": ("proton.me",),
    "protonmail.com": ("proton.me", "protonmail.com"), "wp.pl": ("wp.pl",), "o2.pl": ("o2.pl",),
    "tlen.pl": ("o2.pl",), "onet.pl": ("onet.pl",), "op.pl": ("onet.pl",), "vp.pl": ("onet.pl",),
    "interia.pl": ("interia.pl",), "interia.eu": ("interia.pl",), "poczta.fm": ("interia.pl",),
    "gazeta.pl": ("gazeta.pl",), "gmx.com": ("gmx.com",), "gmx.net": ("gmx.net",), "aol.com": ("aol.com",),
    "zoho.com": ("zoho.com",),
}

# Konta, których przejęcie najbardziej boli (dopasowanie po domenie strony albo nazwie / kategorii wpisu)
IMPORTANT = {
    "bank": (N_("bank"), ("pkobp", "ipko", "mbank", "ing.pl", "santander", "pekao", "millennium", "aliorbank",
                          "bnpparibas", "creditagricole", "citi", "velobank", "revolut", "nest", "bank", "paypal",
                          "wise.com", "zen.com", "blik")),
    "gov": (N_("urząd"), ("gov.pl", "epuap", "pz.gov", "mobywatel", "podatki", "zus", "e-urzad")),
    "shop": (N_("zakupy"), ("allegro", "amazon", "olx", "aliexpress", "temu", "zalando", "empik", "ebay",
                            "vinted")),
    "social": (N_("społecznościowe"), ("facebook", "instagram", "twitter", "x.com", "tiktok", "linkedin")),
    "crypto": (N_("kryptowaluty"), ("binance", "coinbase", "kraken", "zondacrypto", "bitpanda")),
}

# Gdzie wylogować wszystkie urządzenia i włączyć 2FA (strony ustawień dużych dostawców)
SECURITY_PAGES = {
    "google.com": ("https://myaccount.google.com/device-activity", "https://myaccount.google.com/signinoptions/twosv"),
    "live.com": ("https://account.microsoft.com/devices", "https://account.microsoft.com/security"),
    "microsoft.com": ("https://account.microsoft.com/devices", "https://account.microsoft.com/security"),
    "apple.com": ("https://account.apple.com/account/manage", "https://account.apple.com/account/manage"),
    "facebook.com": ("https://www.facebook.com/settings?tab=security", "https://www.facebook.com/security/2fac/settings"),
    "instagram.com": ("https://www.instagram.com/accounts/login_activity/", "https://www.instagram.com/accounts/two_factor_authentication/"),
    "allegro.pl": ("https://allegro.pl/moje-allegro/moje-konto/bezpieczenstwo",
                   "https://allegro.pl/moje-allegro/moje-konto/bezpieczenstwo"),
    "wp.pl": ("https://profil.wp.pl/", "https://profil.wp.pl/"),
    "onet.pl": ("https://konto.onet.pl/", "https://konto.onet.pl/"),
    "interia.pl": ("https://poczta.interia.pl/ustawienia", "https://poczta.interia.pl/ustawienia"),
}


def host(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return (parsed.hostname or "").lower()


def matches_domain(h: str, domain: str) -> bool:
    return h == domain or h.endswith("." + domain)


def entry_emails(entry: VaultEntry) -> Set[str]:
    out = set()
    if EMAIL.match(entry.username.strip()):
        out.add(entry.username.strip().lower())
    for name in EMAIL_FIELDS:
        value = (entry.custom_fields.get(name) or "").strip()
        if EMAIL.match(value):
            out.add(value.lower())
    return out


def importance(entry: VaultEntry) -> Optional[str]:
    h = host(entry.url)
    text = f"{h} {entry.title} {entry.category}".lower()
    for kind, (_label, words) in IMPORTANT.items():
        for w in words:
            # „x.com” to domena – nie może pasować do „netflix.com”; słowa bez kropki szukamy w tekście
            if ("." in w and h and matches_domain(h, w)) or ("." not in w and w in text):
                return kind
    return None


def is_mailbox_for(entry: VaultEntry, email: str) -> bool:
    """Czy wpis to logowanie do skrzynki `email` (adres + strona dostawcy poczty lub poczta firmowa)."""
    if email not in entry_emails(entry):
        return False
    domain = email.split("@", 1)[1]
    h = host(entry.url)
    sites = PROVIDERS.get(domain, (domain,))
    if any(matches_domain(h, s) for s in sites):
        return True
    words = f"{entry.title} {entry.category}".lower()
    return any(w in words for w in ("poczta", "mail", "skrzynka", "e-mail", "outlook", "gmail"))


@dataclass
class Key:
    """Skrzynka e-mail, która może zresetować hasła innych kont."""
    email: str
    mailbox: Optional[VaultEntry]
    dependents: List[VaultEntry] = field(default_factory=list)
    important: Dict[str, int] = field(default_factory=dict)
    problems: List[str] = field(default_factory=list)   # klucze N_() – tłumaczone przy wyświetlaniu
    risk: int = 0                                        # 0 = dobrze … 3 = pilne

    @property
    def provider_host(self) -> str:
        if self.mailbox is not None and host(self.mailbox.url):
            return host(self.mailbox.url)
        domain = self.email.split("@", 1)[1]
        return PROVIDERS.get(domain, (domain,))[0]


PROBLEM_NO_ENTRY = N_("Brak wpisu z hasłem do tej skrzynki – dodaj go, żeby KeyStead mógł ją sprawdzić.")
PROBLEM_NO_2FA = N_("Brak weryfikacji dwuetapowej (2FA) – włącz ją w pierwszej kolejności.")
PROBLEM_WEAK = N_("Słabe hasło do skrzynki.")
PROBLEM_REUSED = N_("To samo hasło jest użyte także w innym koncie.")
PROBLEM_BREACHED = N_("Hasło do skrzynki było w wycieku danych – zmień je natychmiast.")


def analyze(entries: Iterable[VaultEntry], breached_ids: Optional[Set[str]] = None) -> List[Key]:
    """Skrzynki od najbardziej ryzykownej: najpierw stan zabezpieczeń, potem liczba zależnych kont."""
    from core.generator import evaluate_password_strength
    entries = list(entries)
    breached_ids = breached_ids or set()
    keys: Dict[str, Key] = {}
    for e in entries:
        for email in entry_emails(e):
            keys.setdefault(email, Key(email, None))
    for email, key in keys.items():
        key.mailbox = next((e for e in entries if is_mailbox_for(e, email)), None)
        for e in entries:
            if e is not key.mailbox and email in entry_emails(e):
                key.dependents.append(e)
                kind = importance(e)
                if kind:
                    key.important[kind] = key.important.get(kind, 0) + 1
    password_count: Dict[str, int] = {}
    for e in entries:
        if e.password:
            password_count[e.password] = password_count.get(e.password, 0) + 1
    for key in keys.values():
        box = key.mailbox
        if box is None:
            key.problems.append(PROBLEM_NO_ENTRY)
            key.risk = 1
        else:
            if box.id in breached_ids:
                key.problems.append(PROBLEM_BREACHED)
            if not box.totp_secret:
                key.problems.append(PROBLEM_NO_2FA)
            if box.password and password_count.get(box.password, 0) > 1:
                key.problems.append(PROBLEM_REUSED)
            if box.password and evaluate_password_strength(box.password)["score"] < 3:
                key.problems.append(PROBLEM_WEAK)
            key.risk = min(3, len(key.problems) + (1 if PROBLEM_BREACHED in key.problems else 0))
        if not key.dependents:
            key.risk = min(key.risk, 1)
    result = [k for k in keys.values() if k.dependents or k.mailbox is not None]
    result.sort(key=lambda k: (-k.risk, -sum(k.important.values()), -len(k.dependents), k.email))
    return result


def keys_for_entry(entry: VaultEntry, keys: List[Key]) -> List[Key]:
    """Skrzynki, przez które da się przejąć ten wpis (dla kreatora „Ktoś przejął moje konto”)."""
    emails = entry_emails(entry)
    return [k for k in keys if k.email in emails and k.mailbox is not entry]


def mailbox_key(entry: VaultEntry, keys: List[Key]) -> Optional[Key]:
    """Jeśli wpis to skrzynka e-mail – jej „domino” (konta, które od niej zależą)."""
    return next((k for k in keys if k.mailbox is entry), None)


def change_password_url(entry: VaultEntry) -> str:
    """Standardowy adres zmiany hasła (/.well-known/change-password – obsługuje go większość dużych serwisów)."""
    h = host(entry.url)
    return f"https://{h}/.well-known/change-password" if h else ""


def security_pages(entry_or_host) -> tuple:
    h = entry_or_host if isinstance(entry_or_host, str) else host(entry_or_host.url)
    for domain, pages in SECURITY_PAGES.items():
        if matches_domain(h, domain):
            return pages
    return ("", "")
