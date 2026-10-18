"""
Szablony wpisów (wtyczka „Szablony wpisów”): gotowe zestawy pól dla typowych rzeczy w dziale IT.

Nazwy pól to dane sejfu (zostają po polsku w każdym języku – tak samo jak „Numer karty” czy „Autotype adresy”),
nazwy szablonów są tłumaczone. Własne szablony użytkownika są w ustawieniach sejfu (synchronizują się z nim).
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from core.i18n import N_, _
from core.vault import as_text

SETTINGS_KEY = "entry_templates"
MAX_USER_TEMPLATES = 50


@dataclass(frozen=True)
class EntryTemplate:
    id: str
    icon: str
    name: str                       # wbudowane: N_() – tłumaczone przy wyświetlaniu; własne: tekst użytkownika
    category: str                   # nazwa kategorii w sejfie (dane)
    url: str = ""                   # początek adresu, np. "rdp://" (przycisk „Połącz”)
    fields: Tuple[Tuple[str, str], ...] = field(default_factory=tuple)  # (nazwa pola, wartość domyślna)
    builtin: bool = True

    def label(self) -> str:
        return f"{self.icon} {_(self.name) if self.builtin else self.name}"


SERVERS = "Serwery / Wi-Fi"  # i18n: data
LOGINS = "Loginy"  # i18n: data
NOTES = "Bezpieczne notatki"  # i18n: data

BUILTIN: List[EntryTemplate] = [
    EntryTemplate("rdp_server", "🖥️", N_("Serwer Windows (Pulpit zdalny)"), SERVERS, "rdp://",
                  (("Adres IP", ""), ("Domena", ""), ("System", "Windows Server"))),  # i18n: data
    EntryTemplate("ssh_server", "🐧", N_("Serwer Linux (SSH)"), SERVERS, "ssh://",
                  (("Adres IP", ""), ("System", "Ubuntu"))),  # i18n: data
    EntryTemplate("mikrotik", "📶", N_("Router MikroTik (WinBox)"), SERVERS, "winbox://",
                  (("Adres IP", ""), ("Model", ""), ("Numer seryjny", ""))),  # i18n: data
    EntryTemplate("network_device", "🔌", N_("Router / switch / drukarka"), SERVERS, "https://",
                  (("Adres IP", ""), ("Model", ""), ("Numer seryjny", ""), ("Lokalizacja", ""))),  # i18n: data
    EntryTemplate("wifi", "📡", N_("Sieć Wi-Fi"), SERVERS, "",
                  (("SSID", ""), ("Zabezpieczenia", "WPA2"))),  # i18n: data
    EntryTemplate("remote_support", "📞", N_("Zdalna pomoc (AnyDesk / TeamViewer)"), SERVERS, "anydesk://",
                  (("Numer ID", ""),)),  # i18n: data
    EntryTemplate("license", "📜", N_("Licencja oprogramowania"), NOTES, "",
                  (("Klucz licencji", ""), ("Liczba stanowisk", ""), ("Data zakupu", ""), ("Ważna do", ""),  # i18n: data
                   ("Dostawca", ""))),  # i18n: data
    EntryTemplate("email", "📧", N_("Konto e-mail (poczta)"), LOGINS, "",
                  (("Serwer IMAP", ""), ("Serwer SMTP", ""), ("Port SMTP", "587"))),  # i18n: data
    EntryTemplate("database", "🗄️", N_("Baza danych"), SERVERS, "",
                  (("Typ", "SQL Server"), ("Host", ""), ("Port", ""), ("Nazwa bazy", ""))),  # i18n: data
    EntryTemplate("vpn", "🔐", N_("VPN"), SERVERS, "",
                  (("Serwer VPN", ""), ("Typ", ""), ("Klucz współdzielony (PSK)", ""))),  # i18n: data
]


def user_templates(settings: Optional[Dict[str, Any]]) -> List[EntryTemplate]:
    raw = (settings or {}).get(SETTINGS_KEY)
    out = []
    for i, item in enumerate(raw if isinstance(raw, list) else []):
        if not isinstance(item, dict):
            continue
        name = as_text(item.get("name"), 100).strip()
        if not name:
            continue
        fields = item.get("fields")
        fields = tuple((as_text(f, 200).strip(), "") for f in (fields if isinstance(fields, list) else [])[:50]
                       if as_text(f, 200).strip())
        out.append(EntryTemplate(f"user:{i}", "⭐", name, as_text(item.get("category"), 200) or LOGINS,
                                 as_text(item.get("url"), 100), fields, builtin=False))
    return out


def all_templates(settings: Optional[Dict[str, Any]]) -> List[EntryTemplate]:
    return BUILTIN + user_templates(settings)


def url_prefix(url: str) -> str:
    """Sam schemat adresu ("rdp://") – szablon nie zapisuje konkretnych adresów."""
    url = (url or "").strip()
    return url[:url.index("://") + 3].lower() if "://" in url else ""


def save_user_template(settings: Dict[str, Any], name: str, category: str, url: str, field_names: List[str]) -> None:
    """Dodaje (albo zastępuje o tej samej nazwie) własny szablon. Zapisuje tylko nazwy pól – nigdy wartości."""
    name = name.strip()[:100]
    items = [t for t in (settings.get(SETTINGS_KEY) or []) if isinstance(t, dict) and t.get("name") != name]
    items.append({"name": name, "category": category, "url": url_prefix(url),
                  "fields": [f.strip()[:200] for f in field_names if f.strip()][:50]})
    settings[SETTINGS_KEY] = items[-MAX_USER_TEMPLATES:]


def delete_user_template(settings: Dict[str, Any], name: str) -> None:
    settings[SETTINGS_KEY] = [t for t in (settings.get(SETTINGS_KEY) or []) if isinstance(t, dict) and t.get("name") != name]


def apply(template: EntryTemplate, existing: Dict[str, str]) -> Dict[str, str]:
    """Pola po wybraniu szablonu: istniejące wartości zostają, brakujące pola dochodzą z wartościami domyślnymi."""
    fields = dict(existing)
    for name, default in template.fields:
        fields.setdefault(name, default)
    return fields
