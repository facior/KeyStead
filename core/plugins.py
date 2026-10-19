"""
Wbudowane wtyczki KeyStead – dodatkowe funkcje włączane w Ustawienia → Wtyczki.

Nie ładujemy obcego kodu: wtyczka widziałaby otwarty sejf, więc każda „wtyczka” to funkcja aplikacji,
domyślnie wyłączona. Wybór użytkownika jest zapisany w (zaszyfrowanych) ustawieniach sejfu – działa na każdym
jego urządzeniu. Firma może zablokować wybrane wtyczki polityką z serwera (`blocked_plugins`).
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from core.i18n import N_

SETTINGS_KEY = "plugins"          # vault.settings["plugins"] = {"connect": True, ...}
OPTIONS_KEY = "plugin_options"    # vault.settings["plugin_options"] = {"ssh_agent": {"confirm": True}, ...}
POLICY_KEY = "blocked_plugins"    # polityka firmy: lista identyfikatorów wtyczek zablokowanych przez administratora


@dataclass(frozen=True)
class Plugin:
    id: str
    icon: str
    name: str            # N_() – tłumaczone przy wyświetlaniu
    description: str     # N_()
    ready: bool = True   # False = w przygotowaniu (widoczna na liście, nie da się włączyć)


PLUGINS: List[Plugin] = [
    Plugin("connect", "🖥️", N_("Przycisk „Połącz”"),
           N_("Przy wpisach z adresem rdp://, ssh://, winbox://, anydesk:// lub teamviewer:// pojawia się przycisk "
              "„Połącz”. Jedno kliknięcie otwiera Pulpit zdalny, SSH, WinBox, AnyDesk lub TeamViewer i od razu loguje.")),
    Plugin("expiry", "⏰", N_("Data ważności hasła"),
           N_("Wpis może mieć datę „Hasło ważne do”. Program przypomina o hasłach, które wkrótce wygasną "
              "lub już wygasły, i oznacza je na liście.")),
    Plugin("qr_import", "📷", N_("Kod QR 2FA z obrazka"),
           N_("Przy dodawaniu kodu 2FA zamiast przepisywać klucz wklejasz zrzut ekranu z kodem QR "
              "(Win+Shift+S) albo wybierasz plik z obrazkiem.")),
    Plugin("qr_show", "🔳", N_("Hasło jako kod QR"),
           N_("Pokazuje hasło jako kod QR, żeby szybko przenieść je na telefon. Dla sieci Wi-Fi telefon "
              "połączy się od razu po zeskanowaniu. Okno zamyka się samo po minucie.")),
    Plugin("templates", "🧩", N_("Szablony wpisów"),
           N_("Gotowe rodzaje wpisów z polami do uzupełnienia: serwer, router, Wi-Fi, licencja, poczta, baza danych, "
              "VPN. Możesz też zapisać własny szablon.")),
    Plugin("colored_password", "🎨", N_("Kolorowe hasło"),
           N_("Odkryte hasło pokazuje cyfry i znaki specjalne w innych kolorach, żeby nie pomylić np. O z 0 "
              "albo l z 1 przy przepisywaniu.")),
    Plugin("floating_panel", "📌", N_("Pływający panel"),
           N_("Małe okno zawsze na wierzchu z ulubionymi wpisami i wyszukiwarką – kopiujesz login, hasło "
              "lub kod 2FA bez przełączania się do KeyStead.")),
    Plugin("pick_chars", "🔢", N_("Wybrane znaki hasła"),
           N_("Gdy strona prosi np. o 3., 5. i 8. znak hasła (jak w bankach), wybierasz numery, a program "
              "pokazuje i kopiuje tylko te znaki.")),
    Plugin("ssh_agent", "🗝️", N_("Klucze SSH w sejfie"),
           N_("KeyStead działa jak Pageant i ssh-agent: PuTTY, WinSCP, ssh, scp i git biorą klucz SSH z otwartego "
              "sejfu. Klucz dodajesz przy wpisie (plik OpenSSH, PEM lub PuTTY .ppk albo nowy klucz). Po zablokowaniu "
              "sejfu klucze przestają działać.")),
    Plugin("secure_send", "✉️", N_("Bezpieczny link do hasła"),
           N_("Przycisk „Link” przy haśle tworzy jednorazowy link dla kogoś spoza KeyStead. Treść jest szyfrowana "
              "w aplikacji – serwer firmy jej nie zna – i znika po pierwszym otwarciu. Wymaga sejfu na serwerze "
              "KeyStead (w sejfie lokalnym przycisk wyjaśni, dlaczego link nie działa).")),
    Plugin("family_share", "👪", N_("Udostępnianie domownikom"),
           N_("Wysyłasz wpis (np. hasło do Netflixa albo Wi-Fi) żonie, mężowi czy dzieciom – bez serwera i bez chmury. "
              "Każdy daje Ci raz swoją wizytówkę, a paczkę z hasłem otworzy tylko KeyStead tej osoby. Ponowne wysłanie "
              "aktualizuje hasło u odbiorcy.")),
    Plugin("phone_handoff", "📱", N_("Hasło na telefon"),
           N_("Przycisk „📱 Telefon” przy haśle pokazuje kod QR. Skanujesz go telefonem i hasło na chwilę pojawia się "
              "w przeglądarce telefonu – przez domowe Wi-Fi, zaszyfrowane, bez instalowania aplikacji i bez chmury.")),
    Plugin("yubikey", "🔑", N_("Klucz YubiKey"),
           N_("Sejf otwiera się dopiero po podaniu hasła głównego i dotknięciu Twojego YubiKey (tryb "
              "challenge-response). Samo hasło – nawet wykradzione – nie wystarczy. Gdy zgubisz klucz, sejf "
              "otworzysz kodem odzyskiwania.")),
    Plugin("passkeys", "👆", N_("Passkeys"),
           N_("Logowanie na strony bez hasła (passkeys). Wymaga Windows 11."), ready=False),
]

BY_ID: Dict[str, Plugin] = {p.id: p for p in PLUGINS}


def blocked_by_policy(policy: Optional[Dict[str, Any]], plugin_id: str) -> bool:
    blocked = (policy or {}).get(POLICY_KEY)
    return isinstance(blocked, (list, tuple)) and plugin_id in blocked


def user_choices(settings: Optional[Dict[str, Any]]) -> Dict[str, bool]:
    raw = (settings or {}).get(SETTINGS_KEY)
    if not isinstance(raw, dict):
        return {}
    return {k: v is True for k, v in raw.items() if k in BY_ID}


def is_enabled(settings: Optional[Dict[str, Any]], policy: Optional[Dict[str, Any]], plugin_id: str) -> bool:
    """Wtyczka działa, gdy jest gotowa, użytkownik ją włączył i firma jej nie zablokowała."""
    plugin = BY_ID.get(plugin_id)
    if plugin is None or not plugin.ready or blocked_by_policy(policy, plugin_id):
        return False
    return user_choices(settings).get(plugin_id, False)


def enabled_set(settings: Optional[Dict[str, Any]], policy: Optional[Dict[str, Any]]) -> frozenset:
    return frozenset(p.id for p in PLUGINS if is_enabled(settings, policy, p.id))


def options(settings: Optional[Dict[str, Any]], plugin_id: str) -> Dict[str, Any]:
    raw = ((settings or {}).get(OPTIONS_KEY) or {})
    value = raw.get(plugin_id) if isinstance(raw, dict) else None
    return dict(value) if isinstance(value, dict) else {}


def set_options(settings: Dict[str, Any], plugin_id: str, values: Dict[str, Any]) -> None:
    raw = settings.get(OPTIONS_KEY)
    raw = dict(raw) if isinstance(raw, dict) else {}
    raw[plugin_id] = {**options(settings, plugin_id), **values}
    settings[OPTIONS_KEY] = raw


def set_choices(settings: Dict[str, Any], choices: Dict[str, bool]) -> None:
    """Zapisuje wybór użytkownika (tylko znane wtyczki; zablokowane przez firmę zachowują poprzedni wybór)."""
    current = user_choices(settings)
    current.update({k: bool(v) for k, v in choices.items() if k in BY_ID and BY_ID[k].ready})
    settings[SETTINGS_KEY] = current
