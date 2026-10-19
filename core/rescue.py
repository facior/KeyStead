"""
Kreator „Ktoś przejął moje konto!” (Centrum ratunkowe): lista kroków dopasowana do konkretnego wpisu.

Kolejność jak w zaleceniach CERT Polska: najpierw odzyskaj kontrolę (hasło, sesje, 2FA, dane odzyskiwania),
potem odetnij skutki (konta zależne od skrzynki, to samo hasło gdzie indziej, bank), na końcu zgłoś incydent.
Stan odhaczonych kroków jest w ustawieniach sejfu (zaszyfrowany razem z nim).
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from core import domino
from core.i18n import _
from core.vault import VaultEntry

SETTINGS_KEY = "rescue"
CERT_URL = "https://incydent.cert.pl/"
CARD_BLOCK_PHONE = "828 828 828"          # zastrzeganie kart (system Zastrzegam.pl, czynny całą dobę)
PESEL_URL = "https://www.gov.pl/web/gov/zastrzez-swoj-numer-pesel"


@dataclass
class Step:
    id: str
    title: str                                     # tekst już przetłumaczony
    text: str
    links: List[Tuple[str, str]] = field(default_factory=list)   # (podpis, adres)
    kind: str = "check"                            # check | password | entries
    entries: List[VaultEntry] = field(default_factory=list)       # dla kind == "entries"


def build_steps(entry: VaultEntry, all_entries: List[VaultEntry], keys: List[domino.Key]) -> List[Step]:
    steps: List[Step] = []
    change_url = domino.change_password_url(entry)
    sessions_url, twofa_url = domino.security_pages(entry)
    box_key = domino.mailbox_key(entry, keys)
    kind = domino.importance(entry)

    steps.append(Step("password", _("Zmień hasło"),
                      _("Wygeneruj nowe, silne hasło, ustaw je na stronie i zapisz w KeyStead. Jeśli nie możesz się "
                        "zalogować, użyj na stronie „Nie pamiętam hasła” albo formularza odzyskiwania konta."),
                      [(_("Strona zmiany hasła"), change_url)] if change_url else [], kind="password"))
    steps.append(Step("sessions", _("Wyloguj wszystkie inne urządzenia"),
                      _("W ustawieniach bezpieczeństwa konta wybierz „Wyloguj ze wszystkich urządzeń” – napastnik może "
                        "być nadal zalogowany mimo zmiany hasła."),
                      [(_("Urządzenia i sesje"), sessions_url)] if sessions_url else []))
    if entry.totp_secret:
        steps.append(Step("2fa", _("Sprawdź weryfikację dwuetapową"),
                          _("Masz 2FA w tym wpisie. Upewnij się w ustawieniach konta, że napastnik nie dodał własnego "
                            "telefonu ani aplikacji do kodów."), [(_("Ustawienia 2FA"), twofa_url)] if twofa_url else []))
    else:
        steps.append(Step("2fa", _("Włącz weryfikację dwuetapową (2FA)"),
                          _("Kod z telefonu przy logowaniu zatrzyma napastnika, nawet jeśli pozna nowe hasło. Klucz 2FA "
                            "możesz zapisać w tym wpisie KeyStead."), [(_("Ustawienia 2FA"), twofa_url)] if twofa_url else []))
    steps.append(Step("recovery", _("Sprawdź dane odzyskiwania"),
                      _("Napastnicy podmieniają e-mail i numer telefonu do odzyskiwania konta. Sprawdź je w ustawieniach "
                        "i usuń nieznane.")))
    if box_key is not None:
        steps.append(Step("mail_rules", _("Sprawdź przekierowania i filtry poczty"),
                          _("W ustawieniach skrzynki usuń nieznane przekierowania, filtry i aplikacje z dostępem – "
                            "przez nie napastnik może dalej czytać Twoją pocztę.")))
        if box_key.dependents:
            deps = sorted(box_key.dependents, key=lambda e: (domino.importance(e) is None, e.title.lower()))
            steps.append(Step("dependents", _("Zmień hasła w kontach zależnych od tej skrzynki ({count})",
                                              count=len(deps)),
                              _("Przez tę skrzynkę da się zresetować hasła poniższych kont – zacznij od banków i zakupów."),
                              kind="entries", entries=deps))
    else:
        for key in domino.keys_for_entry(entry, keys):
            steps.append(Step(f"mailbox:{key.email}", _("Sprawdź skrzynkę {email}", email=key.email),
                              _("Reset hasła tego konta idzie na ten adres. Jeśli ktoś mógł mieć dostęp do skrzynki, "
                                "zabezpiecz ją najpierw (Centrum ratunkowe → wybierz wpis skrzynki).")))
    same = [e for e in all_entries if e is not entry and e.password and e.password == entry.password]
    if same:
        steps.append(Step("reused", _("Zmień to samo hasło w innych kontach ({count})", count=len(same)),
                          _("To hasło było użyte także tutaj – napastnik spróbuje go w innych serwisach."),
                          kind="entries", entries=same))
    if kind == "bank":
        steps.append(Step("bank", _("Zadzwoń do banku"),
                          _("Poproś o zablokowanie dostępu i sprawdzenie przelewów. Kartę zastrzeżesz całodobowo pod "
                            "numerem {phone}.", phone=CARD_BLOCK_PHONE)))
    if kind in ("bank", "gov"):
        steps.append(Step("pesel", _("Zastrzeż numer PESEL"),
                          _("Utrudnia wzięcie kredytu na Twoje dane. Zrobisz to w aplikacji mObywatel lub na gov.pl."),
                          [(_("Zastrzeżenie PESEL"), PESEL_URL)]))
    steps.append(Step("report", _("Zgłoś incydent"),
                      _("Zgłoś przejęcie konta do CERT Polska. Jeśli straciłeś pieniądze – także na policję."),
                      [(_("Zgłoś do CERT Polska"), CERT_URL)]))
    return steps


# --------------------------------------------------------------------- postęp (w ustawieniach sejfu)
def progress(settings: Dict[str, Any], entry_id: str) -> Dict[str, Any]:
    raw = (settings.get(SETTINGS_KEY) or {}).get(entry_id) if isinstance(settings.get(SETTINGS_KEY), dict) else None
    if not isinstance(raw, dict):
        return {"done": [], "entries_done": []}
    return {"done": [s for s in raw.get("done", []) if isinstance(s, str)],
            "entries_done": [s for s in raw.get("entries_done", []) if isinstance(s, str)],
            "started": raw.get("started")}


def set_done(settings: Dict[str, Any], entry_id: str, step_id: str, done: bool, sub: str = "done") -> None:
    data = settings.get(SETTINGS_KEY)
    data = dict(data) if isinstance(data, dict) else {}
    state = progress(settings, entry_id)
    state.setdefault("started", datetime.now(timezone.utc).isoformat())
    items = set(state[sub])
    (items.add if done else items.discard)(step_id)
    state[sub] = sorted(items)
    data[entry_id] = state
    settings[SETTINGS_KEY] = data


def clear(settings: Dict[str, Any], entry_id: str) -> None:
    data = settings.get(SETTINGS_KEY)
    if isinstance(data, dict) and entry_id in data:
        data = dict(data)
        del data[entry_id]
        settings[SETTINGS_KEY] = data


def open_cases(settings: Dict[str, Any]) -> List[str]:
    data = settings.get(SETTINGS_KEY)
    return list(data) if isinstance(data, dict) else []
