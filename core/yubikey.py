"""
YubiKey jako drugi składnik hasła głównego (wtyczka „Klucz YubiKey”, odpowiednik KeeChallenge).

Tryb challenge-response HMAC-SHA1 (slot 2 – w YubiKey Manager: Applications → OTP → Long Touch → Configure →
Challenge-response, albo `ykman otp chalresp --generate 2`). Sejf zapisuje w nagłówku klucza dostępu „hasło”
losowe wyzwanie (32 bajty, nie jest tajne); przy otwieraniu YubiKey liczy z niego odpowiedź, która razem z hasłem
(i plikiem-kluczem) wchodzi do Argon2id. Bez tego samego YubiKey hasło nie wystarczy.

Kod odzyskiwania i klucz firmy to osobne klucze dostępu – zgubiony YubiKey nie blokuje sejfu na zawsze.
"""

import threading
from typing import Callable, Dict, List, Optional

from core.i18n import _

DEFAULT_SLOT = 2
CHALLENGE_BYTES = 32
TIMEOUT_SECONDS = 25
STATUS_UPNEEDED = 2  # YubiKey czeka na dotknięcie

# Wywoływane (z dowolnego wątku), gdy YubiKey czeka na dotknięcie – aplikacja pokazuje wtedy podpowiedź
on_touch_needed: Optional[Callable[[], None]] = None

# Odpowiedzi z bieżącej sesji (do zablokowania sejfu): nowa wersja sejfu z innego komputera ma to samo wyzwanie,
# więc synchronizacja nie prosi o dotknięcie klucza przy każdej zmianie. Czyszczone przy blokadzie (clear_cache).
_cache: Dict[tuple, bytes] = {}
_cache_lock = threading.Lock()


class YubiKeyError(Exception):
    pass


def available() -> bool:
    try:
        import ykman.hid  # noqa: F401
        import yubikit.yubiotp  # noqa: F401
        return True
    except Exception:
        return False


def _devices():
    try:
        from ykman.hid import list_otp_devices
    except Exception as e:
        raise YubiKeyError(_("Brak obsługi YubiKey w tej wersji programu ({error}).", error=e))
    try:
        return list_otp_devices()
    except Exception as e:
        raise YubiKeyError(_("Nie udało się odczytać urządzeń USB: {error}", error=e))


def list_keys() -> List[Dict[str, object]]:
    """Podłączone YubiKey (numer seryjny, wersja, czy slot 1/2 jest skonfigurowany)."""
    from yubikit.core.otp import OtpConnection
    from yubikit.yubiotp import SLOT, YubiOtpSession
    out = []
    for dev in _devices():
        try:
            with dev.open_connection(OtpConnection) as conn:
                session = YubiOtpSession(conn)
                state = session.get_config_state()
                out.append({"serial": getattr(session, "get_serial", lambda: None)(), "version": str(session.version),
                            "slot1": state.is_configured(SLOT.ONE), "slot2": state.is_configured(SLOT.TWO)})
        except Exception as e:
            out.append({"error": str(e)})
    return out


def cached(challenge: bytes, slot: int = DEFAULT_SLOT) -> Optional[bytes]:
    """Odpowiedź z bieżącej sesji – zapamiętywana dopiero, gdy naprawdę otworzyła sejf (remember)."""
    with _cache_lock:
        return _cache.get((bytes(challenge), int(slot)))


def remember(challenge: bytes, slot: int, response: bytes) -> None:
    with _cache_lock:
        _cache[(bytes(challenge), int(slot))] = bytes(response)


def clear_cache() -> None:
    with _cache_lock:
        _cache.clear()


def respond(challenge: bytes, slot: int = DEFAULT_SLOT) -> bytes:
    """Odpowiedź HMAC-SHA1 (20 bajtów) podłączonego YubiKey. Czeka na dotknięcie, jeśli klucz tego wymaga."""
    from yubikit.core.otp import OtpConnection
    from yubikit.yubiotp import SLOT, YubiOtpSession
    devices = _devices()
    if not devices:
        raise YubiKeyError(_("Podłącz YubiKey – ten sejf wymaga go do otwarcia."))
    if len(devices) > 1:
        raise YubiKeyError(_("Podłączono kilka YubiKey – zostaw podłączony tylko ten, którym zabezpieczono sejf."))
    timeout = threading.Event()
    timer = threading.Timer(TIMEOUT_SECONDS, timeout.set)
    timer.daemon = True
    notified = {"done": False}

    def _keepalive(status: int):
        if status == STATUS_UPNEEDED and not notified["done"]:
            notified["done"] = True
            hook = on_touch_needed
            if hook:
                try:
                    hook()
                except Exception:
                    pass

    try:
        with devices[0].open_connection(OtpConnection) as conn:
            session = YubiOtpSession(conn)
            slot_enum = SLOT.ONE if slot == 1 else SLOT.TWO
            if not session.get_config_state().is_configured(slot_enum):
                raise YubiKeyError(_("Slot {slot} YubiKey nie jest skonfigurowany do trybu challenge-response. "
                                     "Ustaw go w YubiKey Manager (OTP → Long Touch → Challenge-response).", slot=slot))
            timer.start()
            response = session.calculate_hmac_sha1(slot_enum, challenge, event=timeout, on_keepalive=_keepalive)
    except YubiKeyError:
        raise
    except Exception as e:
        if timeout.is_set():
            raise YubiKeyError(_("Nie dotknięto YubiKey w ciągu {seconds} s.", seconds=TIMEOUT_SECONDS)) from e
        raise YubiKeyError(_("YubiKey nie odpowiedział: {error}", error=e)) from e
    finally:
        timer.cancel()
    if len(response) != 20:
        raise YubiKeyError(_("YubiKey zwrócił nieprawidłową odpowiedź."))
    return bytes(response)
