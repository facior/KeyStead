"""
Ochrona drobnych sekretów zapisywanych poza sejfem (np. token urządzenia do serwera synchronizacji).

Windows: DPAPI (CryptProtectData) – dane da się odszyfrować tylko na tym koncie Windows na tym komputerze.
macOS: pęk kluczy użytkownika (Keychain). Linux: magazyn haseł pulpitu (Secret Service – GNOME Keyring, KWallet).
W pliku zostaje wtedy tylko odnośnik „keyring:<nazwa>”.
Gdy systemowego magazynu nie ma (np. Linux bez pulpitu): zapis w pliku z prefiksem "plain:".
"""

import base64
import sys

from core.i18n import _

_DPAPI_PREFIX = "dpapi:"
_KEYRING_PREFIX = "keyring:"
_PLAIN_PREFIX = "plain:"
KEYRING_SERVICE = "KeyStead Manager"


def _dpapi(data: bytes, protect: bool) -> bytes:
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]

    buf = ctypes.create_string_buffer(data, len(data))
    blob_in = DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = DATA_BLOB()
    entropy_raw = b"KeyStead-device-token"
    ent_buf = ctypes.create_string_buffer(entropy_raw, len(entropy_raw))
    entropy = DATA_BLOB(len(entropy_raw), ctypes.cast(ent_buf, ctypes.POINTER(ctypes.c_char)))
    CRYPTPROTECT_UI_FORBIDDEN = 0x01

    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    if protect:
        ok = fn(ctypes.byref(blob_in), "KeyStead", ctypes.byref(entropy), None, None,
                CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(blob_out))
    else:
        ok = fn(ctypes.byref(blob_in), None, ctypes.byref(entropy), None, None,
                CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(blob_out))
    if not ok:
        raise OSError(ctypes.get_last_error(), _("DPAPI: operacja nie powiodła się"))
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)


def _keyring():
    """Systemowy magazyn haseł albo None (brak biblioteki lub działającego magazynu)."""
    try:
        import keyring
        from keyring.backends import fail
        backend = keyring.get_keyring()
        if isinstance(backend, fail.Keyring) or getattr(backend, "priority", 0) <= 0:
            return None
        return keyring
    except Exception:
        return None


def protect_secret(value: str, name: str = "device-token") -> str:
    if not value:
        return ""
    if sys.platform == "win32":
        return _DPAPI_PREFIX + base64.b64encode(_dpapi(value.encode("utf-8"), True)).decode("ascii")
    kr = _keyring()
    if kr is not None:
        try:
            kr.set_password(KEYRING_SERVICE, name, value)
            return _KEYRING_PREFIX + name
        except Exception:
            pass
    return _PLAIN_PREFIX + value


def unprotect_secret(stored: str) -> str:
    if not stored:
        return ""
    if stored.startswith(_DPAPI_PREFIX):
        return _dpapi(base64.b64decode(stored[len(_DPAPI_PREFIX):]), False).decode("utf-8")
    if stored.startswith(_KEYRING_PREFIX):
        kr = _keyring()
        value = None
        if kr is not None:
            try:
                value = kr.get_password(KEYRING_SERVICE, stored[len(_KEYRING_PREFIX):])
            except Exception:
                value = None
        if value is None:
            raise OSError(_("Brak sekretu w systemowym pęku kluczy"))
        return value
    if stored.startswith(_PLAIN_PREFIX):
        return stored[len(_PLAIN_PREFIX):]
    return stored


def forget_secret(stored: str) -> None:
    """Usuwa sekret z systemowego pęku kluczy (dla DPAPI i "plain:" nie ma czego usuwać)."""
    if stored and stored.startswith(_KEYRING_PREFIX):
        kr = _keyring()
        if kr is not None:
            try:
                kr.delete_password(KEYRING_SERVICE, stored[len(_KEYRING_PREFIX):])
            except Exception:
                pass
