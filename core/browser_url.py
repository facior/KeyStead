"""
Adres strony otwartej w przeglądarce – dla bezpiecznego Autotype.

Tytuł okna może ustawić dowolna strona (fałszywa strona banku może mieć tytuł „mBank”), dlatego przed wpisaniem
hasła w przeglądarce sprawdzamy prawdziwy adres z paska adresu. Odczyt przez UI Automation (to samo, czego używają
czytniki ekranu) – bez wtyczek w przeglądarce. Wyłącznie ctypes, bez dodatkowych bibliotek.

Ochrona przed podszyciem: strona może nadać polu formularza klasę/identyfikator paska adresu, dlatego pola leżące
w treści strony (wewnątrz elementu „Dokument”) są pomijane, a wynik jest przyjmowany tylko wtedy, gdy zostaje
dokładnie jedno pasujące pole – w przeciwnym razie adres jest „nieznany”.
"""

import ctypes
import ipaddress
import os
import sys
from ctypes import wintypes
from typing import Iterable, List, Optional, Tuple
from urllib.parse import urlparse

from core.i18n import _

IS_WINDOWS = sys.platform == "win32"

# proces → sposób odszukania paska adresu (właściwość UI Automation, wartość)
UIA_CLASS_NAME, UIA_AUTOMATION_ID = 30012, 30011
_CHROMIUM = (UIA_CLASS_NAME, "OmniboxViewViews")
_FIREFOX = (UIA_AUTOMATION_ID, "urlbar-input")
BROWSERS = {
    "chrome.exe": _CHROMIUM, "msedge.exe": _CHROMIUM, "brave.exe": _CHROMIUM, "opera.exe": _CHROMIUM,
    "vivaldi.exe": _CHROMIUM, "chromium.exe": _CHROMIUM, "yandex.exe": _CHROMIUM, "arc.exe": _CHROMIUM,
    "firefox.exe": _FIREFOX, "librewolf.exe": _FIREFOX, "waterfox.exe": _FIREFOX, "floorp.exe": _FIREFOX,
    "zen.exe": _FIREFOX, "tor.exe": _FIREFOX,
}


# --------------------------------------------------------------------- porównywanie adresów
def page_host(url: str) -> Optional[str]:
    """Nazwa hosta z adresu (także bez „https://”, jak pokazują go przeglądarki): www.mbank.pl/x → mbank.pl."""
    text = (url or "").strip()
    if not text or any(c.isspace() for c in text):
        return None  # pasek adresu z wpisywaną frazą wyszukiwania, nie adres
    try:
        parsed = urlparse(text if "://" in text else f"https://{text}")
        host = (parsed.hostname or "").lower().strip(".")
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https") or not host:
        return None
    if host.startswith("www."):
        host = host[4:]
    return host


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def host_matches(page: str, allowed: str) -> bool:
    """Ta sama domena albo jej poddomena (online.mbank.pl pasuje do mbank.pl; mbank.pl.evil.com – nie)."""
    if not page or not allowed:
        return False
    if page == allowed:
        return True
    if _is_ip(page) or _is_ip(allowed) or "." not in allowed:
        return False
    return page.endswith("." + allowed)


def allowed_hosts(urls: Iterable[str]) -> List[str]:
    out = []
    for u in urls:
        h = page_host(u)
        if h and h not in out:
            out.append(h)
    return out


# --------------------------------------------------------------------- proces okna
def process_name(pid: int) -> str:
    if not IS_WINDOWS or not pid:
        return ""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.QueryFullProcessImageNameW.argtypes = (wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                                    ctypes.POINTER(wintypes.DWORD))
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return ""
    try:
        size = wintypes.DWORD(1024)
        buf = ctypes.create_unicode_buffer(size.value)
        if not kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            return ""
        return os.path.basename(buf.value).lower()
    finally:
        kernel32.CloseHandle(handle)


def is_browser(pid: int) -> bool:
    return process_name(pid) in BROWSERS


# --------------------------------------------------------------------- UI Automation (COM przez ctypes)
class _VARIANT(ctypes.Structure):
    _fields_ = (("vt", ctypes.c_ushort), ("r1", ctypes.c_ushort), ("r2", ctypes.c_ushort), ("r3", ctypes.c_ushort),
                ("val", ctypes.c_void_p), ("val2", ctypes.c_void_p))


class _GUID(ctypes.Structure):
    _fields_ = (("d1", ctypes.c_ulong), ("d2", ctypes.c_ushort), ("d3", ctypes.c_ushort), ("d4", ctypes.c_ubyte * 8))

    def __init__(self, text: str):
        super().__init__()
        ctypes.oledll.ole32.CLSIDFromString(ctypes.c_wchar_p(text), ctypes.byref(self))


_CLSID_CUIAutomation = "{ff48dba4-60ef-4201-aa87-54103eef594e}"
_IID_IUIAutomation = "{30cbe57d-d9d0-452a-ab13-7ac5ac4825ee}"
VT_I4, VT_BSTR = 3, 8
UIA_CONTROL_TYPE, UIA_VALUE_VALUE = 30003, 30045
UIA_EDIT_CONTROL, UIA_COMBOBOX_CONTROL, UIA_DOCUMENT_CONTROL = 50004, 50003, 50030
ADDRESS_BAR_TYPES = (UIA_EDIT_CONTROL, UIA_COMBOBOX_CONTROL)  # Firefox: pole z podpowiedziami (ComboBox)
TREE_SCOPE_DESCENDANTS = 4


def _call(obj, index: int, *args, types=()):
    """Wywołanie metody interfejsu COM po numerze w tablicy metod (HRESULT ≠ 0 → OSError)."""
    vtbl = ctypes.cast(obj, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)))[0]
    fn = ctypes.WINFUNCTYPE(ctypes.HRESULT, ctypes.c_void_p, *types)(vtbl[index])
    return fn(obj, *args)


def _release(obj) -> None:
    if obj:
        _call(obj, 2)


class _UIA:
    """Minimalny klient UI Automation: znajdź pole w oknie i odczytaj jego wartość."""

    def __init__(self):
        self.ole32, self.oleaut32 = ctypes.oledll.ole32, ctypes.WinDLL("oleaut32")
        self.oleaut32.SysAllocString.restype = ctypes.c_void_p
        self.oleaut32.SysAllocString.argtypes = (ctypes.c_wchar_p,)
        self.oleaut32.VariantClear.argtypes = (ctypes.POINTER(_VARIANT),)
        self.uia = ctypes.c_void_p()
        self.ole32.CoCreateInstance(ctypes.byref(_GUID(_CLSID_CUIAutomation)), None, 1,
                                    ctypes.byref(_GUID(_IID_IUIAutomation)), ctypes.byref(self.uia))

    def close(self):
        _release(self.uia)

    def _condition(self, prop: int, value) -> ctypes.c_void_p:
        var = _VARIANT()
        if isinstance(value, str):
            var.vt, var.val = VT_BSTR, self.oleaut32.SysAllocString(value)
        else:
            var.vt, var.val = VT_I4, value
        cond = ctypes.c_void_p()
        try:
            # IUIAutomation::CreatePropertyCondition
            _call(self.uia, 23, prop, var, ctypes.byref(cond), types=(ctypes.c_int, _VARIANT, ctypes.c_void_p))
        finally:
            self.oleaut32.VariantClear(ctypes.byref(var))
        return cond

    def string_property(self, element, prop: int) -> Optional[str]:
        var = _VARIANT()
        # IUIAutomationElement::GetCurrentPropertyValue
        _call(element, 10, prop, ctypes.byref(var), types=(ctypes.c_int, ctypes.POINTER(_VARIANT)))
        try:
            return ctypes.wstring_at(var.val) if var.vt == VT_BSTR and var.val else None
        finally:
            self.oleaut32.VariantClear(ctypes.byref(var))

    def int_property(self, element, prop: int) -> Optional[int]:
        var = _VARIANT()
        _call(element, 10, prop, ctypes.byref(var), types=(ctypes.c_int, ctypes.POINTER(_VARIANT)))
        try:
            return ctypes.c_int32(var.val or 0).value if var.vt == VT_I4 else None
        finally:
            self.oleaut32.VariantClear(ctypes.byref(var))

    def _inside_page(self, walker, element) -> bool:
        """Czy element leży w treści strony (ma przodka typu Dokument) – takie pole może podrobić każda strona."""
        current, owned = element, []
        try:
            for __ in range(60):
                parent = ctypes.c_void_p()
                _call(walker, 3, current, ctypes.byref(parent), types=(ctypes.c_void_p, ctypes.c_void_p))  # GetParent
                if not parent:
                    return False
                owned.append(parent)
                if self.int_property(parent, UIA_CONTROL_TYPE) == UIA_DOCUMENT_CONTROL:
                    return True
                current = parent
            return True  # nienaturalnie głęboko – nie ufamy
        finally:
            for obj in owned:
                _release(obj)

    def address_bar_value(self, hwnd: int, prop: int, value: str) -> Optional[str]:
        root, ident, found, walker = (ctypes.c_void_p() for __ in range(4))
        try:
            _call(self.uia, 6, hwnd, ctypes.byref(root), types=(wintypes.HWND, ctypes.c_void_p))  # ElementFromHandle
            ident = self._condition(prop, value)
            _call(root, 6, TREE_SCOPE_DESCENDANTS, ident, ctypes.byref(found),
                  types=(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p))  # FindAll
            if not found:
                return None
            length = ctypes.c_int()
            _call(found, 3, ctypes.byref(length), types=(ctypes.c_void_p,))  # IUIAutomationElementArray::get_Length
            if not 0 < length.value <= 20:
                return None
            _call(self.uia, 16, ctypes.byref(walker), types=(ctypes.c_void_p,))  # RawViewWalker
            values = []
            for i in range(length.value):
                element = ctypes.c_void_p()
                _call(found, 4, i, ctypes.byref(element), types=(ctypes.c_int, ctypes.c_void_p))  # GetElement
                try:
                    if self.int_property(element, UIA_CONTROL_TYPE) not in ADDRESS_BAR_TYPES:
                        continue
                    if self._inside_page(walker, element):
                        continue  # pole na stronie udające pasek adresu
                    values.append(self.string_property(element, UIA_VALUE_VALUE))
                finally:
                    _release(element)
            return values[0] if len(values) == 1 else None  # niejednoznacznie → adres nieznany
        finally:
            for obj in (walker, found, ident, root):
                _release(obj)


# --------------------------------------------------------------------- MSAA (zapas, np. Opera GX)
_IID_IAccessible = "{618736e0-3c3d-11cf-810c-00aa00389b71}"
ROLE_DOCUMENT, ROLE_TOOLBAR, ROLE_TEXT, ROLE_COMBOBOX = 15, 22, 42, 46
# gałęzie, w których paska adresu na pewno nie ma (przyciski, grafiki, karty, treść strony) – szybsze szukanie
_MSAA_LEAF_ROLES = {ROLE_DOCUMENT, 12, 30, 37, 40, 41, 43, 57, 60}
_MSAA_MAX_NODES, _MSAA_MAX_SECONDS = 4000, 4.0
_msaa_paths = {}  # proces → droga (numery dzieci) do paska adresu, z ostatniego udanego odczytu


class _MSAA:
    """
    Odczyt paska adresu przez starszy interfejs dostępności (IAccessible). Używany, gdy UI Automation zawodzi –
    Opera GX zwraca błąd dla części drzewa okna. Pole jest przyjmowane tylko poza treścią strony (bez przodka
    „dokument”) i wewnątrz paska narzędzi; droga do niego jest zapamiętywana, bo pełne szukanie trwa ~1 s.
    """

    def __init__(self):
        self.oleacc, self.oleaut32 = ctypes.WinDLL("oleacc"), ctypes.WinDLL("oleaut32")
        self.oleaut32.VariantClear.argtypes = (ctypes.POINTER(_VARIANT),)
        self.oleaut32.SysFreeString.argtypes = (ctypes.c_void_p,)
        self.iid = _GUID(_IID_IAccessible)
        self.me = _VARIANT()
        self.me.vt = VT_I4  # CHILDID_SELF
        self.started, self.visited = 0.0, 0

    def root(self, hwnd: int) -> ctypes.c_void_p:
        acc = ctypes.c_void_p()
        hr = self.oleacc.AccessibleObjectFromWindow(wintypes.HWND(hwnd), ctypes.c_long(-4),  # OBJID_CLIENT
                                                    ctypes.byref(self.iid), ctypes.byref(acc))
        if hr != 0 or not acc:
            raise OSError("AccessibleObjectFromWindow")
        return acc

    def role(self, acc) -> Optional[int]:
        var = _VARIANT()
        try:
            _call(acc, 13, self.me, ctypes.byref(var), types=(_VARIANT, ctypes.POINTER(_VARIANT)))  # get_accRole
        except OSError:
            return None
        role = var.val if var.vt == VT_I4 else None
        self.oleaut32.VariantClear(ctypes.byref(var))
        return role

    def value(self, acc) -> Optional[str]:
        text = ctypes.c_void_p()
        try:
            _call(acc, 11, self.me, ctypes.byref(text), types=(_VARIANT, ctypes.c_void_p))  # get_accValue
        except OSError:
            return None
        if not text.value:
            return None
        try:
            return ctypes.wstring_at(text.value)
        finally:
            self.oleaut32.SysFreeString(text)

    def children(self, acc) -> List[Optional[ctypes.c_void_p]]:
        """Dzieci jako IAccessible (None dla prostych elementów bez własnego obiektu). Wywołujący zwalnia."""
        count = ctypes.c_long()
        try:
            _call(acc, 8, ctypes.byref(count), types=(ctypes.c_void_p,))  # get_accChildCount
        except OSError:
            return []
        if not 0 < count.value <= 2000:
            return []
        arr, got = (_VARIANT * count.value)(), ctypes.c_long()
        if self.oleacc.AccessibleChildren(acc, 0, count.value, arr, ctypes.byref(got)) != 0:
            return []
        out = []
        for i in range(got.value):
            child = None
            if arr[i].vt == 9 and arr[i].val:  # VT_DISPATCH
                q = ctypes.c_void_p()
                try:
                    _call(ctypes.c_void_p(arr[i].val), 0, ctypes.byref(self.iid), ctypes.byref(q),
                          types=(ctypes.c_void_p, ctypes.c_void_p))  # QueryInterface
                    child = q
                except OSError:
                    pass
            self.oleaut32.VariantClear(ctypes.byref(arr[i]))
            out.append(child)
        return out

    def _accept(self, acc, role, under_toolbar: bool) -> Optional[str]:
        if role not in (ROLE_TEXT, ROLE_COMBOBOX) or not under_toolbar:
            return None
        value = self.value(acc)
        return value if value and page_host(value) else None

    def follow(self, hwnd: int, path: List[int]) -> Optional[str]:
        """Szybki odczyt zapamiętaną drogą (sprawdza po drodze, że nie wchodzi w treść strony)."""
        acc, under_toolbar = self.root(hwnd), False
        try:
            for index in path:
                if self.role(acc) == ROLE_DOCUMENT:
                    return None
                under_toolbar = under_toolbar or self.role(acc) == ROLE_TOOLBAR
                kids = self.children(acc)
                nxt = kids[index] if index < len(kids) else None
                for k in kids:
                    if k is not None and k is not nxt:
                        _release(k)
                if nxt is None:
                    return None
                _release(acc)
                acc = nxt
            return self._accept(acc, self.role(acc), under_toolbar)
        finally:
            _release(acc)

    def search(self, hwnd: int) -> Tuple[Optional[str], List[int]]:
        """Pełne przeszukanie okna: dokładnie jedno pole z adresem w pasku narzędzi, poza treścią strony."""
        import time
        self.started, self.visited = time.monotonic(), 0
        found: List[Tuple[str, List[int]]] = []
        root = self.root(hwnd)
        try:
            self._walk(root, [], False, found, time)
        finally:
            _release(root)
        if len(found) == 1:
            return found[0]
        return None, []

    def _walk(self, acc, path, under_toolbar, found, time) -> None:
        self.visited += 1
        if self.visited > _MSAA_MAX_NODES or time.monotonic() - self.started > _MSAA_MAX_SECONDS or len(path) > 40:
            raise OSError(_("MSAA: za duże drzewo okna"))
        role = self.role(acc)
        value = self._accept(acc, role, under_toolbar)
        if value is not None:
            found.append((value, list(path)))
            if len(found) > 1:
                return
        if role in _MSAA_LEAF_ROLES:
            return
        under_toolbar = under_toolbar or role == ROLE_TOOLBAR
        kids = self.children(acc)
        try:
            for i, kid in enumerate(kids):
                if kid is not None and len(found) <= 1:
                    self._walk(kid, path + [i], under_toolbar, found, time)
        finally:
            for kid in kids:
                _release(kid)

    def address_bar_value(self, hwnd: int, key: str) -> Optional[str]:
        path = _msaa_paths.get(key)
        if path:
            value = self.follow(hwnd, path)
            if value is not None:
                return value
        value, path = self.search(hwnd)
        if value is not None:
            _msaa_paths[key] = path
        return value


def read_browser_url(hwnd: int, pid: Optional[int] = None) -> Optional[str]:
    """
    Adres z paska adresu przeglądarki w oknie `hwnd` albo None (to nie przeglądarka / nie udało się odczytać).
    Wywoływać w wątku roboczym – odczyt z innego procesu trwa od kilku do kilkuset milisekund.
    """
    if not IS_WINDOWS or not hwnd:
        return None
    if pid is None:
        pid = ctypes.c_ulong()
        ctypes.windll.user32.GetWindowThreadProcessId(wintypes.HWND(hwnd), ctypes.byref(pid))
        pid = pid.value
    name = process_name(pid)
    how = BROWSERS.get(name)
    if how is None:
        return None
    ole32 = ctypes.windll.ole32
    initialized = ole32.CoInitializeEx(None, 0) in (0, 1)  # COINIT_MULTITHREADED; S_FALSE = już zainicjowane
    try:
        try:
            uia = _UIA()
            try:
                url = uia.address_bar_value(hwnd, *how)
            finally:
                uia.close()
        except OSError:
            url = None
        if url is None:
            try:
                url = _MSAA().address_bar_value(hwnd, name)
            except OSError:
                url = None
        return url
    finally:
        if initialized:
            ole32.CoUninitialize()
