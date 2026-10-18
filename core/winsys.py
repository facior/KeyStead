"""
Funkcje systemu Windows (ctypes): stan blokady sesji, globalne skróty klawiszowe, aktywne okno
i wpisywanie tekstu (Autotype). Na innych systemach funkcje są bezpiecznymi atrapami.
"""

import ctypes
import sys
import threading
import time
from ctypes import wintypes
from typing import Callable, Dict, Optional, Tuple

from core.i18n import _

IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    user32.OpenInputDesktop.restype = wintypes.HANDLE
    user32.OpenInputDesktop.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    user32.SwitchDesktop.argtypes = (wintypes.HANDLE,)
    user32.CloseDesktop.argtypes = (wintypes.HANDLE,)
    user32.GetForegroundWindow.restype = wintypes.HWND
    user32.GetWindowTextW.argtypes = (wintypes.HWND, wintypes.LPWSTR, ctypes.c_int)
    user32.GetWindowTextLengthW.argtypes = (wintypes.HWND,)
    user32.SetForegroundWindow.argtypes = (wintypes.HWND,)
    user32.IsWindow.argtypes = (wintypes.HWND,)
    user32.GetWindowThreadProcessId.argtypes = (wintypes.HWND, ctypes.POINTER(wintypes.DWORD))
    user32.RegisterHotKey.argtypes = (wintypes.HWND, ctypes.c_int, wintypes.UINT, wintypes.UINT)
    user32.UnregisterHotKey.argtypes = (wintypes.HWND, ctypes.c_int)
    user32.GetMessageW.argtypes = (ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT)
    user32.PostThreadMessageW.argtypes = (wintypes.DWORD, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)
    user32.GetAsyncKeyState.argtypes = (ctypes.c_int,)
    user32.GetAsyncKeyState.restype = ctypes.c_short
    user32.AttachThreadInput.argtypes = (wintypes.DWORD, wintypes.DWORD, wintypes.BOOL)
    user32.BringWindowToTop.argtypes = (wintypes.HWND,)
    user32.SetActiveWindow.argtypes = (wintypes.HWND,)
    user32.SetFocus.argtypes = (wintypes.HWND,)
    user32.FlashWindowEx.argtypes = (ctypes.c_void_p,)


# --------------------------------------------------------------------- blokada sesji (Win+L)
def is_session_locked() -> bool:
    """Czy pulpit jest zablokowany (Win+L, ekran logowania, wygaszacz z hasłem)."""
    if not IS_WINDOWS:
        return False
    desktop = user32.OpenInputDesktop(0, False, 0x0100)  # DESKTOP_SWITCHDESKTOP
    if not desktop:
        return True
    try:
        return not user32.SwitchDesktop(desktop)
    finally:
        user32.CloseDesktop(desktop)


# --------------------------------------------------------------------- aktywne okno
def foreground_window() -> Tuple[int, str]:
    """(uchwyt, tytuł) okna, w którym użytkownik pracuje."""
    if not IS_WINDOWS:
        return 0, ""
    hwnd = user32.GetForegroundWindow()
    if not hwnd:
        return 0, ""
    length = user32.GetWindowTextLengthW(hwnd)
    buf = ctypes.create_unicode_buffer(length + 1)
    user32.GetWindowTextW(hwnd, buf, length + 1)
    return int(hwnd), buf.value


def window_pid(hwnd: int) -> int:
    if not IS_WINDOWS or not hwnd:
        return 0
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return pid.value


def flash_window(hwnd: int, count: int = 5) -> None:
    """Miganie przycisku aplikacji na pasku zadań (zwraca uwagę, gdy okno jest w tle)."""
    if not IS_WINDOWS or not hwnd:
        return

    class FLASHWINFO(ctypes.Structure):
        _fields_ = (("cbSize", wintypes.UINT), ("hwnd", wintypes.HWND), ("dwFlags", wintypes.DWORD),
                    ("uCount", wintypes.UINT), ("dwTimeout", wintypes.DWORD))
    info = FLASHWINFO(ctypes.sizeof(FLASHWINFO), hwnd, 0x0003 | 0x000C, count, 0)  # FLASHW_ALL | FLASHW_TIMERNOFG
    user32.FlashWindowEx(ctypes.byref(info))


def force_foreground(hwnd: int) -> bool:
    """
    Wysunięcie własnego okna na pierwszy plan z fokusem klawiatury. Windows blokuje to programom w tle
    (foreground lock) – okienko po skrócie klawiszowym nie dostawałoby wpisywanego tekstu. Chwilowe połączenie
    kolejki wejścia z wątkiem aktywnego okna (AttachThreadInput) jest standardowym, dozwolonym obejściem.
    """
    if not IS_WINDOWS or not hwnd:
        return False
    fg = user32.GetForegroundWindow()
    if fg == hwnd:
        return True
    our_tid = kernel32.GetCurrentThreadId()
    fg_tid = user32.GetWindowThreadProcessId(fg, None) if fg else 0
    attached = bool(fg_tid and fg_tid != our_tid and user32.AttachThreadInput(our_tid, fg_tid, True))
    try:
        user32.BringWindowToTop(hwnd)
        user32.SetForegroundWindow(hwnd)
        user32.SetActiveWindow(hwnd)
        user32.SetFocus(hwnd)
    finally:
        if attached:
            user32.AttachThreadInput(our_tid, fg_tid, False)
    return user32.GetForegroundWindow() == hwnd


def activate_window(hwnd: int) -> bool:
    return bool(IS_WINDOWS and hwnd and user32.IsWindow(hwnd) and user32.SetForegroundWindow(hwnd))


# --------------------------------------------------------------------- globalne skróty klawiszowe
MOD_ALT, MOD_CONTROL, MOD_SHIFT, MOD_WIN, MOD_NOREPEAT = 0x1, 0x2, 0x4, 0x8, 0x4000
VK = {"SPACE": 0x20, "TAB": 0x09, "ENTER": 0x0D, "SHIFT": 0x10, "CONTROL": 0x11, "ALT": 0x12, "LWIN": 0x5B,
      "RWIN": 0x5C}
WM_HOTKEY, WM_QUIT = 0x0312, 0x0012


def parse_hotkey(text: str) -> Tuple[int, int]:
    """'Ctrl+Shift+Space' → (modyfikatory, kod klawisza)."""
    mods, key = 0, 0
    for part in [p.strip().upper() for p in text.split("+") if p.strip()]:
        if part in ("CTRL", "CONTROL"):
            mods |= MOD_CONTROL
        elif part == "SHIFT":
            mods |= MOD_SHIFT
        elif part == "ALT":
            mods |= MOD_ALT
        elif part == "WIN":
            mods |= MOD_WIN
        elif part in VK:
            key = VK[part]
        elif len(part) == 1 and part.isalnum():
            key = ord(part)
        elif part.startswith("F") and part[1:].isdigit() and 1 <= int(part[1:]) <= 24:
            key = 0x70 + int(part[1:]) - 1
        else:
            raise ValueError(_("Nieznany klawisz: {key}", key=part))
    if not key or not mods:
        raise ValueError(_("Skrót musi zawierać klawisz modyfikujący (Ctrl/Alt/Shift/Win) i zwykły klawisz."))
    return mods, key


class HotkeyManager:
    """
    Rejestruje globalne skróty (RegisterHotKey) we własnym wątku z pętlą komunikatów.
    Wywołania zwrotne trafiają do `dispatch` (np. kolejka odczytywana przez wątek interfejsu).
    """

    def __init__(self, dispatch: Callable[[str], None]):
        self.dispatch = dispatch
        self._thread: Optional[threading.Thread] = None
        self._thread_id = 0
        self._ready = threading.Event()
        self.registered: Dict[str, bool] = {}
        self._wanted: Dict[int, Tuple[str, int, int]] = {}

    def start(self, hotkeys: Dict[str, str]) -> Dict[str, bool]:
        """hotkeys: nazwa → 'Ctrl+Shift+Space'. Zwraca, które udało się zarejestrować (inne mogą być zajęte)."""
        if not IS_WINDOWS:
            return {}
        self.stop()
        self._wanted = {}
        for i, (name, text) in enumerate(hotkeys.items(), start=1):
            try:
                mods, key = parse_hotkey(text)
            except ValueError:
                self.registered[name] = False
                continue
            self._wanted[i] = (name, mods, key)
        self._ready.clear()
        self._thread = threading.Thread(target=self._loop, name="keystead-hotkeys", daemon=True)
        self._thread.start()
        self._ready.wait(3)
        return dict(self.registered)

    def _loop(self) -> None:
        self._thread_id = kernel32.GetCurrentThreadId()
        for hid, (name, mods, key) in self._wanted.items():
            self.registered[name] = bool(user32.RegisterHotKey(None, hid, mods | MOD_NOREPEAT, key))
        self._ready.set()
        msg = wintypes.MSG()
        try:
            while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
                if msg.message == WM_HOTKEY and msg.wParam in self._wanted:
                    try:
                        self.dispatch(self._wanted[msg.wParam][0])
                    except Exception:
                        pass
        finally:
            for hid in self._wanted:
                user32.UnregisterHotKey(None, hid)

    def stop(self) -> None:
        if self._thread and self._thread.is_alive() and self._thread_id:
            user32.PostThreadMessageW(self._thread_id, WM_QUIT, 0, 0)
            self._thread.join(2)
        self._thread = None
        self.registered = {}


# --------------------------------------------------------------------- wpisywanie tekstu (Autotype)
if IS_WINDOWS:
    ULONG_PTR = ctypes.c_size_t

    class KEYBDINPUT(ctypes.Structure):
        _fields_ = (("wVk", wintypes.WORD), ("wScan", wintypes.WORD), ("dwFlags", wintypes.DWORD),
                    ("time", wintypes.DWORD), ("dwExtraInfo", ULONG_PTR))

    class MOUSEINPUT(ctypes.Structure):
        _fields_ = (("dx", wintypes.LONG), ("dy", wintypes.LONG), ("mouseData", wintypes.DWORD),
                    ("dwFlags", wintypes.DWORD), ("time", wintypes.DWORD), ("dwExtraInfo", ULONG_PTR))

    class _INPUTUNION(ctypes.Union):
        _fields_ = (("ki", KEYBDINPUT), ("mi", MOUSEINPUT))

    class INPUT(ctypes.Structure):
        _fields_ = (("type", wintypes.DWORD), ("u", _INPUTUNION))

    user32.SendInput.argtypes = (wintypes.UINT, ctypes.POINTER(INPUT), ctypes.c_int)

KEYEVENTF_KEYUP, KEYEVENTF_UNICODE = 0x0002, 0x0004


def _send(inputs) -> None:
    arr = (INPUT * len(inputs))(*inputs)
    user32.SendInput(len(inputs), arr, ctypes.sizeof(INPUT))


def _key(vk: int, up: bool = False) -> "INPUT":
    return INPUT(type=1, u=_INPUTUNION(ki=KEYBDINPUT(wVk=vk, wScan=0, dwFlags=KEYEVENTF_KEYUP if up else 0,
                                                    time=0, dwExtraInfo=0)))


def _unicode(ch_code: int, up: bool = False) -> "INPUT":
    flags = KEYEVENTF_UNICODE | (KEYEVENTF_KEYUP if up else 0)
    return INPUT(type=1, u=_INPUTUNION(ki=KEYBDINPUT(wVk=0, wScan=ch_code, dwFlags=flags, time=0, dwExtraInfo=0)))


def wait_modifiers_released(timeout: float = 3.0) -> None:
    """Czeka, aż użytkownik puści Ctrl/Shift/Alt/Win ze skrótu (inaczej wpisywane znaki byłyby skrótami)."""
    if not IS_WINDOWS:
        return
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not any(user32.GetAsyncKeyState(VK[k]) & 0x8000 for k in ("SHIFT", "CONTROL", "ALT", "LWIN", "RWIN")):
            return
        time.sleep(0.03)


def type_text(text: str, delay: float = 0.004) -> None:
    """Wpisuje tekst jako znaki Unicode (niezależnie od układu klawiatury, także polskie znaki)."""
    data = text.encode("utf-16-le")
    for i in range(0, len(data), 2):
        code = int.from_bytes(data[i:i + 2], "little")
        _send([_unicode(code), _unicode(code, up=True)])
        if delay:
            time.sleep(delay)


def press_key(name: str) -> None:
    vk = VK[name]
    _send([_key(vk), _key(vk, up=True)])
