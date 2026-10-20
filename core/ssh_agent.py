"""
Agent SSH (wtyczka „Klucze SSH w sejfie”, odpowiednik KeeAgent): programy biorą klucze z otwartego sejfu.

Dwa kanały, jak w KeeAgent:
    \\\\.\\pipe\\openssh-ssh-agent    Windows OpenSSH (ssh, ssh-add, scp, git z core.sshCommand=…/OpenSSH/ssh.exe)
    okno „Pageant” (WM_COPYDATA)        PuTTY, plink, WinSCP, TortoiseGit, FileZilla
Kanał jest pomijany, gdy zajmuje go już ktoś inny (usługa „OpenSSH Authentication Agent” albo prawdziwy Pageant).

Bezpieczeństwo:
- potok przyjmuje tylko bieżące konto Windows (i SYSTEM) i odrzuca połączenia z sieci, a pamięć współdzielona
  Pageanta musi należeć do bieżącego konta (tak sprawdza to sam Pageant);
- agent tylko podaje listę kluczy publicznych i podpisuje – nie da się przez niego dodać, usunąć ani odczytać klucza;
- każde użycie klucza przechodzi przez `on_use` (powiadomienie albo pytanie o zgodę), a po zablokowaniu sejfu
  agent odmawia wszystkiego.
"""

import ctypes
import os
import struct
import threading
from ctypes import wintypes
from typing import Callable, Dict, List, Optional

from core.ssh_keys import AgentKey, Reader, ssh_string

SSH_AGENT_FAILURE = 5
SSH_AGENTC_REQUEST_IDENTITIES = 11
SSH_AGENT_IDENTITIES_ANSWER = 12
SSH_AGENTC_SIGN_REQUEST = 13
SSH_AGENT_SIGN_RESPONSE = 14
MAX_MESSAGE = 256 * 1024
PAGEANT_MAX_MESSAGE = 8192
PAGEANT_COPYDATA_ID = 0x804E50BA
OPENSSH_PIPE = r"\\.\pipe\openssh-ssh-agent"

FAILURE = bytes([SSH_AGENT_FAILURE])


class SshAgent:
    """Protokół agenta (OpenSSH PROTOCOL.agent) – niezależny od kanału."""

    def __init__(self, keys: Callable[[], List[AgentKey]], on_use: Callable[[AgentKey, str], bool]):
        self.keys = keys        # aktualne klucze (pusta lista = sejf zablokowany)
        self.on_use = on_use    # zgoda na podpis: (klucz, program) -> bool; może czekać na odpowiedź użytkownika
        self.enabled = True

    def handle(self, message: bytes, client: str = "") -> bytes:
        if not self.enabled or not message:
            return FAILURE
        try:
            kind, r = message[0], Reader(message[1:])
            if kind == SSH_AGENTC_REQUEST_IDENTITIES:
                keys = self.keys()
                body = struct.pack(">I", len(keys))
                for key in keys:
                    body += ssh_string(key.public_blob) + ssh_string(key.comment.encode("utf-8", "replace"))
                return bytes([SSH_AGENT_IDENTITIES_ANSWER]) + body
            if kind == SSH_AGENTC_SIGN_REQUEST:
                blob, data, flags = r.string(), r.string(), r.uint32()
                key = next((k for k in self.keys() if k.public_blob == blob), None)
                if key is None or not self.on_use(key, client):
                    return FAILURE
                return bytes([SSH_AGENT_SIGN_RESPONSE]) + ssh_string(key.sign(data, flags))
        except Exception:
            return FAILURE
        return FAILURE  # dodawanie/usuwanie kluczy, blokada agenta, rozszerzenia – nieobsługiwane celowo


# --------------------------------------------------------------------- Windows: wspólne
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True) if os.name == "nt" else None
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True) if os.name == "nt" else None
user32 = ctypes.WinDLL("user32", use_last_error=True) if os.name == "nt" else None

INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value


def _setup_prototypes():
    k = kernel32
    k.CreateNamedPipeW.restype = wintypes.HANDLE
    k.CreateNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
                                   wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    k.ConnectNamedPipe.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    k.DisconnectNamedPipe.argtypes = [wintypes.HANDLE]
    k.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                           ctypes.c_void_p]
    k.WriteFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                            ctypes.c_void_p]
    k.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    k.CreateFileW.restype = wintypes.HANDLE
    k.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                              wintypes.DWORD, wintypes.HANDLE]
    k.GetNamedPipeClientProcessId.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
    k.OpenProcess.restype = wintypes.HANDLE
    k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                             ctypes.POINTER(wintypes.DWORD)]
    k.GetCurrentProcess.restype = wintypes.HANDLE
    k.OpenFileMappingA.restype = wintypes.HANDLE
    k.OpenFileMappingA.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCSTR]
    k.MapViewOfFile.restype = ctypes.c_void_p
    k.MapViewOfFile.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_size_t]
    k.UnmapViewOfFile.argtypes = [ctypes.c_void_p]
    k.VirtualQuery.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    k.LocalFree.argtypes = [ctypes.c_void_p]
    a = advapi32
    a.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    a.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                      ctypes.POINTER(wintypes.DWORD)]
    a.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    a.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.ULONG)]
    a.GetSecurityInfo.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
                                  ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    a.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    u = user32
    u.FindWindowW.restype = wintypes.HWND
    u.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
    u.CreateWindowExW.restype = wintypes.HWND
    u.CreateWindowExW.argtypes = [wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_int,
                                  ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.HWND, wintypes.HMENU,
                                  wintypes.HINSTANCE, ctypes.c_void_p]
    u.DefWindowProcW.restype = ctypes.c_ssize_t
    u.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    u.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
    u.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
    u.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
    u.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    u.DestroyWindow.argtypes = [wintypes.HWND]
    u.UnregisterClassW.argtypes = [wintypes.LPCWSTR, wintypes.HINSTANCE]
    k.GetModuleHandleW.restype = wintypes.HMODULE
    k.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]


if os.name == "nt":
    _setup_prototypes()


class _TokenUser(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


class _CurrentUser:
    """SID bieżącego konta (bufor trzymany przez cały czas działania programu)."""
    _buffer = None
    _owner_buffer = None
    _sid_string = ""

    @staticmethod
    def _token_info(info_class: int):
        token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):  # TOKEN_QUERY
            raise OSError(ctypes.get_last_error(), "OpenProcessToken")
        try:
            size = wintypes.DWORD()
            advapi32.GetTokenInformation(token, info_class, None, 0, ctypes.byref(size))
            buf = ctypes.create_string_buffer(size.value)
            if not advapi32.GetTokenInformation(token, info_class, buf, size, ctypes.byref(size)):
                raise OSError(ctypes.get_last_error(), "GetTokenInformation")
        finally:
            kernel32.CloseHandle(token)
        return buf

    @classmethod
    def sid(cls):
        if cls._buffer is None:
            cls._buffer = cls._token_info(1)  # TokenUser
        return ctypes.cast(cls._buffer, ctypes.POINTER(_TokenUser)).contents.Sid

    @classmethod
    def default_owner_sid(cls):
        """Domyślny właściciel nowych obiektów – w procesie z uprawnieniami administratora to grupa Administratorzy."""
        if cls._owner_buffer is None:
            cls._owner_buffer = cls._token_info(4)  # TokenOwner
        return ctypes.cast(cls._owner_buffer, ctypes.POINTER(ctypes.c_void_p)).contents

    @classmethod
    def sid_string(cls) -> str:
        if not cls._sid_string:
            text = wintypes.LPWSTR()
            if not advapi32.ConvertSidToStringSidW(cls.sid(), ctypes.byref(text)):
                raise OSError(ctypes.get_last_error(), "ConvertSidToStringSid")
            cls._sid_string = text.value
            kernel32.LocalFree(text)
        return cls._sid_string


def _process_name(pid: int) -> str:
    handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return ""
    try:
        buf = ctypes.create_unicode_buffer(1024)
        size = wintypes.DWORD(len(buf))
        if kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            return os.path.basename(buf.value)
        return ""
    finally:
        kernel32.CloseHandle(handle)


# --------------------------------------------------------------------- kanał Windows OpenSSH (nazwany potok)
PIPE_ACCESS_DUPLEX = 0x3
FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
PIPE_REJECT_REMOTE_CLIENTS = 0x8
ERROR_PIPE_CONNECTED = 535


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p), ("bInheritHandle", wintypes.BOOL)]


class OpenSshPipeServer:
    def __init__(self, agent: SshAgent, name: str = OPENSSH_PIPE):
        self.agent, self.name = agent, name
        self.status = "stopped"   # running | busy | error | stopped
        self.error = ""
        self._stop = threading.Event()
        self._sa = None
        self._sd = None
        self._thread: Optional[threading.Thread] = None

    def _security(self):
        if self._sa is None:
            sddl = f"D:P(A;;GA;;;{_CurrentUser.sid_string()})(A;;GA;;;SY)"  # tylko to konto i SYSTEM
            sd = ctypes.c_void_p()
            if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(sd), None):
                raise OSError(ctypes.get_last_error(), "ConvertStringSecurityDescriptor")
            self._sd = sd
            self._sa = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), sd, False)
        return ctypes.byref(self._sa)

    def _create(self, first: bool):
        mode = PIPE_ACCESS_DUPLEX | (FILE_FLAG_FIRST_PIPE_INSTANCE if first else 0)
        return kernel32.CreateNamedPipeW(self.name, mode, PIPE_REJECT_REMOTE_CLIENTS, 255, 65536, 65536, 0,
                                         self._security())

    def start(self) -> str:
        try:
            handle = self._create(first=True)
        except OSError as e:
            self.status, self.error = "error", str(e)
            return self.status
        if handle == INVALID_HANDLE_VALUE or not handle:
            err = ctypes.get_last_error()
            # 5 / 231: potok już istnieje – usługa „OpenSSH Authentication Agent” lub inny agent
            self.status = "busy" if err in (5, 231) else "error"
            self.error = f"WinError {err}"
            return self.status
        self._stop.clear()
        self._thread = threading.Thread(target=self._serve, args=(handle,), daemon=True, name="ssh-agent-pipe")
        self._thread.start()
        self.status = "running"
        return self.status

    def _serve(self, handle):
        while not self._stop.is_set():
            ok = kernel32.ConnectNamedPipe(handle, None)
            if not ok and ctypes.get_last_error() != ERROR_PIPE_CONNECTED:
                kernel32.CloseHandle(handle)
                handle = self._create(first=False)
                if handle == INVALID_HANDLE_VALUE:
                    break
                continue
            if self._stop.is_set():
                kernel32.DisconnectNamedPipe(handle)
                kernel32.CloseHandle(handle)
                break
            threading.Thread(target=self._client, args=(handle,), daemon=True, name="ssh-agent-client").start()
            handle = self._create(first=False)
            if handle == INVALID_HANDLE_VALUE:
                break
        self.status = "stopped"

    def _read(self, handle, n: int) -> Optional[bytes]:
        out = b""
        while len(out) < n:
            buf = ctypes.create_string_buffer(min(n - len(out), 65536))
            got = wintypes.DWORD()
            if not kernel32.ReadFile(handle, buf, len(buf), ctypes.byref(got), None) or not got.value:
                return None
            out += buf.raw[:got.value]
        return out

    def _client(self, handle):
        try:
            pid = wintypes.ULONG()
            client = _process_name(pid.value) if kernel32.GetNamedPipeClientProcessId(handle, ctypes.byref(pid)) else ""
            while not self._stop.is_set():
                head = self._read(handle, 4)
                if head is None:
                    break
                length = struct.unpack(">I", head)[0]
                if length == 0 or length > MAX_MESSAGE:
                    break
                body = self._read(handle, length)
                if body is None:
                    break
                reply = self.agent.handle(body, client)
                data = struct.pack(">I", len(reply)) + reply
                written = wintypes.DWORD()
                if not kernel32.WriteFile(handle, data, len(data), ctypes.byref(written), None):
                    break
        finally:
            kernel32.FlushFileBuffers(handle)
            kernel32.DisconnectNamedPipe(handle)
            kernel32.CloseHandle(handle)

    def stop(self):
        if self.status != "running":
            return
        self._stop.set()
        # Obudzenie wątku czekającego na połączenie (ConnectNamedPipe blokuje)
        h = kernel32.CreateFileW(self.name, 0xC0000000, 0, None, 3, 0, None)  # GENERIC_READ|WRITE, OPEN_EXISTING
        if h and h != INVALID_HANDLE_VALUE:
            kernel32.CloseHandle(h)
        if self._thread is not None:
            self._thread.join(timeout=2)
        self.status = "stopped"


# --------------------------------------------------------------------- kanał Pageant (okno + WM_COPYDATA)
WM_COPYDATA = 0x004A
WM_CLOSE = 0x0010
WM_DESTROY = 0x0002
FILE_MAP_WRITE = 0x0002
READ_CONTROL = 0x00020000
SE_KERNEL_OBJECT = 6
OWNER_SECURITY_INFORMATION = 1

_FUNCTYPE = ctypes.WINFUNCTYPE if os.name == "nt" else ctypes.CFUNCTYPE  # poza Windows tylko, by moduł się wczytał
WNDPROC = _FUNCTYPE(ctypes.c_ssize_t, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)


class _CopyData(ctypes.Structure):
    _fields_ = [("dwData", ctypes.c_size_t), ("cbData", wintypes.DWORD), ("lpData", ctypes.c_void_p)]


class _WndClass(ctypes.Structure):
    _fields_ = [("style", wintypes.UINT), ("lpfnWndProc", WNDPROC), ("cbClsExtra", ctypes.c_int),
                ("cbWndExtra", ctypes.c_int), ("hInstance", wintypes.HINSTANCE), ("hIcon", wintypes.HICON),
                ("hCursor", wintypes.HANDLE), ("hbrBackground", wintypes.HBRUSH), ("lpszMenuName", wintypes.LPCWSTR),
                ("lpszClassName", wintypes.LPCWSTR)]


class _MemoryInfo(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p), ("AllocationProtect", wintypes.DWORD),
                ("PartitionId", wintypes.WORD), ("RegionSize", ctypes.c_size_t), ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD), ("Type", wintypes.DWORD)]


class PageantWindow:
    CLASS = "Pageant"

    def __init__(self, agent: SshAgent, class_name: str = CLASS):
        self.agent, self.class_name = agent, class_name
        self.status = "stopped"
        self.error = ""
        self.hwnd = None
        self._ready = threading.Event()
        self._proc = WNDPROC(self._wndproc)  # referencja – inaczej wywołanie zwrotne zostanie zwolnione

    def start(self) -> str:
        if user32.FindWindowW(self.class_name, self.class_name):
            self.status = "busy"  # działa już Pageant (albo inny agent udający Pageanta)
            return self.status
        self._ready.clear()
        threading.Thread(target=self._run, daemon=True, name="ssh-agent-pageant").start()
        self._ready.wait(5)
        return self.status

    def _run(self):
        instance = kernel32.GetModuleHandleW(None)
        wc = _WndClass(lpfnWndProc=self._proc, hInstance=instance, lpszClassName=self.class_name)
        atom = user32.RegisterClassW(ctypes.byref(wc))
        if not atom:
            self.status, self.error = "error", f"RegisterClass {ctypes.get_last_error()}"
            self._ready.set()
            return
        # Zwykłe (nigdy nie pokazywane) okno: klienci szukają go przez FindWindow, który pomija okna HWND_MESSAGE
        self.hwnd = user32.CreateWindowExW(0, self.class_name, self.class_name, 0, 0, 0, 0, 0, None, None,
                                           instance, None)
        if not self.hwnd:
            self.status, self.error = "error", f"CreateWindow {ctypes.get_last_error()}"
            user32.UnregisterClassW(self.class_name, instance)
            self._ready.set()
            return
        self.status = "running"
        self._ready.set()
        msg = wintypes.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))
        user32.UnregisterClassW(self.class_name, instance)
        self.status = "stopped"

    def _wndproc(self, hwnd, msg, wparam, lparam):
        if msg == WM_COPYDATA:
            try:
                return self._copydata(lparam)
            except Exception:
                return 0
        if msg == WM_CLOSE:
            user32.DestroyWindow(hwnd)
            return 0
        if msg == WM_DESTROY:
            user32.PostQuitMessage(0)
            return 0
        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def _copydata(self, lparam) -> int:
        cds = ctypes.cast(lparam, ctypes.POINTER(_CopyData)).contents
        if cds.dwData != PAGEANT_COPYDATA_ID or not cds.lpData or not 0 < cds.cbData <= 256:
            return 0
        name = ctypes.string_at(cds.lpData, cds.cbData).split(b"\0", 1)[0]
        mapping = kernel32.OpenFileMappingA(FILE_MAP_WRITE | READ_CONTROL, False, name)  # READ_CONTROL: właściciel
        if not mapping:
            return 0
        try:
            # Pamięć musi należeć do tego samego konta – inaczej inny użytkownik komputera mógłby prosić o podpisy
            owner, sd = ctypes.c_void_p(), ctypes.c_void_p()
            if advapi32.GetSecurityInfo(mapping, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION, ctypes.byref(owner),
                                        None, None, None, ctypes.byref(sd)) != 0:
                return 0
            try:
                # Jak w Pageancie z PuTTY: konto użytkownika albo domyślny właściciel obiektów tego procesu
                if not (advapi32.EqualSid(owner, _CurrentUser.sid())
                        or advapi32.EqualSid(owner, _CurrentUser.default_owner_sid())):
                    return 0
            finally:
                kernel32.LocalFree(sd)
            view = kernel32.MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, 0)
            if not view:
                return 0
            try:
                info = _MemoryInfo()
                kernel32.VirtualQuery(view, ctypes.byref(info), ctypes.sizeof(info))
                size = min(info.RegionSize, PAGEANT_MAX_MESSAGE)
                if size < 5:
                    return 0
                length = struct.unpack(">I", ctypes.string_at(view, 4))[0]
                if length == 0 or 4 + length > size:
                    return 0
                reply = self.agent.handle(ctypes.string_at(view + 4, length), "PuTTY/Pageant")
                if 4 + len(reply) > size:
                    reply = FAILURE
                ctypes.memmove(view, struct.pack(">I", len(reply)) + reply, 4 + len(reply))
                return 1
            finally:
                kernel32.UnmapViewOfFile(view)
        finally:
            kernel32.CloseHandle(mapping)

    def stop(self):
        if self.status == "running" and self.hwnd:
            user32.PostMessageW(self.hwnd, WM_CLOSE, 0, 0)
            for _i in range(50):
                if self.status != "running":
                    break
                threading.Event().wait(0.02)
        self.hwnd = None


# --------------------------------------------------------------------- usługa: agent + oba kanały
class AgentService:
    def __init__(self, keys: Callable[[], List[AgentKey]], on_use: Callable[[AgentKey, str], bool],
                 pipe_name: str = OPENSSH_PIPE, pageant_class: str = PageantWindow.CLASS):
        self.agent = SshAgent(keys, on_use)
        self.pipe = OpenSshPipeServer(self.agent, pipe_name)
        self.pageant = PageantWindow(self.agent, pageant_class)
        self.running = False

    def start(self) -> Dict[str, str]:
        if os.name != "nt":
            return {"openssh": "error", "pageant": "error"}
        self.agent.enabled = True
        self.running = True
        return {"openssh": self.pipe.start(), "pageant": self.pageant.start()}

    def status(self) -> Dict[str, str]:
        return {"openssh": self.pipe.status, "pageant": self.pageant.status}

    def stop(self) -> None:
        self.agent.enabled = False  # najpierw: od tej chwili żadnych podpisów, także na otwartych połączeniach
        self.pipe.stop()
        self.pageant.stop()
        self.running = False


# --------------------------------------------------------------------- klient (testy i diagnostyka)
def pageant_request(message: bytes, class_name: str = PageantWindow.CLASS) -> Optional[bytes]:
    """Wysyła żądanie do okna Pageanta tak, jak robi to PuTTY (pamięć współdzielona + WM_COPYDATA)."""
    hwnd = user32.FindWindowW(class_name, class_name)
    if not hwnd:
        return None
    k = kernel32
    k.CreateFileMappingA.restype = wintypes.HANDLE
    k.CreateFileMappingA.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
                                     wintypes.LPCSTR]
    name = f"PageantRequest{threading.get_ident():08x}".encode()
    mapping = k.CreateFileMappingA(INVALID_HANDLE_VALUE, None, 0x04, 0, PAGEANT_MAX_MESSAGE, name)  # PAGE_READWRITE
    if not mapping:
        return None
    try:
        view = k.MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, 0)
        try:
            data = struct.pack(">I", len(message)) + message
            ctypes.memmove(view, data, len(data))
            cds = _CopyData(PAGEANT_COPYDATA_ID, len(name) + 1, ctypes.cast(ctypes.c_char_p(name), ctypes.c_void_p))
            user32.SendMessageW.restype = ctypes.c_ssize_t
            user32.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, ctypes.c_void_p]
            if not user32.SendMessageW(hwnd, WM_COPYDATA, 0, ctypes.byref(cds)):
                return None
            length = struct.unpack(">I", ctypes.string_at(view, 4))[0]
            return ctypes.string_at(view + 4, length)
        finally:
            k.UnmapViewOfFile(view)
    finally:
        k.CloseHandle(mapping)
