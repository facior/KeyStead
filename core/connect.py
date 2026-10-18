"""
Wtyczka „Połącz”: jedno kliknięcie otwiera połączenie zdalne z danymi wpisu.

Adres wpisu wybiera program:
    rdp://host[:port]          Pulpit zdalny (mstsc) – login i hasło trafiają do Menedżera poświadczeń Windows
                               tylko na czas łączenia (jak KeePassRDP), potem są usuwane
    ssh://[login@]host[:port]  OpenSSH (nowe okno konsoli) albo PuTTY – hasło w schowku (czyszczonym jak zwykle)
    winbox://host[:port]       MikroTik WinBox (login i hasło jako argumenty – tak przyjmuje je WinBox)
    anydesk://ID               AnyDesk – hasło podane przez standardowe wejście (--with-password)
    teamviewer://ID            TeamViewer
Adres może być sam schemat („rdp://” z szablonu) – wtedy host jest brany z pola „Adres IP” lub „Host”.

Programy są uruchamiane bez powłoki (lista argumentów), a host, port i identyfikatory są sprawdzane wzorcem –
wpis z „hostem” w rodzaju `x /admin` albo `-o ProxyCommand=…` nie przemyci dodatkowych opcji.
"""

import atexit
import json
import os
import re
import shutil
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.i18n import N_, _
from core.paths import APP_DIR
from core.vault import VaultEntry

PROTOCOLS = {
    "rdp": (N_("Pulpit zdalny"), 3389),
    "ssh": ("SSH", 22),
    "winbox": ("WinBox", 8291),
    "anydesk": ("AnyDesk", 0),
    "teamviewer": ("TeamViewer", 0),
}
HOST_FIELDS = ("Adres IP", "Host", "IP address")  # i18n: data – pola z adresem (szablony serwerów)
DOMAIN_FIELDS = ("Domena", "Domain")  # i18n: data
REMOTE_ID_FIELDS = ("Numer ID", "ID")  # i18n: data

_HOST = re.compile(r"^(?:[A-Za-z0-9_](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9_])?|\[[0-9A-Fa-f:.]{2,45}\])$")
_REMOTE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@._-]{2,63}$")
_DOMAIN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_URL = re.compile(r"^\s*([a-z]+)://(?:([^@/\s]*)@)?([^/\s?#]*)/?\s*$", re.IGNORECASE)

PREFS_FILE = os.path.join(APP_DIR, "connect.json")  # ścieżki programów na tym komputerze (nie w sejfie)
DEFAULT_PREFS = {"ssh_client": "openssh", "putty": "", "winbox": "", "anydesk": "", "teamviewer": ""}
CRED_LIFETIME_SECONDS = 30


class ConnectError(Exception):
    pass


@dataclass
class Target:
    protocol: str
    host: str = ""        # host albo identyfikator AnyDesk / TeamViewer
    port: int = 0
    username: str = ""
    password: str = ""
    domain: str = ""

    @property
    def label(self) -> str:
        return _(PROTOCOLS[self.protocol][0])

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}" if self.port else self.host


@dataclass
class LaunchPlan:
    argv: List[str]
    stdin_text: str = ""                 # wysyłane do programu (AnyDesk --with-password)
    clipboard_text: str = ""             # hasło do wklejenia (SSH)
    rdp_credential: Optional[Dict[str, str]] = None  # {"target", "username", "password"} – na czas łączenia
    new_console: bool = False
    notes: List[str] = field(default_factory=list)


def _first_field(entry: VaultEntry, names) -> str:
    for name in names:
        value = (entry.custom_fields.get(name) or "").strip()
        if value:
            return value
    return ""


def protocol_of(url: str) -> Optional[str]:
    m = _URL.match(url or "")
    return m.group(1).lower() if m and m.group(1).lower() in PROTOCOLS else None


def parse_target(entry: VaultEntry) -> Optional[Target]:
    """Dane połączenia z wpisu albo None, gdy adres nie jest adresem połączenia zdalnego."""
    m = _URL.match(entry.url or "")
    if not m or m.group(1).lower() not in PROTOCOLS:
        return None
    protocol, url_user, hostport = m.group(1).lower(), (m.group(2) or ""), m.group(3)
    host, port = hostport, 0
    pm = re.match(r"^(.*):(\d{1,5})$", hostport)
    if pm and not hostport.endswith("]"):
        host, port = pm.group(1), int(pm.group(2))
    if protocol in ("anydesk", "teamviewer"):
        host = host or _first_field(entry, REMOTE_ID_FIELDS)
        port = 0
    else:
        host = host or _first_field(entry, HOST_FIELDS)
    return Target(protocol=protocol, host=host, port=port, username=url_user or entry.username,
                  password=entry.password, domain=_first_field(entry, DOMAIN_FIELDS))


def validate(target: Target) -> None:
    if not target.host:
        raise ConnectError(_("Wpis nie ma adresu – uzupełnij adres po {scheme}:// albo pole „Adres IP”.",
                             scheme=target.protocol))
    if target.protocol in ("anydesk", "teamviewer"):
        if not _REMOTE_ID.match(target.host):
            raise ConnectError(_("Nieprawidłowy numer ID: {value}", value=target.host))
        if target.protocol == "teamviewer" and not target.host.isdigit():
            raise ConnectError(_("Numer TeamViewer może zawierać tylko cyfry."))
        return
    if not _HOST.match(target.host):
        raise ConnectError(_("Nieprawidłowy adres serwera: {value}", value=target.host))
    if target.port and not 0 < target.port < 65536:
        raise ConnectError(_("Nieprawidłowy port: {value}", value=target.port))
    if target.username and (target.username.startswith("-") or re.search(r"[\x00-\x1f\"]", target.username)):
        raise ConnectError(_("Nieprawidłowy login: {value}", value=target.username))
    if target.domain and not _DOMAIN.match(target.domain):
        raise ConnectError(_("Nieprawidłowa domena: {value}", value=target.domain))


# --------------------------------------------------------------------- programy na tym komputerze
def load_prefs() -> Dict[str, Any]:
    try:
        with open(PREFS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {**DEFAULT_PREFS, **{k: v for k, v in (data if isinstance(data, dict) else {}).items()
                                    if k in DEFAULT_PREFS and isinstance(v, str)}}
    except (OSError, ValueError):
        return dict(DEFAULT_PREFS)


def save_prefs(prefs: Dict[str, Any]) -> None:
    os.makedirs(APP_DIR, exist_ok=True)
    with open(PREFS_FILE, "w", encoding="utf-8") as f:
        json.dump({k: str(prefs.get(k, v) or "") for k, v in DEFAULT_PREFS.items()}, f, indent=2)


def _program_dirs() -> List[str]:
    env = os.environ
    return [d for d in (env.get("ProgramFiles"), env.get("ProgramFiles(x86)"), env.get("ProgramW6432"),
                        os.path.join(env.get("LOCALAPPDATA", ""), "Programs") if env.get("LOCALAPPDATA") else None)
            if d]


_KNOWN = {
    "putty": (["putty.exe"], [("PuTTY", "putty.exe")]),
    "winbox": (["winbox64.exe", "winbox.exe"], [("MikroTik", "winbox64.exe"), ("MikroTik", "winbox.exe"),
                                                ("WinBox", "winbox64.exe"), ("WinBox", "winbox.exe")]),
    "anydesk": (["AnyDesk.exe"], [("AnyDesk", "AnyDesk.exe")]),
    "teamviewer": (["TeamViewer.exe"], [("TeamViewer", "TeamViewer.exe")]),
}


def find_program(name: str, prefs: Optional[Dict[str, Any]] = None) -> str:
    """Ścieżka programu: ustawiona ręcznie, z PATH albo ze standardowych katalogów instalacji ("" = brak)."""
    configured = ((prefs or {}).get(name) or "").strip()
    if configured and os.path.isfile(configured):
        return configured
    if name == "mstsc":
        path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "mstsc.exe")
        return path if os.path.isfile(path) else ""
    if name == "ssh":
        found = shutil.which("ssh")
        if found:
            return found
        path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "OpenSSH", "ssh.exe")
        return path if os.path.isfile(path) else ""
    exe_names, installs = _KNOWN.get(name, ([], []))
    for exe in exe_names:
        found = shutil.which(exe)
        if found:
            return found
    for base in _program_dirs():
        for folder, exe in installs:
            path = os.path.join(base, folder, exe)
            if os.path.isfile(path):
                return path
    return ""


def _missing(program: str) -> ConnectError:
    return ConnectError(_("Nie znaleziono programu {program} na tym komputerze. Zainstaluj go albo wskaż plik "
                          "programu w Ustawienia → Wtyczki → „Połącz”.", program=program))


def build_plan(target: Target, prefs: Optional[Dict[str, Any]] = None) -> LaunchPlan:
    """Co uruchomić – bez uruchamiania (osobno, żeby dało się to sprawdzić testami)."""
    validate(target)
    prefs = prefs if prefs is not None else load_prefs()
    p = target.protocol
    if p == "rdp":
        mstsc = find_program("mstsc", prefs)
        if not mstsc:
            raise _missing(_("Pulpit zdalny (mstsc)"))
        user = target.username
        if user and target.domain and "\\" not in user and "@" not in user:
            user = f"{target.domain}\\{user}"
        cred = {"target": f"TERMSRV/{target.host.strip('[]')}", "username": user, "password": target.password} \
            if user and target.password else None
        return LaunchPlan([mstsc, f"/v:{target.address}"], rdp_credential=cred)
    if p == "ssh":
        if prefs.get("ssh_client") == "putty":
            putty = find_program("putty", prefs)
            if not putty:
                raise _missing("PuTTY")
            argv = [putty, "-ssh", target.host.strip("[]"), "-P", str(target.port or 22)]
            if target.username:
                argv += ["-l", target.username]
            return LaunchPlan(argv, clipboard_text=target.password)
        ssh = find_program("ssh", prefs)
        if not ssh:
            raise _missing("OpenSSH (ssh)")
        argv = [ssh]
        if target.port:
            argv += ["-p", str(target.port)]
        argv.append(f"{target.username}@{target.host.strip('[]')}" if target.username else target.host.strip("[]"))
        return LaunchPlan(argv, clipboard_text=target.password, new_console=True)
    if p == "winbox":
        winbox = find_program("winbox", prefs)
        if not winbox:
            raise _missing("WinBox")
        argv = [winbox, target.address]
        if target.username:
            argv += [target.username, target.password]
        return LaunchPlan(argv)
    if p == "anydesk":
        anydesk = find_program("anydesk", prefs)
        if not anydesk:
            raise _missing("AnyDesk")
        if target.password:
            return LaunchPlan([anydesk, target.host, "--with-password"], stdin_text=target.password + "\n")
        return LaunchPlan([anydesk, target.host])
    if p == "teamviewer":
        tv = find_program("teamviewer", prefs)
        if not tv:
            raise _missing("TeamViewer")
        argv = [tv, "-i", target.host]
        if target.password:
            argv += ["--Password", target.password]
        return LaunchPlan(argv)
    raise ConnectError(_("Nieobsługiwany rodzaj połączenia: {value}", value=p))


# --------------------------------------------------------------------- Menedżer poświadczeń Windows (RDP)
def _credentials_api():
    import ctypes
    from ctypes import wintypes

    class CREDENTIAL(ctypes.Structure):
        _fields_ = [("Flags", wintypes.DWORD), ("Type", wintypes.DWORD), ("TargetName", wintypes.LPWSTR),
                    ("Comment", wintypes.LPWSTR), ("LastWritten", wintypes.FILETIME),
                    ("CredentialBlobSize", wintypes.DWORD), ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
                    ("Persist", wintypes.DWORD), ("AttributeCount", wintypes.DWORD), ("Attributes", ctypes.c_void_p),
                    ("TargetAlias", wintypes.LPWSTR), ("UserName", wintypes.LPWSTR)]

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.CredWriteW.argtypes = [ctypes.POINTER(CREDENTIAL), wintypes.DWORD]
    advapi.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    advapi.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
    advapi.CredFree.argtypes = [ctypes.c_void_p]
    return ctypes, CREDENTIAL, advapi


CRED_TYPE_DOMAIN_PASSWORD = 2
CRED_PERSIST_SESSION = 1


def rdp_credential_exists(target_name: str) -> bool:
    ctypes, _cred, advapi = _credentials_api()
    ptr = ctypes.c_void_p()
    if advapi.CredReadW(target_name, CRED_TYPE_DOMAIN_PASSWORD, 0, ctypes.byref(ptr)):
        advapi.CredFree(ptr)
        return True
    return False


def write_rdp_credential(target_name: str, username: str, password: str) -> None:
    ctypes, CREDENTIAL, advapi = _credentials_api()
    blob = password.encode("utf-16-le")
    buf = (ctypes.c_ubyte * max(len(blob), 1)).from_buffer_copy(blob or b"\0")
    cred = CREDENTIAL(Type=CRED_TYPE_DOMAIN_PASSWORD, TargetName=target_name, CredentialBlobSize=len(blob),
                      CredentialBlob=ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte)), Persist=CRED_PERSIST_SESSION,
                      UserName=username)
    try:
        if not advapi.CredWriteW(ctypes.byref(cred), 0):
            raise ConnectError(_("Windows nie zapisał danych logowania (błąd {code}).", code=ctypes.get_last_error()))
    finally:
        ctypes.memset(buf, 0, len(blob))


def delete_rdp_credential(target_name: str) -> None:
    ctypes, _cred, advapi = _credentials_api()
    advapi.CredDeleteW(target_name, CRED_TYPE_DOMAIN_PASSWORD, 0)


# --------------------------------------------------------------------- uruchomienie
CREATE_NEW_CONSOLE = 0x00000010
_pending_credentials = set()  # dane RDP czekające na usunięcie – usuwane też przy zamknięciu programu
_pending_lock = threading.Lock()


def _expire_credential(target_name: str) -> None:
    with _pending_lock:
        if target_name not in _pending_credentials:
            return
        _pending_credentials.discard(target_name)
    delete_rdp_credential(target_name)


@atexit.register
def _cleanup_credentials() -> None:
    for target_name in list(_pending_credentials):
        try:
            _expire_credential(target_name)
        except Exception:
            pass


def launch(plan: LaunchPlan) -> List[str]:
    """
    Uruchamia program z planu. Zwraca komunikaty dla użytkownika (np. „hasło jest w schowku”);
    schowek ustawia interfejs (żeby działało jego automatyczne czyszczenie).
    """
    notes = list(plan.notes)
    cred = plan.rdp_credential
    if cred:
        if rdp_credential_exists(cred["target"]):
            # Użytkownik ma własne zapisane dane dla tego serwera – nie nadpisujemy ich (i nie usuwamy potem)
            notes.append(_("Windows ma już zapisane dane logowania do tego serwera – użyto zapisanych."))
            cred = None
        else:
            write_rdp_credential(cred["target"], cred["username"], cred["password"])
            with _pending_lock:
                _pending_credentials.add(cred["target"])
            timer = threading.Timer(CRED_LIFETIME_SECONDS, _expire_credential, args=(cred["target"],))
            timer.daemon = True
            timer.start()
    flags = CREATE_NEW_CONSOLE if plan.new_console else 0
    try:
        proc = subprocess.Popen(plan.argv, stdin=subprocess.PIPE if plan.stdin_text else None, creationflags=flags,
                                close_fds=True)
    except OSError as e:
        if cred:
            _expire_credential(cred["target"])
        raise ConnectError(_("Nie udało się uruchomić programu: {error}", error=e)) from e
    if plan.stdin_text:
        try:
            proc.stdin.write(plan.stdin_text.encode("utf-8"))
            proc.stdin.close()
        except OSError:
            pass
    return notes
