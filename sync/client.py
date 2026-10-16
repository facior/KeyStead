"""
Klient HTTP API serwera synchronizacji.
"""

import ipaddress
import os
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

API = "/api/v1"
TAILSCALE_NET = ipaddress.ip_network("100.64.0.0/10")


class SyncError(Exception):
    """Ogólny błąd synchronizacji."""


class NetworkError(SyncError):
    """Serwer nieosiągalny (brak sieci, Tailscale wyłączony, serwer wyłączony)."""


class CertificateError(NetworkError):
    """Certyfikat HTTPS serwera nie jest zaufany (samopodpisany / wewnętrzne CA firmy) lub został podmieniony."""


class AuthError(SyncError):
    """Token urządzenia nieprawidłowy lub odwołany."""


class ConflictError(SyncError):
    """Sejf na serwerze zmienił się od ostatniej synchronizacji."""

    def __init__(self, remote_meta: Optional[Dict[str, Any]]):
        super().__init__("Sejf został zmieniony na innym urządzeniu.")
        self.remote_meta = remote_meta or {}


def check_server_url(url: str) -> Tuple[bool, str]:
    """
    Dozwolone: https:// (np. https://serwer.tailnet.ts.net) albo http:// tylko wewnątrz
    sieci Tailscale (100.64.0.0/10, *.ts.net – ruch szyfruje WireGuard) lub localhost.
    """
    parsed = urlparse(url)
    if parsed.scheme == "https" and parsed.hostname:
        return True, ""
    if parsed.scheme != "http" or not parsed.hostname:
        return False, "Adres serwera musi zaczynać się od https:// (np. https://serwer.twoja-siec.ts.net)."
    host = parsed.hostname.lower()
    if host == "localhost" or host.endswith(".ts.net"):
        return True, ""
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback or ip in TAILSCALE_NET:
            return True, ""
    except ValueError:
        pass
    return False, "Połączenie http:// jest dozwolone tylko w sieci Tailscale. Użyj adresu https://"


def _detail(resp: requests.Response) -> str:
    try:
        return resp.json().get("detail") or resp.text[:200]
    except ValueError:
        return resp.text[:200]


def _plain_http_over_tailnet(url: str) -> bool:
    """http:// do adresu Tailscale – bezpieczne TYLKO, gdy ruch faktycznie idzie tunelem Tailscale."""
    parsed = urlparse(url)
    if parsed.scheme != "http":
        return False
    host = (parsed.hostname or "").lower()
    if host == "localhost":
        return False
    try:
        return not ipaddress.ip_address(host).is_loopback
    except ValueError:
        return True


def _send(session: requests.Session, method: str, url: str, timeout: float, verify, **kwargs) -> requests.Response:
    if _plain_http_over_tailnet(url):
        from sync.tailscale import tailscale_running
        if not tailscale_running():
            # Bez działającego Tailscale adres 100.x / *.ts.net trafiłby otwartym tekstem do sieci dostawcy lub
            # lokalnego DNS – token urządzenia i sejf nie mogą tam wyjść. Traktujemy jak brak połączenia.
            raise NetworkError("Tailscale nie jest połączony – połączenie http:// byłoby nieszyfrowane. "
                               "Włącz Tailscale i spróbuj ponownie.")
        session.trust_env = False  # z pominięciem systemowego proxy: ruch musi iść tunelem Tailscale
    try:
        # Ustawienia proxy systemu (także firmowe proxy z rejestru Windows) są uwzględniane automatycznie
        return session.request(method, url, timeout=timeout, verify=verify, **kwargs)
    except requests.exceptions.SSLError as e:
        raise CertificateError(f"Certyfikat HTTPS serwera nie jest zaufany ({type(e).__name__}).")
    except requests.RequestException as e:
        raise NetworkError(f"Serwer jest nieosiągalny ({type(e).__name__}). Sprawdź połączenie z siecią lub VPN.")


class TotpRequiredError(AuthError):
    """Polityka firmy wymaga kodu 2FA użytkownika przy dodawaniu urządzenia."""


def enroll_device(base_url: str, code: str, device_name: str, ca_file: str = "", timeout: float = 15.0,
                  totp: str = "") -> Dict[str, Any]:
    """
    Dołącza to urządzenie do konta kodem aktywacyjnym z panelu administratora.
    Zwraca m.in. token, a przy pierwszym urządzeniu z wymaganym 2FA także 'totp_setup'.
    Rzuca TotpRequiredError, gdy serwer wymaga kodu z aplikacji uwierzytelniającej.
    """
    ok, msg = check_server_url(base_url)
    if not ok:
        raise SyncError(msg)
    payload = {"code": code.strip(), "device_name": device_name.strip()[:64] or "Komputer"}
    if totp:
        payload["totp"] = totp.strip().replace(" ", "")
    resp = _send(requests.Session(), "POST", f"{base_url.rstrip('/')}{API}/enroll", timeout, ca_file or True, json=payload)
    if resp.status_code == 200:
        return resp.json()
    if resp.status_code == 404:
        raise SyncError("Ten serwer nie obsługuje kodów aktywacyjnych – zaktualizuj serwer lub użyj tokenu urządzenia.")
    try:
        body = resp.json()
    except ValueError:
        body = {}
    if resp.status_code == 401 and body.get("totp_required"):
        raise TotpRequiredError(body.get("detail") or "Wymagany kod 2FA.")
    raise AuthError(_detail(resp))


class RemoteVaultClient:
    def __init__(self, base_url: str, token: str, timeout: float = 15.0, ca_file: str = ""):
        ok, msg = check_server_url(base_url)
        if not ok:
            raise SyncError(msg)
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        # Przypięty certyfikat (serwer z certyfikatem samopodpisanym / firmowym) albo systemowy magazyn CA
        self.verify = ca_file if ca_file and os.path.exists(ca_file) else True
        self._session = requests.Session()
        self._session.headers.update({"Authorization": f"Bearer {token}", "User-Agent": "KeyStead-Desktop"})

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        resp = _send(self._session, method, f"{self.base_url}{API}{path}", self.timeout, self.verify, **kwargs)
        # Tylko 401 oznacza odebranie dostępu (odcięte urządzenie / zablokowane konto) – skutkuje usunięciem
        # lokalnej kopii. 403 to np. połączenie z niedozwolonej sieci, więc NIE może niczego kasować.
        if resp.status_code == 401:
            raise AuthError(_detail(resp) or "Serwer odrzucił token urządzenia.")
        if resp.status_code in (403, 429):
            raise SyncError(_detail(resp))
        return resp

    _detail = staticmethod(_detail)

    def health(self) -> Dict[str, Any]:
        resp = self._request("GET", "/health")
        if resp.status_code != 200:
            raise SyncError(f"Serwer zwrócił błąd {resp.status_code}.")
        return resp.json()

    def meta(self) -> Dict[str, Any]:
        """Zwraca {"exists": bool, "meta": {...}|None, "device": nazwa, "server_id": ...}."""
        resp = self._request("GET", "/vault/meta")
        if resp.status_code != 200:
            raise SyncError(f"Błąd serwera ({resp.status_code}): {self._detail(resp)}")
        return resp.json()

    def download(self, version: Optional[int] = None) -> Tuple[bytes, int]:
        path = "/vault" if version is None else f"/vault/history/{int(version)}"
        resp = self._request("GET", path)
        if resp.status_code != 200:
            raise SyncError(f"Nie udało się pobrać sejfu ({resp.status_code}): {self._detail(resp)}")
        return resp.content, int(resp.headers.get("X-Vault-Version", "0"))

    def upload(self, blob: bytes, base_version: int) -> Dict[str, Any]:
        resp = self._request(
            "PUT", "/vault", data=blob,
            headers={"If-Match": str(base_version), "Content-Type": "application/octet-stream"}
        )
        if resp.status_code == 409:
            raise ConflictError(resp.json().get("meta"))
        if resp.status_code != 200:
            raise SyncError(f"Serwer odrzucił zapis ({resp.status_code}): {self._detail(resp)}")
        return resp.json()["meta"]

    def history(self) -> List[Dict[str, Any]]:
        resp = self._request("GET", "/vault/history")
        if resp.status_code != 200:
            raise SyncError(f"Nie udało się pobrać historii ({resp.status_code}).")
        return resp.json().get("versions", [])

    def confirm_totp(self, code: str) -> None:
        """Potwierdza konfigurację 2FA użytkownika (pierwsze urządzenie przy polityce wymagającej 2FA)."""
        resp = _send(self._session, "POST", f"{self.base_url}{API}/account/totp/confirm", self.timeout, self.verify,
                     json={"code": code.strip().replace(" ", "")})
        if resp.status_code != 200:
            raise SyncError(_detail(resp))

    def send_report(self, report: Dict[str, Any]) -> bool:
        """Wysyła zbiorczy wynik audytu (tylko liczby). Zwraca False, gdy raporty są wyłączone."""
        resp = _send(self._session, "POST", f"{self.base_url}{API}/report", self.timeout, self.verify, json=report)
        return resp.status_code == 200

    def fetch_logo(self, max_bytes: int = 512 * 1024) -> Optional[bytes]:
        try:
            resp = _send(self._session, "GET", f"{self.base_url}{API}/branding/logo", self.timeout, self.verify,
                         stream=True)
        except SyncError:
            return None
        try:
            if resp.status_code != 200:
                return None
            data = resp.raw.read(max_bytes + 1, decode_content=True)  # limit – logo z serwera nie zapcha pamięci
        except Exception:
            return None
        finally:
            resp.close()
        if len(data) > max_bytes or not data.startswith(b"\x89PNG"):
            return None
        try:
            from PIL import Image
            import io
            with Image.open(io.BytesIO(data)) as img:
                if img.width * img.height > 4_000_000:  # „bomba” w małym pliku PNG
                    return None
        except Exception:
            return None
        return data
