"""
Dostawca kopii zapasowej przez uniwersalny protokół WebDAV.
Doskonale współpracuje z Nextcloud, ownCloud, Synology NAS, QNAP oraz dowolnym serwerem WebDAV.
"""

import ipaddress
import os
from datetime import datetime
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse
import requests
from requests.auth import HTTPBasicAuth
from backups.base import BaseBackupProvider, BackupStatus
from core.crypto import compute_sha256


class WebDAVBackupProvider(BaseBackupProvider):
    @property
    def name(self) -> str:
        return "WebDAV (Nextcloud / ownCloud / NAS)"

    @property
    def key(self) -> str:
        return "webdav"

    def is_configured(self, config: Dict[str, Any]) -> bool:
        url = config.get("url", "").strip()
        username = config.get("username", "").strip()
        return bool(url and username)

    def _get_auth(self, config: Dict[str, Any]) -> Optional[HTTPBasicAuth]:
        user = config.get("username", "").strip()
        pwd = config.get("password", "").strip()
        if user or pwd:
            return HTTPBasicAuth(user, pwd)
        return None

    def _build_url(self, base_url: str, relative_path: str) -> str:
        base = base_url.rstrip("/") + "/"
        rel = relative_path.lstrip("/")
        return urljoin(base, rel)

    @staticmethod
    def check_transport(url: str) -> Tuple[bool, str]:
        """
        Login i hasło WebDAV (Basic Auth) idą w nagłówku – bez HTTPS są widoczne w sieci.
        Zwraca (dozwolone, ostrzeżenie): http:// jest dozwolone tylko w sieci lokalnej.
        """
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        if scheme == "https":
            return True, ""
        if scheme != "http" or not parsed.hostname:
            return False, "Adres WebDAV musi zaczynać się od https://"
        host = parsed.hostname.lower()
        is_local = host in ("localhost",) or host.endswith((".local", ".lan", ".home.arpa"))
        try:
            ip = ipaddress.ip_address(host)
            is_local = ip.is_private or ip.is_loopback or ip.is_link_local
        except ValueError:
            pass
        if not is_local:
            return False, ("Połączenie http:// przez internet wysłałoby login i hasło WebDAV otwartym tekstem. "
                           "Użyj adresu https://")
        return True, "⚠️ Połączenie bez szyfrowania (http://) – dopuszczalne tylko w zaufanej sieci domowej."

    def test_connection(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        url = config.get("url", "").strip()
        if not url:
            return False, "Brak podanego adresu URL serwera WebDAV."
        allowed, warning = self.check_transport(url)
        if not allowed:
            return False, warning

        auth = self._get_auth(config)
        try:
            # Wysłanie żądania PROPFIND lub OPTIONS w celu weryfikacji serwera
            resp = requests.request("PROPFIND", url, auth=auth, headers={"Depth": "0"}, timeout=10)
            if resp.status_code in [200, 207]:
                return True, f"Połączenie z serwerem WebDAV udane! (Kod: {resp.status_code})" + (f"\n\n{warning}" if warning else "")
            elif resp.status_code == 401:
                return False, "Błąd uwierzytelnienia: Niepoprawny login lub hasło/token aplikacji."
            elif resp.status_code == 404:
                # Niektóre serwery mogą nie mieć ścieżki głównej, spróbujmy OPTIONS
                opt_resp = requests.options(url, auth=auth, timeout=10)
                if opt_resp.status_code in [200, 204]:
                    return True, "Połączenie z serwerem WebDAV udane (OPTIONS)."
                return False, f"Zasób nie został odnaleziony (404): {url}"
            else:
                return False, f"Serwer zwrócił status {resp.status_code}: {resp.reason}"
        except Exception as e:
            return False, f"Nie można połączyć się z serwerem WebDAV: {str(e)}"

    def upload_backup(
        self,
        vault_file_path: str,
        config: Dict[str, Any],
        custom_filename: Optional[str] = None
    ) -> BackupStatus:
        if not os.path.exists(vault_file_path):
            return BackupStatus(self.name, False, error_message="Plik źródłowy sejfu nie istnieje.")

        base_url = config.get("url", "").strip()
        remote_folder = config.get("remote_folder", "KeyStead-Backups").strip("/")
        auth = self._get_auth(config)

        if not base_url:
            return BackupStatus(self.name, False, error_message="Brak adresu URL WebDAV w konfiguracji.")
        allowed, warning = self.check_transport(base_url)
        if not allowed:
            return BackupStatus(self.name, False, error_message=warning)

        try:
            with open(vault_file_path, "rb") as f:
                data = f.read()

            sha256_sum = compute_sha256(data)
            base_name = os.path.splitext(os.path.basename(vault_file_path))[0]
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = custom_filename or f"{base_name}_backup_{timestamp}.vault"

            folder_url = self._build_url(base_url, remote_folder) + "/"

            # Próba utworzenia katalogu docelowego jeśli nie istnieje (MKCOL)
            try:
                requests.request("MKCOL", folder_url, auth=auth, timeout=10)
            except Exception:
                pass

            target_url = self._build_url(folder_url, filename)

            # Wysłanie pliku (PUT)
            headers = {"Content-Type": "application/octet-stream"}
            put_resp = requests.put(target_url, data=data, auth=auth, headers=headers, timeout=30)

            if put_resp.status_code in [200, 201, 204]:
                return BackupStatus(
                    self.name,
                    True,
                    destination_path=target_url,
                    checksum=sha256_sum,
                    size_bytes=len(data)
                )
            else:
                return BackupStatus(
                    self.name,
                    False,
                    destination_path=target_url,
                    error_message=f"Błąd WebDAV ({put_resp.status_code}): {put_resp.reason}"
                )

        except Exception as e:
            return BackupStatus(self.name, False, error_message=f"Nieudane wysyłanie na WebDAV: {str(e)}")
