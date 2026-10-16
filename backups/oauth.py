"""
Logowanie OAuth 2.0 do chmur (Microsoft OneDrive, Google Drive, Dropbox) dla aplikacji desktopowej.

Przepływ: Authorization Code + PKCE z lokalnym przekierowaniem (loopback, RFC 8252):
1. Aplikacja uruchamia mini-serwer HTTP na http://localhost:53682/.
2. Otwiera w przeglądarce stronę logowania dostawcy (Microsoft / Google / Dropbox).
3. Po zalogowaniu i wyrażeniu zgody dostawca przekierowuje przeglądarkę z jednorazowym kodem.
4. Kod jest wymieniany na tokeny (access + refresh). Hasło do konta chmury nigdy nie trafia do aplikacji.

Tokeny są przechowywane w ustawieniach sejfu, czyli w zaszyfrowanym pliku .vault.
Identyfikatory aplikacji (Client ID) pochodzą z rejestracji aplikacji u dostawcy i są
trzymane w ~/.keystead/config.json (sekcja "oauth_clients").
"""

import base64
import hashlib
import json
import os
import secrets
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable, Dict, Optional
from urllib.parse import parse_qs, urlencode, urlparse

import requests

from core.paths import CONFIG_FILE  # noqa: E402
REDIRECT_PORT = 53682
LOGIN_TIMEOUT_SECONDS = 300

# Identyfikatory wbudowane w dystrybucję aplikacji (opcjonalne). Wartości z ~/.keystead/config.json mają pierwszeństwo.
BUILTIN_CLIENTS: Dict[str, Dict[str, str]] = {
    "onedrive": {"client_id": ""},
    "google_drive": {"client_id": "", "client_secret": ""},
    "dropbox": {"client_id": ""},
}

PROVIDERS: Dict[str, Dict[str, Any]] = {
    "onedrive": {
        "label": "Microsoft",
        "auth_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "scope": "Files.ReadWrite User.Read offline_access",
        "redirect_host": "localhost",
        "extra_auth_params": {"prompt": "select_account"},
        "needs_secret": False,
    },
    "google_drive": {
        "label": "Google",
        "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        # drive.file: dostęp wyłącznie do plików utworzonych przez tę aplikację
        "scope": "https://www.googleapis.com/auth/drive.file openid email",
        "redirect_host": "127.0.0.1",
        "extra_auth_params": {"access_type": "offline", "prompt": "consent select_account"},
        "needs_secret": True,
    },
    "dropbox": {
        "label": "Dropbox",
        "auth_url": "https://www.dropbox.com/oauth2/authorize",
        "token_url": "https://api.dropboxapi.com/oauth2/token",
        "scope": "",
        "redirect_host": "localhost",
        "extra_auth_params": {"token_access_type": "offline"},
        "needs_secret": False,
    },
}


class OAuthError(Exception):
    """Błąd logowania lub odświeżania tokenu."""


# ----------------------------------------------------------------- konfiguracja Client ID

def _read_config() -> Dict[str, Any]:
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def get_client_config(provider_key: str) -> Dict[str, str]:
    """Zwraca {client_id, client_secret} dla dostawcy (konfiguracja użytkownika lub wbudowana)."""
    merged = dict(BUILTIN_CLIENTS.get(provider_key, {}))
    user = _read_config().get("oauth_clients", {}).get(provider_key, {})
    for k, v in user.items():
        if v:
            merged[k] = v
    return merged


def save_client_config(provider_key: str, client_id: str, client_secret: str = "") -> None:
    data = _read_config()
    clients = data.setdefault("oauth_clients", {})
    clients[provider_key] = {"client_id": client_id.strip(), "client_secret": client_secret.strip()}
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def is_client_configured(provider_key: str) -> bool:
    cfg = get_client_config(provider_key)
    if not cfg.get("client_id"):
        return False
    return bool(cfg.get("client_secret")) or not PROVIDERS[provider_key]["needs_secret"]


def redirect_uri(provider_key: str) -> str:
    return f"http://{PROVIDERS[provider_key]['redirect_host']}:{REDIRECT_PORT}/"


# ----------------------------------------------------------------- PKCE + serwer loopback

def _pkce_pair():
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    return verifier, challenge


_SUCCESS_PAGE = """<!doctype html><html lang="pl"><meta charset="utf-8"><title>KeyStead Manager</title>
<body style="font-family:Segoe UI,sans-serif;background:#090d16;color:#f8fafc;display:flex;align-items:center;
justify-content:center;height:100vh;margin:0"><div style="text-align:center"><h1>{title}</h1>
<p style="color:#94a3b8">{message}</p></div></body></html>"""


def _wait_for_redirect(host: str, expected_state: str, cancel_event: threading.Event) -> Dict[str, str]:
    """Czeka na przekierowanie przeglądarki z kodem autoryzacyjnym."""
    result: Dict[str, str] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 (nazwa wymagana przez BaseHTTPRequestHandler)
            params = {k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()}
            if "code" not in params and "error" not in params:
                self.send_response(404)
                self.end_headers()
                return
            result.update(params)
            ok = "code" in params and params.get("state") == expected_state
            page = _SUCCESS_PAGE.format(
                title="✅ Zalogowano pomyślnie" if ok else "❌ Logowanie nieudane",
                message="Możesz zamknąć tę kartę i wrócić do KeyStead Manager." if ok
                else params.get("error_description") or params.get("error") or "Nieprawidłowa odpowiedź."
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)

        def log_message(self, *args):
            pass

    bind_host = "127.0.0.1" if host in ("localhost", "127.0.0.1") else host
    try:
        server = HTTPServer((bind_host, REDIRECT_PORT), Handler)
    except OSError as e:
        raise OAuthError(f"Port {REDIRECT_PORT} jest zajęty – zamknij inne okno logowania i spróbuj ponownie. ({e})")

    server.timeout = 0.5
    deadline = time.time() + LOGIN_TIMEOUT_SECONDS
    try:
        while not result and time.time() < deadline and not cancel_event.is_set():
            server.handle_request()
    finally:
        server.server_close()

    if cancel_event.is_set():
        raise OAuthError("Logowanie anulowane.")
    if not result:
        raise OAuthError("Upłynął czas na zalogowanie w przeglądarce.")
    if "error" in result:
        raise OAuthError(f"Dostawca odrzucił logowanie: {result.get('error_description') or result['error']}")
    if result.get("state") != expected_state:
        raise OAuthError("Nieprawidłowy parametr state – możliwa próba podszycia się. Spróbuj ponownie.")
    return result


def _token_request(provider_key: str, data: Dict[str, str]) -> Dict[str, Any]:
    client = get_client_config(provider_key)
    data = dict(data, client_id=client.get("client_id", ""))
    if client.get("client_secret"):
        data["client_secret"] = client["client_secret"]
    try:
        resp = requests.post(PROVIDERS[provider_key]["token_url"], data=data, timeout=20)
    except requests.RequestException as e:
        raise OAuthError(f"Brak połączenia z serwerem logowania: {e}")
    try:
        payload = resp.json()
    except ValueError:
        payload = {}
    if resp.status_code != 200 or "access_token" not in payload:
        detail = payload.get("error_description") or payload.get("error") or resp.text[:200]
        raise OAuthError(f"Serwer logowania zwrócił błąd ({resp.status_code}): {detail}")
    return payload


def _store_tokens(payload: Dict[str, Any], previous: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    previous = previous or {}
    return {
        "access_token": payload["access_token"],
        # Google i Dropbox nie zawsze zwracają nowy refresh token przy odświeżaniu
        "refresh_token": payload.get("refresh_token") or previous.get("refresh_token", ""),
        "expires_at": time.time() + int(payload.get("expires_in", 3600)),
        "account": previous.get("account", ""),
    }


# ----------------------------------------------------------------- API publiczne

def login(
    provider_key: str,
    cancel_event: Optional[threading.Event] = None,
    open_browser: Callable[[str], Any] = webbrowser.open
) -> Dict[str, Any]:
    """
    Pełne logowanie interaktywne w przeglądarce. Blokuje wątek do zakończenia (uruchamiać w tle).
    Zwraca słownik tokenów do zapisania w config["oauth"].
    """
    if provider_key not in PROVIDERS:
        raise OAuthError(f"Nieznany dostawca: {provider_key}")
    if not is_client_configured(provider_key):
        raise OAuthError("Brak identyfikatora aplikacji (Client ID). Uzupełnij go w sekcji 'Konfiguracja logowania do chmury'.")

    spec = PROVIDERS[provider_key]
    cancel_event = cancel_event or threading.Event()
    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(24)
    uri = redirect_uri(provider_key)

    params = {
        "client_id": get_client_config(provider_key)["client_id"],
        "response_type": "code",
        "redirect_uri": uri,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    if spec["scope"]:
        params["scope"] = spec["scope"]
    params.update(spec["extra_auth_params"])
    auth_url = f"{spec['auth_url']}?{urlencode(params)}"

    # Serwer musi nasłuchiwać zanim przeglądarka wróci z kodem
    outcome: Dict[str, Any] = {}

    def _listen():
        try:
            outcome["params"] = _wait_for_redirect(spec["redirect_host"], state, cancel_event)
        except Exception as e:
            outcome["error"] = e

    listener = threading.Thread(target=_listen, daemon=True)
    listener.start()
    time.sleep(0.2)
    if "error" in outcome:
        raise outcome["error"]
    open_browser(auth_url)
    listener.join()
    if "error" in outcome:
        raise outcome["error"]

    payload = _token_request(provider_key, {
        "grant_type": "authorization_code",
        "code": outcome["params"]["code"],
        "redirect_uri": uri,
        "code_verifier": verifier,
    })
    return _store_tokens(payload)


def get_access_token(provider_key: str, config: Dict[str, Any]) -> Optional[str]:
    """
    Zwraca ważny access token dla konfiguracji dostawcy, odświeżając go w razie potrzeby.
    Odświeżone tokeny są zapisywane z powrotem w config["oauth"].
    Zwraca None, gdy konto nie jest połączone.
    """
    tokens = config.get("oauth") or {}
    if not tokens.get("refresh_token") and not tokens.get("access_token"):
        legacy = (config.get("api_token") or "").strip()
        return legacy or None

    if tokens.get("access_token") and tokens.get("expires_at", 0) - 60 > time.time():
        return tokens["access_token"]

    if not tokens.get("refresh_token"):
        raise OAuthError("Sesja wygasła – zaloguj się ponownie.")

    data = {"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"]}
    if PROVIDERS[provider_key]["scope"] and provider_key == "onedrive":
        data["scope"] = PROVIDERS[provider_key]["scope"]
    try:
        payload = _token_request(provider_key, data)
    except OAuthError as e:
        raise OAuthError(f"Nie udało się odnowić sesji ({e}). Zaloguj się ponownie.")
    config["oauth"] = _store_tokens(payload, tokens)
    return config["oauth"]["access_token"]


def revoke(provider_key: str, tokens: Dict[str, Any]) -> bool:
    """
    Unieważnia tokeny u dostawcy przy wylogowaniu (best-effort).
    Google i Dropbox udostępniają endpoint revoke. Microsoft go nie ma – dla kont
    Microsoft dostęp odbiera się na account.microsoft.com → Prywatność → Aplikacje.
    """
    token = tokens.get("refresh_token") or tokens.get("access_token")
    if not token:
        return True
    try:
        if provider_key == "google_drive":
            resp = requests.post("https://oauth2.googleapis.com/revoke", data={"token": token}, timeout=10)
            return resp.status_code == 200
        if provider_key == "dropbox" and tokens.get("access_token"):
            resp = requests.post(
                "https://api.dropboxapi.com/2/auth/token/revoke",
                headers={"Authorization": f"Bearer {tokens['access_token']}"},
                timeout=10
            )
            return resp.status_code == 200
    except requests.RequestException:
        return False
    return False


def is_connected(config: Dict[str, Any]) -> bool:
    tokens = config.get("oauth") or {}
    return bool(tokens.get("refresh_token") or tokens.get("access_token") or (config.get("api_token") or "").strip())
