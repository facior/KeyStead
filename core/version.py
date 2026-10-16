"""Wersja aplikacji KeyStead Manager (podnoszona przy każdym wydaniu – tools/release_app.py)."""

APP_NAME = "KeyStead Manager"
APP_VERSION = "2.0.0"

# Wersjonowanie produktu: pierwsze dwie liczby wspólne dla aplikacji i serwera (nowe funkcje – razem),
# ostatnia osobno (poprawki). Aplikacja X.Y.* współpracuje z serwerem X.Y.* (i nowszym).
AUTHOR = "Łukasz Kubieniec"
AUTHOR_GITHUB = "https://github.com/facior"
APP_REPOSITORY_URL = "https://github.com/facior/KeyStead"
SERVER_REPOSITORY_URL = "https://github.com/facior/KeyStead-Manager"
COPYRIGHT = "© 2026 Łukasz Kubieniec. Wszelkie prawa zastrzeżone."


def product_line(version: str) -> tuple:
    """(2, 0) z „2.0.3” – linia produktu, w obrębie której aplikacja i serwer są zgodne."""
    try:
        major, minor = (int(p) for p in str(version).split(".")[:2])
        return major, minor
    except ValueError:
        return 0, 0


def server_compatibility(server_version: str) -> str:
    """'ok' | 'server_older' (serwer wymaga aktualizacji) | 'app_older' (aplikacja wymaga aktualizacji) | 'unknown'."""
    if not server_version:
        return "unknown"
    app, server = product_line(APP_VERSION), product_line(server_version)
    if server < app:
        return "server_older"
    if server > app:
        return "app_older"
    return "ok"
