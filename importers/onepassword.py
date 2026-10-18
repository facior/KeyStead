"""
Importer danych z menedżera 1Password (obsługuje format .1pux / ZIP oraz CSV).
"""

import csv
import json
import os
import zipfile
from typing import Optional, List
from importers.base import BaseImporter, ImportResult, ImportItem
from core.totp_service import parse_otpauth_uri, sanitize_secret
from core.i18n import _


MAX_EXPORT_DATA_BYTES = 50 * 1024 * 1024  # JSON 200 MB to kilka GB obiektów Pythona – realne eksporty są dużo mniejsze

CATEGORY_MAP = {
    "001": "Loginy",  # i18n: data
    "002": "Karty płatnicze",  # i18n: data
    "003": "Bezpieczne notatki",  # i18n: data
    "004": "Tożsamości",  # i18n: data
    "005": "Loginy",  # i18n: data
    "006": "Dokumenty",  # i18n: data
    "100": "Karty płatnicze",  # i18n: data
    "101": "Konta bankowe",  # i18n: data
    "110": "Bazy danych",  # i18n: data
    "111": "Serwery"  # i18n: data
}


def _unwrap_value(value) -> str:
    """Wartości pól w .1pux są słownikami typu {"concealed": "..."}, {"totp": "..."} itp."""
    if value is None:
        return ""
    if isinstance(value, dict):
        if not value:
            return ""
        inner = next(iter(value.values()))
        if isinstance(inner, dict):
            return ", ".join(str(v) for v in inner.values() if v)
        return "" if inner is None else str(inner)
    return str(value)


def _extract_totp(raw: str) -> str:
    if raw.startswith("otpauth://"):
        parsed = parse_otpauth_uri(raw)
        return parsed[0] if parsed else raw
    return sanitize_secret(raw)


class OnePasswordImporter(BaseImporter):
    @property
    def name(self) -> str:
        return "1Password (.1pux / CSV)"

    @property
    def supported_extensions(self) -> List[str]:
        return [".1pux", ".zip", ".csv"]

    def can_handle(self, file_path: str, preview_header: bytes) -> bool:
        ext = os.path.splitext(file_path)[1].lower()
        if ext in [".1pux", ".zip"]:
            return preview_header.startswith(b"PK\x03\x04")
        elif ext == ".csv":
            try:
                snippet = preview_header.decode("utf-8", errors="ignore").lower()
                return "title" in snippet and ("username" in snippet or "password" in snippet)
            except Exception:
                return False
        return False

    def parse(
        self,
        file_path: str,
        password: Optional[str] = None,
        keyfile_path: Optional[str] = None
    ) -> ImportResult:
        result = ImportResult(self.name)
        ext = os.path.splitext(file_path)[1].lower()

        try:
            if ext in [".1pux", ".zip"]:
                self._parse_1pux(file_path, result)
            elif ext == ".csv":
                self._parse_csv(file_path, result)
            else:
                result.add_error(_("Nieobsługiwane rozszerzenie: {ext}", ext=ext))
        except Exception as e:
            result.add_error(_("Błąd podczas wczytywania danych 1Password: {error}", error=e))

        result.success = len(result.items) > 0 and len(result.errors) == 0
        return result

    def _parse_1pux(self, file_path: str, result: ImportResult) -> None:
        try:
            with zipfile.ZipFile(file_path, "r") as z:
                if "export.data" not in z.namelist():
                    result.add_error(_("Archiwum .1pux nie zawiera pliku export.data."))
                    return
                # Ochrona przed "zip bombą" – prawdziwe eksporty mają co najwyżej kilkadziesiąt MB
                if z.getinfo("export.data").file_size > MAX_EXPORT_DATA_BYTES:
                    result.add_error(_("Plik export.data jest podejrzanie duży (>200 MB) – import przerwany."))
                    return
                with z.open("export.data") as f:
                    data = json.load(f)
        except Exception as e:
            result.add_error(_("Błąd odczytu archiwum zip 1Password: {error}", error=e))
            return

        accounts = data.get("accounts", [])
        for acc in accounts:
            vaults = acc.get("vaults", [])
            for v in vaults:
                items = v.get("items", [])
                for item in items:
                    cat_uuid = item.get("categoryUuid", "")
                    category = CATEGORY_MAP.get(cat_uuid, "Loginy")  # i18n: data

                    overview = item.get("overview") or {}
                    title = overview.get("title") or item.get("title") or _("Bez tytułu")
                    url = overview.get("url") or ""
                    if not url and overview.get("urls"):
                        first_url = overview["urls"][0]
                        url = first_url.get("url", "") if isinstance(first_url, dict) else str(first_url)
                    tags = overview.get("tags") or []

                    details = item.get("details") or {}
                    notes = details.get("notesPlain") or ""

                    username = ""
                    password = details.get("password") or ""
                    totp = ""
                    custom_fields = {}

                    # Pola logowania (loginFields; starsze eksporty używają 'fields')
                    login_fields = details.get("loginFields") or details.get("fields") or []
                    for f in login_fields:
                        designation = f.get("designation", "")
                        fval = _unwrap_value(f.get("value"))

                        if designation == "username" and not username:
                            username = fval
                        elif designation == "password" and not password:
                            password = fval
                        elif fval and f.get("fieldType") not in ("B", "I"):
                            flabel = f.get("name") or f.get("title") or f.get("id") or _("pole")
                            custom_fields[str(flabel)] = fval

                    # Sekcje (TOTP, dane karty, pola niestandardowe)
                    sections = details.get("sections") or []
                    for s in sections:
                        for sf in s.get("fields") or []:
                            raw_value = sf.get("value")
                            s_val = _unwrap_value(raw_value)
                            s_title = sf.get("title") or sf.get("id") or ""
                            is_totp = isinstance(raw_value, dict) and "totp" in raw_value
                            if (is_totp or "totp" in s_title.lower()) and s_val and not totp:
                                totp = _extract_totp(s_val)
                            elif s_title and s_val:
                                custom_fields[s_title] = s_val

                    result.add_item(ImportItem(
                        title=title,
                        category=category,
                        username=username,
                        password=password,
                        url=url,
                        totp_secret=totp,
                        notes=notes,
                        tags=tags,
                        custom_fields=custom_fields
                    ))

    def _parse_csv(self, file_path: str, result: ImportResult) -> None:
        with open(file_path, "r", encoding="utf-8-sig", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                title = row.get("Title") or row.get("title") or _("Bez tytułu")
                username = row.get("Username") or row.get("username") or ""
                password = row.get("Password") or row.get("password") or ""
                url = row.get("Url") or row.get("URL") or row.get("url") or ""
                notes = row.get("Notes") or row.get("notes") or ""
                category = row.get("Type") or row.get("type") or "Loginy"  # i18n: data

                raw_totp = row.get("OTP") or row.get("totp") or row.get("one-time password") or ""
                totp = _extract_totp(raw_totp)

                result.add_item(ImportItem(
                    title=title,
                    category=category,
                    username=username,
                    password=password,
                    url=url,
                    totp_secret=totp,
                    notes=notes
                ))
