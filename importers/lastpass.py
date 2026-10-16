"""
Importer danych z menedżera LastPass (obsługuje format CSV).
"""

import csv
import os
from typing import Optional, List
from importers.base import BaseImporter, ImportResult, ImportItem
from core.totp_service import parse_otpauth_uri, sanitize_secret


class LastPassImporter(BaseImporter):
    @property
    def name(self) -> str:
        return "LastPass (CSV)"

    @property
    def supported_extensions(self) -> List[str]:
        return [".csv"]

    def can_handle(self, file_path: str, preview_header: bytes) -> bool:
        ext = os.path.splitext(file_path)[1].lower()
        if ext == ".csv":
            try:
                snippet = preview_header.decode("utf-8", errors="ignore").lower()
                return "grouping" in snippet or ("extra" in snippet and "fav" in snippet)
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

        try:
            with open(file_path, "r", encoding="utf-8-sig", errors="replace", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    title = row.get("name") or row.get("Name") or "Bez tytułu"
                    url = row.get("url") or row.get("URL") or ""
                    username = row.get("username") or row.get("Username") or ""
                    password_val = row.get("password") or row.get("Password") or ""
                    notes = row.get("extra") or row.get("Notes") or ""
                    grouping = row.get("grouping") or row.get("Grouping") or "Loginy"
                    raw_totp = row.get("totp") or ""

                    totp = ""
                    if raw_totp.startswith("otpauth://"):
                        parsed = parse_otpauth_uri(raw_totp)
                        totp = parsed[0] if parsed else raw_totp
                    else:
                        totp = sanitize_secret(raw_totp)

                    fav_val = str(row.get("fav", "0")).strip()
                    favorite = fav_val in ["1", "true", "yes"]

                    result.add_item(ImportItem(
                        title=title,
                        category=grouping if grouping else "Loginy",
                        username=username,
                        password=password_val,
                        url=url,
                        totp_secret=totp,
                        notes=notes,
                        favorite=favorite
                    ))
        except Exception as e:
            result.add_error(f"Błąd podczas wczytywania pliku LastPass: {str(e)}")

        result.success = len(result.items) > 0 and len(result.errors) == 0
        return result
