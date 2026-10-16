"""
Importer danych z menedżera Bitwarden (obsługuje format JSON oraz CSV).
"""

import csv
import json
import os
from typing import Optional, List
from importers.base import BaseImporter, ImportResult, ImportItem
from core.totp_service import parse_otpauth_uri, sanitize_secret


class BitwardenImporter(BaseImporter):
    @property
    def name(self) -> str:
        return "Bitwarden (JSON / CSV)"

    @property
    def supported_extensions(self) -> List[str]:
        return [".json", ".csv"]

    def can_handle(self, file_path: str, preview_header: bytes) -> bool:
        ext = os.path.splitext(file_path)[1].lower()
        if ext == ".json":
            try:
                snippet = preview_header.decode("utf-8", errors="ignore").lower()
                return '"items"' in snippet or '"folders"' in snippet
            except Exception:
                return False
        elif ext == ".csv":
            try:
                snippet = preview_header.decode("utf-8", errors="ignore").lower()
                return "login_username" in snippet or ("login_uri" in snippet and "login_password" in snippet)
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
            if ext == ".json":
                self._parse_json(file_path, result)
            elif ext == ".csv":
                self._parse_csv(file_path, result)
            else:
                result.add_error(f"Nieobsługiwane rozszerzenie: {ext}")
        except Exception as e:
            result.add_error(f"Błąd podczas przetwarzania pliku Bitwarden: {str(e)}")

        result.success = len(result.items) > 0 and len(result.errors) == 0
        return result

    def _parse_json(self, file_path: str, result: ImportResult) -> None:
        with open(file_path, "r", encoding="utf-8-sig", errors="replace", newline="") as f:
            data = json.load(f)

        if data.get("encrypted") is True:
            result.add_error("Plik JSON Bitwarden jest zaszyfrowany. Wyeksportuj sejf z Bitwarden jako niezaszyfrowany JSON.")
            return

        folder_map = {}
        for folder in data.get("folders", []):
            if isinstance(folder, dict) and "id" in folder and "name" in folder:
                folder_map[folder["id"]] = folder["name"]

        items = data.get("items", [])
        for item in items:
            name = item.get("name", "Bez nazwy")
            notes = item.get("notes") or ""
            favorite = bool(item.get("favorite", False))
            folder_id = item.get("folderId")
            folder_name = folder_map.get(folder_id, "")

            item_type = item.get("type", 1)
            # Typy: 1 = Login, 2 = Bezpieczna notatka, 3 = Karta, 4 = Tożsamość
            if item_type == 1:
                category = folder_name or "Loginy"
            elif item_type == 2:
                category = "Bezpieczne notatki"
            elif item_type == 3:
                category = "Karty płatnicze"
            elif item_type == 4:
                category = "Tożsamości"
            else:
                category = folder_name or "Loginy"

            username = ""
            password = ""
            url = ""
            totp = ""

            login_info = item.get("login") or {}
            if isinstance(login_info, dict):
                username = login_info.get("username") or ""
                password = login_info.get("password") or ""
                uris = login_info.get("uris") or []
                if uris and isinstance(uris, list) and isinstance(uris[0], dict):
                    url = uris[0].get("uri", "")

                raw_totp = login_info.get("totp") or ""
                if raw_totp.startswith("otpauth://"):
                    parsed = parse_otpauth_uri(raw_totp)
                    totp = parsed[0] if parsed else raw_totp
                else:
                    totp = sanitize_secret(raw_totp)

            # Pola dodatkowe (custom fields)
            custom_fields = {}
            for field in item.get("fields", []):
                fname = field.get("name")
                fval = field.get("value")
                if fname and fval is not None:
                    custom_fields[str(fname)] = str(fval)

            # Obsługa kart płatniczych
            card_info = item.get("card") or {}
            if isinstance(card_info, dict) and card_info:
                if card_info.get("cardholderName"):
                    custom_fields["Właściciel karty"] = card_info["cardholderName"]
                if card_info.get("number"):
                    custom_fields["Numer karty"] = card_info["number"]
                if card_info.get("expMonth") and card_info.get("expYear"):
                    custom_fields["Ważność"] = f"{card_info['expMonth']}/{card_info['expYear']}"
                if card_info.get("code"):
                    custom_fields["CVV/CVC"] = card_info["code"]

            result.add_item(ImportItem(
                title=name,
                category=category,
                username=username,
                password=password,
                url=url,
                totp_secret=totp,
                notes=notes,
                custom_fields=custom_fields,
                favorite=favorite
            ))

    def _parse_csv(self, file_path: str, result: ImportResult) -> None:
        with open(file_path, "r", encoding="utf-8-sig", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                name = row.get("name") or row.get("Name") or "Bez tytułu"
                username = row.get("login_username") or row.get("Username") or ""
                password = row.get("login_password") or row.get("Password") or ""
                url = row.get("login_uri") or row.get("URI") or row.get("URL") or ""
                notes = row.get("notes") or row.get("Notes") or ""
                folder = row.get("folder") or "Loginy"
                raw_totp = row.get("login_totp") or ""

                totp = ""
                if raw_totp.startswith("otpauth://"):
                    parsed = parse_otpauth_uri(raw_totp)
                    totp = parsed[0] if parsed else raw_totp
                else:
                    totp = sanitize_secret(raw_totp)

                fav_val = str(row.get("favorite", "0")).lower()
                favorite = fav_val in ["1", "true", "yes"]

                result.add_item(ImportItem(
                    title=name,
                    category=folder if folder else "Loginy",
                    username=username,
                    password=password,
                    url=url,
                    totp_secret=totp,
                    notes=notes,
                    favorite=favorite
                ))
