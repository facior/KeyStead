"""
Importer haseł wyeksportowanych z przeglądarek internetowych:
Google Chrome, Microsoft Edge, Brave, Mozilla Firefox (CSV).
"""

import csv
import os
from typing import Optional, List
from importers.base import BaseImporter, ImportResult, ImportItem


class BrowserImporter(BaseImporter):
    @property
    def name(self) -> str:
        return "Przeglądarki (Chrome / Edge / Firefox CSV)"

    @property
    def supported_extensions(self) -> List[str]:
        return [".csv"]

    def can_handle(self, file_path: str, preview_header: bytes) -> bool:
        ext = os.path.splitext(file_path)[1].lower()
        if ext == ".csv":
            try:
                snippet = preview_header.decode("utf-8", errors="ignore").lower()
                return ("httprealm" in snippet) or ("formactionorigin" in snippet) or ("name,url,username,password" in snippet)
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
                    url = row.get("url") or row.get("URL") or ""
                    title = row.get("name") or row.get("Name") or url or "Konto internetowe"
                    username = row.get("username") or row.get("Username") or ""
                    pwd = row.get("password") or row.get("Password") or ""

                    result.add_item(ImportItem(
                        title=title,
                        category="Loginy",
                        username=username,
                        password=pwd,
                        url=url,
                        notes=""
                    ))
        except Exception as e:
            result.add_error(f"Błąd podczas wczytywania CSV przeglądarki: {str(e)}")

        result.success = len(result.items) > 0 and len(result.errors) == 0
        return result
