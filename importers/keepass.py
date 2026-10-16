"""
Importer danych z menedżera KeePass (obsługuje bazy .kdbx oraz eksport XML i CSV).
"""

import csv
import os
import xml.etree.ElementTree as ET
from typing import Optional, List
from importers.base import BaseImporter, ImportResult, ImportItem
from core.totp_service import parse_otpauth_uri, sanitize_secret

try:
    from pykeepass import PyKeePass
    HAS_PYKEEPASS = True
except ImportError:
    HAS_PYKEEPASS = False

# Limity parametrów funkcji wyprowadzania klucza z nagłówka .kdbx – sprawdzane PRZED otwarciem bazy, bo
# pykeepass liczy klucz jeszcze przed weryfikacją hasła (złośliwy plik mógłby zawiesić aplikację lub zająć GB RAM).
# Domyślne wartości KeePass/KeePassXC są wielokrotnie mniejsze.
MAX_KDBX_FILE_BYTES = 200 * 1024 * 1024
MAX_AES_ROUNDS = 50_000_000
MAX_ARGON2_MEMORY = 1024 * 1024 * 1024
MAX_ARGON2_ITERATIONS = 1000
MAX_ARGON2_PARALLELISM = 64
_KDBX_SIG = (0x9AA2D903, 0xB54BFB67)


def _variant_dict(data: bytes) -> dict:
    """VariantDictionary z nagłówka KDBX4 (parametry KDF): klucz -> wartość liczbowa/bajty."""
    import struct
    out, pos = {}, 2  # 2 bajty wersji
    while pos < len(data):
        vtype = data[pos]
        pos += 1
        if vtype == 0:
            break
        (klen,) = struct.unpack_from("<I", data, pos)
        pos += 4
        key = data[pos:pos + klen].decode("utf-8", "replace")
        pos += klen
        (vlen,) = struct.unpack_from("<I", data, pos)
        pos += 4
        raw = data[pos:pos + vlen]
        pos += vlen
        if vtype in (0x04, 0x05) and vlen in (4, 8):      # UInt32 / UInt64
            out[key] = int.from_bytes(raw, "little")
        else:
            out[key] = raw
    return out


def check_kdbx_header(path: str) -> str:
    """Zwraca opis problemu (plik odrzucony) albo pusty tekst, gdy parametry są rozsądne."""
    import struct
    try:
        if os.path.getsize(path) > MAX_KDBX_FILE_BYTES:
            return "Plik bazy KeePass jest zbyt duży."
        with open(path, "rb") as f:
            head = f.read(64 * 1024)
        sig1, sig2, minor, major = struct.unpack_from("<IIHH", head, 0)
        if (sig1, sig2) != _KDBX_SIG:
            return "To nie jest baza KeePass (.kdbx)."
        pos, wide = 12, major >= 4
        while pos < len(head):
            fid = head[pos]
            if wide:
                (size,) = struct.unpack_from("<I", head, pos + 1)
                pos += 5
            else:
                (size,) = struct.unpack_from("<H", head, pos + 1)
                pos += 3
            data = head[pos:pos + size]
            pos += size
            if fid == 0:
                break
            if fid == 6 and len(data) == 8:  # KDBX3: TransformRounds (AES-KDF)
                if int.from_bytes(data, "little") > MAX_AES_ROUNDS:
                    return "Baza KeePass ma nierealnie dużą liczbę rund szyfrowania – plik odrzucony."
            if fid == 11:  # KDBX4: KdfParameters
                params = _variant_dict(data)
                if int(params.get("R", 0)) > MAX_AES_ROUNDS:
                    return "Baza KeePass ma nierealnie dużą liczbę rund szyfrowania – plik odrzucony."
                if (int(params.get("M", 0)) > MAX_ARGON2_MEMORY or int(params.get("I", 0)) > MAX_ARGON2_ITERATIONS
                        or int(params.get("P", 0)) > MAX_ARGON2_PARALLELISM):
                    return "Baza KeePass wymaga nierealnie dużo pamięci lub obliczeń (Argon2) – plik odrzucony."
        return ""
    except (OSError, struct.error, IndexError, ValueError):
        return "Nie udało się odczytać nagłówka bazy KeePass – plik jest uszkodzony."


class KeePassImporter(BaseImporter):
    @property
    def name(self) -> str:
        return "KeePass (.kdbx / XML / CSV)"

    @property
    def supported_extensions(self) -> List[str]:
        return [".kdbx", ".xml", ".csv"]

    def can_handle(self, file_path: str, preview_header: bytes) -> bool:
        ext = os.path.splitext(file_path)[1].lower()
        if ext == ".kdbx":
            # Sygnatury binarne KeePass KDBX: 0x9AA2D903 lub 0xB54BFB67
            return preview_header.startswith(b"\x03\xd9\xa2\x9a") or preview_header.startswith(b"\x67\xfb\x4b\xb5")
        elif ext == ".xml":
            try:
                snippet = preview_header.decode("utf-8", errors="ignore").lower()
                return "<keepassfile>" in snippet or "<pwentry>" in snippet
            except Exception:
                return False
        elif ext == ".csv":
            try:
                snippet = preview_header.decode("utf-8", errors="ignore").lower()
                return "account" in snippet and ("login name" in snippet or "web site" in snippet)
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
            if ext == ".kdbx":
                if not HAS_PYKEEPASS:
                    result.add_error("Biblioteka pykeepass nie jest zainstalowana.")
                    return result
                self._parse_kdbx(file_path, password, keyfile_path, result)
            elif ext == ".xml":
                self._parse_xml(file_path, result)
            elif ext == ".csv":
                self._parse_csv(file_path, result)
            else:
                result.add_error(f"Nieobsługiwane rozszerzenie: {ext}")
        except Exception as e:
            result.add_error(f"Błąd podczas wczytywania pliku KeePass: {str(e)}")

        result.success = len(result.items) > 0 and len(result.errors) == 0
        return result

    def _parse_kdbx(
        self,
        file_path: str,
        password: Optional[str],
        keyfile_path: Optional[str],
        result: ImportResult
    ) -> None:
        if not password and not keyfile_path:
            result.add_error("Do otwarcia bazy KeePass (.kdbx) wymagane jest hasło lub plik klucza.")
            return

        problem = check_kdbx_header(file_path)
        if problem:
            result.add_error(problem)
            return

        try:
            kp = PyKeePass(filename=file_path, password=password, keyfile=keyfile_path)
        except Exception as e:
            result.add_error(f"Błędne hasło główne lub uszkodzona baza KeePass: {str(e)}")
            return

        for entry in kp.entries:
            # Pomijamy wpisy z kosza jeśli istnieją
            if entry.group and entry.group.name and "Recycle" in entry.group.name:
                continue

            title = entry.title or "Bez tytułu"
            username = entry.username or ""
            pwd = entry.password or ""
            url = entry.url or ""
            notes = entry.notes or ""
            group_name = entry.group.name if (entry.group and entry.group.name != "Root") else "Loginy"
            tags = [t.strip() for t in (entry.tags or []) if t.strip()]

            # Odczyt TOTP
            totp = ""
            if hasattr(entry, "otp") and entry.otp:
                raw_otp = str(entry.otp)
                if raw_otp.startswith("otpauth://"):
                    parsed = parse_otpauth_uri(raw_otp)
                    totp = parsed[0] if parsed else raw_otp
                else:
                    totp = sanitize_secret(raw_otp)

            custom_fields = {}
            if hasattr(entry, "custom_properties") and entry.custom_properties:
                for k, v in entry.custom_properties.items():
                    if k and v is not None and k.lower() not in ["otp", "totp seed"]:
                        custom_fields[str(k)] = str(v)
                    elif k.lower() in ["otp", "totp seed"] and not totp:
                        totp = sanitize_secret(str(v))

            result.add_item(ImportItem(
                title=title,
                category=group_name,
                username=username,
                password=pwd,
                url=url,
                totp_secret=totp,
                notes=notes,
                tags=tags,
                custom_fields=custom_fields
            ))

    def _parse_xml(self, file_path: str, result: ImportResult) -> None:
        tree = ET.parse(file_path)
        root = tree.getroot()

        # KeePass XML ma elementy <Entry> lub <PwEntry>
        entries = root.findall(".//Entry")
        if not entries:
            entries = root.findall(".//PwEntry")

        for entry_el in entries:
            field_dict = {}
            for str_el in entry_el.findall("./String"):
                key_el = str_el.find("Key")
                val_el = str_el.find("Value")
                if key_el is not None and key_el.text:
                    val_text = val_el.text if val_el is not None and val_el.text else ""
                    field_dict[key_el.text] = val_text

            title = field_dict.get("Title", "Bez tytułu")
            username = field_dict.get("UserName", "")
            password = field_dict.get("Password", "")
            url = field_dict.get("URL", "")
            notes = field_dict.get("Notes", "")

            # Szukamy TOTP
            raw_totp = field_dict.get("otp") or field_dict.get("TOTP Seed") or ""
            totp = ""
            if raw_totp.startswith("otpauth://"):
                parsed = parse_otpauth_uri(raw_totp)
                totp = parsed[0] if parsed else raw_totp
            else:
                totp = sanitize_secret(raw_totp)

            custom_fields = {}
            for k, v in field_dict.items():
                if k not in ["Title", "UserName", "Password", "URL", "Notes", "otp", "TOTP Seed"]:
                    custom_fields[k] = v

            result.add_item(ImportItem(
                title=title,
                category="Loginy",
                username=username,
                password=password,
                url=url,
                totp_secret=totp,
                notes=notes,
                custom_fields=custom_fields
            ))

    def _parse_csv(self, file_path: str, result: ImportResult) -> None:
        with open(file_path, "r", encoding="utf-8-sig", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                title = row.get("Account") or row.get("Title") or "Bez tytułu"
                username = row.get("Login Name") or row.get("Username") or ""
                password = row.get("Password") or ""
                url = row.get("Web Site") or row.get("URL") or ""
                notes = row.get("Comments") or row.get("Notes") or ""
                group = row.get("Group") or "Loginy"

                result.add_item(ImportItem(
                    title=title,
                    category=group,
                    username=username,
                    password=password,
                    url=url,
                    notes=notes
                ))
