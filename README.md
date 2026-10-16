# 🛡️ KeyStead Manager - Profesjonalny Menedżer Haseł

Nowoczesny, bezpieczny menedżer haseł o architekturze **Zero-Knowledge**, stworzony w Pythonie z eleganckim, w pełni responsywnym interfejsem (`CustomTkinter`). Zamiast wyskakujących okien dialogowych aplikacja posiada **płynnie wysuwany z prawej strony panel boczny (Sliding Drawer)**, obsługę **kopii zapasowych w chmurze** (WebDAV / Nextcloud, Google Drive, OneDrive, Dropbox, USB), **kreator importu** (Bitwarden, KeePass, 1Password, LastPass, przeglądarki), **Kosz z opcją przywracania**, **wizualizator kart płatniczych** oraz **Centrum Audytu Wycieków (HIBP)**.

---

## ⬇️ Pobieranie (Windows)

Najnowsza wersja: **[Wydania → najnowsze](https://github.com/facior/KeyStead/releases/latest)**

- `KeyStead-Manager-Setup-X.Y.Z.exe` – instalator (bez uprawnień administratora; skrót w menu Start),
- `KeyStead-Manager-X.Y.Z-portable.zip` – wersja przenośna, bez instalacji.

Aplikacja sama sprawdza nowe wersje i instaluje je po kliknięciu – wyłącznie wydania z poprawnym podpisem
wydawcy (`SHA256SUMS.sig`, klucz Ed25519). Przy pierwszym uruchomieniu Windows może pokazać ostrzeżenie
SmartScreen: *Więcej informacji → Uruchom mimo to*.

Serwer synchronizacji dla firm i zespołów (Linux, panel WEB administratora): **[facior/KeyStead-Manager](https://github.com/facior/KeyStead-Manager)**.

---

## 🚀 Uruchomienie z kodu źródłowego

1. Uruchomienie za pomocą skrótu:
   - Kliknij dwukrotnie plik `uruchom.bat` w folderze głównym.

2. LUB ręcznie z poziomu wiersza poleceń / PowerShell:
   ```powershell
   python -m pip install -r requirements.txt
   python main.py
   ```

---

## 🔒 Architektura Bezpieczeństwa (Security Model)

- **Zero-Knowledge Encryption**: Twoje hasła są szyfrowane i deszyfrowane wyłącznie lokalnie na Twoim komputerze.
- **Argon2id (RFC 9106)**: Zwycięzca konkursu Password Hashing Competition. Odporny na ataki brute-force z wykorzystaniem GPU/ASIC (64 MB pamięci RAM, 4 wątki, sól 256-bitowa).
- **AES-256-GCM (NIST Authenticated Encryption)**: Uwierzytelnione szyfrowanie symetryczne z 96-bitowym losowym wektorem inicjalizacyjnym (Nonce) oraz 128-bitowym tagiem uwierzytelniającym. Zabezpiecza dane przed podsłuchem oraz jakimkolwiek manipulowaniem zawartością pliku.
- **Weryfikacja wycieków haseł (Have I Been Pwned z k-Anonymity)**: Sprawdzanie czy hasło figuruje w globalnych wyciekach danych bez wysyłania hasła przez sieć (wysyłane jest jedynie pierwsze 5 znaków skrótu SHA-1).
- **Centrum Audytu Bezpieczeństwa (Watchtower)**: Kompleksowy raport kondycji sejfu:
  - 🚨 Wykrywanie wyciekłych haseł w sieci (HIBP)
  - 🔁 Wykrywanie powtórzonych haseł współdzielonych przez różne konta
  - ⚠️ Wykrywanie słabych haseł o niskiej entropii
  - 🛡️ Identyfikacja kont bez zabezpieczenia 2FA / TOTP
  - ⏳ Wykrywanie starych haseł (niezmienianych > 180 dni)
  - Przycisk szybkiej naprawy i bezpośredniego wygenerowania nowego hasła
- **Ochrona Schowka**: Po skopiowaniu hasła do schowka systemowego, uruchamiany jest timer bezpieczeństwa (domyślnie 30 sekund), który bezpowrotnie usuwa hasło ze schowka.
- **Automatyczna blokada (Auto-lock)**: Sejf automatycznie blokuje się po określonym czasie bezczynności użytkownika.
- **Plik-klucz (Keyfile)**: Opcjonalne dodatkowe zabezpieczenie sejfu drugim składnikiem w postaci pliku z dysku (np. pendrive'a).

---

## 📥 Import z Innych Menedżerów Haseł

Program zawiera uniwersalny **Kreator Importu**, który potrafi automatycznie rozpoznać format pliku lub pozwolić na ręczny wybór:

1. **Bitwarden**:
   - Eksport nieszyfrowany JSON (`folders`, `items`, typy: Login, Bezpieczna notatka, Karta płatnicza, Tożsamość, kody TOTP, pola niestandardowe).
   - Eksport CSV Bitwarden.
2. **KeePass**:
   - Bezpośredni odczyt baz **`.kdbx`** (wymaga podania hasła bazy KeePass oraz opcjonalnego pliku klucza).
   - Eksport XML oraz CSV z KeePass.
3. **1Password**:
   - Format **`.1pux`** (archiwa ZIP z eksportem 1Password).
   - Eksport CSV z 1Password.
4. **LastPass**:
   - Eksport CSV (url, login, hasło, notatki, grupy, TOTP).
5. **Przeglądarki internetowe**:
   - Eksport CSV z Google Chrome, Microsoft Edge, Brave, Mozilla Firefox.

### Rozwiązywanie konfliktów duplikatów:
- *Pomiń istniejące wpisy*
- *Dodaj wszystkie jako nowe*
- *Zaktualizuj istniejące wpisy*

---

## ☁️ Kopie Zapasowe i Chmura (Backup Center)

Wszystkie kopie zapasowe przed wysłaniem są **w pełni zaszyfrowane kluczem głównym sejfu (AES-256-GCM)** z dołączoną sumą kontrolną SHA-256.

1. **Dysk lokalny / Nośnik USB / Dysk sieciowy**:
   - Automatyczne tworzenie kopii ze znacznikiem czasu (`sejf_backup_YYYYMMDD_HHMMSS.vault`).
   - Automatyczna rotacja starszych kopii (np. zachowywanie ostatnich 15 wersji).
2. **WebDAV (Nextcloud / ownCloud / Synology NAS / QNAP)**:
   - Połączenie przez HTTPS z dowolnym serwerem WebDAV.
   - Obsługa autoryzacji login/hasło oraz tokenów aplikacji (App passwords).
   - Automatyczne tworzenie katalogu docelowego (`MKCOL`) i transfer pliku (`PUT`).
3. **Dysk Google / Microsoft OneDrive / Dropbox – logowanie w przeglądarce**:
   - Przycisk *Zaloguj przez Google / Microsoft / Dropbox* otwiera oficjalną stronę logowania dostawcy (OAuth 2.0 + PKCE). Aplikacja nigdy nie widzi hasła do konta chmury.
   - Tokeny dostępu są przechowywane wyłącznie w zaszyfrowanym pliku sejfu i odświeżane automatycznie.
   - Kopie trafiają do folderu `KeyStead-Backups` (Google Drive: zakres `drive.file` – aplikacja widzi tylko utworzone przez siebie pliki).
   - Alternatywnie: zapis do lokalnego folderu synchronizacji (Google Drive for Desktop, OneDrive, Dropbox).
   - **Jednorazowa konfiguracja:** każdy dostawca wymaga zarejestrowania aplikacji i wpisania jej *Client ID* w sekcji *Konfiguracja logowania do chmury* (instrukcja krok po kroku pod przyciskiem *❓ Jak uzyskać Client ID*). Adres przekierowania: `http://localhost:53682/`.
4. **Automatyczny backup w tle**:
   - Opcja automatycznego tworzenia kopii na wszystkich skonfigurowanych platformach przy każdym zapisie wpisu (w osobnym wątku, bez zacinania interfejsu).

---

## 🌐 Własny Serwer Synchronizacji (Ubuntu + Tailscale)

Sejf może być synchronizowany między komputerami (np. dom ↔ praca) przez własny serwer na Linuksie.
Serwer przechowuje wyłącznie zaszyfrowany plik i historię wersji – hasło główne nigdy nie opuszcza Twojego komputera.
W aplikacji: ekran logowania → zakładka **🌐 Serwer**. Instalacja i konfiguracja: [server/README.md](server/README.md).

---

## 🔑 Dodatkowe Funkcje

- **Wbudowany Authenticator TOTP (2FA)**:
  - Generuje kody dwuskładnikowe zgodnie z RFC 6238.
  - Odliczanie na żywo z paskiem postępu (30 sekund).
  - Obsługuje linki `otpauth://totp/...` wklejane prosto z kodów QR!
- **Generator Haseł i Passphrase (Diceware)**:
  - Losowe hasła o regulowanej długości (8-64 znaków) z wykluczeniem mylących znaków (`0, O, 1, l, I`).
  - Hasła wielowyrazowe (łatwe do zapamiętania, a kryptograficznie silne frazy).
  - Wskaźnik siły oraz entropii hasła w bitach.
- **Wyszukiwanie Błyskawiczne**:
  - Filtrowanie w czasie rzeczywistym po tytule, loginie, adresie URL, notatkach i tagach.
- **Historia haseł**:
  - Każda zmiana hasła we wpisie zachowuje poprzednie hasło w historii wraz z datą archiwizacji.

---

## 🧪 Testy Jednostkowe

Pakiet posiada zestaw 121 testów weryfikujących kryptografię, parsery, import, audyt, logowanie OAuth, zabezpieczenia, kopie zapasowe, serwer synchronizacji i panel administratora:

```powershell
python -m unittest discover tests
```

---

## 📦 Budowanie pliku wykonywalnego (.exe)

Aplikację można skompilować do samodzielnego pliku wykonywalnego na system Windows za pomocą PyInstaller:

```powershell
pyinstaller --noconsole --onefile --name "KeyStead" main.py
```
Plik `.exe` znajdzie się w katalogu `dist/`.


## Wersje, autor i licencja

- **Numeracja wersji:** pierwsze dwie liczby są wspólne dla aplikacji i serwera (nowe funkcje wydawane razem),
  ostatnia oznacza poprawki tylko w jednej części. Aplikacja **2.0.x** współpracuje z serwerem **2.0.x** i nowszym.
- **Autor:** Łukasz Kubieniec – [github.com/facior](https://github.com/facior)
- **Licencja:** © 2026 Łukasz Kubieniec. Wszelkie prawa zastrzeżone. Oprogramowanie zastrzeżone – udostępnienie kodu
  nie oznacza udzielenia licencji; szczegóły w pliku [LICENSE](LICENSE).
