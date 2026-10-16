"""
Widok logowania / tworzenia nowego sejfu haseł (Unlock / Create Vault View).
"""

import os
import json
import socket
import threading
from urllib.parse import urlparse
from typing import Optional, Callable, List
import customtkinter as ctk
from tkinter import filedialog, messagebox

from core.paths import RECENT_VAULTS_FILE, ensure_app_dir
from core.vault import Vault
from core.storage import save_vault, load_vault, VAULT_FILE_EXTENSION
from core.crypto import (
    InvalidPasswordOrCorruptDataError,
    InvalidVaultHeaderError,
    encrypt_payload
)
from sync import EmptyServerError, ServerProfile, SyncSession, delete_profile, load_profile, save_profile
from sync.client import AuthError, CertificateError, TotpRequiredError, check_server_url, enroll_device
from sync.session import read_cached_branding, read_cached_policy
from ui.quick_unlock_ui import file_target, quick, server_target
from ui.recovery_ui import NewPasswordDialog, PasswordPrompt
from core.crypto import seal, unseal_with_recovery_code
from core.storage import write_encrypted_file
from sync.client import RemoteVaultClient
from core.paths import branding_logo_path
from core.version import APP_VERSION
from ui.totp_dialog import TotpDialog
from sync.tailscale import discover_servers
from sync.tls import fetch_server_certificate, fingerprint_of_pem, save_pinned_certificate
from core.generator import evaluate_password_strength, check_master_password
from ui.theme import (
    FONT_TITLE, FONT_SUBTITLE, FONT_BODY, FONT_BODY_BOLD, FONT_SMALL,
    COLOR_PRIMARY, COLOR_PRIMARY_HOVER, COLOR_CARD_DARK, COLOR_CARD_HOVER, COLOR_PANEL_DARK,
    COLOR_SUCCESS, COLOR_DANGER, COLOR_BORDER, COLOR_TEXT_PRIMARY, COLOR_TEXT_MUTED
)


RECENT_VAULTS_CONFIG = RECENT_VAULTS_FILE
_AUTO_PROMPTED = False  # automatyczne pytanie o Windows Hello tylko raz – przy starcie aplikacji


def _safe(fn):
    """Wynik albo wyjątek (dla pracy w wątku tła – błąd trafia do interfejsu zamiast ginąć)."""
    try:
        return fn()
    except Exception as e:
        return e


def load_recent_vaults() -> List[str]:
    try:
        if os.path.exists(RECENT_VAULTS_CONFIG):
            with open(RECENT_VAULTS_CONFIG, "r", encoding="utf-8") as f:
                data = json.load(f)
                return [p for p in data if os.path.exists(p)]
    except Exception:
        pass
    return []


def save_recent_vault(path: str) -> None:
    try:
        recents = load_recent_vaults()
        if path in recents:
            recents.remove(path)
        recents.insert(0, path)
        recents = recents[:8]
        ensure_app_dir()
        with open(RECENT_VAULTS_CONFIG, "w", encoding="utf-8") as f:
            json.dump(recents, f)
    except Exception:
        pass


class LoginView(ctk.CTkFrame):
    def __init__(
        self,
        parent,
        on_vault_unlocked: Callable[[Vault, str, str, Optional[bytes]], None],
        on_open_wizard: Optional[Callable[[], None]] = None,
        on_remote_unlocked: Optional[Callable[[Vault, str, Optional[bytes], SyncSession], None]] = None
    ):
        super().__init__(parent, fg_color="transparent")
        self.on_vault_unlocked = on_vault_unlocked
        self.on_open_wizard = on_open_wizard
        self.on_remote_unlocked = on_remote_unlocked
        self.recent_vaults = load_recent_vaults()
        self.server_profile: Optional[ServerProfile] = load_profile()
        self._pinned_ca: dict = {}  # certyfikaty zaakceptowane w tej sesji logowania (adres → plik)
        self._enroll_totp = ""           # kod 2FA do ponowienia dołączenia urządzenia
        self._pending_totp_setup = None  # konfiguracja 2FA zwrócona przez serwer przy pierwszym urządzeniu
        self._logo_image = None
        self.unlock_method = "password"  # „hello”, gdy sejf odblokowano przez Windows Hello

        self._build_ui()
        # Dostępność Windows Hello sprawdzana w tle; przyciski pojawiają się, gdy jest zapisane odblokowanie
        quick.check_availability(lambda _ok: self._refresh_hello_buttons(auto=True), widget=self)

    def _show_about(self):
        from ui.about_view import show_about_window
        profile = getattr(self, "server_profile", None)
        show_about_window(self, server_url=profile.url if profile else "")

    def _build_ui(self):
        # Wycentrowana karta logowania
        card = ctk.CTkFrame(self, fg_color=COLOR_PANEL_DARK, corner_radius=16, width=540)
        card.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkButton(self, text=f"KeyStead Manager {APP_VERSION}  ·  O programie", font=FONT_SMALL, height=22,
                      fg_color="transparent", hover_color=COLOR_PANEL_DARK, text_color=COLOR_TEXT_MUTED,
                      command=self._show_about).place(relx=1.0, rely=1.0, anchor="se", x=-10, y=-6)

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=35, pady=35)

        # Logo / Branding
        logo_label = ctk.CTkLabel(
            inner,
            text="🛡️ KEYSTEAD MANAGER",
            font=(FONT_TITLE[0], 24, "bold"),
            text_color=COLOR_PRIMARY
        )
        logo_label.pack(pady=(0, 4))

        subtitle = ctk.CTkLabel(
            inner,
            text="Profesjonalny menedżer haseł z kopią chmurową",
            font=FONT_BODY,
            text_color=COLOR_TEXT_MUTED
        )
        subtitle.pack(pady=(0, 10))

        # Przycisk samouczka
        ctk.CTkButton(
            inner,
            text="✨ Nowy w aplikacji? Uruchom Asystenta Krok po Kroku",
            font=FONT_SMALL,
            fg_color=COLOR_CARD_DARK,
            hover_color=COLOR_CARD_HOVER,
            corner_radius=8,
            height=30,
            command=self._open_wizard
        ).pack(pady=(0, 15))

        # Komunikat o błędzie (ukryty)
        self.error_label = ctk.CTkLabel(
            inner,
            text="",
            font=FONT_BODY_BOLD,
            text_color=COLOR_DANGER,
            wraplength=440
        )
        self.error_label.pack(pady=(0, 8))

        # Zakładki: Odblokuj / Utwórz nowy / Serwer
        self.tabview = ctk.CTkTabview(inner, height=360, width=460)
        self.tabview.pack(fill="both", expand=True)

        self.tab_unlock = self.tabview.add("Odblokuj Sejf")
        self.tab_create = self.tabview.add("Utwórz Nowy Sejf")
        self.tab_server = self.tabview.add("🌐 Serwer")

        self._setup_unlock_tab()
        self._setup_create_tab()
        self._setup_server_tab()

        # Jeśli komputer jest już połączony z serwerem – to domyślny sposób logowania
        if self.server_profile:
            self.tabview.set("🌐 Serwer")

    def _setup_unlock_tab(self):
        f = self.tab_unlock

        # Wybór pliku sejfu
        ctk.CTkLabel(f, text="Plik bazy sejfu:", font=FONT_BODY_BOLD).pack(anchor="w", pady=(8, 2))
        file_box = ctk.CTkFrame(f, fg_color="transparent")
        file_box.pack(fill="x", pady=(0, 10))

        self.unlock_file_entry = ctk.CTkEntry(file_box, placeholder_text="Wskaż plik .vault...")
        if self.recent_vaults:
            self.unlock_file_entry.insert(0, self.recent_vaults[0])
        self.unlock_file_entry.pack(side="left", expand=True, fill="x", padx=(0, 8))

        ctk.CTkButton(file_box, text="Przeglądaj...", width=95, fg_color=COLOR_CARD_DARK, command=self._browse_unlock_file).pack(side="left")

        # Hasło główne
        ctk.CTkLabel(f, text="Hasło główne (Master Password):", font=FONT_BODY_BOLD).pack(anchor="w", pady=(2, 2))
        pwd_box = ctk.CTkFrame(f, fg_color="transparent")
        pwd_box.pack(fill="x", pady=(0, 10))

        self.unlock_pwd_entry = ctk.CTkEntry(pwd_box, show="•", placeholder_text="Wpisz hasło główne...")
        self.unlock_pwd_entry.pack(side="left", expand=True, fill="x", padx=(0, 6))
        self.unlock_pwd_entry.bind("<Return>", lambda e: self._do_unlock())

        self.unlock_eye_btn = ctk.CTkButton(pwd_box, text="👁", width=38, fg_color=COLOR_CARD_DARK, command=self._toggle_unlock_eye)
        self.unlock_eye_btn.pack(side="left")

        # Opcjonalny plik klucza
        key_box = ctk.CTkFrame(f, fg_color="transparent")
        key_box.pack(fill="x", pady=(0, 15))
        self.unlock_key_entry = ctk.CTkEntry(key_box, placeholder_text="Opcjonalny plik-klucz (Keyfile)...")
        self.unlock_key_entry.pack(side="left", expand=True, fill="x", padx=(0, 6))
        ctk.CTkButton(key_box, text="Klucz...", width=70, fg_color=COLOR_CARD_DARK, command=self._browse_unlock_keyfile).pack(side="left")

        # Przycisk Odblokuj
        self.unlock_btn = ctk.CTkButton(
            f,
            text="🔓 Odblokuj sejf",
            font=FONT_SUBTITLE,
            height=42,
            fg_color=COLOR_PRIMARY,
            hover_color=COLOR_PRIMARY_HOVER,
            command=self._do_unlock
        )
        self.unlock_btn.pack(fill="x", pady=(10, 0))

        self.hello_local_btn = ctk.CTkButton(
            f, text="🔐 Odblokuj przez Windows Hello", height=34, fg_color=COLOR_CARD_DARK,
            hover_color=COLOR_CARD_HOVER, command=self._hello_local
        )
        self.unlock_file_entry.bind("<FocusOut>", lambda e: self._refresh_hello_buttons())
        ctk.CTkButton(f, text="Nie pamiętam hasła", height=22, font=FONT_SMALL, fg_color="transparent",
                      hover_color=COLOR_CARD_HOVER, text_color=COLOR_TEXT_MUTED,
                      command=lambda: self._forgot_password("local")).pack(side="bottom", anchor="e", pady=(6, 0))

    # ------------------------------------------------------------- odzyskiwanie dostępu (kod odzyskiwania)
    def _forgot_password(self, mode: str):
        self.error_label.configure(text="", text_color=COLOR_DANGER)
        if mode == "local":
            path = self.unlock_file_entry.get().strip()
            if not path or not os.path.isfile(path):
                self.error_label.configure(text="Najpierw wskaż plik sejfu, do którego chcesz odzyskać dostęp.")
                return
            client = None
        else:
            profile = self.server_profile
            if not profile or not profile.token:
                self.error_label.configure(text="Ten komputer nie jest połączony z serwerem – poproś administratora "
                                                "o odzyskanie dostępu lub użyj kodu odzyskiwania przy pliku sejfu.")
                return
            path = None
            client = RemoteVaultClient(profile.url, profile.token, ca_file=profile.ca_file)
        code = PasswordPrompt(self, "Odzyskiwanie dostępu",
                              "Wpisz kod odzyskiwania (30 znaków, np. ABCDE-FGHJK-…). Myślniki i wielkość liter nie mają znaczenia.\n"
                              "Nie masz kodu? W firmie dostęp może przywrócić administrator.", secret=False).wait()
        if not code:
            return
        self.error_label.configure(text="🔑 Sprawdzanie kodu odzyskiwania...", text_color=COLOR_TEXT_MUTED)

        def _work():
            if client is None:
                with open(path, "rb") as fh:
                    blob, version = fh.read(), None
            else:
                blob, version = client.download()
            plaintext, ring = unseal_with_recovery_code(blob, code)
            return plaintext, ring, version

        def _checked(result):
            if isinstance(result, Exception):
                self.error_label.configure(text=f"❌ {result}", text_color=COLOR_DANGER)
                return
            plaintext, ring, version = result
            new_pwd = NewPasswordDialog(self, intro="Kod odzyskiwania poprawny. Ustaw nowe hasło główne – stary plik-klucz "
                                                    "(jeśli był używany) przestaje być wymagany.").wait()
            if not new_pwd:
                self.error_label.configure(text="Odzyskiwanie przerwane – hasło nie zostało zmienione.")
                return
            self.error_label.configure(text="🔑 Zapisywanie nowego hasła...", text_color=COLOR_TEXT_MUTED)
            self._run_bg(lambda: self._apply_recovery(plaintext, ring, version, new_pwd, path, client),
                         lambda res: self._recovered(res, mode, new_pwd))

        self._run_bg(lambda: _safe(_work), _checked)

    @staticmethod
    def _apply_recovery(plaintext, ring, version, new_pwd, path, client):
        try:
            data = json.loads(plaintext.decode("utf-8"))
            data["revision"] = int(data.get("revision", 0) or 0) + 1  # nowa treść (inne urządzenia przyjmą ją normalnie)
            blob = seal(json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8"), new_pwd, None, ring)
            if client is None:
                write_encrypted_file(path, blob)
            else:
                client.upload(blob, version)
            return None
        except Exception as e:
            return e

    def _recovered(self, error, mode: str, new_pwd: str):
        if error is not None:
            self.error_label.configure(text=f"❌ Nie udało się zapisać nowego hasła: {error}", text_color=COLOR_DANGER)
            return
        target = self._hello_local_target() if mode == "local" else self._hello_server_target()
        if target:
            quick.disable(target)  # zapisane dla Windows Hello stare hasło jest już nieaktualne
        messagebox.showinfo("Odzyskiwanie dostępu", "Nowe hasło główne zostało ustawione. Odblokowuję sejf.")
        if mode == "local":
            self.unlock_key_entry.delete(0, "end")
            self._do_unlock(password=new_pwd, keyfile=None)
        else:
            self.server_key_entry.delete(0, "end")
            self._do_server_unlock(password=new_pwd, keyfile=None)

    # ------------------------------------------------------------- Windows Hello
    def _hello_local_target(self) -> Optional[str]:
        path = self.unlock_file_entry.get().strip()
        return file_target(path) if path and os.path.isfile(path) else None

    def _hello_server_target(self) -> Optional[str]:
        p = self.server_profile
        return server_target(p.url, p.token) if p and p.token else None

    def _refresh_hello_buttons(self, auto: bool = False):
        if not self.winfo_exists():
            return
        local_ok = quick.can_use(self._hello_local_target())
        server_policy = read_cached_policy(self.server_profile) if self.server_profile else {}
        server_ok = quick.can_use(self._hello_server_target(), server_policy) and not self.server_fields.winfo_ismapped()
        if local_ok:
            self.hello_local_btn.pack(fill="x", pady=(8, 0))
        else:
            self.hello_local_btn.pack_forget()
        if server_ok:
            self.hello_server_btn.pack(fill="x", pady=(8, 0))
        else:
            self.hello_server_btn.pack_forget()
        # Przy starcie aplikacji od razu pytamy o Windows Hello (raz – nie po każdej blokadzie)
        global _AUTO_PROMPTED
        if auto and not _AUTO_PROMPTED and (local_ok or server_ok):
            _AUTO_PROMPTED = True
            on_server_tab = self.tabview.get() == "🌐 Serwer"
            if on_server_tab and server_ok:
                self.after(300, self._hello_server)
            elif not on_server_tab and local_ok:
                self.after(300, self._hello_local)

    def _hello_failed(self, error: Exception, password_entry):
        self.error_label.configure(text=f"🔐 {error}", text_color=COLOR_DANGER)
        password_entry.focus()

    def _hello_local(self):
        target = self._hello_local_target()
        if not target:
            return
        self.error_label.configure(text="🔐 Potwierdź tożsamość w oknie Windows Hello...", text_color=COLOR_TEXT_MUTED)
        self.hello_local_btn.configure(state="disabled")

        def _done(result):
            self.hello_local_btn.configure(state="normal")
            if isinstance(result, Exception):
                self._hello_failed(result, self.unlock_pwd_entry)
                return
            password, keyfile = result
            self.unlock_method = "hello"
            self._do_unlock(password=password, keyfile=keyfile)
        quick.unlock_async(self, target, {}, _done)

    def _hello_server(self):
        target = self._hello_server_target()
        if not target:
            return
        self.error_label.configure(text="🔐 Potwierdź tożsamość w oknie Windows Hello...", text_color=COLOR_TEXT_MUTED)
        self.hello_server_btn.configure(state="disabled")

        def _done(result):
            self.hello_server_btn.configure(state="normal")
            if isinstance(result, Exception):
                self._hello_failed(result, self.server_pwd_entry)
                return
            password, keyfile = result
            self.unlock_method = "hello"
            self._do_server_unlock(password=password, keyfile=keyfile)
        quick.unlock_async(self, target, read_cached_policy(self.server_profile), _done)

    def _setup_create_tab(self):
        f = self.tab_create

        ctk.CTkLabel(f, text="Gdzie zapisać nowy sejf:", font=FONT_BODY_BOLD).pack(anchor="w", pady=(6, 2))
        file_box = ctk.CTkFrame(f, fg_color="transparent")
        file_box.pack(fill="x", pady=(0, 8))

        self.create_path_entry = ctk.CTkEntry(file_box, placeholder_text="Ścieżka do nowego pliku .vault...")
        default_new_path = os.path.join(os.path.expanduser("~"), "Documents", "MojSejf.vault")
        self.create_path_entry.insert(0, default_new_path)
        self.create_path_entry.pack(side="left", expand=True, fill="x", padx=(0, 8))

        ctk.CTkButton(file_box, text="Wybierz...", width=95, fg_color=COLOR_CARD_DARK, command=self._browse_create_path).pack(side="left")

        # Nowe hasło i potwierdzenie
        ctk.CTkLabel(f, text="Hasło główne do sejfu:", font=FONT_BODY_BOLD).pack(anchor="w", pady=(2, 2))
        self.create_pwd1 = ctk.CTkEntry(f, show="•", placeholder_text="Silne hasło główne...")
        self.create_pwd1.pack(fill="x", pady=(0, 4))
        self.create_pwd1.bind("<KeyRelease>", self._on_create_pwd_typed)

        self.create_strength_bar = ctk.CTkProgressBar(f, height=5)
        self.create_strength_bar.pack(fill="x", pady=(0, 6))
        self.create_strength_bar.set(0)

        ctk.CTkLabel(f, text="Powtórz hasło główne:", font=FONT_BODY_BOLD).pack(anchor="w", pady=(2, 2))
        self.create_pwd2 = ctk.CTkEntry(f, show="•", placeholder_text="Powtórz hasło...")
        self.create_pwd2.pack(fill="x", pady=(0, 15))

        self.create_btn = ctk.CTkButton(
            f,
            text="✨ Utwórz zaszyfrowany sejf",
            font=FONT_SUBTITLE,
            height=40,
            fg_color=COLOR_SUCCESS,
            command=self._do_create_vault
        )
        self.create_btn.pack(fill="x", pady=(5, 0))

    def _toggle_unlock_eye(self):
        cur_show = self.unlock_pwd_entry.cget("show")
        if cur_show == "•":
            self.unlock_pwd_entry.configure(show="")
            self.unlock_eye_btn.configure(text="🔒")
        else:
            self.unlock_pwd_entry.configure(show="•")
            self.unlock_eye_btn.configure(text="👁")

    def _browse_unlock_file(self):
        p = filedialog.askopenfilename(
            title="Wybierz plik sejfu",
            filetypes=[("Pliki Sejfu", "*.vault"), ("Wszystkie pliki", "*.*")]
        )
        if p:
            self.unlock_file_entry.delete(0, "end")
            self.unlock_file_entry.insert(0, p)
            self.unlock_pwd_entry.focus()
            self._refresh_hello_buttons()

    def _browse_unlock_keyfile(self):
        p = filedialog.askopenfilename(title="Wybierz plik klucza")
        if p:
            self.unlock_key_entry.delete(0, "end")
            self.unlock_key_entry.insert(0, p)

    def _browse_create_path(self):
        p = filedialog.asksaveasfilename(
            title="Wybierz lokalizację nowego sejfu",
            defaultextension=".vault",
            filetypes=[("Plik Sejfu", "*.vault")]
        )
        if p:
            self.create_path_entry.delete(0, "end")
            self.create_path_entry.insert(0, p)

    def _on_create_pwd_typed(self, event=None):
        pwd = self.create_pwd1.get()
        if not pwd:
            self.create_strength_bar.set(0)
            return
        eval_res = evaluate_password_strength(pwd)
        self.create_strength_bar.set(eval_res["score"] / 4.0)
        self.create_strength_bar.configure(progress_color=eval_res["color"])

    def _do_unlock(self, password: Optional[str] = None, keyfile: Optional[bytes] = None):
        """Odblokowanie sejfu z pliku – hasłem z formularza albo danymi z Windows Hello."""
        file_path = self.unlock_file_entry.get().strip()
        from_hello = password is not None
        if not from_hello:
            self.unlock_method = "password"
            password = self.unlock_pwd_entry.get()
        key_path = "" if from_hello else self.unlock_key_entry.get().strip()

        self.error_label.configure(text="", text_color=COLOR_DANGER)

        if not file_path or not os.path.exists(file_path):
            self.error_label.configure(text="Wskazany plik sejfu nie istnieje.")
            return

        if not password:
            self.error_label.configure(text="Podaj hasło główne sejfu.")
            return

        keyfile_bytes = keyfile if from_hello else None
        if key_path:
            if not os.path.isfile(key_path):
                self.error_label.configure(text="Wskazany plik-klucz nie istnieje.")
                return
            with open(key_path, "rb") as kf:
                keyfile_bytes = kf.read()

        self.unlock_btn.configure(text="Deszyfrowanie i weryfikacja...", state="disabled")
        self.update_idletasks()

        vault = None
        try:
            vault = load_vault(file_path, password, keyfile_bytes)
        except InvalidPasswordOrCorruptDataError:
            if self.winfo_exists():
                self.error_label.configure(text="❌ Niepoprawne hasło główne (bądź plik klucza).")
                self.unlock_btn.configure(text="🔓 Odblokuj sejf", state="normal")
            return
        except InvalidVaultHeaderError:
            if self.winfo_exists():
                self.error_label.configure(text="❌ Plik nie jest prawidłowym sejfem lub jest uszkodzony.")
                self.unlock_btn.configure(text="🔓 Odblokuj sejf", state="normal")
            return
        except Exception as e:
            if self.winfo_exists():
                self.error_label.configure(text=f"Błąd odczytu: {str(e)}")
                self.unlock_btn.configure(text="🔓 Odblokuj sejf", state="normal")
            return

        # Przejście do widoku głównego sejfu (LoginView zostanie zniszczone)
        self.on_vault_unlocked(vault, password, file_path, keyfile_bytes)

    def _do_create_vault(self):
        save_path = self.create_path_entry.get().strip()
        p1 = self.create_pwd1.get()
        p2 = self.create_pwd2.get()

        self.error_label.configure(text="")

        if not save_path:
            self.error_label.configure(text="Podaj ścieżkę do pliku nowego sejfu.")
            return

        allowed, policy_msg = check_master_password(p1)
        if not allowed:
            self.error_label.configure(text=policy_msg)
            return

        if p1 != p2:
            self.error_label.configure(text="Wprowadzone hasła różnią się od siebie.")
            return

        if policy_msg and not messagebox.askyesno("Średnio silne hasło główne", policy_msg + "\n\nUżyć mimo to?", icon="warning"):
            return

        if not save_path.lower().endswith(VAULT_FILE_EXTENSION):
            save_path += VAULT_FILE_EXTENSION

        if os.path.exists(save_path) and not messagebox.askyesno(
            "Plik już istnieje",
            f"Plik {save_path} już istnieje.\n\nNadpisanie go NIEODWRACALNIE usunie zapisany w nim sejf. Kontynuować?",
            icon="warning"
        ):
            return

        base_name = os.path.splitext(os.path.basename(save_path))[0]
        vault = Vault(name=base_name)

        try:
            save_vault(vault, save_path, p1)
            messagebox.showinfo("Sukces", f"Utworzono nowy, zaszyfrowany sejf:\n{save_path}")
        except Exception as e:
            if self.winfo_exists():
                self.error_label.configure(text=f"Nie udało się utworzyć sejfu: {str(e)}")
            return

        self.on_vault_unlocked(vault, p1, save_path, None)

    # ----------------------------------------------------------------- SERWER SYNCHRONIZACJI
    def _setup_server_tab(self):
        f = self.tab_server

        self.server_info_lbl = ctk.CTkLabel(f, text="", font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, justify="left", wraplength=420)
        self.server_info_lbl.pack(anchor="w", pady=(4, 2))

        # Adres i kod – widoczne przy pierwszym połączeniu lub po kliknięciu "Zmień serwer"
        self.server_fields = ctk.CTkFrame(f, fg_color="transparent")
        ctk.CTkLabel(self.server_fields, text="Adres serwera:", font=FONT_BODY_BOLD).pack(anchor="w", pady=(2, 2))
        url_row = ctk.CTkFrame(self.server_fields, fg_color="transparent")
        url_row.pack(fill="x", pady=(0, 6))
        self.server_url_entry = ctk.CTkEntry(url_row, placeholder_text="https://vault.twojafirma.pl lub https://serwer.siec.ts.net")
        self.server_url_entry.pack(side="left", expand=True, fill="x", padx=(0, 6))
        self.ts_detect_btn = ctk.CTkButton(url_row, text="🔍 Tailscale", width=95, fg_color=COLOR_CARD_DARK,
                                           hover_color=COLOR_CARD_HOVER, command=self._detect_tailscale)
        self.ts_detect_btn.pack(side="left")
        ctk.CTkLabel(self.server_fields, text="Kod aktywacyjny od administratora (lub token urządzenia):", font=FONT_BODY_BOLD).pack(anchor="w", pady=(2, 2))
        self.server_token_entry = ctk.CTkEntry(self.server_fields, placeholder_text="np. K7QM-4XTP-9HRW")
        self.server_token_entry.pack(fill="x", pady=(0, 6))

        self.server_change_btn = ctk.CTkButton(
            f, text="Zmień serwer / dołącz ponownie", height=24, font=FONT_SMALL,
            fg_color="transparent", hover_color=COLOR_CARD_HOVER, command=self._show_server_fields
        )

        ctk.CTkLabel(f, text="Hasło główne:", font=FONT_BODY_BOLD).pack(anchor="w", pady=(2, 2))
        self.server_pwd_entry = ctk.CTkEntry(f, show="•", placeholder_text="Hasło główne sejfu...")
        self.server_pwd_entry.pack(fill="x", pady=(0, 6))
        self.server_pwd_entry.bind("<Return>", lambda e: self._do_server_unlock())

        key_box = ctk.CTkFrame(f, fg_color="transparent")
        key_box.pack(fill="x", pady=(0, 8))
        self.server_key_entry = ctk.CTkEntry(key_box, placeholder_text="Opcjonalny plik-klucz (Keyfile)...")
        self.server_key_entry.pack(side="left", expand=True, fill="x", padx=(0, 6))
        ctk.CTkButton(key_box, text="Klucz...", width=70, fg_color=COLOR_CARD_DARK, command=lambda: self._browse_into(self.server_key_entry)).pack(side="left")

        self.server_btn = ctk.CTkButton(
            f, text="🌐 Połącz i odblokuj", font=FONT_SUBTITLE, height=40,
            fg_color=COLOR_PRIMARY, hover_color=COLOR_PRIMARY_HOVER, command=self._do_server_unlock
        )
        self.server_btn.pack(fill="x", pady=(4, 0))
        self.hello_server_btn = ctk.CTkButton(
            f, text="🔐 Odblokuj przez Windows Hello", height=34, fg_color=COLOR_CARD_DARK,
            hover_color=COLOR_CARD_HOVER, command=self._hello_server
        )
        ctk.CTkButton(f, text="Nie pamiętam hasła", height=22, font=FONT_SMALL, fg_color="transparent",
                      hover_color=COLOR_CARD_HOVER, text_color=COLOR_TEXT_MUTED,
                      command=lambda: self._forgot_password("server")).pack(side="bottom", anchor="e", pady=(6, 0))
        self._refresh_server_header()

    def _refresh_server_header(self):
        p = self.server_profile
        if p:
            if not self.server_url_entry.get():
                self.server_url_entry.insert(0, p.url)
            account = f"Konto: {p.account_name}\n" if p.account_name else ""
            company = read_cached_branding(p).get("company_name")
            firm = f"Firma: {company}\n" if company else ""
            self.server_info_lbl.configure(text=f"{firm}Serwer: {p.url}\n{account}Urządzenie: {p.device_name or '—'}")
            self._show_cached_logo(p)
            self.server_fields.pack_forget()
            self.server_change_btn.pack(anchor="w", pady=(0, 4), after=self.server_info_lbl)
            self._refresh_hello_buttons()
        else:
            self.server_info_lbl.configure(text="Połącz ten komputer z serwerem synchronizacji swojej firmy lub własnym (np. przez Tailscale).")
            self.server_change_btn.pack_forget()
            self.server_fields.pack(fill="x", after=self.server_info_lbl)

    def _show_cached_logo(self, profile: ServerProfile):
        """Logo firmy zapamiętane przy ostatniej synchronizacji – nad informacją o serwerze."""
        path = branding_logo_path(profile.server_id)
        if not os.path.exists(path) or getattr(self, "_logo_label", None) is not None:
            return
        try:
            from PIL import Image
            img = Image.open(path)
            img.thumbnail((200, 44))
            self._logo_image = ctk.CTkImage(light_image=img, dark_image=img, size=img.size)
            self._logo_label = ctk.CTkLabel(self.tab_server, text="", image=self._logo_image)
            self._logo_label.pack(pady=(2, 0), before=self.server_info_lbl)
        except Exception:
            self._logo_label = None

    def _show_server_fields(self):
        self.server_change_btn.pack_forget()
        self.server_fields.pack(fill="x", after=self.server_info_lbl)
        self.server_token_entry.focus()
        self.hello_server_btn.pack_forget()

    # ------------------------------------------------------------- Tailscale
    def _detect_tailscale(self):
        self.error_label.configure(text="")
        self.ts_detect_btn.configure(text="Szukam...", state="disabled")

        def _work():
            try:
                return discover_servers()
            except Exception as e:
                return e

        def _done(res):
            self.ts_detect_btn.configure(text="🔍 Tailscale", state="normal")
            if isinstance(res, Exception):
                self.error_label.configure(text=str(res))
                return
            if not res:
                self.error_label.configure(text="W Twojej sieci Tailscale nie znaleziono serwera KeyStead (sprawdź, czy serwer jest włączony).")
                return
            if len(res) == 1:
                self._use_discovered(res[0])
            else:
                self._choose_discovered(res)

        self._run_bg(_work, _done)

    def _use_discovered(self, server):
        self.server_url_entry.delete(0, "end")
        self.server_url_entry.insert(0, server.url)
        self.error_label.configure(text=f"✅ Znaleziono serwer w Tailscale: {server.name}", text_color=COLOR_SUCCESS)
        self.after(4000, lambda: self.winfo_exists() and self.error_label.configure(text="", text_color=COLOR_DANGER))
        self.server_token_entry.focus()

    def _choose_discovered(self, servers):
        win = ctk.CTkToplevel(self)
        win.title("Serwery w sieci Tailscale")
        win.geometry("460x320")
        win.transient(self.winfo_toplevel())
        ctk.CTkLabel(win, text="Wybierz serwer:", font=FONT_SUBTITLE).pack(anchor="w", padx=16, pady=(14, 8))
        for s in servers:
            def _pick(server=s):
                win.destroy()
                self._use_discovered(server)
            ctk.CTkButton(win, text=f"{s.name}   ·   {s.url}", anchor="w", fg_color=COLOR_CARD_DARK,
                          hover_color=COLOR_CARD_HOVER, command=_pick).pack(fill="x", padx=16, pady=3)

    # ------------------------------------------------------------- łączenie
    def _browse_into(self, entry):
        p = filedialog.askopenfilename(title="Wybierz plik klucza")
        if p:
            entry.delete(0, "end")
            entry.insert(0, p)

    def _server_busy(self, busy: bool, text: str = "🌐 Połącz i odblokuj"):
        if self.winfo_exists():
            self.server_btn.configure(text=text, state="disabled" if busy else "normal")

    def _do_server_unlock(self, password: Optional[str] = None, keyfile: Optional[bytes] = None):
        self.error_label.configure(text="", text_color=COLOR_DANGER)
        from_hello = password is not None
        if not from_hello:
            self.unlock_method = "password"
            password = self.server_pwd_entry.get()
        key_path = "" if from_hello else self.server_key_entry.get().strip()

        credential = ""
        if not from_hello and (self.server_fields.winfo_ismapped() or not self.server_profile):
            url = self.server_url_entry.get().strip().rstrip("/")
            credential = self.server_token_entry.get().strip()
            if not url or not credential:
                self.error_label.configure(text="Podaj adres serwera i kod aktywacyjny od administratora.")
                return
            ok, msg = check_server_url(url)
            if not ok:
                self.error_label.configure(text=msg)
                return
            same_server = self.server_profile and self.server_profile.url == url
            ca_file = self._pinned_ca.get(url) or (self.server_profile.ca_file if same_server else "")
            profile = ServerProfile(url=url, token="", ca_file=ca_file)
        else:
            profile = self.server_profile

        if not password:
            self.error_label.configure(text="Podaj hasło główne sejfu.")
            return

        keyfile_bytes = keyfile if from_hello else None
        if key_path:
            if not os.path.isfile(key_path):
                self.error_label.configure(text="Wskazany plik-klucz nie istnieje.")
                return
            with open(key_path, "rb") as kf:
                keyfile_bytes = kf.read()

        self._server_busy(True, "Łączenie z serwerem...")

        totp_code, self._enroll_totp = self._enroll_totp, ""

        def _work():
            enrolled = False
            try:
                if credential:
                    if credential.startswith("ks_"):
                        profile.token = credential  # token wygenerowany w terminalu serwera
                    else:
                        info = enroll_device(profile.url, credential, socket.gethostname(), profile.ca_file, totp=totp_code)
                        profile.token = info["token"]
                        profile.device_name = info.get("device_name", "")
                        profile.account_name = info.get("display_name", "")
                        self._pending_totp_setup = info.get("totp_setup")
                        enrolled = True
                session = SyncSession(profile)
                return ("ok", session, session.open(password, keyfile_bytes), enrolled)
            except TotpRequiredError as e:
                return ("totp", e, None, enrolled)
            except CertificateError:
                try:
                    pem, fp = fetch_server_certificate(profile.url)
                    return ("cert", (pem, fp), None, enrolled)
                except Exception as e:
                    return ("error", e, None, enrolled)
            except EmptyServerError:
                return ("empty", session, None, enrolled)
            except Exception as e:
                return ("error", e, None, enrolled)

        def _done(result):
            kind, value, vault, enrolled = result
            if enrolled:
                # Kod aktywacyjny jest jednorazowy – zapamiętaj urządzenie od razu (np. przy błędnym haśle)
                self._remember_profile(profile)
            if kind == "totp":
                self._server_busy(False)
                code = TotpDialog.ask_code(self, str(value))
                if code:
                    self._enroll_totp = code
                    self._do_server_unlock()  # kod aktywacyjny nie został zużyty – ponawiamy z kodem 2FA
                else:
                    self.error_label.configure(text="Dodanie urządzenia wymaga kodu 2FA – przerwano.")
                return
            setup, self._pending_totp_setup = self._pending_totp_setup, None
            if kind in ("ok", "empty") and setup:
                session = value
                self._setup_user_totp(session, setup)
            if kind == "ok":
                self._finish_server_login(value, vault, password, keyfile_bytes)
            elif kind == "empty":
                self._server_busy(False)
                self._bootstrap_server(value, password, keyfile_bytes)
            elif kind == "cert":
                self._server_busy(False)
                self._confirm_certificate(profile, *value, retry_credential=credential and not enrolled)
            else:
                self._server_busy(False)
                if isinstance(value, AuthError) and not enrolled and not credential and self.server_profile:
                    # Zapamiętane urządzenie zostało odcięte – lokalną kopię usunęła już sesja synchronizacji
                    try:
                        delete_profile()
                    except OSError:
                        pass
                    self.forget_server_profile()
                    self.error_label.configure(
                        text=f"❌ {value}\nTo urządzenie nie ma już dostępu – lokalna kopia sejfu została usunięta. "
                             "Poproś administratora o nowy kod aktywacyjny."
                    )
                    return
                self.error_label.configure(text=self._describe_error(value))

        self._run_bg(_work, _done)

    def _setup_user_totp(self, session: SyncSession, setup: dict):
        """Pierwsze urządzenie przy polityce wymagającej 2FA: dodanie konta w aplikacji uwierzytelniającej."""
        for _ in range(5):
            code = TotpDialog.setup(self, setup.get("secret", ""), setup.get("uri", ""))
            if not code:
                break
            try:
                session.client.confirm_totp(code)
                messagebox.showinfo("2FA włączone", "Logowanie dwuskładnikowe zostało skonfigurowane. "
                                                    "Kod z aplikacji będzie potrzebny przy dodawaniu kolejnych urządzeń.")
                return
            except Exception as e:
                messagebox.showerror("Nieprawidłowy kod", str(e))
        messagebox.showwarning("2FA nie zostało potwierdzone",
                               "Konfiguracja 2FA zostanie zaproponowana ponownie przy dodawaniu kolejnego urządzenia.")

    def forget_server_profile(self):
        """Urządzenie straciło dostęp – wróć do formularza dołączania (adres zostaje wpisany)."""
        url = self.server_profile.url if self.server_profile else ""
        self.server_profile = None
        if url and not self.server_url_entry.get():
            self.server_url_entry.insert(0, url)
        self.server_token_entry.delete(0, "end")
        self._refresh_server_header()
        self.tabview.set("🌐 Serwer")

    def _remember_profile(self, profile: ServerProfile):
        try:
            save_profile(profile)
        except OSError:
            pass
        self.server_profile = profile
        self.server_token_entry.delete(0, "end")
        self._refresh_server_header()

    def _confirm_certificate(self, profile: ServerProfile, pem: str, fingerprint: str, retry_credential):
        """Serwer z certyfikatem nieznanym systemowi – pokaż odcisk do porównania i zapamiętaj po akceptacji."""
        pinned_fp = ""
        if profile.ca_file and os.path.exists(profile.ca_file):
            try:
                with open(profile.ca_file, "r", encoding="ascii") as f:
                    pinned_fp = fingerprint_of_pem(f.read())
            except (OSError, ValueError):
                pinned_fp = ""
        if pinned_fp == fingerprint:
            # Certyfikat jest już zaufany, a połączenie i tak się nie udaje – ponowne pytanie nic nie da
            self.error_label.configure(
                text="❌ Certyfikat serwera jest zaufany, ale nie pasuje do adresu, pod którym się łączysz. "
                     "Użyj dokładnie adresu wypisanego przez instalator (np. https://192.168.0.10:8443)."
            )
            return
        host = (urlparse(profile.url).hostname or "").lower()
        known_by_system = bool(self.server_profile and self.server_profile.url == profile.url
                               and self.server_profile.token and not pinned_fp)
        if host.endswith(".ts.net") or known_by_system:
            # Ten serwer miał certyfikat zaufany przez system (Tailscale / publiczne CA). Nagle niezaufany certyfikat
            # to najpewniej przechwycenie połączenia – nie proponujemy „zaufaj temu certyfikatowi”.
            self.error_label.configure(
                text="❌ Serwer przedstawił certyfikat, któremu system nie ufa, choć wcześniej był on zaufany. "
                     "Możliwa próba przechwycenia połączenia (np. publiczne Wi-Fi) – połączenie przerwane. "
                     "Spróbuj z innej sieci lub skontaktuj się z administratorem.")
            return
        changed = bool(pinned_fp)
        title = "⚠️ Certyfikat serwera się zmienił" if changed else "Nowy certyfikat serwera"
        intro = ("Serwer przedstawił INNY certyfikat niż zapamiętany. Może to oznaczać odnowienie certyfikatu "
                 "albo próbę przechwycenia połączenia.\n\n") if changed else (
                 "Serwer używa certyfikatu, którego system nie zna (np. certyfikat samopodpisany "
                 "albo wewnętrzny certyfikat firmy).\n\n")
        if not messagebox.askyesno(
            title,
            intro + f"Odcisk SHA-256:\n{fingerprint}\n\n"
            "Porównaj go z odciskiem podanym przez administratora serwera (instalator / panel administratora "
            "albo na serwerze: sudo openssl x509 -in /etc/keystead/tls/server.crt -noout -fingerprint -sha256). "
            "Ufasz temu certyfikatowi?",
            icon="warning"
        ):
            self.error_label.configure(text="Połączenie przerwane – certyfikat serwera nie został zaakceptowany.")
            return
        profile.ca_file = save_pinned_certificate(profile.url, pem)
        self._pinned_ca[profile.url] = profile.ca_file
        if self.server_profile and self.server_profile.url == profile.url:
            self.server_profile.ca_file = profile.ca_file
            if not retry_credential:
                save_profile(self.server_profile)
        self._do_server_unlock()

    @staticmethod
    def _describe_error(e: Exception) -> str:
        if isinstance(e, InvalidPasswordOrCorruptDataError):
            return "❌ Niepoprawne hasło główne (bądź plik klucza)."
        if isinstance(e, InvalidVaultHeaderError):
            return "❌ Sejf na serwerze jest uszkodzony lub w nieznanym formacie."
        return f"❌ {e}"

    def _run_bg(self, work, done):
        poster = getattr(self.winfo_toplevel(), "post_to_ui", None) or (lambda fn: self.after(0, fn))

        def _worker():
            result = work()
            try:
                poster(lambda: self.winfo_exists() and done(result))
            except Exception:
                pass
        threading.Thread(target=_worker, daemon=True).start()

    def _bootstrap_server(self, session: SyncSession, password: str, keyfile_bytes: Optional[bytes]):
        """Pierwsze użycie pustego serwera: wyślij istniejący sejf albo utwórz nowy."""
        choice = messagebox.askyesnocancel(
            "Serwer jest pusty",
            "Na serwerze nie ma jeszcze sejfu.\n\n"
            "TAK – wyślij istniejący sejf z tego komputera (plik .vault)\n"
            "NIE – utwórz nowy, pusty sejf na serwerze"
        )
        if choice is None:
            return

        if choice:
            path = filedialog.askopenfilename(
                title="Wybierz sejf do wysłania na serwer",
                initialfile=os.path.basename(self.recent_vaults[0]) if self.recent_vaults else "",
                initialdir=os.path.dirname(self.recent_vaults[0]) if self.recent_vaults else None,
                filetypes=[("Pliki Sejfu", "*.vault"), ("Wszystkie pliki", "*.*")]
            )
            if not path:
                return
            try:
                load_vault(path, password, keyfile_bytes)  # weryfikacja hasła przed wysłaniem
                with open(path, "rb") as fh:
                    blob = fh.read()
            except Exception as e:
                self.error_label.configure(text=self._describe_error(e) + " (hasło musi pasować do wybranego sejfu)")
                return
        else:
            allowed, policy_msg = check_master_password(password)
            if not allowed:
                self.error_label.configure(text=policy_msg)
                return
            if policy_msg and not messagebox.askyesno("Średnio silne hasło główne", policy_msg + "\n\nUżyć mimo to?", icon="warning"):
                return
            blob = encrypt_payload(Vault(name="Mój Sejf").to_json().encode("utf-8"), password, keyfile_bytes)

        self._server_busy(True, "Wysyłanie sejfu na serwer...")

        def _work():
            try:
                session.create_on_server(blob)
                return ("ok", session.open(password, keyfile_bytes))
            except Exception as e:
                return ("error", e)

        def _done(result):
            kind, value = result
            if kind == "ok":
                self._finish_server_login(session, value, password, keyfile_bytes)
            else:
                self._server_busy(False)
                self.error_label.configure(text=self._describe_error(value))

        self._run_bg(_work, _done)

    def _finish_server_login(self, session: SyncSession, vault: Vault, password: str, keyfile_bytes: Optional[bytes]):
        try:
            save_profile(session.profile)
        except OSError:
            pass
        if self.on_remote_unlocked:
            self.on_remote_unlocked(vault, password, keyfile_bytes, session)

    def _open_wizard(self):
        if self.on_open_wizard:
            self.on_open_wizard()
