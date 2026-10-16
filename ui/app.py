"""
Główne okno aplikacji (Application Controller).
Zarządza cyklem życia sejfu, przełączaniem widoków (Login <-> Main),
automatyczną blokadą przy bezczynności oraz asynchronicznym backupem w tle.
"""

import copy
import os
import sys
import time
import threading
import webbrowser
from typing import Optional
import customtkinter as ctk

from core import app_update
from core.generator import evaluate_password_strength
from core.version import APP_VERSION
from core.paths import branding_logo_path
from core.storage import background_saver
from core.security_audit import run_vault_audit
from core.vault import Vault
from ui.policy import (SCORE_LABELS, build_security_report, effective_auto_lock, min_master_score,
                       personal_backups_allowed)
from backups import BackupManager, vault_snapshot, merge_runtime_state
from tkinter import messagebox
from sync import SyncSession, delete_profile
from sync.session import REVOKED
from ui.clipboard import SecureClipboard
from ui.login_view import LoginView, save_recent_vault
from ui.main_view import MainView
from ui.onboarding_wizard import OnboardingWizard, is_first_run


SYNC_POLL_SECONDS = 30
ICON_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "keystead.ico")


class UpdateBar(ctk.CTkFrame):
    """Pasek nad treścią okna: „Dostępna nowa wersja” → pobranie, weryfikacja podpisu, instalacja."""

    def __init__(self, app: "PasswordManagerApp", release: "app_update.AppRelease"):
        super().__init__(app, corner_radius=0, fg_color=("#e0e7ff", "#1e1b4b"))
        self.app = app
        self.release = release
        self.label = ctk.CTkLabel(self, text=f"⬆️  Dostępna nowa wersja KeyStead Manager {release.version} "
                                             f"(masz {APP_VERSION})", anchor="w")
        self.label.pack(side="left", padx=14, pady=6)
        self.later = ctk.CTkButton(self, text="Później", width=80, fg_color="transparent", border_width=1,
                                   text_color=("#1e1b4b", "#e0e7ff"), command=self.destroy)
        self.later.pack(side="right", padx=(4, 12), pady=6)
        if app_update.can_self_install():
            text, cmd = "Zaktualizuj teraz", self._install
        else:
            text, cmd = "Pobierz", lambda: webbrowser.open(release.page_url)
        self.action = ctk.CTkButton(self, text=text, width=140, command=cmd)
        self.action.pack(side="right", padx=4, pady=6)
        if release.page_url:
            info = ctk.CTkButton(self, text="Co nowego?", width=90, fg_color="transparent",
                                 text_color=("#4338ca", "#a5b4fc"), command=lambda: webbrowser.open(release.page_url))
            info.pack(side="right", padx=4, pady=6)

    def _install(self):
        session = self.app.sync_session
        if session and session.has_unsent_changes:
            messagebox.showinfo("Aktualizacja", "Trwa wysyłanie zmian na serwer – spróbuj ponownie za chwilę.")
            return
        if not messagebox.askyesno("Aktualizacja", f"Pobrać i zainstalować wersję {self.release.version}?\n\n"
                                                   "Aplikacja zamknie się na czas instalacji i uruchomi ponownie. "
                                                   "Sejf trzeba będzie odblokować hasłem głównym."):
            return
        self.action.configure(state="disabled", text="Pobieranie...")
        self.later.configure(state="disabled")

        def _progress(done, total):
            pct = f"{done * 100 // total}%" if total else f"{done // (1024 * 1024)} MB"
            self.app._post_to_ui(lambda: self.winfo_exists() and self.action.configure(text=f"Pobieranie {pct}"))

        def _worker():
            try:
                path = app_update.download_update(self.release, progress=_progress)
            except Exception as e:
                msg = str(e) if isinstance(e, app_update.UpdateError) else f"Błąd pobierania: {e}"
                self.app._post_to_ui(lambda: self._failed(msg))
                return
            self.app._post_to_ui(lambda: self._run_installer(path))

        threading.Thread(target=_worker, daemon=True).start()

    def _failed(self, message: str):
        if self.winfo_exists():
            self.action.configure(state="normal", text="Spróbuj ponownie")
            self.later.configure(state="normal")
        messagebox.showerror("Aktualizacja", message)

    def _run_installer(self, path: str):
        session = self.app.sync_session
        if session and session.has_unsent_changes:
            self.app.after(1000, lambda: self._run_installer(path))  # najpierw dokończ wysyłkę zmian
            return
        try:
            app_update.launch_installer(path)
        except app_update.UpdateError as e:
            self._failed(str(e))
            return
        except OSError as e:
            self._failed(f"Nie udało się uruchomić instalatora: {e}")
            return
        self.app._on_close()


class PasswordManagerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("KeyStead Manager")
        self._set_icon(self)
        self.geometry("1240x800")
        self.minsize(1050, 680)

        # Stan sesji
        self.current_vault: Optional[Vault] = None
        self.master_password: Optional[str] = None
        self.vault_file_path: Optional[str] = None
        self.keyfile_bytes: Optional[bytes] = None

        self.last_activity_time = time.time()
        self.backup_manager = BackupManager()
        self._backup_lock = threading.Lock()

        self._current_view: Optional[ctk.CTkFrame] = None
        self.sync_session: Optional[SyncSession] = None
        self._sync_timer = None
        self._revoke_handled = False
        self._last_branding: dict = {}
        self._branding_key = None

        # Śledzenie aktywności użytkownika w celu automatycznej blokady
        self.bind_all("<KeyPress>", self._on_user_activity, add="+")
        self.bind_all("<ButtonPress>", self._on_user_activity, add="+")
        self.bind_all("<MouseWheel>", self._on_user_activity, add="+")

        # Bezpieczne zamykanie okna
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self._show_login_view()
        self._check_idle_loop()

        # Pierwsze uruchomienie: poprowadzenie użytkownika za rękę
        if is_first_run():
            self.after(400, self.open_onboarding_wizard)

        # Aktualizacje aplikacji (tylko zbudowana wersja – nie przy uruchamianiu z kodu źródłowego)
        self._update_bar: Optional[UpdateBar] = None
        if app_update.is_frozen() or os.environ.get("KEYSTEAD_CHECK_UPDATES"):
            self.after(5000, self._check_app_update)

    # ------------------------------------------------------------ ikona i aktualizacje
    @staticmethod
    def _set_icon(window):
        if sys.platform != "win32" or not os.path.isfile(ICON_PATH):
            return
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("KeyStead.Manager")
        except Exception:
            pass
        # CustomTkinter ustawia własną ikonę z opóźnieniem – nadpisujemy ją po nim
        window.after(250, lambda: window.winfo_exists() and window.iconbitmap(ICON_PATH))

    def _check_app_update(self):
        def _worker():
            try:
                release = app_update.check_for_update()
            except Exception:
                release = None  # brak sieci / limit GitHuba – spróbujemy później
            if release:
                self._post_to_ui(lambda: self._show_update_bar(release))
        threading.Thread(target=_worker, daemon=True).start()
        self.after(app_update.CHECK_INTERVAL_HOURS * 3600 * 1000, self._check_app_update)

    def _show_update_bar(self, release):
        if self._update_bar is not None and self._update_bar.winfo_exists():
            if self._update_bar.release.version == release.version:
                return
            self._update_bar.destroy()
        self._update_bar = UpdateBar(self, release)
        if self._current_view is not None:
            self._update_bar.pack(side="top", fill="x", before=self._current_view)
        else:
            self._update_bar.pack(side="top", fill="x")

    def open_onboarding_wizard(self):
        """Otwiera asystenta pierwszego uruchomienia."""
        if self.current_vault is None:
            OnboardingWizard(
                self,
                on_vault_ready=self._on_vault_unlocked,
                on_import_requested=self._open_import_after_setup
            )

    def _open_import_after_setup(self):
        if isinstance(self._current_view, MainView):
            self.after(300, self._current_view.open_import_dialog)

    def _on_user_activity(self, event=None):
        self.last_activity_time = time.time()

    def _check_idle_loop(self):
        """Sprawdza bezczynność użytkownika i automatycznie blokuje sejf."""
        now = time.time()
        # Pętla tyka co 5 s – dłuższa przerwa oznacza uśpienie/hibernację komputera
        slept = now - getattr(self, "_last_idle_tick", now) > 60
        self._last_idle_tick = now

        if self.current_vault:
            timeout_min = effective_auto_lock(int(self.current_vault.settings.get("auto_lock_minutes", 5) or 0),
                                              self.current_policy())
            if slept and timeout_min and timeout_min > 0:
                self.lock_vault()
            elif timeout_min and timeout_min > 0:
                elapsed = time.time() - self.last_activity_time
                if elapsed >= (timeout_min * 60):
                    self.lock_vault()

        self.after(5000, self._check_idle_loop)

    def _show_login_view(self):
        if self._current_view:
            self._current_view.destroy()

        self.current_vault = None
        self.master_password = None
        self.vault_file_path = None
        self.keyfile_bytes = None
        if self.sync_session:
            self.sync_session.close()
            self.sync_session = None
        if self._sync_timer:
            self.after_cancel(self._sync_timer)
            self._sync_timer = None

        self._current_view = LoginView(
            self,
            on_vault_unlocked=self._on_vault_unlocked,
            on_open_wizard=self.open_onboarding_wizard,
            on_remote_unlocked=self._on_remote_unlocked
        )
        self._current_view.pack(fill="both", expand=True)

    def _on_remote_unlocked(self, vault: Vault, password: str, keyfile_bytes: Optional[bytes], session: SyncSession):
        """Sejf otwarty z serwera synchronizacji: pracujemy na lokalnej kopii, zmiany idą na serwer."""
        self.sync_session = session
        self._revoke_handled = False
        self._last_branding = {}
        self._on_vault_unlocked(vault, password, session.cache_path, keyfile_bytes, remember_recent=False)
        view = self._current_view
        session.add_listener(lambda status: self._post_to_ui(lambda: self._on_sync_status(view, status)))
        self._on_sync_status(view, session.status())
        self._schedule_sync_poll()
        self.after(600, lambda: self._enforce_master_password_policy(view, password))
        self.after(4000, lambda: self._maybe_send_security_report(view))

    # ------------------------------------------------------------ polityki firmy
    def current_policy(self) -> dict:
        return dict(self.sync_session.policy) if self.sync_session else {}

    def _enforce_master_password_policy(self, view, password: str):
        """Polityka firmy wymaga silniejszego hasła głównego – poproś o zmianę od razu po odblokowaniu."""
        if view is not self._current_view or not isinstance(view, MainView):
            return
        required = min_master_score(self.current_policy())
        if required and evaluate_password_strength(password)["score"] < required:
            messagebox.showwarning(
                "Wymagana zmiana hasła głównego",
                f"Polityka bezpieczeństwa firmy wymaga hasła głównego o sile co najmniej: „{SCORE_LABELS[required]}”.\n\n"
                "Twoje obecne hasło jest słabsze – ustaw nowe w panelu, który za chwilę się otworzy."
            )
            view.open_settings_for_password_change()

    def _maybe_send_security_report(self, view=None, force: bool = False):
        """Raz na dobę (lub po audycie) wysyła zbiorczy wynik audytu – wyłącznie liczby, bez danych z sejfu."""
        session, vault = self.sync_session, self.current_vault
        if not session or not vault or not (force or session.report_due()):
            return

        def _worker():
            try:
                report = run_vault_audit(vault, check_hibp=True)
                session.send_security_report(build_security_report(report))
            except Exception:
                pass
        threading.Thread(target=_worker, daemon=True).start()

    def send_audit_report(self, report):
        """Wynik audytu uruchomionego ręcznie w aplikacji – od razu na serwer, jeśli firma zbiera raporty."""
        session = self.sync_session
        if session and session.policy.get("security_report"):
            threading.Thread(target=session.send_security_report, args=(build_security_report(report),), daemon=True).start()

    def _refresh_branding(self, view, branding: dict):
        """Nazwa i logo firmy z serwera: tytuł okna, górny pasek; logo pobierane w tle i zapisywane lokalnie."""
        company = (branding or {}).get("company_name") or ""
        self.title(f"KeyStead Manager – {company}" if company else "KeyStead Manager")
        session = self.sync_session
        logo_path = branding_logo_path(session.profile.server_id) if session else ""
        view.apply_branding(company, logo_path if logo_path and os.path.exists(logo_path) else "")
        if not session or not branding.get("has_logo"):
            return
        key = (session.profile.server_id, company, branding.get("accent_color"))
        if self._branding_key == key and os.path.exists(logo_path):
            return
        self._branding_key = key

        def _worker():
            data = session.client.fetch_logo()
            if data:
                os.makedirs(os.path.dirname(logo_path), exist_ok=True)
                with open(logo_path, "wb") as f:
                    f.write(data)
                self._post_to_ui(lambda: view.winfo_exists() and view.apply_branding(company, logo_path))
        threading.Thread(target=_worker, daemon=True).start()

    def _post_to_ui(self, fn):
        """Przekazuje wywołanie z wątku roboczego do wątku interfejsu."""
        try:
            self.after(0, fn)
        except Exception:
            pass

    def _on_sync_status(self, view, status):
        if view is not self._current_view or not isinstance(view, MainView) or not view.winfo_exists():
            return
        if status.state == REVOKED:
            self._handle_access_revoked(status.message)
            return
        view.update_sync_status(status)
        view.policy = dict(status.policy or {})
        if (status.branding or {}) != self._last_branding:
            self._last_branding = dict(status.branding or {})
            self._refresh_branding(view, self._last_branding)

    def _handle_access_revoked(self, reason: str):
        """Administrator odciął urządzenie lub zablokował konto: zamknij sejf i usuń dane dostępowe."""
        if self._revoke_handled:
            return
        self._revoke_handled = True
        self.lock_vault()  # najpierw zamykamy sejf – dane znikają z ekranu i pamięci aplikacji
        try:
            delete_profile()  # token urządzenia jest już bezużyteczny
        except OSError:
            pass
        if isinstance(self._current_view, LoginView):
            self._current_view.forget_server_profile()
        messagebox.showwarning(
            "Dostęp odebrany",
            f"{reason}\n\nSejf został zamknięty, a jego lokalna kopia usunięta z tego komputera.\n"
            "Jeśli to pomyłka, poproś administratora o nowy kod aktywacyjny."
        )

    def _schedule_sync_poll(self):
        self._sync_timer = self.after(SYNC_POLL_SECONDS * 1000, self._sync_poll_tick)

    def _sync_poll_tick(self):
        """Co kilkadziesiąt sekund sprawdza serwer w tle i wczytuje zmiany z innych urządzeń."""
        self._sync_timer = None
        session, view = self.sync_session, self._current_view
        if not session or not isinstance(view, MainView):
            return
        self.sync_now(on_finished=self._schedule_sync_poll)

    def sync_now(self, on_finished=None):
        session, view = self.sync_session, self._current_view
        if not session or not isinstance(view, MainView):
            return

        def _worker():
            try:
                update = session.poll()
            except Exception:
                update = None

            def _apply():
                active = view is self._current_view and session is self.sync_session
                # Gdy użytkownik właśnie coś zapisuje, nie podmieniamy mu sejfu – jego zapis
                # trafi na serwer jako konflikt do świadomego rozstrzygnięcia
                if update is not None and active and not session.has_unsent_changes:
                    view.apply_remote_vault(update.vault, f"🔄 Pobrano zmiany z urządzenia „{update.updated_by}”")
                    session.adopt(update)
                if on_finished and session is self.sync_session:
                    on_finished()
            self._post_to_ui(_apply)

        threading.Thread(target=_worker, daemon=True).start()

    def _on_vault_replaced(self, vault: Vault):
        self.current_vault = vault

    def _on_vault_unlocked(
        self,
        vault: Vault,
        password: str,
        file_path: str,
        keyfile_bytes: Optional[bytes],
        remember_recent: bool = True
    ):
        self.current_vault = vault
        self.master_password = password
        self.vault_file_path = file_path
        self.keyfile_bytes = keyfile_bytes
        self.last_activity_time = time.time()
        if remember_recent:
            save_recent_vault(file_path)

        # Zastosuj motyw zapisany w sejfie
        theme = vault.settings.get("theme", "dark")
        if theme in ["dark", "light", "system"]:
            ctk.set_appearance_mode(theme)

        self._show_main_view()

    def _on_master_password_changed(self, new_password: str):
        self.master_password = new_password

    def _show_main_view(self):
        if self._current_view:
            self._current_view.destroy()

        self._current_view = MainView(
            parent=self,
            vault=self.current_vault,
            master_password=self.master_password,
            vault_file_path=self.vault_file_path,
            keyfile_bytes=self.keyfile_bytes,
            on_lock_requested=self.lock_vault,
            on_auto_backup_trigger=self._trigger_background_backup,
            on_master_password_changed=self._on_master_password_changed,
            sync_session=self.sync_session,
            on_sync_requested=self.sync_now,
            on_vault_replaced=self._on_vault_replaced,
            on_audit_report=self.send_audit_report
        )
        self._current_view.pack(fill="both", expand=True)

    def lock_vault(self):
        """Blokuje sejf i czyści ze schowka skopiowane sekrety."""
        SecureClipboard.clear()
        self._show_login_view()

    def _trigger_background_backup(self):
        """Asynchronicznie wykonuje kopie zapasowe w osobnym wątku."""
        if not self.current_vault or not self.vault_file_path:
            return

        if not self.current_vault.settings.get("auto_backup_on_save", True):
            return
        if not personal_backups_allowed(self.current_policy()):
            return  # firma wyłączyła własne kopie (sejf i tak jest na serwerze z historią wersji)

        settings_copy = copy.deepcopy(self.current_vault.settings.get("backup_destinations", {}))
        original = copy.deepcopy(settings_copy)  # stan z chwili startu – wykrycie zmiany konta w trakcie backupu
        vault_path = self.vault_file_path
        view = self._current_view

        def _worker():
            # Jeden backup naraz – kolejne zapisy czekają w kolejce zamiast dublować transfery
            with self._backup_lock:
                try:
                    with vault_snapshot(vault_path) as snapshot:
                        results = self.backup_manager.backup_to_all_configured(snapshot, settings_copy)
                except Exception as e:
                    results = None
                    error = str(e)
                else:
                    error = None

            try:
                self.after(0, lambda: self._persist_runtime_state(view, settings_copy, original))
            except Exception:
                pass

            failed = [r for r in (results or []) if not r.success]
            if error or failed:
                msg = error or ", ".join(r.provider_name for r in failed)
                try:
                    self.after(0, lambda: self._report_backup_failure(view, msg))
                except Exception:
                    pass

        threading.Thread(target=_worker, daemon=True).start()

    def _persist_runtime_state(self, view, settings_copy, original=None):
        """Zapisuje w sejfie tokeny OAuth odświeżone podczas backupu w tle."""
        if view is not self._current_view or not isinstance(view, MainView) or not self.current_vault:
            return
        dest = self.current_vault.settings.get("backup_destinations", {})
        if merge_runtime_state(dest, settings_copy, original):
            view._save_vault_to_disk(trigger_backup=False)

    def _report_backup_failure(self, view, message: str):
        if view is self._current_view and isinstance(view, MainView) and view.winfo_exists():
            view.show_toast(f"⚠️ Automatyczna kopia nie powiodła się: {message}", error=True)

    def _on_close(self):
        """Zdarzenie zamknięcia okna: czyszczenie schowka i bezpieczne zakończenie."""
        SecureClipboard.clear()
        self.withdraw()  # okno znika od razu, a zapisy w tle zdążą się dokończyć
        background_saver.flush()
        self.destroy()
