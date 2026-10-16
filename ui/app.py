"""
Główne okno aplikacji (Application Controller).
Zarządza cyklem życia sejfu, przełączaniem widoków (Login <-> Main),
automatyczną blokadą przy bezczynności oraz asynchronicznym backupem w tle.
"""

import copy
import hmac
import os
import queue
import sys
import time
import threading
import webbrowser
from typing import Optional
import customtkinter as ctk

from core import app_update
from core.generator import evaluate_password_strength
from core.version import APP_VERSION, server_compatibility
from core.paths import branding_logo_path
from core.attachments import cleanup_temp_copies
from core.crypto import Keyring, org_key_id, parse_org_public_key
from core.storage import background_saver
from core.watchtower import CONSENT_KEY as WATCH_CONSENT_KEY, Watchtower, attention_count, consent as watch_consent
from core.winsys import flash_window, is_session_locked
from ui.quick_access import QuickAccess
from ui.quick_unlock_ui import file_target, policy_allows, quick, server_target, valid_days
from core.security_audit import run_vault_audit
from core.vault import Vault
from ui.policy import (SCORE_LABELS, build_security_report, effective_auto_lock, min_master_score,
                       personal_backups_allowed)
from backups import BackupManager, vault_snapshot, merge_runtime_state
from tkinter import messagebox
from sync import SyncSession, delete_profile
from sync.session import REVOKED, SYNCED
from ui.clipboard import SecureClipboard
from ui.login_view import LoginView, save_recent_vault
from ui.main_view import MainView
from ui.onboarding_wizard import OnboardingWizard, is_first_run
from ui.recovery_ui import FORCE_CHANGE_KEY, AdminRecoveryTools, PasswordPrompt, RecoveryCodeDialog
from ui.site_icons_ui import IconProvider
from ui import perf


SYNC_POLL_SECONDS = 30
ORG_PIN_KEY = "org_recovery_key_id"  # odcisk zaakceptowanego klucza firmy – w zaszyfrowanym sejfie (serwer go nie zmieni)
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
        self._ui_queue: "queue.Queue" = queue.Queue()
        self.after(40, self._drain_ui_queue)
        self.icon_provider = IconProvider(self)  # ikony stron przy wpisach (pobierane bezpośrednio ze stron)
        cleanup_temp_copies()  # pozostałości po nieoczekiwanym zamknięciu (np. awaria zasilania)
        self._resize_freeze = perf.install_resize_freeze(self)  # pełny ekran bez rysowania okna „po kawałku”

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

        # Globalne skróty: Ctrl+Shift+Spacja (szybkie wyszukiwanie), Ctrl+Shift+L (Autotype)
        self.quick_access = QuickAccess(self)
        self.quick_access.start()

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
            if self.current_vault.settings.get("lock_on_session_lock", True) and is_session_locked():
                self.lock_vault()  # Win+L / wylogowanie / ekran blokady – sejf zamyka się razem z komputerem
            elif slept and timeout_min and timeout_min > 0:
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

    # ------------------------------------------------------------ szybki dostęp (skróty globalne)
    def on_user_activity(self):
        self.last_activity_time = time.time()

    def post_to_ui(self, fn):
        self._post_to_ui(fn)

    def notify(self, text: str, error: bool = False):
        view = self._current_view
        if isinstance(view, MainView) and view.winfo_exists():
            view.show_toast(text, error=error)
        elif error:
            messagebox.showwarning("KeyStead Manager", text)

    def bring_to_front(self, message: str = ""):
        """Skrót przy zablokowanym sejfie: okno na wierzch (a w nim Windows Hello / hasło)."""
        try:
            self.deiconify()
            self.lift()
            self.attributes("-topmost", True)
            self.after(300, lambda: self.attributes("-topmost", False))
            self.focus_force()
        except Exception:
            pass
        view = self._current_view
        if message and isinstance(view, LoginView):
            view.error_label.configure(text=message)
            view._refresh_hello_buttons()

    def autotype_allowed(self) -> bool:
        return (self.current_policy() or {}).get("allow_autotype", True) is not False

    def quick_copy(self, entry_id: str, what: str):
        """Kopiowanie z okienka szybkiego wyszukiwania – przez bezpieczny schowek (z czyszczeniem)."""
        view = self._current_view
        if not isinstance(view, MainView) or not self.current_vault:
            return
        entry = self.current_vault.get_entry(entry_id)
        if not entry:
            return
        self.on_user_activity()
        if what == "username":
            if entry.username:
                view._copy_to_clipboard(entry.username, f"Login „{entry.title}” skopiowany")
        elif what == "totp":
            if entry.totp_secret:
                view._copy_current_totp(entry)
            else:
                view.show_toast(f"„{entry.title}” nie ma kodu 2FA.", error=True)
        elif entry.password:
            view._copy_password_safe(entry.password)

    # ------------------------------------------------------------ monitorowanie haseł (wycieki, stare hasła)
    WATCH_INTERVAL_MS = 3 * 3600 * 1000

    def _watchtower_tick(self, view, first: bool = False):
        if view is not self._current_view or not isinstance(view, MainView) or not self.current_vault:
            return
        vault, target = self.current_vault, self.quick_unlock_target()
        if not target:
            return
        if first and watch_consent(vault.settings) is None and not getattr(self, "_breach_consent_asked", False):
            self._breach_consent_asked = True
            agreed = messagebox.askyesno(
                "Monitorowanie wycieków",
                "Sprawdzać automatycznie raz dziennie, czy Twoje hasła nie pojawiły się w nowych wyciekach danych?\n\n"
                "Hasła nie opuszczają komputera – do usługi Have I Been Pwned trafia tylko początek (5 znaków) "
                "ich skrótu SHA-1. O nowym wycieku dowiesz się od razu.\n\nMożna to zmienić w Audycie."
            )
            vault.settings[WATCH_CONSENT_KEY] = bool(agreed)
            view._save_vault_to_disk(trigger_backup=False)
        watch = Watchtower(target)
        check_breaches = bool(watch_consent(vault.settings)) and watch.breach_check_due()

        def _worker():
            try:
                report = run_vault_audit(vault, check_hibp=check_breaches)
                new = watch.record(report, check_breaches)
                known = set(watch.known_breached())
                count = attention_count(report)
                breached = bool(known & set(vault.entries))
            except Exception:
                return
            self._post_to_ui(lambda: self._watchtower_result(view, count, breached, new))
        threading.Thread(target=_worker, daemon=True).start()
        self.after(self.WATCH_INTERVAL_MS, lambda: self._watchtower_tick(view))

    def _watchtower_result(self, view, count: int, breached: bool, new_breaches):
        if view is not self._current_view or not isinstance(view, MainView):
            return
        view.set_audit_badge(count, critical=breached)
        if new_breaches:
            names = ", ".join(f"„{title}”" for _, title in new_breaches[:3])
            more = f" i {len(new_breaches) - 3} innych" if len(new_breaches) > 3 else ""
            view.show_toast(f"🚨 Nowy wyciek: {names}{more} – zmień te hasła (Audyt Wycieków)", error=True)
            try:
                flash_window(int(self.wm_frame(), 16))  # uchwyt okna głównego (ramka Windows)
            except (TypeError, ValueError):
                pass

    # ------------------------------------------------------------ Windows Hello
    def quick_unlock_target(self) -> Optional[str]:
        if self.sync_session:
            p = self.sync_session.profile
            return server_target(p.url, p.token)
        return file_target(self.vault_file_path) if self.vault_file_path else None

    def _toast(self, text: str, error: bool = False):
        view = self._current_view
        if isinstance(view, MainView) and view.winfo_exists():
            view.show_toast(text, error=error)

    def _after_quick_enroll(self, error, ok_text: str):
        if error is None:
            self._toast(ok_text)
        else:
            self._toast(f"🔐 Windows Hello: {error}", error=True)

    def _offer_quick_unlock(self, view, method: str):
        """Po odblokowaniu: propozycja Windows Hello albo odnowienie okresu ważności po wpisaniu hasła."""
        if view is not self._current_view or not isinstance(view, MainView) or not quick.available:
            return
        target, policy = self.quick_unlock_target(), self.current_policy()
        if not target:
            return
        if not policy_allows(policy):
            quick.disable(target)  # firma wyłączyła szybkie odblokowanie
            return
        if quick.store.is_enrolled(target):
            if method == "password" and quick.needs_renewal(target, policy):
                self._toast("🔐 Potwierdź Windows Hello – odnowienie szybkiego odblokowania")
                quick.enroll_async(self, target, self.master_password, self.keyfile_bytes,
                                   lambda e: self._after_quick_enroll(e, "🔐 Szybkie odblokowanie odnowione"))
            return
        if not quick.can_offer(target, policy):
            return
        days = valid_days(policy)
        if messagebox.askyesno(
            "Windows Hello",
            "Odblokowywać ten sejf odciskiem palca, twarzą lub PIN-em Windows (Windows Hello)?\n\n"
            f"Hasło główne będzie potrzebne raz na {days} dni – żeby go nie zapomnieć. "
            "Dane szybkiego odblokowania są chronione modułem bezpieczeństwa tego komputera.\n\n"
            "Możesz to zmienić w Ustawieniach."
        ):
            quick.enroll_async(self, target, self.master_password, self.keyfile_bytes,
                               lambda e: self._after_quick_enroll(e, "🔐 Windows Hello włączone"))
        else:
            quick.set_declined(target)

    def set_quick_unlock(self, enabled: bool):
        """Przełącznik w Ustawieniach."""
        target = self.quick_unlock_target()
        if not target:
            return
        if not enabled:
            quick.disable(target)
            quick.set_declined(target)
            self._toast("Szybkie odblokowanie wyłączone")
            return
        if not quick.available:
            messagebox.showinfo("Windows Hello", "Windows Hello nie jest skonfigurowane na tym komputerze.\n\n"
                                                 "Ustaw PIN lub odcisk palca: Ustawienia Windows → Konta → Opcje logowania.")
            return
        if not policy_allows(self.current_policy()):
            messagebox.showinfo("Windows Hello", "Polityka Twojej firmy nie pozwala na szybkie odblokowanie.")
            return
        quick.enroll_async(self, target, self.master_password, self.keyfile_bytes,
                           lambda e: self._after_quick_enroll(e, "🔐 Windows Hello włączone"))

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
        """
        Przekazuje wywołanie z wątku roboczego do wątku interfejsu – przez kolejkę odczytywaną w wątku okna
        (wywołania Tk z innych wątków działają tylko w określonych warunkach, kolejka zawsze).
        """
        self._ui_queue.put(fn)

    def _drain_ui_queue(self):
        try:
            while True:
                fn = self._ui_queue.get_nowait()
                try:
                    fn()
                except Exception:
                    pass
        except queue.Empty:
            pass
        try:
            self.after(40, self._drain_ui_queue)
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
        if status.state == SYNCED:
            self._sync_org_recovery(view, view.policy)
            self._check_server_version(view)
        if (status.branding or {}) != self._last_branding:
            self._last_branding = dict(status.branding or {})
            self._refresh_branding(view, self._last_branding)

    def _check_server_version(self, view):
        """Raz na sesję: ostrzeżenie, gdy linia wersji serwera i aplikacji się różni (np. serwer 2.0, aplikacja 2.1)."""
        session = self.sync_session
        version = getattr(session, "server_version", "") if session else ""
        if not version or getattr(self, "_version_warned", None) == version:
            return
        self._version_warned = version
        state = server_compatibility(version)
        if state == "server_older":
            view.show_toast(f"Serwer ma starszą wersję ({version}) niż aplikacja ({APP_VERSION}) – "
                            "poproś administratora o aktualizację serwera.", error=True)
        elif state == "app_older":
            view.show_toast(f"Serwer ma nowszą wersję ({version}) – zaktualizuj aplikację.", error=True)

    def _handle_access_revoked(self, reason: str):
        """Administrator odciął urządzenie lub zablokował konto: zamknij sejf i usuń dane dostępowe."""
        if self._revoke_handled:
            return
        self._revoke_handled = True
        target = self.quick_unlock_target()
        self.lock_vault()  # najpierw zamykamy sejf – dane znikają z ekranu i pamięci aplikacji
        if target:
            quick.disable(target)  # hasło zapamiętane dla Windows Hello też znika
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

        method = getattr(self._current_view, "unlock_method", "password")
        self._show_main_view()
        view = self._current_view
        if vault.settings.get(FORCE_CHANGE_KEY):
            self.after(700, lambda: self._check_forced_password_change(view))
        else:
            self.after(1200, lambda: self._offer_quick_unlock(view, method))
        self.after(3500, lambda: self._watchtower_tick(view, first=True))

    def _on_master_password_changed(self, new_password: str):
        self.master_password = new_password
        target = self.quick_unlock_target()
        if target and quick.store.is_enrolled(target):
            # Zapisane hasło jest nieaktualne – od razu zapisujemy nowe (potwierdzenie Windows Hello)
            quick.disable(target)
            if quick.available and policy_allows(self.current_policy()):
                self._toast("🔐 Potwierdź Windows Hello – zapis nowego hasła do szybkiego odblokowania")
                quick.enroll_async(self, target, new_password, self.keyfile_bytes,
                                   lambda e: self._after_quick_enroll(e, "🔐 Windows Hello zaktualizowane"))

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
        popup = getattr(getattr(self, "quick_access", None), "popup", None)
        if popup is not None and popup.winfo_exists():
            popup.close()  # okienko szybkiego wyszukiwania pokazuje wpisy – znika razem z sejfem
        cleanup_temp_copies()  # odszyfrowane kopie otwartych załączników
        self._show_login_view()

    # ------------------------------------------------------------ odzyskiwanie dostępu
    def _confirm_master_password(self, why: str) -> bool:
        entered = PasswordPrompt(self, "Potwierdź hasło główne", why).wait()
        if entered is None:
            return False
        if not hmac.compare_digest(entered.encode("utf-8"), (self.master_password or "").encode("utf-8")):
            messagebox.showerror("Odzyskiwanie dostępu", "Nieprawidłowe hasło główne.")
            return False
        return True

    def _ensure_keyring(self) -> Optional[Keyring]:
        vault = self.current_vault
        if vault is None:
            return None
        if vault.keyring is None:
            vault.keyring = Keyring.new(self.master_password, self.keyfile_bytes)  # przejście na format v2
        return vault.keyring

    def create_recovery_code(self):
        view, vault = self._current_view, self.current_vault
        if not isinstance(view, MainView) or vault is None:
            return
        if not self._confirm_master_password("Aby utworzyć kod odzyskiwania, wpisz hasło główne:"):
            return
        if self.sync_session and vault.keyring is None and not messagebox.askyesno(
                "Kod odzyskiwania",
                "Sejf z kodem odzyskiwania zapisywany jest w nowym formacie – na wszystkich urządzeniach "
                "korzystających z tego sejfu potrzebny jest KeyStead Manager 1.2 lub nowszy.\n\nKontynuować?"):
            return
        ring = self._ensure_keyring()
        code = ring.add_recovery_code()
        view._save_vault_to_disk(trigger_backup=False)
        RecoveryCodeDialog(self, code, vault.name).wait()
        view.show_toast("🔑 Kod odzyskiwania zapisany w sejfie")

    def remove_recovery_code(self):
        view, vault = self._current_view, self.current_vault
        if not isinstance(view, MainView) or vault is None or vault.keyring is None:
            return
        if not messagebox.askyesno("Kod odzyskiwania", "Usunąć kod odzyskiwania? Po zapomnieniu hasła głównego "
                                                       "nie będzie już można odzyskać sejfu tym kodem."):
            return
        vault.keyring.remove_recovery_code()
        view._save_vault_to_disk(trigger_backup=False)
        view.show_toast("Kod odzyskiwania usunięty")

    def open_admin_tools(self):
        view = self._current_view
        if isinstance(view, MainView):
            view.drawer.open("Narzędzia administratora firmy",
                             "Klucz odzyskiwania firmy i odzyskiwanie dostępu pracownikom", build=AdminRecoveryTools)

    def _sync_org_recovery(self, view, policy: dict):
        """Klucz odzyskiwania firmy z polityki serwera → klucz dostępu w sejfie (odcisk zapamiętany w sejfie)."""
        vault = self.current_vault
        if vault is None or not isinstance(view, MainView):
            return
        key_text = (policy or {}).get("recovery_public_key") or ""
        state = (key_text, id(vault))
        if state == getattr(self, "_org_state", None):
            return
        self._org_state = state
        ring = vault.keyring
        if not key_text:
            if ring is not None and ring.org_key_id:
                ring.remove_org_key()  # firma wyłączyła odzyskiwanie – stary klucz przestaje działać dla nowych wersji
                view._save_vault_to_disk(trigger_backup=False)
                view.show_toast("🏢 Firma wyłączyła odzyskiwanie dostępu")
            return
        try:
            key_id = org_key_id(parse_org_public_key(key_text))
        except Exception:
            return
        if ring is not None and ring.org_key_id == key_id:
            return
        pinned = vault.settings.get(ORG_PIN_KEY)
        if pinned and pinned != key_id:
            # Zmiana klucza może oznaczać przejęcie serwera – decyzja użytkownika
            if not messagebox.askyesno(
                    "⚠️ Klucz odzyskiwania firmy się zmienił",
                    f"Serwer przekazał NOWY klucz odzyskiwania dostępu.\n\nDotychczasowy: {pinned}\nNowy: {key_id}\n\n"
                    "Zaakceptuj tylko, jeśli administrator potwierdził wymianę klucza (porównaj odcisk w panelu). "
                    "Nowy klucz pozwoli administratorowi przywrócić Ci dostęp do sejfu.", icon="warning"):
                return
        elif not pinned:
            messagebox.showinfo(
                "Odzyskiwanie dostępu przez firmę",
                "Twoja firma włączyła odzyskiwanie dostępu: jeśli zapomnisz hasła głównego, administrator będzie mógł "
                f"przywrócić Ci dostęp do sejfu.\n\nOdcisk klucza firmy: {key_id}")
        ring = self._ensure_keyring()
        ring.set_org_key(key_text)
        vault.settings[ORG_PIN_KEY] = key_id
        view._save_vault_to_disk(trigger_backup=False)

    def _check_forced_password_change(self, view):
        vault = self.current_vault
        if view is not self._current_view or not isinstance(view, MainView) or vault is None:
            return
        if vault.settings.get(FORCE_CHANGE_KEY):
            messagebox.showwarning("Ustaw własne hasło główne",
                                   "Dostęp do sejfu przywrócił administrator – używasz hasła tymczasowego.\n\n"
                                   "Ustaw teraz własne hasło główne (znasz je tylko Ty).")
            view.open_settings_for_password_change()

    def _icons_setting_changed(self):
        view = self._current_view
        if isinstance(view, MainView):
            view._refresh_entries_list()
            if view.selected_entry_id:
                view._render_entry_details(view.selected_entry_id)

    def security_options(self) -> dict:
        """Dane dla kart „Windows Hello i skróty” oraz „Odzyskiwanie dostępu” w Ustawieniach."""
        target = self.quick_unlock_target()
        ring = self.current_vault.keyring if self.current_vault else None
        return {
            "recovery": {
                "has_code": bool(ring and ring.has_recovery_code),
                "org_key_id": ring.org_key_id if ring else None,
                "org_policy": bool(self.current_policy().get("recovery_public_key")),
                "on_create": self.create_recovery_code,
                "on_remove": self.remove_recovery_code,
                "on_admin_tools": self.open_admin_tools,
            },
            "hello_available": bool(quick.available),
            "hello_allowed": policy_allows(self.current_policy()),
            "hello_enabled": bool(target and quick.store.is_enrolled(target)),
            "hello_days": valid_days(self.current_policy()),
            "on_hello_toggle": self.set_quick_unlock,
            "hotkeys": dict(self.quick_access.prefs),
            "hotkeys_registered": dict(self.quick_access.registered),
            "on_hotkeys_save": self.quick_access.apply_prefs,
            "autotype_allowed": self.autotype_allowed(),
            "on_icons_changed": self._icons_setting_changed,
        }

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
        cleanup_temp_copies()
        try:
            self.quick_access.stop()
        except Exception:
            pass
        self.withdraw()  # okno znika od razu, a zapisy w tle zdążą się dokończyć
        background_saver.flush()
        self.destroy()
