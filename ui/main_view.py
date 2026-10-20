"""
Główny pulpit nawigacyjny odblokowanego sejfu haseł (Main Vault View).
W pełni responsywny interfejs z bocznym, płynnie wysuwanym panelem (Sliding Drawer),
obsługą kosza (Trash / Recycle Bin), wizualizatorem kart płatniczych oraz serwerów/Wi-Fi.
"""

import os
import re
from collections import OrderedDict
import webbrowser
from urllib.parse import urlparse
import threading
import tkinter as tk
import tkinter.font as tkfont
from typing import Optional, Callable, List, Dict, Any
import customtkinter as ctk
from tkinter import filedialog, messagebox
from datetime import datetime, timezone

from core.attachments import (DEFAULT_MAX_MB as DEFAULT_ATTACHMENT_MB, decrypt_attachment, new_attachment, store_for,
                              write_temp_copy)

from core.vault import Vault, VaultEntry, DEFAULT_CATEGORIES
from core.desktop import open_path
from core.i18n import _, _n
from core.crypto import seal
from core.storage import background_saver
from core.totp_service import get_current_totp, get_totp_remaining_seconds
from core.generator import evaluate_password_strength
from core.security_audit import check_password_breach_hibp
from ui.theme import (FONT_FAMILY, FONT_MONO, 
    FONT_TITLE, FONT_SUBTITLE, FONT_BODY, FONT_BODY_BOLD, FONT_CODE, FONT_SMALL, FONT_TOTP,
    COLOR_PRIMARY, COLOR_PRIMARY_HOVER, COLOR_PRIMARY_LIGHT, COLOR_CARD_DARK, COLOR_CARD_HOVER, COLOR_PANEL_DARK,
    COLOR_SUCCESS, COLOR_DANGER, COLOR_WARNING, COLOR_BORDER, COLOR_TEXT_PRIMARY,
    COLOR_TEXT_MUTED, COLOR_TEXT_ACCENT
)
from ui.clipboard import SecureClipboard
from ui.policy import effective_clipboard, personal_backups_allowed
from ui.drawer import SlidingDrawer
from ui.entry_list import EntryList
from ui.flat_button import FlatButton
from core.watchtower import attention_count
from core import connect, expiry, plugins, ssh_keys
from core.site_icons import site_domain
from ui.site_icons_ui import avatar_for
from ui import perf
from ui.ssh_agent_ui import AgentController

perf.apply()
from ui.drawer_views import (
    EntryDrawerView,
    GeneratorDrawerView,
    AuditDrawerView,
    BackupDrawerView,
    ImportDrawerView,
    SettingsDrawerView,
    SyncDrawerView
)


# Pseudo-kategorie paska bocznego – wartości porównywane z filtrem sejfu (Vault.search), więc zawsze po polsku
ALL_CATEGORY = "Wszystkie"  # i18n: data
FAVORITES_CATEGORY = "⭐ Ulubione"  # i18n: data
TRASH_CATEGORY = "Kosz"  # i18n: data
EXPIRY_CATEGORY = "⏰ Do zmiany"  # i18n: data – wtyczka „Data ważności hasła”: hasła wygasłe i wkrótce wygasające


def category_label(category: str) -> str:
    """Nazwa kategorii do wyświetlenia: domyślne kategorie i pseudo-kategorie tłumaczone, własne bez zmian."""
    if category in DEFAULT_CATEGORIES or category in (ALL_CATEGORY, FAVORITES_CATEGORY, EXPIRY_CATEGORY):
        return _(category)
    return category


def _entries_count(n: int) -> str:
    return _n(n, "({n} wpis)", "({n} wpisy)", "({n} wpisów)")


def _human_size(size: int) -> str:
    for unit in ("B", "KB", "MB"):
        if size < 1024 or unit == "MB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} MB"


class MainView(ctk.CTkFrame):
    def __init__(
        self,
        parent,
        vault: Vault,
        master_password: str,
        vault_file_path: str,
        keyfile_bytes: Optional[bytes] = None,
        on_lock_requested: Optional[Callable[[], None]] = None,
        on_auto_backup_trigger: Optional[Callable[[], None]] = None,
        on_master_password_changed: Optional[Callable[[str], None]] = None,
        sync_session=None,
        on_sync_requested: Optional[Callable[..., None]] = None,
        on_vault_replaced: Optional[Callable[[Vault], None]] = None,
        on_audit_report: Optional[Callable[[Any], None]] = None
    ):
        super().__init__(parent, fg_color="transparent")
        self.vault = vault
        self.master_password = master_password
        self.vault_file_path = vault_file_path
        self.keyfile_bytes = keyfile_bytes
        self.on_lock_requested = on_lock_requested
        self.on_auto_backup_trigger = on_auto_backup_trigger
        self.on_master_password_changed = on_master_password_changed
        # Tryb serwerowy: zapis idzie do lokalnej kopii i jest wysyłany na serwer synchronizacji
        self.sync_session = sync_session
        self.on_sync_requested = on_sync_requested
        self.on_vault_replaced = on_vault_replaced
        self.on_audit_report = on_audit_report
        self.policy: Dict[str, Any] = {}  # polityki firmy z serwera (puste przy sejfie lokalnym)
        self._pending_remote_vault: Optional[Vault] = None
        self._last_sync_state: Optional[str] = None
        self._last_sync_status = None

        self.selected_entry_id: Optional[str] = None
        self.selected_category: str = ALL_CATEGORY
        self.selected_tag: Optional[str] = None
        self.favorite_filter: bool = False
        self.expiry_filter: bool = False
        self.trash_mode: bool = False
        self._floating_panel = None
        self.search_query: str = ""

        self._password_revealed = False
        self._details_cache: "OrderedDict[tuple, tuple]" = OrderedDict()
        self._detail_fillers = []
        self._totp_timer_id = None
        self._is_compact_sidebar = False
        self._last_win_width = 1200
        self._label_pad_cache = {}

        self.ssh_agent = AgentController(self)
        self._build_ui()
        self._applied_plugins = self._enabled_plugins()
        self.ssh_agent.sync()
        self._refresh_entries_list()
        self._start_totp_ticker()

        # Inicjalizacja wysuwanego z boku panelu (Sliding Drawer)
        self.drawer = SlidingDrawer(self)

        # Nasłuchiwanie zmiany rozmiaru okna dla pełnej responsywności
        tk.Misc.bind(self, "<Configure>", self._on_window_resized, "+")
        self._idle_jobs = [self.after(300, self._warm_up_glyphs), self.after(700, self._prebuild_details),
                           self.after(2500, self._remind_expiring_passwords)]

    WARM_UP_GLYPHS = "✏️📋🗑️👁🔒🔍🌐♻️✕📂📄⭐⚠️💳🔐⏰🖥️🔳🔢"

    # ----------------- WTYCZKI -----------------
    def plugin_on(self, plugin_id: str) -> bool:
        return plugins.is_enabled(self.vault.settings, self.policy, plugin_id)

    def _enabled_plugins(self) -> frozenset:
        return plugins.enabled_set(self.vault.settings, self.policy)

    def apply_plugins(self):
        """Po zmianie wtyczek (ustawienia, polityka firmy, sejf z innego urządzenia): odświeża to, co od nich zależy."""
        if not self.winfo_exists():
            return
        enabled = self._enabled_plugins()
        if enabled == getattr(self, "_applied_plugins", None):
            return
        self._applied_plugins = enabled
        self.ssh_agent.sync()
        if "floating_panel" in enabled:
            if not self.floating_btn.winfo_manager():
                self.floating_btn.pack(side="left", padx=3, before=self.settings_btn)
        else:
            self.floating_btn.pack_forget()
            self._close_floating_panel()
        if "family_share" in enabled:
            if not self.family_btn.winfo_manager():
                self.family_btn.pack(side="left", padx=3, before=self.settings_btn)
        else:
            self.family_btn.pack_forget()
        if "expiry" not in enabled:
            self.expiry_filter = False
        self._build_sidebar()
        self._refresh_entries_list()
        if self.selected_entry_id and not self.trash_mode:
            self._render_entry_details(self.selected_entry_id)  # panel ma nowy układ (klucz pamięci z wtyczkami)

    def on_ssh_keys_loaded(self):
        """Klucze SSH wczytane w tle – odśwież kartę klucza w otwartym wpisie."""
        entry = getattr(self, "_details_entry", None)
        if self.winfo_exists() and entry is not None and self.selected_entry_id == entry.id \
                and ssh_keys.field_name(entry):
            self._fill_entry_details(entry)

    def _copy_ssh_public_key(self, entry: VaultEntry):
        key = self.ssh_agent.key_for(entry.id)
        if key is None:
            self.show_toast(self.ssh_agent.errors.get(entry.id) or _("Klucz SSH jest jeszcze wczytywany…"), error=True)
            return
        SecureClipboard.copy(key.public_line(), timeout_seconds=0)  # klucz publiczny nie jest tajny
        self.show_toast(_("Klucz publiczny skopiowany – wklej go na serwerze do ~/.ssh/authorized_keys"))

    def _remind_expiring_passwords(self):
        if not self.winfo_exists() or not self.plugin_on("expiry"):
            return
        due = expiry.attention(self.vault.entries.values())
        expired = sum(1 for _e, state, _d in due if state == expiry.EXPIRED)
        soon = len(due) - expired
        if not due:
            return
        parts = []
        if expired:
            parts.append(_n(expired, "{n} hasło wygasło", "{n} hasła wygasły", "{n} haseł wygasło"))
        if soon:
            parts.append(_n(soon, "{n} wkrótce wygaśnie", "{n} wkrótce wygasną", "{n} wkrótce wygaśnie"))
        self.show_toast(_("⏰ {summary} – zobacz „Do zmiany” w menu po lewej.", summary=", ".join(parts)),
                        error=bool(expired))

    def _connect(self, entry: VaultEntry):
        target = connect.parse_target(entry)
        if target is None:
            return
        try:
            plan = connect.build_plan(target)
            notes = connect.launch(plan)
        except connect.ConnectError as e:
            messagebox.showwarning(_("Połącz"), str(e), parent=self.winfo_toplevel())
            return
        if plan.clipboard_text:
            self._copy_password_safe(plan.clipboard_text)
            notes.append(_("Hasło jest w schowku – wklej je, gdy program o nie zapyta."))
        self.show_toast(" ".join(notes) or _("🖥️ Łączenie: {target} ({kind})", target=target.address, kind=target.label))

    def _show_password_qr(self, entry: VaultEntry):
        from ui.plugin_dialogs import QrDialog
        try:
            QrDialog(self, entry)
        except Exception as e:
            self.show_toast(_("Nie można utworzyć kodu QR: {error}", error=e), error=True)

    def _pick_password_chars(self, entry: VaultEntry):
        from ui.plugin_dialogs import PickCharsDialog
        PickCharsDialog(self, entry, on_copy=self._copy_to_clipboard)

    def _secure_send(self, entry: VaultEntry):
        from ui.plugin_dialogs import SecureSendDialog
        if self.sync_session is None:
            # Link musi być gdzieś dostępny dla odbiorcy – lokalny sejf to tylko plik na tym komputerze
            messagebox.showinfo(_("Bezpieczny link"),
                                _("Bezpieczny link wymaga serwera KeyStead – to on przechowuje zaszyfrowany link, "
                                  "dopóki odbiorca go nie otworzy.\n\nTen sejf jest plikiem na tym komputerze, więc "
                                  "linku nie da się z niego wysłać. Pozostałe wtyczki działają normalnie."),
                                parent=self.winfo_toplevel())
            return
        SecureSendDialog(self, entry, self.sync_session, self.vault.settings, self._run_in_background,
                         on_sent=lambda: self._save_vault_to_disk(trigger_backup=False))

    def _send_to_phone(self, entry: VaultEntry):
        from ui.plugin_dialogs import PhoneHandoffDialog
        poster = getattr(self.winfo_toplevel(), "post_to_ui", None) or (lambda fn: self.after(0, fn))
        PhoneHandoffDialog(self, entry, poster)

    def _family_name(self) -> str:
        from core import family_share
        ident = self.vault.settings.get(family_share.IDENTITY_KEY)
        return (ident or {}).get("name") or self.vault.name

    def _open_family_dialog(self):
        from ui.family_view import FamilyDrawerView

        def _received(entry: VaultEntry):
            self.drawer.close()
            self._build_sidebar()
            self._refresh_entries_list()
            self._select_entry(entry.id)
            self.show_toast(_("👪 Dodano wpis „{title}”", title=entry.title))

        self.drawer.open(_("Domownicy"), _("Wysyłaj hasła bliskim bez serwera i chmury"),
                         build=lambda c: FamilyDrawerView(c, vault=self.vault,
                                                          on_saved=lambda: self._save_vault_to_disk(trigger_backup=False),
                                                          on_received=_received, copy_text=self._copy_share_text))

    def _copy_share_text(self, text: str):
        # Wizytówki i paczki są zaszyfrowane / publiczne – schowek czyszczony po 5 minutach, żeby zdążyć wkleić
        SecureClipboard.copy(text, timeout_seconds=300)
        self.show_toast(_("Skopiowano – wklej w wiadomości"))

    def _send_to_family(self, entry: VaultEntry):
        from ui.family_view import SendShareDialog
        SendShareDialog(self, self.vault, entry, self._family_name(), copy_text=self._copy_share_text,
                        on_sent=lambda: self._save_vault_to_disk(trigger_backup=False))

    def _toggle_floating_panel(self):
        if self._floating_panel is not None and self._floating_panel.winfo_exists():
            self._close_floating_panel()
            return
        from ui.plugin_dialogs import FloatingPanel

        def _copy(text: str) -> int:
            seconds = effective_clipboard(int(self.vault.settings.get("clipboard_clear_seconds", 30) or 0), self.policy)
            SecureClipboard.copy(text, timeout_seconds=seconds)
            return seconds

        def _select(entry_id: str):
            top = self.winfo_toplevel()
            top.deiconify()
            top.lift()
            if self.vault.get_entry(entry_id):
                self._select_entry(entry_id)

        self._floating_panel = FloatingPanel(self, vault_getter=lambda: self.vault, copy=_copy, on_select=_select)

    def _close_floating_panel(self):
        panel, self._floating_panel = self._floating_panel, None
        if panel is not None:
            try:
                panel.destroy()
            except Exception:
                pass

    def _refresh_floating_panel(self):
        panel = self._floating_panel
        if panel is not None and panel.winfo_exists():
            panel.refresh()

    def _warm_up_glyphs(self):
        """
        Pierwsze użycie emoji w danej czcionce Tk na Windows szuka czcionki zastępczej (~10 ms na znak).
        Robimy to raz, zaraz po otwarciu sejfu, zamiast przy pierwszym kliknięciu wpisu.
        """
        if not self.winfo_exists():
            return
        s = self._get_widget_scaling()
        for family, size, *style in (FONT_BODY, FONT_SMALL, FONT_BODY_BOLD, FONT_TITLE):
            try:
                tk.Label(self, text=self.WARM_UP_GLYPHS, font=(family, -int(round(size * s)), *style)).destroy()
            except tk.TclError:
                pass

    def destroy(self):
        """Zatrzymuje timery i odpina skróty przed zniszczeniem widoku (blokada sejfu)."""
        for job in getattr(self, "_idle_jobs", []):
            try:
                self.after_cancel(job)
            except Exception:
                pass
        if self._totp_timer_id:
            try:
                self.after_cancel(self._totp_timer_id)
            except Exception:
                pass
            self._totp_timer_id = None
        self._close_floating_panel()
        self.ssh_agent.stop()  # zablokowany sejf = agent nie podpisuje już niczego
        if hasattr(self, "drawer"):
            self.drawer.destroy()
        super().destroy()

    def _run_in_background(self, work: Callable[[], Any], on_done: Callable[[Any], None]):
        """Uruchamia pracę sieciową w wątku i bezpiecznie wraca z wynikiem do wątku UI."""
        poster = getattr(self.winfo_toplevel(), "post_to_ui", None) or (lambda fn: self.after(0, fn))

        def _worker():
            try:
                result = work()
            except Exception as e:
                result = e
            try:
                poster(lambda: self.winfo_exists() and on_done(result))
            except Exception:
                pass  # Widok został zniszczony (np. blokada sejfu)
        threading.Thread(target=_worker, daemon=True).start()

    # ----------------- ZAŁĄCZNIKI -----------------
    @property
    def attachment_store(self):
        if getattr(self, "_attachment_store", None) is None:
            self._attachment_store = store_for(self.vault_file_path, self.sync_session)
        return self._attachment_store

    def _attachments_allowed(self) -> bool:
        return (self.policy or {}).get("allow_attachments", True) is not False

    def _attachment_limit(self) -> int:
        try:
            mb = int((self.policy or {}).get("max_attachment_mb") or DEFAULT_ATTACHMENT_MB)
        except (TypeError, ValueError):
            mb = DEFAULT_ATTACHMENT_MB
        return max(1, min(mb, 50)) * 1024 * 1024

    def _render_attachments(self, container, entry: VaultEntry, read_only: bool):
        if not entry.attachments and (read_only or not self._attachments_allowed()):
            return
        card = ctk.CTkFrame(container, fg_color=COLOR_CARD_DARK, corner_radius=10)
        card.pack(fill="x", pady=(0, 10), ipady=6)
        head = self._plain_frame(card)
        head.pack(fill="x", padx=12, pady=(6, 4))
        self._label(head, text=_("📂 Załączniki ({count})", count=len(entry.attachments)), font=FONT_SMALL,
                    text_color=COLOR_TEXT_MUTED).pack(side="left")
        if not read_only and self._attachments_allowed():
            FlatButton(head, text=_("+ Dodaj plik"), width=95, height=24, font=FONT_SMALL, fg_color=COLOR_PANEL_DARK,
                          command=lambda: self._add_attachment(self._details_entry)).pack(side="right")
        for meta in list(entry.attachments):
            row = self._plain_frame(card)
            row.pack(fill="x", padx=12, pady=2)
            self._label(row, text=f"📄 {meta['name']}", font=FONT_BODY, anchor="w").pack(side="left")
            self._label(row, text=f"  {_human_size(meta.get('size', 0))}", font=FONT_SMALL,
                        text_color=COLOR_TEXT_MUTED).pack(side="left")
            if not read_only:
                FlatButton(row, text=_("Usuń"), width=50, height=22, font=FONT_SMALL, fg_color=COLOR_PANEL_DARK,
                              command=lambda m=meta: self._remove_attachment(self._details_entry, m)).pack(side="right", padx=(4, 0))
            FlatButton(row, text=_("Zapisz…"), width=62, height=22, font=FONT_SMALL, fg_color=COLOR_PANEL_DARK,
                          command=lambda m=meta: self._save_attachment_as(m)).pack(side="right", padx=(4, 0))
            FlatButton(row, text=_("Otwórz"), width=58, height=22, font=FONT_SMALL, fg_color=COLOR_PRIMARY,
                          command=lambda m=meta: self._open_attachment(m)).pack(side="right")

    def _add_attachment(self, entry: VaultEntry):
        path = filedialog.askopenfilename(title=_("Wybierz plik do zaszyfrowania i dołączenia"))
        if not path:
            return
        limit = self._attachment_limit()
        store = self.attachment_store
        self.show_toast(_("🔐 Szyfrowanie i zapisywanie załącznika..."))

        def _work():
            meta, blob = new_attachment(path, limit)
            store.put(meta["id"], blob)  # najpierw plik (także na serwerze), dopiero potem wpis w sejfie
            return meta

        def _done(result):
            if isinstance(result, Exception):
                self.show_toast(_("Nie dodano załącznika: {error}", error=result), error=True)
                return
            entry.attachments.append(result)
            entry.updated_at = datetime.now(timezone.utc).isoformat()
            self._save_vault_to_disk()
            if self.selected_entry_id == entry.id:
                self._render_entry_details(entry.id)
            self.show_toast(_("📂 Dodano „{name}”", name=result["name"]))
        self._run_in_background(_work, _done)

    def _load_attachment(self, meta, on_data):
        store = self.attachment_store
        self._run_in_background(lambda: decrypt_attachment(meta, store.get(meta["id"])), on_data)

    def _open_attachment(self, meta):
        def _done(data):
            if isinstance(data, Exception):
                self.show_toast(_("Nie można otworzyć: {error}", error=data), error=True)
                return
            path = write_temp_copy(meta, data)
            try:
                open_path(path)  # domyślny program dla tego typu pliku
            except (AttributeError, OSError) as e:
                self.show_toast(_("Nie można otworzyć pliku: {error}", error=e), error=True)
                return
            self.show_toast(_("Otwarto kopię tymczasową – zostanie usunięta po zablokowaniu sejfu"))
        self._load_attachment(meta, _done)

    def _save_attachment_as(self, meta):
        target = filedialog.asksaveasfilename(title=_("Zapisz odszyfrowany załącznik"), initialfile=meta["name"])
        if not target:
            return

        def _done(data):
            if isinstance(data, Exception):
                self.show_toast(_("Nie można zapisać: {error}", error=data), error=True)
                return
            with open(target, "wb") as f:
                f.write(data)
            self.show_toast(_("Zapisano „{name}”", name=os.path.basename(target)))
        self._load_attachment(meta, _done)

    def _remove_attachment(self, entry: VaultEntry, meta):
        if not messagebox.askyesno(_("Usuń załącznik"), _("Usunąć załącznik „{name}” z tego wpisu?", name=meta["name"])):
            return
        entry.attachments = [a for a in entry.attachments if a.get("id") != meta["id"]]
        entry.updated_at = datetime.now(timezone.utc).isoformat()
        self._save_vault_to_disk()
        self._delete_unused_attachments([meta["id"]])
        if self.selected_entry_id == entry.id:
            self._render_entry_details(entry.id)

    def _delete_unused_attachments(self, ids):
        """Po zapisie sejfu: usuwa pliki, których nie używa już żaden wpis (najpierw sejf, potem pliki)."""
        unused = [i for i in ids if not self.vault.attachment_in_use(i)]
        if not unused:
            return
        store = self.attachment_store

        def _work():
            for att_id in unused:
                try:
                    store.delete(att_id)
                except Exception:
                    pass
        self._run_in_background(_work, lambda _r: None)

    def _build_ui(self):
        # 1. Pasek górny (Top Navigation Bar)
        self.top_bar = ctk.CTkFrame(self, fg_color=COLOR_PANEL_DARK, height=65, corner_radius=0)
        self.top_bar.pack(fill="x", side="top")

        # Lewa strona paska: Tytuł sejfu i przycisk zwijania bocznego menu
        brand_box = ctk.CTkFrame(self.top_bar, fg_color="transparent")
        brand_box.pack(side="left", padx=15, pady=12)

        self.sidebar_toggle_btn = ctk.CTkButton(
            brand_box,
            text="☰",
            width=36,
            height=36,
            font=(FONT_FAMILY, 16, "bold"),
            fg_color=COLOR_CARD_DARK,
            hover_color=COLOR_CARD_HOVER,
            command=self._toggle_sidebar_manually
        )
        self.sidebar_toggle_btn.pack(side="left", padx=(0, 10))

        self.vault_title_lbl = ctk.CTkLabel(
            brand_box,
            text=f"🛡️ {self.vault.name}",
            font=FONT_TITLE,
            text_color=COLOR_TEXT_PRIMARY
        )
        self.vault_title_lbl.pack(side="left")

        self.count_badge = ctk.CTkLabel(
            brand_box,
            text=_entries_count(len(self.vault.entries)),
            font=FONT_SMALL,
            text_color=COLOR_TEXT_MUTED
        )
        self.count_badge.pack(side="left", padx=(8, 0))


        # Środek: Wyszukiwarka na żywo
        self.search_box = ctk.CTkFrame(self.top_bar, fg_color="transparent")
        self.search_box.pack(side="left", expand=True, fill="x", padx=15)

        self.search_entry = ctk.CTkEntry(
            self.search_box,
            placeholder_text=_("🔍 Szukaj wpisu (nazwa, login, tag, url)..."),
            height=36
        )
        self.search_entry.pack(side="left", fill="x", expand=True)
        self.search_entry.bind("<KeyRelease>", self._on_search_typed)

        # Prawa strona: Przyciski akcji (każdy wysuwa panel boczny)
        self.actions_box = ctk.CTkFrame(self.top_bar, fg_color="transparent")
        self.actions_box.pack(side="right", padx=15, pady=12)
        self._toolbar_buttons = []  # (przycisk, pełny opis, krótki opis, szerokość pełna, szerokość krótka)

        btn = ctk.CTkButton(
            self.actions_box,
            text=_("+ Nowy Wpis"),
            fg_color=COLOR_PRIMARY,
            hover_color=COLOR_PRIMARY_HOVER,
            width=100,
            command=self._open_new_entry_dialog
        )
        btn.pack(side="left", padx=3)
        self._toolbar_buttons.append((btn, _("+ Nowy Wpis"), _("+ Nowy"), 100, 64))

        btn = ctk.CTkButton(
            self.actions_box,
            text=_("⚡ Generator"),
            fg_color=COLOR_CARD_DARK,
            hover_color=COLOR_CARD_HOVER,
            width=85,
            command=self._open_generator_dialog
        )
        btn.pack(side="left", padx=3)
        self._toolbar_buttons.append((btn, _("⚡ Generator"), "⚡", 85, 36))

        self.audit_btn = ctk.CTkButton(
            self.actions_box,
            text=_("🛡️ Audyt Wycieków"),
            fg_color="#7c3aed",
            hover_color="#6d28d9",
            width=125,
            command=self._open_audit_dialog
        )
        self.audit_btn.pack(side="left", padx=3)
        self._toolbar_buttons.append((self.audit_btn, _("🛡️ Audyt Wycieków"), "🛡️", 125, 36))

        btn = ctk.CTkButton(
            self.actions_box,
            text=_("🚨 Ratunek"),
            fg_color=COLOR_DANGER,
            hover_color="#e11d48",
            width=95,
            command=self._open_rescue_dialog
        )
        btn.pack(side="left", padx=3)
        self._toolbar_buttons.append((btn, _("🚨 Ratunek"), "🚨", 95, 36))

        btn = ctk.CTkButton(
            self.actions_box,
            text=_("☁️ Kopie i Chmura"),
            fg_color=COLOR_CARD_DARK,
            hover_color=COLOR_CARD_HOVER,
            width=115,
            command=self._open_backup_dialog
        )
        btn.pack(side="left", padx=3)
        self._toolbar_buttons.append((btn, _("☁️ Kopie i Chmura"), "☁️", 115, 36))

        btn = ctk.CTkButton(
            self.actions_box,
            text=_("📥 Import"),
            fg_color=COLOR_CARD_DARK,
            hover_color=COLOR_CARD_HOVER,
            width=75,
            command=self._open_import_dialog
        )
        btn.pack(side="left", padx=3)
        self._toolbar_buttons.append((btn, _("📥 Import"), "📥", 75, 36))

        # Wtyczka „Pływający panel” – przycisk widoczny tylko, gdy jest włączona (apply_plugins)
        self.floating_btn = ctk.CTkButton(
            self.actions_box,
            text="📌",
            fg_color=COLOR_CARD_DARK,
            hover_color=COLOR_CARD_HOVER,
            width=36,
            command=self._toggle_floating_panel
        )

        self.family_btn = ctk.CTkButton(
            self.actions_box,
            text="👪",
            fg_color=COLOR_CARD_DARK,
            hover_color=COLOR_CARD_HOVER,
            width=36,
            command=self._open_family_dialog
        )

        self.settings_btn = ctk.CTkButton(
            self.actions_box,
            text="⚙️",
            fg_color=COLOR_CARD_DARK,
            hover_color=COLOR_CARD_HOVER,
            width=36,
            command=self._open_settings_dialog
        )
        self.settings_btn.pack(side="left", padx=3)
        if self.plugin_on("floating_panel"):
            self.floating_btn.pack(side="left", padx=3, before=self.settings_btn)
        if self.plugin_on("family_share"):
            self.family_btn.pack(side="left", padx=3, before=self.settings_btn)

        ctk.CTkButton(
            self.actions_box,
            text="🔒",
            fg_color=COLOR_DANGER,
            width=36,
            command=self._lock_vault
        ).pack(side="left", padx=3)

        # 2. Główny kontener roboczy
        self.workspace_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.workspace_frame.pack(fill="both", expand=True, padx=12, pady=12)

        # 2.1 Pasek boczny (Sidebar)
        self.sidebar_width = 220
        self.sidebar_frame = ctk.CTkFrame(self.workspace_frame, width=self.sidebar_width, fg_color=COLOR_PANEL_DARK, corner_radius=12)
        self.sidebar_frame.pack(side="left", fill="y", padx=(0, 10))
        self.sidebar_frame.pack_propagate(False)

        # Wskaźnik synchronizacji z serwerem (tylko w trybie serwerowym) – na górze bocznego menu
        self.sync_btn = None
        if self.sync_session:
            self.sync_btn = ctk.CTkButton(
                self.sidebar_frame, text=_("⏳ Łączenie..."), height=32, font=FONT_BODY_BOLD,
                fg_color=COLOR_CARD_DARK, hover_color=COLOR_CARD_HOVER, corner_radius=8,
                command=self._open_sync_dialog
            )
            self.sync_btn.pack(fill="x", padx=8, pady=(10, 0))

        # Kategorie i tagi (przebudowywane przy każdej zmianie filtrów)
        self.sidebar_body = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        self.sidebar_body.pack(fill="both", expand=True)

        self._build_sidebar()

        # 2.2 Lista wpisów (Center Column)
        self.entries_list_width = 300
        self.entries_list_frame = ctk.CTkFrame(self.workspace_frame, width=self.entries_list_width, fg_color=COLOR_PANEL_DARK, corner_radius=12)
        self.entries_list_frame.pack(side="left", fill="y", padx=(0, 10))
        self.entries_list_frame.pack_propagate(False)

        list_header = ctk.CTkFrame(self.entries_list_frame, fg_color="transparent")
        list_header.pack(fill="x", padx=12, pady=(12, 6))

        self.list_title_lbl = ctk.CTkLabel(list_header, text=_("Wszystkie wpisy"), font=FONT_SUBTITLE, text_color=COLOR_TEXT_PRIMARY)
        self.list_title_lbl.pack(side="left")

        self.icon_provider = getattr(self.winfo_toplevel(), "icon_provider", None)
        self.entry_list = EntryList(self.entries_list_frame, bg=COLOR_PANEL_DARK, on_select=self._select_entry,
                                    icon_provider=self.icon_provider)
        self.entry_list.pack(fill="both", expand=True, padx=6, pady=(0, 10))

        # 2.3 Szczegóły wpisu (Right Detail View)
        self.details_frame = ctk.CTkFrame(self.workspace_frame, fg_color=COLOR_PANEL_DARK, corner_radius=12)
        self.details_frame.pack(side="left", fill="both", expand=True)

        self.details_scroll = ctk.CTkScrollableFrame(self.details_frame, fg_color="transparent")
        self.details_scroll.pack(fill="both", expand=True, padx=20, pady=15)

        self._show_empty_details()

    # ----------------- RESPONSYWNOŚĆ OKNA -----------------
    # Progi szerokości okna (w punktach interfejsu, niezależnie od skalowania Windows)
    TOOLBAR_ICONS_BELOW = 1180   # przyciski paska: same ikony
    SIDEBAR_COMPACT_BELOW = 1000 # panel kategorii: same ikony
    NARROW_BELOW = 900           # węższa lista wpisów, bez licznika wpisów

    def _on_window_resized(self, event):
        # Filtrujemy zdarzenia resize tylko z głównego widgetu
        if event.widget is not self:
            return
        w = event.width / max(self._get_widget_scaling(), 0.1)
        layout = (w < self.TOOLBAR_ICONS_BELOW, w < self.SIDEBAR_COMPACT_BELOW, w < self.NARROW_BELOW)
        if layout == getattr(self, "_layout_mode", None):
            return
        previous = getattr(self, "_layout_mode", None)
        self._layout_mode = layout
        icons_only, compact_sidebar, narrow = layout

        for btn, full, short, wf, ws in self._toolbar_buttons:
            btn.configure(text=short if icons_only else full, width=ws if icons_only else wf)
        if narrow:
            self.count_badge.pack_forget()
        elif not self.count_badge.winfo_manager():
            self.count_badge.pack(side="left", padx=(8, 0))
        list_width = 250 if narrow else self.entries_list_width
        if int(self.entries_list_frame.cget("width")) != list_width:
            self.entries_list_frame.configure(width=list_width)

        # Panel kategorii zwija się automatycznie tylko przy przekroczeniu progu – ręczne przełączenie (☰) zostaje
        if previous is None or previous[1] != compact_sidebar:
            if compact_sidebar != self._is_compact_sidebar:
                self._is_compact_sidebar = compact_sidebar
                self.sidebar_frame.configure(width=60 if compact_sidebar else 220)
                self._build_sidebar()

    def _toggle_sidebar_manually(self):
        self._is_compact_sidebar = not self._is_compact_sidebar
        self.sidebar_frame.configure(width=60 if self._is_compact_sidebar else 220)
        self._build_sidebar()

    # ----------------- SIDEBAR I FILTRY -----------------
    def _build_sidebar(self):
        for w in self.sidebar_body.winfo_children():
            w.destroy()
        if self._last_sync_status is not None:
            self.update_sync_status(self._last_sync_status)  # tryb kompaktowy: sama ikona

        scroll = ctk.CTkScrollableFrame(self.sidebar_body, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=4, pady=10)
        self._sidebar_buttons = {}  # klucz filtra -> przycisk (zmiana zaznaczenia bez przebudowy paska)

        is_compact = self._is_compact_sidebar

        if not is_compact:
            ctk.CTkLabel(scroll, text=_("KATEGORIE"), font=FONT_SMALL, text_color=COLOR_TEXT_MUTED).pack(anchor="w", padx=8, pady=(0, 6))

        all_cats = [ALL_CATEGORY, FAVORITES_CATEGORY] + self.vault.categories
        due_count = len(expiry.attention(self.vault.entries.values())) if self.plugin_on("expiry") else 0
        if due_count or self.expiry_filter:
            all_cats.insert(2, EXPIRY_CATEGORY)

        for cat in all_cats:
            is_active = self._category_active(cat)
            btn_color = COLOR_PRIMARY if is_active else "transparent"
            text_color = COLOR_TEXT_PRIMARY if is_active else COLOR_TEXT_MUTED

            if cat == ALL_CATEGORY:
                cnt = len(self.vault.entries)
                icon = "📂"
            elif cat == FAVORITES_CATEGORY:
                cnt = sum(1 for e in self.vault.entries.values() if e.favorite)
                icon = "⭐"
            elif cat == EXPIRY_CATEGORY:
                cnt = due_count
                icon = "⏰"
            else:
                cnt = sum(1 for e in self.vault.entries.values() if e.category == cat)
                icon = self._get_category_icon(cat)

            shown = category_label(cat).replace("⏰ ", "") if cat == EXPIRY_CATEGORY else category_label(cat)
            btn_text = f"{icon}" if is_compact else f"{icon}  {shown} ({cnt})"

            btn = ctk.CTkButton(
                scroll,
                text=btn_text,
                anchor="center" if is_compact else "w",
                fg_color=btn_color,
                text_color=text_color,
                hover_color=COLOR_CARD_HOVER,
                corner_radius=8,
                height=34,
                command=lambda c=cat: self._select_category(c)
            )
            btn.pack(fill="x", pady=2)
            self._sidebar_buttons[("cat", cat)] = btn

        # Przycisk Kosza (Trash / Recycle Bin)
        trash_cnt = len(self.vault.trash)
        trash_active = self.trash_mode
        trash_text = "🗑️" if is_compact else _("🗑️  Kosz ({count})", count=trash_cnt)

        trash_btn = ctk.CTkButton(
            scroll,
            text=trash_text,
            anchor="center" if is_compact else "w",
            fg_color=COLOR_PRIMARY if trash_active else "transparent",
            text_color=COLOR_DANGER if not trash_active else "#ffffff",
            hover_color=COLOR_CARD_HOVER,
            corner_radius=8,
            height=34,
            command=self._select_trash
        )
        trash_btn.pack(fill="x", pady=(10, 4))
        self._sidebar_buttons[("trash", None)] = trash_btn

        if not is_compact:
            new_cat_btn = ctk.CTkButton(
                scroll,
                text=_("+ Nowa kategoria"),
                anchor="w",
                font=FONT_SMALL,
                fg_color="transparent",
                text_color=COLOR_TEXT_ACCENT,
                hover_color=COLOR_CARD_HOVER,
                command=self._prompt_new_category
            )
            new_cat_btn.pack(fill="x", pady=(4, 15))

            # Tagi
            tags = set()
            for e in self.vault.entries.values():
                for t in e.tags:
                    tags.add(t)

            if tags:
                ctk.CTkLabel(scroll, text=_("TAGI"), font=FONT_SMALL, text_color=COLOR_TEXT_MUTED).pack(anchor="w", padx=8, pady=(8, 4))
                for t in sorted(tags):
                    tag_active = (self.selected_tag == t)
                    tag_btn = ctk.CTkButton(
                        scroll,
                        text=f"🏷️ #{t}",
                        anchor="w",
                        fg_color=COLOR_PRIMARY if tag_active else "transparent",
                        text_color=COLOR_TEXT_PRIMARY if tag_active else COLOR_TEXT_MUTED,
                        height=26,
                        corner_radius=6,
                        command=lambda tag=t: self._toggle_tag_filter(tag)
                    )
                    tag_btn.pack(fill="x", pady=1)
                    self._sidebar_buttons[("tag", t)] = tag_btn

    def _get_category_icon(self, cat: str) -> str:
        c = cat.lower()
        if "login" in c or "konto" in c:
            return "🔑"
        elif "kart" in c or "bank" in c:
            return "💳"
        elif "notatk" in c:
            return "📝"
        elif "serwer" in c or "wi-fi" in c or "wifi" in c:
            return "🖥️"
        elif "tożsamoś" in c or "osob" in c:  # i18n: data
            return "👤"
        return "📁"

    def _category_active(self, cat: str) -> bool:
        if self.trash_mode:
            return False
        if cat == FAVORITES_CATEGORY:
            return self.favorite_filter
        if cat == EXPIRY_CATEGORY:
            return self.expiry_filter
        return cat == self.selected_category and not self.favorite_filter and not self.expiry_filter

    def _select_category(self, cat: str):
        self.trash_mode = False
        self.favorite_filter = cat == FAVORITES_CATEGORY
        self.expiry_filter = cat == EXPIRY_CATEGORY
        self.selected_category = ALL_CATEGORY if cat in (FAVORITES_CATEGORY, EXPIRY_CATEGORY) else cat

        self.selected_tag = None
        self._paint_sidebar_selection()
        self._refresh_entries_list(keep_scroll=False)

    def _select_trash(self):
        self.trash_mode = True
        self.favorite_filter = False
        self.expiry_filter = False
        self.selected_category = TRASH_CATEGORY
        self.selected_tag = None
        self._paint_sidebar_selection()
        self._refresh_entries_list(keep_scroll=False)
        self._show_trash_header_in_details()

    def _toggle_tag_filter(self, tag: str):
        self.trash_mode = False
        self.selected_tag = None if self.selected_tag == tag else tag
        self._paint_sidebar_selection()
        self._refresh_entries_list(keep_scroll=False)

    def _paint_sidebar_selection(self):
        """Zmiana filtra: przekolorowanie przycisków zamiast przebudowy całego paska (liczniki się nie zmieniły)."""
        buttons = getattr(self, "_sidebar_buttons", None)
        if not buttons or any(not b.winfo_exists() for b in buttons.values()):
            self._build_sidebar()
            return
        for (kind, name), btn in buttons.items():
            if kind == "cat":
                active = self._category_active(name)
                colors = (COLOR_PRIMARY, COLOR_TEXT_PRIMARY) if active else ("transparent", COLOR_TEXT_MUTED)
            elif kind == "trash":
                colors = (COLOR_PRIMARY, "#ffffff") if self.trash_mode else ("transparent", COLOR_DANGER)
            else:
                active = self.selected_tag == name
                colors = (COLOR_PRIMARY, COLOR_TEXT_PRIMARY) if active else ("transparent", COLOR_TEXT_MUTED)
            if (btn.cget("fg_color"), btn.cget("text_color")) != colors:
                btn.configure(fg_color=colors[0], text_color=colors[1])

    def _prompt_new_category(self):
        dialog = ctk.CTkInputDialog(text=_("Podaj nazwę nowej kategorii:"), title=_("Nowa kategoria"))
        val = dialog.get_input()
        if val and val.strip():
            if self.vault.add_category(val.strip()):
                self._save_vault_to_disk()
                self._build_sidebar()

    def _on_search_typed(self, event=None):
        # Przy szybkim pisaniu filtrujemy raz, po krótkiej przerwie, a nie po każdym klawiszu
        if getattr(self, "_search_job", None):
            self.after_cancel(self._search_job)
        self._search_job = self.after(120, self._flush_search)

    def _flush_search(self):
        if getattr(self, "_search_job", None):
            self.after_cancel(self._search_job)
        self._search_job = None
        query = self.search_entry.get().strip()
        if query != self.search_query:
            self.search_query = query
            self._refresh_entries_list(keep_scroll=False)

    # ----------------- LISTA WPISÓW -----------------
    def _refresh_entries_list(self, keep_scroll: bool = True):
        if self.trash_mode:
            results = self.vault.search(query=self.search_query, in_trash=True)
            self.list_title_lbl.configure(text=_("🗑️ Kosz ({count})", count=len(results)))
        else:
            results = self.vault.search(
                query=self.search_query,
                category=self.selected_category if self.selected_category != ALL_CATEGORY else None,
                tag=self.selected_tag,
                favorite_only=self.favorite_filter,
                in_trash=False
            )
            if self.expiry_filter:
                due = {e.id for e, _state, _days in expiry.attention(self.vault.entries.values())}
                results = [e for e in results if e.id in due]
            title_text = category_label(self.selected_category)
            if self.favorite_filter:
                title_text = category_label(FAVORITES_CATEGORY)
            elif self.expiry_filter:
                title_text = category_label(EXPIRY_CATEGORY)
            if self.selected_tag:
                title_text += f" [#{self.selected_tag}]"
            self.list_title_lbl.configure(text=f"{title_text} ({len(results)})")

        items = []
        show_expiry = self.plugin_on("expiry")
        for e in results:
            domain, avatar, color = avatar_for(e.title, e.url, self._get_category_icon(e.category) if not e.url else "")
            state = expiry.status(e) if show_expiry else None
            badge = "⏰ " if state and state[0] != expiry.OK else ""
            items.append({"id": e.id, "title": f"{badge}{e.title}{' ⭐' if e.favorite else ''}",
                          "subtitle": e.username or category_label(e.category), "domain": domain, "avatar": avatar, "color": color})
        empty = _("Kosz jest pusty.") if self.trash_mode else _("Brak wpisów spełniających kryteria.")
        self.entry_list.selected_id = self.selected_entry_id
        self.entry_list.set_items(items, empty_text=empty, keep_scroll=keep_scroll)

    def _select_entry(self, entry_id: str):
        if entry_id == self.selected_entry_id and self.details_scroll.winfo_children():
            return  # ponowne kliknięcie tego samego wpisu – nic do przerysowania
        self.selected_entry_id = entry_id
        self._password_revealed = False
        self.entry_list.set_selected(entry_id)
        self._render_entry_details(entry_id)

    # ----------------- WIDOK SZCZEGÓŁÓW WPISU -----------------
    def _show_empty_details(self):
        for w in self.details_scroll.winfo_children():
            w.destroy()

        if len(self.vault.entries) == 0:
            welcome_card = ctk.CTkFrame(self.details_scroll, fg_color=COLOR_CARD_DARK, corner_radius=14)
            welcome_card.pack(fill="x", pady=20, padx=10, ipady=12)

            ctk.CTkLabel(welcome_card, text=_("🛡️ Witaj w Twoim nowym sejfie!"), font=FONT_TITLE, text_color=COLOR_TEXT_PRIMARY).pack(anchor="w", padx=20, pady=(15, 4))
            ctk.CTkLabel(welcome_card, text=_("Twój sejf jest bezpiecznie zaszyfrowany (Argon2id + AES-256-GCM). Wybierz od czego chcesz zacząć:"), font=FONT_BODY, text_color=COLOR_TEXT_MUTED, wraplength=520, justify="left").pack(anchor="w", padx=20, pady=(0, 15))

            actions_grid = ctk.CTkFrame(welcome_card, fg_color="transparent")
            actions_grid.pack(fill="x", padx=15, pady=(0, 15))

            cards_def = [
                ("➕", _("Dodaj pierwsze hasło ręcznie"), _("Zapisz login, hasło, stronę www i 2FA."), _("Dodaj wpis"), self._open_new_entry_dialog, COLOR_PRIMARY),
                ("📥", _("Zaimportuj hasła z innego menedżera"), _("Bitwarden, KeePass (.kdbx), 1Password, Chrome..."), _("Kreator importu"), self._open_import_dialog, COLOR_PANEL_DARK),
                ("⚡", _("Wygeneruj silne hasło"), _("Losowe hasło o wysokiej entropii lub fraza Diceware."), _("Generator"), self._open_generator_dialog, COLOR_PANEL_DARK),
                ("☁️", _("Włącz kopię w chmurze"), _("Automatyczne kopie na WebDAV/Nextcloud, Google Drive lub USB."), _("Konfiguruj"), self._open_backup_dialog, COLOR_PANEL_DARK)
            ]

            for icon, title, desc, btn_txt, cmd, btn_c in cards_def:
                c = ctk.CTkFrame(actions_grid, fg_color=COLOR_PANEL_DARK, corner_radius=10)
                c.pack(fill="x", pady=4)
                r = ctk.CTkFrame(c, fg_color="transparent")
                r.pack(fill="x", padx=12, pady=10)
                ctk.CTkLabel(r, text=icon, font=(FONT_FAMILY, 22)).pack(side="left", padx=(0, 10))
                col = ctk.CTkFrame(r, fg_color="transparent")
                col.pack(side="left", fill="x", expand=True)
                ctk.CTkLabel(col, text=title, font=FONT_SUBTITLE, text_color=COLOR_TEXT_PRIMARY, anchor="w").pack(anchor="w")
                ctk.CTkLabel(col, text=desc, font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, anchor="w").pack(anchor="w")
                ctk.CTkButton(r, text=btn_txt, width=105, fg_color=btn_c, hover_color=COLOR_PRIMARY_HOVER, command=cmd).pack(side="right")
        else:
            empty_box = ctk.CTkFrame(self.details_scroll, fg_color="transparent")
            empty_box.pack(fill="both", expand=True, pady=140)
            ctk.CTkLabel(empty_box, text="🔐", font=(FONT_FAMILY, 48)).pack(pady=(0, 10))
            ctk.CTkLabel(empty_box, text=_("Wybierz wpis z listy po lewej stronie,"), font=FONT_SUBTITLE, text_color=COLOR_TEXT_PRIMARY).pack()
            ctk.CTkLabel(empty_box, text=_("aby wyświetlić jego hasło, kod 2FA i szczegóły."), font=FONT_BODY, text_color=COLOR_TEXT_MUTED).pack(pady=(4, 20))
            ctk.CTkButton(empty_box, text=_("+ Utwórz nowy wpis"), fg_color=COLOR_PRIMARY, command=self._open_new_entry_dialog).pack()

    def _show_trash_header_in_details(self):
        for w in self.details_scroll.winfo_children():
            w.destroy()
        box = ctk.CTkFrame(self.details_scroll, fg_color="transparent")
        box.pack(fill="both", expand=True, pady=120)
        ctk.CTkLabel(box, text="🗑️", font=(FONT_FAMILY, 48)).pack(pady=(0, 10))
        ctk.CTkLabel(box, text=_("Kosz (Usunięte elementy)"), font=FONT_TITLE, text_color=COLOR_TEXT_PRIMARY).pack()
        ctk.CTkLabel(box, text=_("Elementy w koszu można przywrócić lub trwale usunąć."), font=FONT_BODY, text_color=COLOR_TEXT_MUTED).pack(pady=(4, 15))

        if len(self.vault.trash) > 0:
            ctk.CTkButton(box, text=_("Opróżnij cały kosz"), fg_color=COLOR_DANGER, command=self._empty_entire_trash).pack()

    def _empty_entire_trash(self):
        if messagebox.askyesno(_("Opróżnianie kosza"), _("Czy na pewno chcesz bezpowrotnie usunąć wszystkie elementy z kosza?")):
            ids = [a["id"] for e in self.vault.trash.values() for a in e.attachments]
            self.vault.empty_trash()
            self._save_vault_to_disk()
            self._delete_unused_attachments(ids)
            self._build_sidebar()
            self._refresh_entries_list()
            self._show_trash_header_in_details()

    @classmethod
    def _plain_frame(cls, parent) -> tk.Frame:
        """Ramka wyłącznie do układu: zwykła ramka Tk w kolorze rodzica (CTkFrame rysuje własne płótno – wolniej)."""
        return tk.Frame(parent, bg=cls._bg_of(parent), bd=0, highlightthickness=0)

    def _label(self, parent, text: str = "", font=FONT_BODY, text_color=COLOR_TEXT_PRIMARY, anchor: str = "center",
               justify: str = "center", wraplength: int = 0) -> tk.Label:
        """Statyczny tekst jako zwykła etykieta Tk – wygląda jak CTkLabel (ta sama czcionka i wysokość), a powstaje kilka razy szybciej."""
        s = self._get_widget_scaling()
        family, size, *style = font
        tk_font = (family, -int(round(size * s)), *style)
        # CTkLabel ma minimalną wysokość 28 px – zachowujemy ją, aby odstępy w panelu się nie zmieniły
        key = (tk_font, s)
        if key not in self._label_pad_cache:
            line_h = tkfont.Font(family=family, size=tk_font[1], weight="bold" if "bold" in style else "normal") \
                .metrics("linespace")
            self._label_pad_cache[key] = max(0, int(28 * s) - line_h) // 2
        return tk.Label(parent, text=text, font=tk_font, fg=text_color, bg=self._bg_of(parent), bd=0, padx=0,
                        pady=self._label_pad_cache[key], anchor=anchor, justify=justify, wraplength=int(wraplength * s))

    def _tk_font(self, font) -> tuple:
        family, size, *style = font
        return (family, -int(round(size * self._get_widget_scaling())), *style)

    @staticmethod
    def _wrap_beside(label: tk.Label, row, *others) -> None:
        """Tekst w wierszu z przyciskami zawija się do miejsca, które zostaje obok nich (także po zmianie rozmiaru)."""
        def _on_resize(event):
            width = max(80, event.width - sum(o.winfo_reqwidth() for o in others) - 16)
            if abs(int(label.cget("wraplength")) - width) > 6:
                label.configure(wraplength=width)
        row.bind("<Configure>", _on_resize, add="+")

    @staticmethod
    def _bg_of(parent) -> str:
        try:
            return parent.cget("bg")  # widżety Tk oraz wnętrze CTkScrollableFrame
        except (ValueError, tk.TclError):
            color = parent.cget("fg_color")
            if color == "transparent":
                color = parent.cget("bg_color")
            return parent._apply_appearance_mode(color)

    def _details_shape(self, entry: VaultEntry, entry_id: str) -> tuple:
        """Układ panelu szczegółów (jakie sekcje i wiersze). Ten sam układ = wystarczy podmienić treść."""
        category = entry.category.lower()
        return (
            entry_id in self.vault.trash,
            "kart" in category or "bank" in category,  # podgląd karty płatniczej
            bool(entry.username), bool(entry.password), bool(entry.totp_secret), bool(entry.url),
            tuple(entry.custom_fields), bool(entry.notes), tuple(entry.tags),
            tuple((a.get("id"), a.get("name"), a.get("size")) for a in entry.attachments),
            self._attachments_allowed(), self.icon_provider is not None and bool(entry.url),
            self._enabled_plugins(), connect.protocol_of(entry.url) is not None, bool(ssh_keys.field_name(entry)),
        )

    def _render_entry_details(self, entry_id: str):
        entry = self.vault.get_entry(entry_id)
        if not entry:
            self._show_empty_details()
            return

        # Gotowe panele dla kilku ostatnich układów (jakie sekcje ma wpis). Przejście do wpisu o znanym układzie
        # to tylko podmiana treści (kilka ms) zamiast budowania panelu od nowa (~100 ms).
        cache = self._details_cache
        for key in [k for k, (panel, _state) in cache.items() if not panel.winfo_exists()]:
            del cache[key]  # panel usunięty razem z zawartością prawego panelu (np. widok kosza)
        panel, state = self._details_panel_for(entry, entry_id)
        self._detail_fillers = state["fillers"]
        for name in self.DETAIL_WIDGETS:
            setattr(self, name, state[name])
        self._fill_entry_details(entry)
        if not panel.winfo_manager():
            # Zamiana w jednym kroku – bez migania pustego panelu; inne gotowe panele tylko się chowają
            for w in self.details_scroll.winfo_children():
                if w is not panel:
                    if any(w is p for p, _s in cache.values()):
                        w.pack_forget()
                    else:
                        w.destroy()
            panel.pack(fill="both", expand=True)

    def _details_panel_for(self, entry: VaultEntry, entry_id: str):
        """Gotowy (być może ukryty) panel dla układu wpisu – z pamięci albo zbudowany teraz."""
        cache = self._details_cache
        shape = self._details_shape(entry, entry_id)
        if shape in cache:
            cache.move_to_end(shape)
            return cache[shape]
        panel = self._plain_frame(self.details_scroll)
        previous = {name: getattr(self, name, None) for name in self.DETAIL_WIDGETS}
        previous_fillers = self._detail_fillers
        self._detail_fillers = []
        self._details_entry, shown_entry = entry, getattr(self, "_details_entry", None)
        for name in self.DETAIL_WIDGETS:
            setattr(self, name, None)
        self._build_entry_details(panel, entry, entry_id)
        state = {"fillers": self._detail_fillers, **{name: getattr(self, name) for name in self.DETAIL_WIDGETS}}
        # budowa nie zmienia tego, co jest teraz na ekranie (ważne przy budowie zawczasu)
        self._detail_fillers, self._details_entry = previous_fillers, shown_entry
        for name, widget in previous.items():
            setattr(self, name, widget)
        cache[shape] = (panel, state)
        while len(cache) > 6:
            cache.popitem(last=False)[1][0].destroy()
        return panel, state

    def _prebuild_details(self):
        """Panel szczegółów pierwszego wpisu budowany w chwili bezczynności po otwarciu – pierwsze kliknięcie bez czekania."""
        if not self.winfo_exists() or self._details_cache or self.selected_entry_id:
            return
        first = self.entry_list.items[0]["id"] if self.entry_list.items else None
        entry = self.vault.get_entry(first) if first else None
        if entry is not None:
            self._details_panel_for(entry, first)

    # Widżety panelu odświeżane z zewnątrz (licznik TOTP, „Pokaż hasło”) – osobne w każdym zapamiętanym panelu
    DETAIL_WIDGETS = ("pwd_display_lbl", "pwd_color_txt", "_pwd_toggle_btn", "totp_timer_label", "totp_code_lbl",
                      "totp_progress")

    def _fill_entry_details(self, entry: VaultEntry):
        self._details_entry = entry
        for fill in self._detail_fillers:
            fill(entry)

    def _build_entry_details(self, container, entry: VaultEntry, entry_id: str):
        """
        Buduje układ panelu. Wszystko, co zależy od wpisu, ustawiają funkcje z self._detail_fillers,
        a przyciski działają na self._details_entry – dzięki temu panel można ponownie użyć dla innego wpisu.
        """
        fillers = self._detail_fillers
        current = lambda: self._details_entry  # noqa: E731
        is_in_trash = (entry_id in self.vault.trash)

        # 1. Pasek informacyjny jeśli wpis jest w koszu
        if is_in_trash:
            trash_bar = ctk.CTkFrame(container, fg_color=COLOR_DANGER, corner_radius=8)
            trash_bar.pack(fill="x", pady=(0, 10), ipady=4)
            r = self._plain_frame(trash_bar)
            r.pack(fill="x", padx=12, pady=4)
            self._label(r, text=_("⚠️ Ten wpis znajduje się w koszu."), font=FONT_BODY_BOLD, text_color="#ffffff").pack(side="left")
            FlatButton(r, text=_("Przywróć ♻️"), width=95, fg_color=COLOR_SUCCESS, command=lambda: self._restore_entry(current())).pack(side="right", padx=(0, 6))
            FlatButton(r, text=_("Usuń trwale ✕"), width=95, fg_color="#991b1b", command=lambda: self._purge_entry(current())).pack(side="right")

        # 2. Nagłówek szczegółów: Tytuł, Kategoria, Akcje
        top_header = self._plain_frame(container)
        top_header.pack(fill="x", pady=(0, 15))

        title_col = self._plain_frame(top_header)
        title_col.pack(side="left", fill="x", expand=True)
        title_lbl = self._label(title_col, font=FONT_TITLE, text_color=COLOR_TEXT_PRIMARY, anchor="w", justify="left")
        title_lbl.pack(anchor="w", fill="x")
        category_lbl = self._label(title_col, font=FONT_SMALL, text_color=COLOR_TEXT_MUTED)
        category_lbl.pack(anchor="w")

        def fill_header(e: VaultEntry):
            fav_symbol = "⭐ " if e.favorite else ""
            site_icon = self.icon_provider.image(site_domain(e.url), int(30 * self._get_widget_scaling())) \
                if self.icon_provider is not None and e.url else None
            if site_icon is not None:
                title_lbl.configure(image=site_icon, compound="left", text=f"  {fav_symbol}{e.title}")
            else:
                title_lbl.configure(image="", text=f"{self._get_category_icon(e.category)} {fav_symbol}{e.title}")
            title_lbl.image = site_icon  # referencja – inaczej obraz znika
            category_lbl.configure(text=_("Kategoria: {category}", category=category_label(e.category)))
        fillers.append(fill_header)

        if not is_in_trash:
            btn_actions = self._plain_frame(top_header)
            btn_actions.pack(side="right", anchor="n")
            narrow_state = {"narrow": None}

            def _header_layout(event):
                narrow = event.width < 520 * self._get_widget_scaling()
                if narrow != narrow_state["narrow"]:
                    narrow_state["narrow"] = narrow
                    btn_actions.pack_forget()
                    title_col.pack_forget()
                    if narrow:
                        title_col.pack(side="top", fill="x")
                        btn_actions.pack(side="top", anchor="w", pady=(8, 0))
                    else:
                        btn_actions.pack(side="right", anchor="n")
                        title_col.pack(side="left", fill="x", expand=True)
                title_lbl.configure(wraplength=max(120, event.width - (0 if narrow else btn_actions.winfo_reqwidth() + 16)))
            container.bind("<Configure>", _header_layout, add="+")
            if self.plugin_on("family_share"):
                FlatButton(btn_actions, text=_("👪 Udostępnij"), width=95, fg_color=COLOR_CARD_DARK,
                           hover_color=COLOR_CARD_HOVER, command=lambda: self._send_to_family(current())).pack(side="left", padx=3)
            if self.plugin_on("connect") and connect.protocol_of(entry.url):
                FlatButton(btn_actions, text=_("🖥️ Połącz"), width=80, fg_color=COLOR_SUCCESS,
                           command=lambda: self._connect(current())).pack(side="left", padx=3)
            FlatButton(btn_actions, text=_("✏️ Edytuj"), width=75, fg_color=COLOR_CARD_DARK, hover_color=COLOR_CARD_HOVER, command=lambda: self._open_edit_entry_dialog(current())).pack(side="left", padx=3)
            FlatButton(btn_actions, text=_("📋 Duplikuj"), width=80, fg_color=COLOR_CARD_DARK, hover_color=COLOR_CARD_HOVER, command=lambda: self._duplicate_entry(current())).pack(side="left", padx=3)
            FlatButton(btn_actions, text=_("🗑️ Do kosza"), width=85, fg_color=COLOR_DANGER, command=lambda: self._delete_entry(current())).pack(side="left", padx=3)

        # 3. Specjalny wizualizator dla Kart Płatniczych
        if "kart" in entry.category.lower() or "bank" in entry.category.lower():
            self._render_credit_card_preview(entry, container)

        # 4. Blok Loginu / Użytkownika
        if entry.username:
            u_card = ctk.CTkFrame(container, fg_color=COLOR_CARD_DARK, corner_radius=10)
            u_card.pack(fill="x", pady=(0, 10), ipady=4)
            u_h = self._plain_frame(u_card)
            u_h.pack(fill="x", padx=12, pady=(6, 2))
            self._label(u_h, text=_("Login / Nazwa użytkownika"), font=FONT_SMALL, text_color=COLOR_TEXT_MUTED).pack(side="left")

            u_b = self._plain_frame(u_card)
            u_b.pack(fill="x", padx=12, pady=(0, 6))
            FlatButton(u_b, text=_("Kopiuj"), width=65, height=26, fg_color=COLOR_PANEL_DARK, command=lambda: self._copy_to_clipboard(current().username, _("Login skopiowany!"))).pack(side="right")
            user_lbl = self._label(u_b, font=FONT_BODY_BOLD, text_color=COLOR_TEXT_PRIMARY, anchor="w", justify="left")
            user_lbl.pack(side="left", fill="x", expand=True)
            self._wrap_beside(user_lbl, u_b, u_b.winfo_children()[0])
            fillers.append(lambda e: user_lbl.configure(text=e.username))

        # 5. Blok Hasła
        if entry.password:
            p_card = ctk.CTkFrame(container, fg_color=COLOR_CARD_DARK, corner_radius=10)
            p_card.pack(fill="x", pady=(0, 10), ipady=6)

            p_h = self._plain_frame(p_card)
            p_h.pack(fill="x", padx=12, pady=(6, 2))
            self._label(p_h, text=_("Hasło"), font=FONT_SMALL, text_color=COLOR_TEXT_MUTED).pack(side="left")
            strength_lbl = self._label(p_h, font=FONT_SMALL)
            strength_lbl.pack(side="right")

            p_b = self._plain_frame(p_card)
            p_b.pack(fill="x", padx=12, pady=(2, 6))
            pwd_holder = self._plain_frame(p_b)
            pwd_holder.pack(side="left")
            self.pwd_display_lbl = ctk.CTkLabel(pwd_holder, text="", font=(FONT_MONO, 18, "bold"), text_color=COLOR_TEXT_PRIMARY)
            self.pwd_display_lbl.pack(side="left")
            self.pwd_color_txt = None
            if self.plugin_on("colored_password"):
                from ui.plugin_dialogs import DIGIT_COLOR, SYMBOL_COLOR
                txt = tk.Text(pwd_holder, height=1, width=24, bd=0, highlightthickness=0, wrap="char", cursor="arrow",
                              bg=self._bg_of(pwd_holder), fg=COLOR_TEXT_PRIMARY, font=self._tk_font(FONT_CODE),
                              takefocus=0)
                txt.tag_configure("digit", foreground=DIGIT_COLOR)
                txt.tag_configure("symbol", foreground=SYMBOL_COLOR)
                self.pwd_color_txt = txt

            p_acts = self._plain_frame(p_b)
            p_acts.pack(side="right")
            self._pwd_toggle_btn = FlatButton(p_acts, text=_("👁 Pokaż"), width=78, height=28, fg_color=COLOR_PANEL_DARK, command=lambda: self._toggle_details_password(current().password))
            self._pwd_toggle_btn.pack(side="left", padx=(0, 5))
            FlatButton(p_acts, text=_("Kopiuj hasło"), width=95, height=28, fg_color=COLOR_PRIMARY, command=lambda: self._copy_password_safe(current().password)).pack(side="left")
            if self.plugin_on("qr_show"):
                FlatButton(p_acts, text="🔳 QR", width=52, height=28, fg_color=COLOR_PANEL_DARK,
                           command=lambda: self._show_password_qr(current())).pack(side="left", padx=(5, 0))
            if self.plugin_on("pick_chars"):
                FlatButton(p_acts, text=_("🔢 Znaki"), width=70, height=28, fg_color=COLOR_PANEL_DARK,
                           command=lambda: self._pick_password_chars(current())).pack(side="left", padx=(5, 0))
            if self.plugin_on("phone_handoff"):
                FlatButton(p_acts, text=_("📱 Telefon"), width=82, height=28, fg_color=COLOR_PANEL_DARK,
                           command=lambda: self._send_to_phone(current())).pack(side="left", padx=(5, 0))
            if self.plugin_on("secure_send"):
                FlatButton(p_acts, text=_("✉ Link"), width=62, height=28, fg_color=COLOR_PANEL_DARK,
                           command=lambda: self._secure_send(current())).pack(side="left", padx=(5, 0))
            pwd_state = {"narrow": None}

            def _password_layout(event, dots=pwd_holder, acts=p_acts):
                narrow = event.width < 470 * self._get_widget_scaling()
                if narrow == pwd_state["narrow"]:
                    return
                pwd_state["narrow"] = narrow
                acts.pack_forget()
                dots.pack_forget()
                if narrow:
                    dots.pack(side="top", anchor="w")
                    acts.pack(side="top", anchor="w", pady=(4, 0))
                else:
                    dots.pack(side="left")
                    acts.pack(side="right")
            p_b.bind("<Configure>", _password_layout, add="+")

            # Inline weryfikacja wycieku HIBP
            leak_box = self._plain_frame(p_card)
            leak_box.pack(fill="x", padx=12, pady=(4, 6))
            leak_status_lbl = self._label(leak_box, font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, anchor="w", justify="left")

            def _check_leak_action(lbl=leak_status_lbl):
                checked = current()
                lbl.configure(text=_("Sprawdzanie w bazie HIBP..."), fg=COLOR_PRIMARY_LIGHT)

                def _ui(res):
                    if not lbl.winfo_exists() or self._details_entry is not checked:
                        return  # w międzyczasie wybrano inny wpis
                    is_pwned, cnt = res
                    if is_pwned:
                        lbl.configure(text=_("🚨 WYCIEKŁO! Znaleziono {count:,} razy w znanych wyciekach!", count=cnt), fg=COLOR_DANGER, font=self._tk_font(FONT_BODY_BOLD))
                    elif cnt < 0:
                        lbl.configure(text=_("⚠️ Nie udało się połączyć z HIBP (brak internetu?)."), fg=COLOR_WARNING, font=self._tk_font(FONT_BODY_BOLD))
                    else:
                        lbl.configure(text=_("✅ Bezpieczne: Hasło NIE występuje w znanych wyciekach (HIBP)."), fg=COLOR_SUCCESS, font=self._tk_font(FONT_BODY_BOLD))

                self._run_in_background(lambda pwd=checked.password: check_password_breach_hibp(pwd), _ui)

            leak_btn = FlatButton(leak_box, text=_("Sprawdź wyciek 🔍"), width=120, height=24, font=FONT_SMALL, fg_color=COLOR_PANEL_DARK, command=_check_leak_action)
            leak_btn.pack(side="right")
            leak_status_lbl.pack(side="left", fill="x", expand=True)
            self._wrap_beside(leak_status_lbl, leak_box, leak_btn)

            expiry_lbl = None
            if self.plugin_on("expiry"):
                expiry_lbl = self._label(p_card, font=FONT_SMALL, anchor="w", justify="left")

            def fill_password(e: VaultEntry):
                eval_res = evaluate_password_strength(e.password)
                strength_lbl.configure(text=_("Siła: {label} ({bits} bitów)", label=eval_res["label"], bits=eval_res["entropy"]),
                                        fg=eval_res["color"])
                self._show_password_text(e.password)
                if expiry_lbl is not None:
                    text, color = self._expiry_text(e)
                    expiry_lbl.configure(text=text, fg=color)
                    if text and not expiry_lbl.winfo_manager():
                        expiry_lbl.pack(fill="x", padx=12, pady=(0, 2), after=p_b)
                    elif not text:
                        expiry_lbl.pack_forget()
                self._pwd_toggle_btn.configure(text=_("🔒 Ukryj") if self._password_revealed else _("👁 Pokaż"))
                leak_status_lbl.configure(text=_("Weryfikacja wycieków (Have I Been Pwned - k-Anonymity):"),
                                          fg=COLOR_TEXT_MUTED, font=self._tk_font(FONT_SMALL))
            fillers.append(fill_password)

        # 6. Blok TOTP 2FA
        if entry.totp_secret:
            totp_card = ctk.CTkFrame(container, fg_color=COLOR_CARD_DARK, corner_radius=10)
            totp_card.pack(fill="x", pady=(0, 10), ipady=6)

            t_h = self._plain_frame(totp_card)
            t_h.pack(fill="x", padx=12, pady=(6, 2))
            self._label(t_h, text=_("KOD 2FA / TOTP (Token jednorazowy)"), font=FONT_SMALL, text_color=COLOR_TEXT_MUTED).pack(side="left")
            self.totp_timer_label = ctk.CTkLabel(t_h, text=_("Wygasa za: {seconds}s", seconds=30), font=FONT_SMALL, text_color=COLOR_PRIMARY_LIGHT)
            self.totp_timer_label.pack(side="right")

            t_b = self._plain_frame(totp_card)
            t_b.pack(fill="x", padx=12, pady=(2, 6))
            self.totp_code_lbl = ctk.CTkLabel(t_b, text="--- ---", font=FONT_TOTP, text_color=COLOR_SUCCESS)
            self.totp_code_lbl.pack(side="left")
            FlatButton(t_b, text=_("Kopiuj kod 2FA"), width=110, height=28, fg_color=COLOR_SUCCESS, command=lambda: self._copy_current_totp(current())).pack(side="right")

            self.totp_progress = ctk.CTkProgressBar(totp_card, height=4)
            self.totp_progress.pack(fill="x", padx=12, pady=(0, 4))

            def fill_totp(e: VaultEntry):
                cur_code = get_current_totp(e.totp_secret) or "--- ---"
                self.totp_code_lbl.configure(text=f"{cur_code[:3]} {cur_code[3:]}" if len(cur_code) == 6 else cur_code)
                self.totp_progress.set(get_totp_remaining_seconds() / 30.0)
            fillers.append(fill_totp)

        # 7. URL
        if entry.url:
            url_card = ctk.CTkFrame(container, fg_color=COLOR_CARD_DARK, corner_radius=10)
            url_card.pack(fill="x", pady=(0, 10), ipady=4)
            u_h = self._plain_frame(url_card)
            u_h.pack(fill="x", padx=12, pady=(6, 2))
            self._label(u_h, text=_("Strona logowania / URL"), font=FONT_SMALL, text_color=COLOR_TEXT_MUTED).pack(side="left")

            u_b = self._plain_frame(url_card)
            u_b.pack(fill="x", padx=12, pady=(0, 6))
            FlatButton(u_b, text=_("Otwórz stronę 🌐"), width=130, height=26, fg_color=COLOR_PANEL_DARK, command=lambda: self._open_url(current().url)).pack(side="right")
            url_lbl = self._label(u_b, font=FONT_BODY, text_color=COLOR_TEXT_ACCENT, anchor="w", justify="left")
            url_lbl.pack(side="left", fill="x", expand=True)
            self._wrap_beside(url_lbl, u_b, u_b.winfo_children()[0])
            fillers.append(lambda e: url_lbl.configure(text=e.url))

        # 8. Pola niestandardowe (data ważności hasła ma własny wiersz, gdy wtyczka jest włączona)
        hidden_fields = {expiry.field_name(entry) if self.plugin_on("expiry") else None,
                         ssh_keys.field_name(entry) if self.plugin_on("ssh_agent") else None}
        shown_fields = [k for k in entry.custom_fields if k not in hidden_fields]
        if self.plugin_on("ssh_agent") and ssh_keys.field_name(entry):
            self._build_ssh_key_card(container)
        if shown_fields:
            cf_card = ctk.CTkFrame(container, fg_color=COLOR_CARD_DARK, corner_radius=10)
            cf_card.pack(fill="x", pady=(0, 10), ipady=6)
            self._label(cf_card, text=_("Pola niestandardowe"), font=FONT_SMALL, text_color=COLOR_TEXT_MUTED).pack(anchor="w", padx=12, pady=(6, 4))

            for k in shown_fields:
                row = self._plain_frame(cf_card)
                row.pack(fill="x", padx=12, pady=2)
                FlatButton(row, text=_("Kopiuj"), width=60, height=22, fg_color=COLOR_PANEL_DARK, command=lambda name=k: self._copy_to_clipboard(str(current().custom_fields.get(name, "")), _("Skopiowano {name}!", name=name))).pack(side="right")
                self._label(row, text=f"{k}:", font=FONT_BODY_BOLD, text_color=COLOR_TEXT_MUTED).pack(side="left")
                value_lbl = self._label(row, font=FONT_BODY, text_color=COLOR_TEXT_PRIMARY, anchor="w", justify="left")
                value_lbl.pack(side="left", padx=6, fill="x", expand=True)
                self._wrap_beside(value_lbl, row, *row.winfo_children()[:2])
                fillers.append(lambda e, name=k, lbl=value_lbl: lbl.configure(text=str(e.custom_fields.get(name, ""))))

        # 9. Notatki – zawijane do bieżącej szerokości panelu (także po zmianie rozmiaru okna)
        if entry.notes:
            n_card = ctk.CTkFrame(container, fg_color=COLOR_CARD_DARK, corner_radius=10)
            n_card.pack(fill="x", pady=(0, 10), ipady=6)
            self._label(n_card, text=_("Bezpieczne notatki"), font=FONT_SMALL, text_color=COLOR_TEXT_MUTED).pack(anchor="w", padx=12, pady=(6, 4))
            notes_lbl = self._label(n_card, font=FONT_BODY, text_color=COLOR_TEXT_PRIMARY, wraplength=480, justify="left", anchor="w")
            notes_lbl.pack(anchor="w", fill="x", padx=12, pady=(0, 6))

            def _rewrap(event, lbl=notes_lbl):
                width = max(200, event.width - 30)
                if abs(int(lbl.cget("wraplength")) - width) > 8:
                    lbl.configure(wraplength=width)
            n_card.bind("<Configure>", _rewrap, add="+")
            fillers.append(lambda e: notes_lbl.configure(text=e.notes))

        # 9b. Załączniki
        self._render_attachments(container, entry, read_only=is_in_trash)

        # 10. Tagi
        if entry.tags:
            t_box = self._plain_frame(container)
            t_box.pack(fill="x", pady=(2, 8))
            for t in entry.tags:
                ctk.CTkLabel(t_box, text=f"  #{t}  ", fg_color=COLOR_PANEL_DARK, corner_radius=6, font=FONT_SMALL, text_color=COLOR_TEXT_ACCENT).pack(side="left", padx=2)

    def _build_ssh_key_card(self, container):
        card = ctk.CTkFrame(container, fg_color=COLOR_CARD_DARK, corner_radius=10)
        card.pack(fill="x", pady=(0, 10), ipady=6)
        head = self._plain_frame(card)
        head.pack(fill="x", padx=12, pady=(6, 2))
        self._label(head, text=_("🗝️ Klucz SSH"), font=FONT_SMALL, text_color=COLOR_TEXT_MUTED).pack(side="left")
        copy_btn = FlatButton(head, text=_("Kopiuj klucz publiczny"), width=150, height=24, font=FONT_SMALL,
                              fg_color=COLOR_PANEL_DARK, command=lambda: self._copy_ssh_public_key(self._details_entry))
        copy_btn.pack(side="right")
        info_lbl = self._label(card, font=FONT_BODY_BOLD, anchor="w", justify="left")
        info_lbl.pack(fill="x", padx=12)
        detail_lbl = self._label(card, font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, anchor="w", justify="left")
        detail_lbl.pack(fill="x", padx=12, pady=(0, 4))
        self._wrap_beside(detail_lbl, card)

        def fill_key(e: VaultEntry):
            key, error = self.ssh_agent.key_for(e.id), self.ssh_agent.errors.get(e.id)
            if key is not None:
                info_lbl.configure(text=f"{key.description()}  ·  {key.fingerprint()}", fg=COLOR_TEXT_PRIMARY)
                channels = self.ssh_agent.status()
                ready = [name for name, kind in (("OpenSSH", "openssh"), ("PuTTY/Pageant", "pageant"))
                         if channels.get(kind) == "running"]
                detail_lbl.configure(text=(_("{comment} – dostępny dla: {channels}", comment=key.comment,
                                             channels=", ".join(ready)) if ready else
                                           _("{comment} – agent SSH nie działa (szczegóły: Ustawienia → Wtyczki)",
                                             comment=key.comment)))
            elif error:
                info_lbl.configure(text=_("⚠️ Klucza nie można użyć"), fg=COLOR_DANGER)
                detail_lbl.configure(text=error)
            else:
                info_lbl.configure(text=_("Wczytywanie klucza…"), fg=COLOR_TEXT_MUTED)
                detail_lbl.configure(text="")
        self._detail_fillers.append(fill_key)

    def _render_credit_card_preview(self, entry: VaultEntry, container):
        """Generuje fotorealistyczny, nowoczesny widok karty płatniczej."""
        card_box = ctk.CTkFrame(container, fg_color="#1e1b4b", corner_radius=14, border_width=1, border_color="#4338ca")
        card_box.pack(fill="x", pady=(0, 15), padx=2, ipady=8)

        # Górny wiersz karty (Chip i Logo)
        top_r = self._plain_frame(card_box)
        top_r.pack(fill="x", padx=20, pady=(12, 6))
        self._label(top_r, text="💳 CHIP", font=FONT_CODE, text_color="#cbd5e1").pack(side="left")
        self._label(top_r, text="VIRTUAL CARD", font=FONT_BODY_BOLD, text_color=COLOR_PRIMARY_LIGHT).pack(side="right")

        num_lbl = self._label(card_box, font=(FONT_MONO, 17, "bold"), text_color="#f8fafc", anchor="w")
        num_lbl.pack(anchor="w", padx=20, pady=(6, 8))

        # Dolny wiersz karty: Właściciel, Ważność, CVV
        bot_r = self._plain_frame(card_box)
        bot_r.pack(fill="x", padx=20, pady=(0, 10))
        holder_lbl = self._label(bot_r, font=FONT_SMALL, text_color="#cbd5e1", justify="left")
        holder_lbl.pack(side="left")
        exp_lbl = self._label(bot_r, font=FONT_SMALL, text_color="#cbd5e1", justify="left")
        exp_lbl.pack(side="left", padx=25)
        cvv_lbl = self._label(bot_r, font=FONT_SMALL, text_color="#cbd5e1", justify="left")
        cvv_lbl.pack(side="left")

        def card_number(e: VaultEntry) -> str:
            return e.custom_fields.get("Numer karty") or e.password  # i18n: data or "•••• •••• •••• ••••"

        FlatButton(bot_r, text=_("Kopiuj numer"), width=95, height=24, fg_color="#4338ca",
                   command=lambda: self._copy_to_clipboard(card_number(self._details_entry).replace(" ", ""),
                                                           _("Numer karty skopiowany!"))).pack(side="right")

        def fill_card(e: VaultEntry):
            raw_num = card_number(e)
            num_lbl.configure(text=" ".join(raw_num[i:i + 4] for i in range(0, len(raw_num), 4)) if len(raw_num) == 16 else raw_num)
            holder = e.custom_fields.get("Właściciel karty") or e.username or _("KARTOWNIK")  # i18n: data
            holder_lbl.configure(text=_("WŁAŚCICIEL:\n{holder}", holder=holder.upper()))
            expiry = e.custom_fields.get("Ważność") or _("MM/RR")  # i18n: data
            exp_lbl.configure(text=_("WAŻNOŚĆ:\n{expiry}", expiry=expiry))
            cvv_lbl.configure(text=f"CVV:\n{e.custom_fields.get('CVV/CVC') or '•••'}")
        self._detail_fillers.append(fill_card)

    def _copy_current_totp(self, entry: VaultEntry):
        code = get_current_totp(entry.totp_secret)
        if code:
            self._copy_to_clipboard(code, _("Kod 2FA skopiowany!"))
        else:
            self.show_toast(_("Nieprawidłowy klucz TOTP – nie można wygenerować kodu."), error=True)

    def _show_password_text(self, password: str):
        """Hasło w panelu: kropki, odkryte albo odkryte w kolorach (wtyczka „Kolorowe hasło”)."""
        label, colored = getattr(self, "pwd_display_lbl", None), getattr(self, "pwd_color_txt", None)
        if label is None:
            return
        if self._password_revealed and colored is not None:
            from ui.plugin_dialogs import char_kind
            colored.configure(state="normal")
            colored.delete("1.0", "end")
            for ch in password:
                colored.insert("end", ch, char_kind(ch))
            per_line = 32
            colored.configure(width=max(1, min(len(password), per_line)), height=max(1, -(-len(password) // per_line)),
                              state="disabled")
            label.pack_forget()
            if not colored.winfo_manager():
                colored.pack(side="left", pady=4)
            return
        if colored is not None:
            colored.pack_forget()
        label.configure(text=password if self._password_revealed else "•" * min(len(password), 24),
                        font=FONT_CODE if self._password_revealed else (FONT_MONO, 18, "bold"))
        if not label.winfo_manager():
            label.pack(side="left")

    @staticmethod
    def _expiry_text(entry: VaultEntry):
        """Opis daty ważności hasła i jego kolor (pusty tekst = wpis bez daty)."""
        state = expiry.status(entry)
        if state is None:
            return "", COLOR_TEXT_MUTED
        kind, days = state
        date_text = expiry.get_expiry(entry).strftime("%d.%m.%Y")
        if kind == expiry.EXPIRED:
            return _n(-days, "⏰ Hasło wygasło {n} dzień temu ({date}) – zmień je.",
                      "⏰ Hasło wygasło {n} dni temu ({date}) – zmień je.",
                      "⏰ Hasło wygasło {n} dni temu ({date}) – zmień je.", date=date_text), COLOR_DANGER
        if kind == expiry.SOON:
            if days == 0:
                return _("⏰ Hasło wygasa dzisiaj ({date}).", date=date_text), COLOR_WARNING
            return _n(days, "⏰ Hasło wygasa za {n} dzień ({date}).", "⏰ Hasło wygasa za {n} dni ({date}).",
                      "⏰ Hasło wygasa za {n} dni ({date}).", date=date_text), COLOR_WARNING
        return _("⏰ Hasło ważne do {date}", date=date_text), COLOR_TEXT_MUTED

    def _toggle_details_password(self, password: str):
        self._password_revealed = not self._password_revealed
        self._show_password_text(password)
        button = getattr(self, "_pwd_toggle_btn", None)
        if button is not None and button.winfo_exists():
            button.configure(text=_("🔒 Ukryj") if self._password_revealed else _("👁 Pokaż"))

    def _open_url(self, url: str):
        url = url.strip()
        # "host:port" to nie schemat – schemat to "nazwa:" bez cyfr portu po dwukropku
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:(?!\d)", url):
            url = "https://" + url
        # Tylko strony WWW – inne schematy (file:, ms-msdt:, search-ms: itp.) mogą uruchamiać programy
        parsed = urlparse(url)
        if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
            messagebox.showwarning(
                _("Zablokowano adres"),
                _("Ze względów bezpieczeństwa otwierane są tylko adresy http:// i https://.\n\n{url}", url=url)
            )
            return
        webbrowser.open(url)

    def _copy_password_safe(self, password: str):
        clip_sec = effective_clipboard(int(self.vault.settings.get("clipboard_clear_seconds", 30) or 0), self.policy)
        SecureClipboard.copy(password, timeout_seconds=clip_sec)
        msg = _("Hasło skopiowane! (Zostanie wyczyszczone za {seconds}s)", seconds=clip_sec) if clip_sec > 0 else _("Hasło skopiowane!")
        self._show_toast(msg)

    def _copy_to_clipboard(self, text: str, toast_msg: str):
        clip_sec = effective_clipboard(int(self.vault.settings.get("clipboard_clear_seconds", 30) or 0), self.policy)
        SecureClipboard.copy(text, timeout_seconds=clip_sec)
        self._show_toast(toast_msg)

    def set_audit_badge(self, count: int, critical: bool = False):
        """Plakietka na przycisku audytu: liczba haseł wymagających uwagi (czerwona przy wycieku)."""
        if not self.winfo_exists():
            return
        full = _("🛡️ Audyt Wycieków ({count})", count=count) if count else _("🛡️ Audyt Wycieków")
        short = f"🛡️ {count}" if count else "🛡️"
        widths = (150 if count else 125, 52 if count else 36)
        self._toolbar_buttons = [(b, full, short, *widths) if b is self.audit_btn else (b, f, sh, wf, ws)
                                 for b, f, sh, wf, ws in self._toolbar_buttons]
        icons_only = bool(getattr(self, "_layout_mode", None) and self._layout_mode[0])
        color = (COLOR_DANGER, "#e11d48") if critical else ("#7c3aed", "#6d28d9")
        self.audit_btn.configure(text=short if icons_only else full, fg_color=color[0], hover_color=color[1],
                                 width=widths[1] if icons_only else widths[0])

    def show_toast(self, message: str, error: bool = False):
        """Krótki komunikat w prawym dolnym rogu okna."""
        toast = ctk.CTkToplevel(self)
        toast.overrideredirect(True)
        toast.attributes("-topmost", True)

        width = 460 if error or len(message) > 40 else 320
        lines = max(1, -(-len(message) // 52))  # ~52 znaki w wierszu przy szerokości 460 px
        height = (60 if error else 45) + max(0, lines - (2 if error else 1)) * 20
        x = self.winfo_rootx() + self.winfo_width() - width - 20
        y = self.winfo_rooty() + self.winfo_height() - height - 25
        toast.geometry(f"{width}x{height}+{x}+{y}")

        card = ctk.CTkFrame(toast, fg_color=COLOR_DANGER if error else COLOR_PRIMARY, corner_radius=8)
        card.pack(fill="both", expand=True)
        icon = "" if error else "📋 "
        ctk.CTkLabel(card, text=f"{icon}{message}", font=FONT_BODY_BOLD, text_color="#ffffff", wraplength=width - 30).pack(expand=True, padx=10)
        toast.after(6000 if error else 2500, toast.destroy)

    _show_toast = show_toast

    def _start_totp_ticker(self):
        rem = get_totp_remaining_seconds()
        progress = getattr(self, "totp_progress", None)
        if progress is not None and progress.winfo_exists() and progress.winfo_ismapped():
            progress.set(rem / 30.0)
            if getattr(self, "totp_timer_label", None) is not None:
                self.totp_timer_label.configure(text=_("Wygasa za: {seconds}s", seconds=rem))
            entry = getattr(self, "_details_entry", None)
            if getattr(self, "totp_code_lbl", None) is not None and entry is not None and entry.totp_secret:
                new_code = get_current_totp(entry.totp_secret) or "--- ---"
                self.totp_code_lbl.configure(text=f"{new_code[:3]} {new_code[3:]}" if len(new_code) == 6 else new_code)

        self._totp_timer_id = self.after(1000, self._start_totp_ticker)

    def _save_vault_to_disk(self, trigger_backup: bool = True) -> bool:
        self._refresh_floating_panel()
        self.ssh_agent.refresh_keys()
        try:
            if self.sync_session:
                # Tryb serwerowy: szyfrujemy tutaj, zapis lokalnej kopii i wysyłka idą w tle
                # Każdy zapis podnosi licznik w zaszyfrowanej treści – ochrona przed podsunięciem starej wersji przez serwer
                self.vault.revision = self.sync_session.next_revision(self.vault.revision)
                # Migawka sejfu teraz (wątek UI), kosztowne szyfrowanie w kolejce synchronizacji – okno nie zamarza
                data = self.vault.to_json().encode("utf-8")
                pwd, kf, ring = self.master_password, self.keyfile_bytes, self.vault.keyring
                future = self.sync_session.queue_save(lambda: seal(data, pwd, kf, ring), revision=self.vault.revision)
                self.count_badge.configure(text=_entries_count(len(self.vault.entries)))
                if trigger_backup and self.on_auto_backup_trigger:
                    # Kopia zapasowa dopiero po zapisaniu lokalnej kopii
                    def _after_save(_f, cb=self.on_auto_backup_trigger):
                        try:
                            self.after(0, cb)
                        except Exception:
                            pass
                    future.add_done_callback(_after_save)
                return True
            else:
                data = self.vault.to_json().encode("utf-8")
                future = background_saver.submit(data, self.vault_file_path, self.master_password, self.keyfile_bytes,
                                                 keyring=self.vault.keyring)
                self.count_badge.configure(text=_entries_count(len(self.vault.entries)))

                def _local_done(f, backup=trigger_backup and self.on_auto_backup_trigger):
                    error = f.exception()
                    if error is None and not (backup and f.result()):
                        return

                    def _ui():
                        if error is not None:
                            messagebox.showerror(
                                _("Błąd zapisu sejfu"),
                                _("Nie udało się zapisać sejfu na dysku:\n{error}\n\n"
                                  "Zmiany są tylko w pamięci – spróbuj ponownie przed zamknięciem aplikacji.", error=error))
                        else:
                            backup()  # kopia zapasowa dopiero, gdy plik jest już na dysku
                    try:
                        self.after(0, _ui)
                    except Exception:
                        pass
                future.add_done_callback(_local_done)
                return True
        except Exception as e:
            messagebox.showerror(
                _("Błąd zapisu sejfu"),
                _("Nie udało się zapisać sejfu na dysku:\n{error}\n\n"
                  "Zmiany są tylko w pamięci – spróbuj ponownie przed zamknięciem aplikacji.", error=e)
            )
            return False
        self.count_badge.configure(text=_entries_count(len(self.vault.entries)))
        if trigger_backup and self.on_auto_backup_trigger:
            self.on_auto_backup_trigger()
        return True

    # ----------------- OPERACJE NA WPISACH (KOSZ / DUPLIKACJA) -----------------
    def _delete_entry(self, entry: VaultEntry):
        if messagebox.askyesno(_("Przenieś do kosza"), _("Czy przenieść wpis '{title}' do kosza?", title=entry.title)):
            self.vault.delete_entry(entry.id)
            self._save_vault_to_disk()
            self.selected_entry_id = None
            self._build_sidebar()
            self._refresh_entries_list()
            self._show_empty_details()

    def _restore_entry(self, entry: VaultEntry):
        self.vault.restore_from_trash(entry.id)
        self._save_vault_to_disk()
        self._build_sidebar()
        self._refresh_entries_list()
        self._render_entry_details(entry.id)

    def _purge_entry(self, entry: VaultEntry):
        if messagebox.askyesno(_("Trwałe usunięcie"), _("Czy na pewno trwale usunąć wpis '{title}'? Tej operacji nie można cofnąć.", title=entry.title)):
            self.vault.empty_trash(entry.id)
            self._save_vault_to_disk()
            self._delete_unused_attachments([a["id"] for a in entry.attachments])
            self.selected_entry_id = None
            self._build_sidebar()
            self._refresh_entries_list()
            self._show_empty_details()

    def _duplicate_entry(self, entry: VaultEntry):
        dup = VaultEntry(
            title=_("{title} (Kopia)", title=entry.title),
            category=entry.category,
            username=entry.username,
            password=entry.password,
            url=entry.url,
            totp_secret=entry.totp_secret,
            notes=entry.notes,
            tags=list(entry.tags),
            custom_fields=dict(entry.custom_fields),
            favorite=entry.favorite
        )
        self.vault.add_entry(dup)
        self._save_vault_to_disk()
        self._build_sidebar()
        self._select_entry(dup.id)

    # ----------------- WYSKIWANIE BOCZNYCH PANELI (DRAWER) -----------------
    def _open_new_entry_dialog(self):
        def _build(container):
            def _on_save(new_entry):
                self.vault.add_entry(new_entry)
                self.vault.add_category(new_entry.category)
                self._save_vault_to_disk()
                self.drawer.close()
                self._build_sidebar()
                self._select_entry(new_entry.id)

            EntryDrawerView(
                container,
                categories=self.vault.categories,
                entry=None,
                on_save=_on_save,
                on_cancel=self.drawer.close,
                **self._entry_form_plugins()
            )

        self.drawer.open(_("Nowy Wpis"), _("Wprowadź dane nowego konta lub usługi"), build=_build)

    def _open_edit_entry_dialog(self, entry: VaultEntry):
        password_before = entry.password

        def _build(container):
            def _on_save(saved_entry):
                if self.plugin_on("family_share") and saved_entry.password != password_before:
                    from core import family_share
                    people = [i.get("name", "") for i in family_share.shared_with(self.vault.settings, saved_entry.id)]
                    if people:
                        self.after(600, lambda: self.show_toast(_("👪 To hasło udostępniłeś: {names} – wyślij im "
                                                                  "aktualizację (przycisk „Udostępnij”)",
                                                                  names=", ".join(people))))
                self.vault.add_category(saved_entry.category)
                self._save_vault_to_disk()
                self.drawer.close()
                self._build_sidebar()
                self._select_entry(saved_entry.id)

            EntryDrawerView(
                container,
                categories=self.vault.categories,
                entry=entry,
                on_save=_on_save,
                on_cancel=self.drawer.close,
                **self._entry_form_plugins()
            )

        self.drawer.open(_("Edycja: {title}", title=entry.title), _("Zaktualizuj hasło lub dane wpisu"), build=_build)

    def _entry_form_plugins(self) -> Dict[str, Any]:
        return {"settings": self.vault.settings, "plugin_on": self.plugin_on,
                "on_settings_changed": lambda: self._save_vault_to_disk(trigger_backup=False)}

    def _open_generator_dialog(self):
        def _build(container):
            GeneratorDrawerView(container)

        self.drawer.open(_("Generator Haseł i Passphrase"), _("Generowanie silnych, losowych haseł oraz fraz Diceware"), build=_build)

    def _open_audit_dialog(self):
        def _build(container):
            def _fix_entry(eid):
                entry = self.vault.get_entry(eid)
                if entry:
                    self._open_edit_entry_dialog(entry)

            def _report(report):
                # Ręczny audyt odświeża też plakietkę na przycisku
                self.set_audit_badge(attention_count(report), critical=bool(report.breached_issues))
                if self.on_audit_report:
                    self.on_audit_report(report)

            AuditDrawerView(container, vault=self.vault, on_fix_entry=_fix_entry, on_report=_report,
                            on_settings_changed=lambda: self._save_vault_to_disk(trigger_backup=False))

        self.drawer.open(_("Centrum Audytu Bezpieczeństwa"), _("Monitor wycieków Have I Been Pwned i higiena haseł"), build=_build)

    def _open_rescue_dialog(self, entry_id: Optional[str] = None):
        """Centrum ratunkowe: mapa domina kont i kreator „Ktoś przejął moje konto!”."""
        from ui.rescue_view import RescueDrawerView
        breached = set(getattr(self.winfo_toplevel(), "known_breached_ids", lambda: [])())

        def _saved():
            self._save_vault_to_disk(trigger_backup=False)
            if self.selected_entry_id and not self.trash_mode:
                self._render_entry_details(self.selected_entry_id)

        def _select(eid: str):
            self.drawer.close()
            self._select_entry(eid)

        self.drawer.open(_("Centrum ratunkowe"), _("Co się stanie, gdy ktoś przejmie Twój e-mail – i co zrobić, gdy już to zrobił"),
                         build=lambda c: RescueDrawerView(c, vault=self.vault, breached_ids=breached, on_select_entry=_select,
                                                          on_save=_saved, copy_secret=self._copy_password_safe,
                                                          open_url=self._open_url, start_entry_id=entry_id,
                                                          on_emergency_card=getattr(self.winfo_toplevel(),
                                                                                    "create_emergency_card", None)))

    def _open_backup_dialog(self):
        if not personal_backups_allowed(self.policy):
            messagebox.showinfo(
                _("Kopie zarządzane przez firmę"),
                _("Administrator wyłączył własne kopie sejfu (USB, prywatne chmury).\n\n"
                  "Twój sejf jest bezpiecznie przechowywany na serwerze firmy razem z historią wersji – "
                  "w razie potrzeby administrator może przywrócić wcześniejszą wersję.")
            )
            return
        def _build(container):
            BackupDrawerView(
                container,
                vault=self.vault,
                vault_file_path=self.vault_file_path,
                on_saved=lambda: self._save_vault_to_disk(trigger_backup=False)
            )

        self.drawer.open(_("Centrum Kopii Zapasowych i Chmury"), _("Konfiguracja kopii na WebDAV, Google Drive, OneDrive lub USB"), build=_build)

    def open_import_dialog(self):
        self._open_import_dialog()

    def _open_import_dialog(self):
        def _build(container):
            def _on_done(count):
                self._save_vault_to_disk()
                self.drawer.close()
                self._build_sidebar()
                self._refresh_entries_list()
                if self.selected_entry_id:
                    self._render_entry_details(self.selected_entry_id)
                else:
                    self._show_empty_details()

            ImportDrawerView(container, vault=self.vault, on_done=_on_done)

        self.drawer.open(_("Kreator Importu"), _("Przenieś hasła z Bitwarden, KeePass, 1Password lub Chrome"), build=_build)

    def _open_settings_dialog(self):
        def _build(container):
            def _pwd_changed(new_pwd):
                self.master_password = new_pwd
                if self.sync_session:
                    self.sync_session.update_credentials(new_pwd, self.keyfile_bytes)
                if self.on_master_password_changed:
                    self.on_master_password_changed(new_pwd)

            def _save_with_new_password(new_pwd):
                # Tryb serwerowy: nowa wersja (zaszyfrowana nowym hasłem) idzie przez kolejkę synchronizacji
                _pwd_changed(new_pwd)
                if not self._save_vault_to_disk():
                    raise OSError(_("Nie udało się zapisać sejfu."))

            SettingsDrawerView(
                container,
                vault=self.vault,
                current_password=self.master_password,
                vault_file_path=self.vault_file_path,
                keyfile_bytes=self.keyfile_bytes,
                on_pwd_changed=_pwd_changed,
                on_saved=self._save_vault_to_disk,
                password_saver=_save_with_new_password if self.sync_session else None,
                policy=self.policy,
                security_options=getattr(self.winfo_toplevel(), "security_options", lambda: None)(),
                on_open_about=self._open_about_dialog,
                on_open_plugins=self._open_plugins_dialog
            )

        self.drawer.open(_("Ustawienia Sejfu"), _("Zarządzanie czasem blokady, schowkiem i hasłem głównym"), build=_build)

    def _open_plugins_dialog(self):
        from ui.plugins_view import PluginsDrawerView

        def _saved():
            self._save_vault_to_disk(trigger_backup=False)
            self.apply_plugins()

        self.drawer.open(_("Wtyczki"), _("Dodatkowe funkcje, które włączasz według potrzeb"),
                         build=lambda c: PluginsDrawerView(c, vault=self.vault, policy=self.policy, on_saved=_saved,
                                                           agent_status=self.ssh_agent.status,
                                                           yubikey_actions=self._yubikey_actions()))

    def _yubikey_actions(self):
        app = self.winfo_toplevel()
        if not hasattr(app, "yubikey_state"):
            return None
        return {"state": app.yubikey_state, "enable": app.enable_yubikey, "disable": app.disable_yubikey}

    def _open_about_dialog(self):
        from ui.about_view import AboutView
        session = self.sync_session
        url = session.profile.url if session else ""
        version = getattr(session, "server_version", "") if session else ""
        self.drawer.open(_("O programie"), _("Wersja, zgodność z serwerem, autor i licencja"),
                         build=lambda c: AboutView(c, server_url=url, server_version=version))

    # ----------------- SYNCHRONIZACJA Z SERWEREM -----------------
    # stan → (ikona, tekst, tło, kolor tekstu)
    SYNC_LOOK = {
        "synced": ("☁", _("Zsynchronizowano"), COLOR_CARD_DARK, COLOR_SUCCESS),
        "syncing": ("⟳", _("Synchronizacja..."), COLOR_CARD_DARK, COLOR_PRIMARY_LIGHT),
        "pending": ("⟳", _("Zapisywanie..."), COLOR_CARD_DARK, COLOR_PRIMARY_LIGHT),
        "offline": ("⚠", _("Offline"), COLOR_CARD_DARK, COLOR_WARNING),
        "conflict": ("⚠", _("Konflikt – kliknij"), COLOR_DANGER, "#ffffff"),
        "error": ("⚠", _("Wymaga uwagi"), COLOR_DANGER, "#ffffff"),
    }

    def update_sync_status(self, status):
        """Aktualizuje wskaźnik synchronizacji (wywoływane przy każdej zmianie stanu)."""
        if not self.sync_btn or not self.sync_btn.winfo_exists():
            return
        self._last_sync_status = status
        icon, label, bg, fg = self.SYNC_LOOK.get(status.state, ("☁", _("Serwer"), COLOR_CARD_DARK, COLOR_TEXT_PRIMARY))
        self.sync_btn.configure(text=icon if self._is_compact_sidebar else f"{icon}  {label}", fg_color=bg, text_color=fg)

        previous, self._last_sync_state = self._last_sync_state, status.state
        if status.state != previous and status.state in ("conflict", "error"):
            self.show_toast(status.message, error=True)

    def apply_remote_vault(self, vault: Vault, message: str = ""):
        """Wczytuje nowszą wersję sejfu pobraną z serwera (zmiany z innego urządzenia)."""
        if self.drawer.is_open:
            # Nie podmieniamy danych pod otwartym formularzem – wczytamy po zamknięciu panelu
            self._pending_remote_vault = (vault, message)
            self.after(1500, self._apply_pending_remote_vault)
            return
        self.vault = vault
        if self.on_vault_replaced:
            self.on_vault_replaced(vault)
        if self.selected_entry_id and not vault.get_entry(self.selected_entry_id):
            self.selected_entry_id = None
        self.vault_title_lbl.configure(text=f"🛡️ {vault.name}")
        self.count_badge.configure(text=_entries_count(len(vault.entries)))
        self._applied_plugins = None  # wtyczki mogły zostać zmienione na innym urządzeniu
        self.apply_plugins()
        if self.selected_entry_id:
            self._render_entry_details(self.selected_entry_id)
        elif self.trash_mode:
            self._show_trash_header_in_details()
        else:
            self._show_empty_details()
        self._refresh_floating_panel()
        if message:
            self.show_toast(message)

    def apply_branding(self, company: str, logo_path: str = ""):
        """Nazwa i logo firmy (z serwera) na górze bocznego menu."""
        if getattr(self, "company_box", None) is not None and self.company_box.winfo_exists():
            self.company_box.destroy()
        self.company_box = None
        if not company and not logo_path:
            return
        box = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        image = None
        if logo_path:
            try:
                from PIL import Image
                img = Image.open(logo_path)
                img.thumbnail((180, 40))
                image = ctk.CTkImage(light_image=img, dark_image=img, size=img.size)
            except Exception:
                image = None
        if image is not None:
            ctk.CTkLabel(box, text="", image=image).pack(pady=(10, 2))
        if company and not self._is_compact_sidebar:
            ctk.CTkLabel(box, text=company, font=FONT_BODY_BOLD, text_color=COLOR_TEXT_PRIMARY,
                         wraplength=190, justify="center").pack(pady=(4 if image else 10, 0), padx=6)
        first = self.sync_btn if self.sync_btn is not None else self.sidebar_body
        box.pack(fill="x", before=first)
        self.company_box = box
        self._company = (company, logo_path)

    def open_settings_for_password_change(self):
        """Polityka firmy wymaga zmiany hasła głównego – otwórz ustawienia z sekcją zmiany hasła."""
        self._open_settings_dialog()

    def _apply_pending_remote_vault(self):
        if self._pending_remote_vault and not self.drawer.is_open:
            vault, message = self._pending_remote_vault
            self._pending_remote_vault = None
            self.apply_remote_vault(vault, message)
        elif self._pending_remote_vault:
            self.after(1500, self._apply_pending_remote_vault)

    def _open_sync_dialog(self):
        if not self.sync_session:
            return
        def _build(container):
            SyncDrawerView(
                container,
                session=self.sync_session,
                on_vault_replaced=lambda v, msg: self._replace_vault_from_sync(v, msg),
                on_sync_now=self.on_sync_requested
            )

        self.drawer.open(_("Synchronizacja z serwerem"), _("Stan sejfu na serwerze, konflikty i historia wersji"), build=_build)

    def _replace_vault_from_sync(self, vault: Vault, message: str):
        """Wynik rozwiązania konfliktu / przywrócenia wersji – zamyka panel i wczytuje sejf."""
        self.drawer.close()
        self._pending_remote_vault = (vault, message)
        self.after(400, self._apply_pending_remote_vault)

    def _lock_vault(self):
        if self._totp_timer_id:
            try:
                self.after_cancel(self._totp_timer_id)
            except Exception:
                pass
        SecureClipboard.clear()
        if self.on_lock_requested:
            self.on_lock_requested()
