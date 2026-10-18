"""
Widoki montowane wewnątrz wysuwanego panelu bocznego (Sliding Drawer Views).
Zastępują tradycyjne okna dialogowe:
- Formularz Wpisu (Dodawanie / Edycja)
- Generator Haseł i Passphrase
- Centrum Audytu Bezpieczeństwa (Watchtower & HIBP)
- Centrum Kopii Zapasowych i Chmury
- Kreator Importu
- Ustawienia Sejfu
"""

import copy
import hmac
import os
import threading
from datetime import datetime
from typing import Optional, Callable, Dict, Any, List
import tkinter as tk
import customtkinter as ctk
from tkinter import filedialog, messagebox

from core.vault import Vault, VaultEntry
from core.generator import generate_password, generate_passphrase, evaluate_password_strength, check_master_password
from core.totp_service import parse_otpauth_uri, sanitize_secret
from core.security_audit import check_password_breach_hibp, run_vault_audit, AuditReport
from core.watchtower import CONSENT_KEY as WATCH_CONSENT_KEY
from core.storage import save_vault
from backups import BackupManager, vault_snapshot, merge_runtime_state, oauth
from importers import (
    get_available_importers, detect_importer, run_import, apply_import,
    is_plaintext_export, secure_delete_file,
    STRATEGY_SKIP, STRATEGY_ADD_ALL, STRATEGY_UPDATE
)
from importers.base import tidy_vault, untidy_entries
from core.i18n import LANGUAGES, N_, _, _n, current_language, save_language
from core.version import APP_VERSION
from ui.theme import (
    FONT_TITLE, FONT_SUBTITLE, FONT_BODY, FONT_BODY_BOLD, FONT_CODE, FONT_SMALL,
    COLOR_PRIMARY, COLOR_PRIMARY_HOVER, COLOR_PRIMARY_LIGHT, COLOR_CARD_DARK, COLOR_CARD_HOVER,
    COLOR_PANEL_DARK, COLOR_BORDER, COLOR_SUCCESS, COLOR_DANGER, COLOR_WARNING,
    COLOR_TEXT_PRIMARY, COLOR_TEXT_MUTED, COLOR_TEXT_ACCENT
)
from ui.clipboard import SecureClipboard
from ui.language_ui import LanguageMenu
from ui.policy import (SCORE_LABELS, clipboard_choices, effective_auto_lock, effective_clipboard, lock_choices,
                       min_master_score)


def run_in_background(widget, work: Callable[[], Any], on_done: Callable[[Any], None]) -> None:
    """Wykonuje `work` w wątku roboczym i przekazuje wynik do `on_done` w wątku UI (jeśli widget nadal istnieje)."""
    def _worker():
        try:
            result = work()
        except Exception as e:  # Błąd zwracamy do UI zamiast gubić go w wątku
            result = e
        try:
            widget.after(0, lambda: widget.winfo_exists() and on_done(result))
        except Exception:
            pass  # Widget zniszczony (zamknięty panel / blokada sejfu)
    threading.Thread(target=_worker, daemon=True).start()


# =====================================================================
# 1. FORMULARZ WPISU (ENTRY DRAWER VIEW)
# =====================================================================

def layout_frame(parent) -> tk.Frame:
    """
    Ramka wyłącznie do układania elementów: zwykła ramka Tk w kolorze rodzica.
    Przezroczysta CTkFrame ma własne płótno i rysuje się przy każdej zmianie rozmiaru – kilka razy wolniej,
    a panel boczny miał ich kilkadziesiąt.
    """
    try:
        bg = parent.cget("bg")  # zwykłe widżety Tk i wnętrze CTkScrollableFrame
    except (ValueError, tk.TclError):
        color = parent.cget("fg_color")
        if color == "transparent":
            color = parent.cget("bg_color")
        bg = parent._apply_appearance_mode(color)
    return tk.Frame(parent, bg=bg, bd=0, highlightthickness=0)

class EntryDrawerView(ctk.CTkFrame):
    def __init__(
        self,
        parent,
        categories: List[str],
        entry: Optional[VaultEntry] = None,
        on_save: Optional[Callable[[VaultEntry], None]] = None,
        on_cancel: Optional[Callable[[], None]] = None,
        on_open_generator: Optional[Callable[[], None]] = None,
        settings: Optional[Dict[str, Any]] = None,
        plugin_on: Optional[Callable[[str], bool]] = None,
        on_settings_changed: Optional[Callable[[], None]] = None
    ):
        super().__init__(parent, fg_color="transparent")
        self.pack(fill="both", expand=True)
        self.categories = categories
        self.entry = entry
        self.on_save = on_save
        self.on_cancel = on_cancel
        self.on_open_generator = on_open_generator
        # Wtyczki: ustawienia sejfu (własne szablony) i informacja, które wtyczki są włączone
        self.settings = settings if settings is not None else {}
        self.plugin_on = plugin_on or (lambda _plugin_id: False)
        self.on_settings_changed = on_settings_changed
        self.expiry_entry = None
        self._ssh_key_text = ""  # tekst pliku klucza SSH (wtyczka „Klucze SSH w sejfie”)
        self.ssh_key_lbl = None

        self._password_hidden = True
        self._custom_field_widgets: List[Dict[str, Any]] = []

        self._build_ui()
        if entry:
            self._populate(entry)

    def _build_ui(self):
        self.scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.scroll.pack(fill="both", expand=True, padx=5, pady=(0, 10))

        if self.plugin_on("templates"):
            self._build_template_row()

        # Tytuł
        ctk.CTkLabel(self.scroll, text=_("Tytuł / Nazwa usługi *"), font=FONT_BODY_BOLD).pack(anchor="w", pady=(2, 2))
        self.title_entry = ctk.CTkEntry(self.scroll, placeholder_text=_("np. Google, GitHub, Bank..."))
        self.title_entry.pack(fill="x", pady=(0, 10))

        # Kategoria i Ulubione
        cat_fav = layout_frame(self.scroll)
        cat_fav.pack(fill="x", pady=(0, 10))

        c_col = layout_frame(cat_fav)
        c_col.pack(side="left", expand=True, fill="x", padx=(0, 10))
        ctk.CTkLabel(c_col, text=_("Kategoria:"), font=FONT_BODY_BOLD).pack(anchor="w", pady=(0, 2))
        # Nazwy kategorii to dane sejfu: lista pokazuje je przetłumaczone, zapis przywraca zapisaną nazwę
        available_cats = [c for c in self.categories if c not in ("Wszystkie", _("Wszystkie"))]  # i18n: data
        self._cat_names = {_(c): c for c in available_cats}
        self.cat_combo = ctk.CTkComboBox(c_col, values=list(self._cat_names))
        self.cat_combo.set(_(available_cats[0]) if available_cats else _("Loginy"))
        self.cat_combo.pack(fill="x")

        f_col = layout_frame(cat_fav)
        f_col.pack(side="right", padx=(10, 0), pady=(18, 0))
        self.fav_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(f_col, text=_("⭐ Ulubione"), variable=self.fav_var).pack()

        # Login
        ctk.CTkLabel(self.scroll, text=_("Login / E-mail / Nazwa użytkownika"), font=FONT_BODY_BOLD).pack(anchor="w", pady=(2, 2))
        self.user_entry = ctk.CTkEntry(self.scroll, placeholder_text=_("jan.kowalski@example.com"))
        self.user_entry.pack(fill="x", pady=(0, 10))

        # Hasło
        ctk.CTkLabel(self.scroll, text=_("Hasło"), font=FONT_BODY_BOLD).pack(anchor="w", pady=(2, 2))
        pwd_box = layout_frame(self.scroll)
        pwd_box.pack(fill="x", pady=(0, 2))

        self.pwd_entry = ctk.CTkEntry(pwd_box, show="•", placeholder_text=_("Wpisz hasło lub wygeneruj..."))
        self.pwd_entry.pack(side="left", expand=True, fill="x", padx=(0, 5))
        self.pwd_entry.bind("<KeyRelease>", self._on_password_typed)

        self.eye_btn = ctk.CTkButton(pwd_box, text="👁", width=36, fg_color=COLOR_CARD_DARK, command=self._toggle_eye)
        self.eye_btn.pack(side="left", padx=(0, 5))

        ctk.CTkButton(pwd_box, text=_("⚡ Generuj"), width=80, fg_color=COLOR_PRIMARY, command=self._generate_inline_pwd).pack(side="left")

        # Pasek siły hasła
        self.strength_bar = ctk.CTkProgressBar(self.scroll, height=5)
        self.strength_bar.pack(fill="x", pady=(4, 2))
        self.strength_bar.set(0)

        # Wiersz wskaźnika siły i weryfikacji HIBP
        s_row = layout_frame(self.scroll)
        s_row.pack(fill="x", pady=(0, 10))

        self.strength_lbl = ctk.CTkLabel(s_row, text="", font=FONT_SMALL, text_color=COLOR_TEXT_MUTED)
        self.strength_lbl.pack(side="left")

        self.hibp_btn = ctk.CTkButton(
            s_row,
            text=_("Sprawdź w wyciekach (HIBP)"),
            width=165,
            height=20,
            font=FONT_SMALL,
            fg_color=COLOR_CARD_DARK,
            command=self._check_hibp
        )
        self.hibp_btn.pack(side="right")

        if self.plugin_on("expiry"):
            self._build_expiry_row()

        # URL
        ctk.CTkLabel(self.scroll, text=_("Adres URL (Strona logowania)"), font=FONT_BODY_BOLD).pack(anchor="w", pady=(2, 2))
        self.url_entry = ctk.CTkEntry(self.scroll, placeholder_text="https://...")
        self.url_entry.pack(fill="x", pady=(0, 10))

        # TOTP 2FA
        totp_head = layout_frame(self.scroll)
        totp_head.pack(fill="x", pady=(2, 2))
        ctk.CTkLabel(totp_head, text=_("Klucz TOTP (2FA) - Base32 lub link otpauth://"), font=FONT_BODY_BOLD).pack(side="left")
        if self.plugin_on("qr_import"):
            ctk.CTkButton(totp_head, text=_("📂 Z pliku"), width=80, height=24, font=FONT_SMALL, fg_color=COLOR_CARD_DARK,
                          command=lambda: self._read_qr("file")).pack(side="right")
            ctk.CTkButton(totp_head, text=_("📷 Wklej kod QR"), width=110, height=24, font=FONT_SMALL,
                          fg_color=COLOR_PRIMARY, command=lambda: self._read_qr("clipboard")).pack(side="right", padx=(0, 4))
        self.totp_entry = ctk.CTkEntry(self.scroll, placeholder_text="JBSWY3DPEHPK3PXP...")
        self.totp_entry.pack(fill="x", pady=(0, 10))

        if self.plugin_on("ssh_agent"):
            self._build_ssh_key_row()

        # Notatki
        ctk.CTkLabel(self.scroll, text=_("Bezpieczne notatki"), font=FONT_BODY_BOLD).pack(anchor="w", pady=(2, 2))
        self.notes_box = ctk.CTkTextbox(self.scroll, height=75)
        self.notes_box.pack(fill="x", pady=(0, 10))

        # Tagi
        ctk.CTkLabel(self.scroll, text=_("Tagi (oddzielone przecinkami)"), font=FONT_BODY_BOLD).pack(anchor="w", pady=(2, 2))
        self.tags_entry = ctk.CTkEntry(self.scroll, placeholder_text=_("praca, finanse, vpn..."))
        self.tags_entry.pack(fill="x", pady=(0, 12))

        # Pola dodatkowe
        c_head = layout_frame(self.scroll)
        c_head.pack(fill="x", pady=(0, 4))
        ctk.CTkLabel(c_head, text=_("Pola niestandardowe (PIN, Pytania, Klucze)"), font=FONT_BODY_BOLD).pack(side="left")
        ctk.CTkButton(c_head, text=_("+ Dodaj pole"), width=90, height=24, fg_color=COLOR_CARD_DARK, command=self._add_field_row).pack(side="right")
        if self.plugin_on("templates"):
            ctk.CTkButton(c_head, text=_("⭐ Zapisz jako szablon"), width=140, height=24, font=FONT_SMALL,
                          fg_color=COLOR_CARD_DARK, command=self._save_as_template).pack(side="right", padx=(0, 4))

        self.custom_fields_box = ctk.CTkFrame(self.scroll, fg_color=COLOR_CARD_DARK, corner_radius=8)
        self.custom_fields_box.pack(fill="x", pady=(0, 15))

        # Przyciski na dole
        action_bar = ctk.CTkFrame(self, fg_color=COLOR_CARD_DARK, corner_radius=8, height=50)
        action_bar.pack(fill="x", side="bottom", pady=(5, 0))

        if self.on_cancel:
            ctk.CTkButton(action_bar, text=_("Anuluj"), fg_color=COLOR_PANEL_DARK, command=self.on_cancel).pack(side="left", padx=10, pady=8)

        ctk.CTkButton(
            action_bar,
            text=_("💾 Zapisz wpis"),
            fg_color=COLOR_PRIMARY,
            hover_color=COLOR_PRIMARY_HOVER,
            command=self._save_entry
        ).pack(side="right", padx=10, pady=8)

    def _toggle_eye(self):
        if self._password_hidden:
            self.pwd_entry.configure(show="")
            self.eye_btn.configure(text="🔒")
            self._password_hidden = False
        else:
            self.pwd_entry.configure(show="•")
            self.eye_btn.configure(text="👁")
            self._password_hidden = True

    def _generate_inline_pwd(self):
        new_pwd = generate_password(length=20, avoid_ambiguous=True)
        self.pwd_entry.delete(0, "end")
        self.pwd_entry.insert(0, new_pwd)
        self._on_password_typed()

    def _on_password_typed(self, event=None):
        pwd = self.pwd_entry.get()
        if not pwd:
            self.strength_bar.set(0)
            self.strength_lbl.configure(text="")
            return
        eval_res = evaluate_password_strength(pwd)
        self.strength_bar.set(eval_res["score"] / 4.0)
        self.strength_bar.configure(progress_color=eval_res["color"])
        self.strength_lbl.configure(text=_("{label} ({entropy} bitów)", label=_(eval_res['label']), entropy=eval_res['entropy']), text_color=eval_res["color"])
        self.hibp_btn.configure(text=_("Sprawdź w wyciekach (HIBP)"), fg_color=COLOR_CARD_DARK)

    def _check_hibp(self):
        pwd = self.pwd_entry.get()
        if not pwd:
            return
        self.hibp_btn.configure(text=_("Sprawdzanie..."), state="disabled")

        def _ui(res):
            is_pwned, cnt = res
            self.hibp_btn.configure(state="normal")
            if is_pwned:
                self.hibp_btn.configure(text=_("🚨 Wyciekło ({cnt:,}x)!", cnt=cnt), fg_color=COLOR_DANGER)
            elif cnt < 0:
                self.hibp_btn.configure(text=_("⚠️ Brak połączenia z HIBP"), fg_color=COLOR_WARNING)
            else:
                self.hibp_btn.configure(text=_("✅ Bezpieczne (0x)"), fg_color=COLOR_SUCCESS)

        run_in_background(self, lambda: check_password_breach_hibp(pwd), _ui)

    def _add_field_row(self, k: str = "", v: str = ""):
        row = layout_frame(self.custom_fields_box)
        row.pack(fill="x", padx=8, pady=4)

        ke = ctk.CTkEntry(row, placeholder_text=_("Pole (np. PIN)"))
        ke.insert(0, k)
        ke.pack(side="left", expand=True, fill="x", padx=(0, 4))

        ve = ctk.CTkEntry(row, placeholder_text=_("Wartość"))
        ve.insert(0, v)
        ve.pack(side="left", expand=True, fill="x", padx=(0, 4))

        item_dict = {"frame": row, "key": ke, "val": ve}
        def _rem():
            row.destroy()
            if item_dict in self._custom_field_widgets:
                self._custom_field_widgets.remove(item_dict)

        ctk.CTkButton(row, text="✕", width=26, height=26, fg_color=COLOR_DANGER, command=_rem).pack(side="left")
        self._custom_field_widgets.append(item_dict)

    def _populate(self, entry: VaultEntry):
        self.title_entry.insert(0, entry.title)
        values = list(self.cat_combo.cget("values"))
        shown = _(entry.category) if entry.category else _("Loginy")
        if entry.category and entry.category not in self._cat_names.values():
            # Kategoria spoza listy (np. z importu) – nie zmieniaj jej po cichu przy edycji
            values.append(shown)
            self._cat_names[shown] = entry.category
            self.cat_combo.configure(values=values)
        self.cat_combo.set(shown)
        self.fav_var.set(entry.favorite)
        self.user_entry.insert(0, entry.username)
        self.pwd_entry.insert(0, entry.password)
        self.url_entry.insert(0, entry.url)
        self.totp_entry.insert(0, entry.totp_secret)
        self.notes_box.insert("1.0", entry.notes)
        self.tags_entry.insert(0, ", ".join(entry.tags))

        hidden = set()
        if self.ssh_key_lbl is not None:
            from core import ssh_keys
            name = ssh_keys.field_name(entry)
            if name:
                hidden.add(name)
                self._set_ssh_key(entry.custom_fields[name], password=entry.password)
        if self.expiry_entry is not None:
            from core import expiry
            name = expiry.field_name(entry)
            if name:
                hidden.add(name)  # pokazana w osobnym polu „Hasło ważne do”
                self.expiry_entry.insert(0, entry.custom_fields.get(name, ""))
        for k, v in entry.custom_fields.items():
            if k not in hidden:
                self._add_field_row(k, v)
        self._on_password_typed()

    def _save_entry(self):
        title = self.title_entry.get().strip()
        if not title:
            self.title_entry.focus()
            return

        shown = self.cat_combo.get().strip()
        cat = self._cat_names.get(shown, shown) or "Loginy"  # i18n: data
        u = self.user_entry.get().strip()
        p = self.pwd_entry.get()
        url = self.url_entry.get().strip()
        raw_totp = self.totp_entry.get().strip()

        totp = ""
        if raw_totp.startswith("otpauth://"):
            parsed = parse_otpauth_uri(raw_totp)
            totp = parsed[0] if parsed else raw_totp
        else:
            totp = sanitize_secret(raw_totp)

        notes = self.notes_box.get("1.0", "end-1c").strip()
        tags = [t.strip() for t in self.tags_entry.get().split(",") if t.strip()]

        cfields = {}
        for w in self._custom_field_widgets:
            k = w["key"].get().strip()
            v = w["val"].get().strip()
            if k:
                cfields[k] = v

        if self.ssh_key_lbl is not None:
            from core import ssh_keys
            for name in (ssh_keys.KEY_FIELD, *ssh_keys.KEY_ALIASES):
                cfields.pop(name, None)
            if self._ssh_key_text:
                try:
                    ssh_keys.load_key(self._ssh_key_text, p)
                except ssh_keys.SshKeyError as e:
                    if not messagebox.askyesno(_("Klucz SSH"), _("Tego klucza SSH nie da się teraz użyć:\n{error}\n\n"
                                                                 "Zapisać wpis mimo to?", error=e),
                                               parent=self.winfo_toplevel()):
                        return
                cfields[ssh_keys.KEY_FIELD] = self._ssh_key_text

        if self.expiry_entry is not None:
            from core import expiry
            raw = self.expiry_entry.get().strip()
            when = expiry.parse_date(raw) if raw else None
            if raw and when is None:
                messagebox.showerror(_("Data ważności hasła"), _("Nieprawidłowa data „{value}”. Wpisz ją jako "
                                                                 "RRRR-MM-DD, np. 2027-03-31.", value=raw),
                                     parent=self.winfo_toplevel())
                self.expiry_entry.focus()
                return
            expiry.set_expiry_field(cfields, when)

        if self.entry:
            self.entry.update(
                title=title, category=cat, username=u, password=p,
                url=url, totp_secret=totp, notes=notes, tags=tags,
                custom_fields=cfields, favorite=self.fav_var.get()
            )
            saved = self.entry
        else:
            saved = VaultEntry(
                title=title, category=cat, username=u, password=p,
                url=url, totp_secret=totp, notes=notes, tags=tags,
                custom_fields=cfields, favorite=self.fav_var.get()
            )

        if self.on_save:
            self.on_save(saved)


    # ----------------- wtyczki: szablony, data ważności, kod QR 2FA -----------------
    def _build_template_row(self):
        from core.entry_templates import all_templates
        self._templates = {t.label(): t for t in all_templates(self.settings)}
        row = layout_frame(self.scroll)
        row.pack(fill="x", pady=(2, 10))
        ctk.CTkLabel(row, text=_("🧩 Szablon:"), font=FONT_BODY_BOLD).pack(side="left")
        self.template_combo = ctk.CTkComboBox(row, values=[_("— bez szablonu —")] + list(self._templates),
                                              state="readonly", command=self._apply_template)
        self.template_combo.set(_("— bez szablonu —"))
        self.template_combo.pack(side="left", fill="x", expand=True, padx=(8, 0))

    def _apply_template(self, label: str):
        from core.entry_templates import apply
        template = self._templates.get(label)
        if template is None:
            return
        shown = _(template.category)
        if shown not in self._cat_names:
            self._cat_names[shown] = template.category
            self.cat_combo.configure(values=list(self._cat_names))
        self.cat_combo.set(shown)
        if template.url and not self.url_entry.get().strip():
            self.url_entry.insert(0, template.url)
        existing = {w["key"].get().strip(): w["val"].get() for w in self._custom_field_widgets if w["key"].get().strip()}
        for name, value in apply(template, existing).items():
            if name not in existing:
                self._add_field_row(name, value)
        if not self.title_entry.get().strip():
            self.title_entry.focus()

    def _save_as_template(self):
        from core.entry_templates import save_user_template
        names = [w["key"].get().strip() for w in self._custom_field_widgets if w["key"].get().strip()]
        if not names:
            messagebox.showinfo(_("Szablon"), _("Dodaj najpierw pola niestandardowe, które ma mieć szablon."),
                                parent=self.winfo_toplevel())
            return
        name = ctk.CTkInputDialog(text=_("Nazwa szablonu (zapisane zostaną tylko nazwy pól, bez wartości):"),
                                  title=_("Zapisz jako szablon")).get_input()
        if not name or not name.strip():
            return
        shown = self.cat_combo.get().strip()
        save_user_template(self.settings, name, self._cat_names.get(shown, shown), self.url_entry.get(), names)
        if self.on_settings_changed:
            self.on_settings_changed()
        if hasattr(self, "template_combo"):
            from core.entry_templates import all_templates
            self._templates = {t.label(): t for t in all_templates(self.settings)}
            self.template_combo.configure(values=[_("— bez szablonu —")] + list(self._templates))
        messagebox.showinfo(_("Szablon"), _("Zapisano szablon „{name}”.", name=name.strip()), parent=self.winfo_toplevel())

    def _build_ssh_key_row(self):
        ctk.CTkLabel(self.scroll, text=_("🗝️ Klucz SSH (hasło klucza = pole „Hasło” powyżej)"),
                     font=FONT_BODY_BOLD).pack(anchor="w", pady=(2, 2))
        box = ctk.CTkFrame(self.scroll, fg_color=COLOR_CARD_DARK, corner_radius=8)
        box.pack(fill="x", pady=(0, 10))
        self.ssh_key_lbl = ctk.CTkLabel(box, text=_("Brak klucza"), font=FONT_SMALL, text_color=COLOR_TEXT_MUTED,
                                        wraplength=420, justify="left", anchor="w")
        self.ssh_key_lbl.pack(fill="x", padx=10, pady=(6, 2))
        row = layout_frame(box)
        row.pack(fill="x", padx=8, pady=(0, 8))
        ctk.CTkButton(row, text=_("📂 Wczytaj plik…"), width=110, height=26, font=FONT_SMALL, fg_color=COLOR_PRIMARY,
                      command=self._load_ssh_key_file).pack(side="left", padx=2)
        ctk.CTkButton(row, text=_("✨ Nowy klucz"), width=100, height=26, font=FONT_SMALL, fg_color=COLOR_PANEL_DARK,
                      command=self._generate_ssh_key).pack(side="left", padx=2)
        self.ssh_pub_btn = ctk.CTkButton(row, text=_("📋 Klucz publiczny"), width=120, height=26, font=FONT_SMALL,
                                         fg_color=COLOR_PANEL_DARK, command=self._copy_ssh_public, state="disabled")
        self.ssh_pub_btn.pack(side="left", padx=2)
        ctk.CTkButton(row, text="✕", width=28, height=26, fg_color=COLOR_PANEL_DARK,
                      command=lambda: self._set_ssh_key("")).pack(side="left", padx=2)

    def _set_ssh_key(self, text: str, password: Optional[str] = None):
        from core import ssh_keys
        self._ssh_key_text = (text or "").strip() + ("\n" if (text or "").strip() else "")
        self._ssh_public_line = ""
        if not self._ssh_key_text:
            self.ssh_key_lbl.configure(text=_("Brak klucza"), text_color=COLOR_TEXT_MUTED)
            self.ssh_pub_btn.configure(state="disabled")
            return
        try:
            key = ssh_keys.load_key(self._ssh_key_text, self.pwd_entry.get() if password is None else password)
        except ssh_keys.SshKeyError as e:
            self.ssh_key_lbl.configure(text=_("⚠️ {error}", error=e), text_color=COLOR_WARNING)
            self.ssh_pub_btn.configure(state="disabled")
            return
        self._ssh_public_line = key.public_line()
        self.ssh_key_lbl.configure(text=f"✓ {key.description()} · {key.fingerprint()}" +
                                   (f" · {key.comment}" if key.comment else ""), text_color=COLOR_SUCCESS)
        self.ssh_pub_btn.configure(state="normal")

    def _load_ssh_key_file(self):
        path = filedialog.askopenfilename(title=_("Plik klucza prywatnego SSH"), parent=self.winfo_toplevel(),
                                          filetypes=[(_("Klucze SSH"), "*.ppk *.pem *.key id_* *"), (_("Wszystkie pliki"), "*")])
        if not path:
            return
        try:
            if os.path.getsize(path) > 20_000:
                raise ValueError(_("To nie wygląda na plik klucza SSH (za długi)."))
            with open(path, "r", encoding="utf-8") as f:
                text = f.read()
        except (OSError, UnicodeDecodeError, ValueError) as e:
            messagebox.showerror(_("Klucz SSH"), _("Nie udało się wczytać pliku: {error}", error=e),
                                 parent=self.winfo_toplevel())
            return
        self._set_ssh_key(text)
        if not self.title_entry.get().strip():
            self.title_entry.insert(0, os.path.basename(path))

    def _generate_ssh_key(self):
        from core import ssh_keys
        if self._ssh_key_text and not messagebox.askyesno(_("Klucz SSH"), _("Zastąpić obecny klucz nowym?"),
                                                          parent=self.winfo_toplevel()):
            return
        comment = self.user_entry.get().strip() or self.title_entry.get().strip() or "keystead"
        self._set_ssh_key(ssh_keys.generate_ed25519(comment), password="")
        messagebox.showinfo(_("Klucz SSH"), _("Utworzono nowy klucz Ed25519. Skopiuj klucz publiczny i dodaj go na "
                                              "serwerze (plik ~/.ssh/authorized_keys), a potem zapisz wpis."),
                            parent=self.winfo_toplevel())

    def _copy_ssh_public(self):
        if getattr(self, "_ssh_public_line", ""):
            SecureClipboard.copy(self._ssh_public_line, timeout_seconds=0)  # klucz publiczny nie jest tajny
            self.ssh_pub_btn.configure(text=_("✓ Skopiowano"))
            self.after(2000, lambda: self.ssh_pub_btn.winfo_exists() and
                       self.ssh_pub_btn.configure(text=_("📋 Klucz publiczny")))

    def _build_expiry_row(self):
        ctk.CTkLabel(self.scroll, text=_("⏰ Hasło ważne do (RRRR-MM-DD, puste = bez terminu)"),
                     font=FONT_BODY_BOLD).pack(anchor="w", pady=(2, 2))
        row = layout_frame(self.scroll)
        row.pack(fill="x", pady=(0, 10))
        self.expiry_entry = ctk.CTkEntry(row, width=120, placeholder_text="2027-03-31")
        self.expiry_entry.pack(side="left")
        for label, days in ((_("+30 dni"), 30), (_("+90 dni"), 90), (_("+1 rok"), 365)):
            ctk.CTkButton(row, text=label, width=64, height=26, font=FONT_SMALL, fg_color=COLOR_CARD_DARK,
                          command=lambda d=days: self._set_expiry_in(d)).pack(side="left", padx=(6, 0))
        ctk.CTkButton(row, text="✕", width=28, height=26, fg_color=COLOR_CARD_DARK,
                      command=lambda: self.expiry_entry.delete(0, "end")).pack(side="left", padx=(6, 0))

    def _set_expiry_in(self, days: int):
        from core import expiry
        self.expiry_entry.delete(0, "end")
        self.expiry_entry.insert(0, expiry.in_days(days).isoformat())

    def _read_qr(self, source: str):
        from core import qr
        from PIL import Image, ImageGrab
        try:
            if source == "clipboard":
                image = ImageGrab.grabclipboard()  # obraz skopiowany przez użytkownika (np. Win+Shift+S)
                if not isinstance(image, Image.Image):
                    messagebox.showinfo(_("Kod QR"), _("W schowku nie ma obrazka. Zrób zrzut kodu QR klawiszami "
                                                       "Win+Shift+S i kliknij ponownie „Wklej kod QR”."),
                                        parent=self.winfo_toplevel())
                    return
            else:
                path = filedialog.askopenfilename(title=_("Obrazek z kodem QR"), parent=self.winfo_toplevel(),
                                                  filetypes=[(_("Obrazy"), "*.png *.jpg *.jpeg *.bmp *.gif *.webp")])
                if not path:
                    return
                image = Image.open(path)
            uri = qr.find_otpauth(qr.read_codes(image))
        except Exception as e:
            messagebox.showerror(_("Kod QR"), _("Nie udało się odczytać obrazka: {error}", error=e),
                                 parent=self.winfo_toplevel())
            return
        parsed = parse_otpauth_uri(uri) if uri else None
        if not parsed or not parsed[0]:
            messagebox.showwarning(_("Kod QR"), _("Na obrazku nie ma kodu QR do weryfikacji dwuetapowej (2FA). "
                                                  "Upewnij się, że cały kod jest widoczny i ostry."),
                                   parent=self.winfo_toplevel())
            return
        secret, account, issuer = parsed
        self.totp_entry.delete(0, "end")
        self.totp_entry.insert(0, uri)
        if issuer and not self.title_entry.get().strip():
            self.title_entry.insert(0, issuer)
        if account and not self.user_entry.get().strip():
            self.user_entry.insert(0, account)
        messagebox.showinfo(_("Kod QR"), _("✅ Odczytano klucz 2FA{issuer}. Zapisz wpis, aby zachować zmiany.",
                                          issuer=f" ({issuer})" if issuer else ""), parent=self.winfo_toplevel())


# =====================================================================
# 2. GENERATOR HASEŁ (GENERATOR DRAWER VIEW)
# =====================================================================
class GeneratorDrawerView(ctk.CTkFrame):
    def __init__(self, parent, on_use_password: Optional[Callable[[str], None]] = None):
        super().__init__(parent, fg_color="transparent")
        self.pack(fill="both", expand=True)
        self.on_use_password = on_use_password
        self._mode = "random"

        self._build_ui()
        self._regenerate()

    def _build_ui(self):
        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.pack(fill="both", expand=True)

        # Pole wygenerowanego hasła
        out_frame = ctk.CTkFrame(scroll, fg_color=COLOR_CARD_DARK, corner_radius=10)
        out_frame.pack(fill="x", pady=(0, 15), ipady=6)

        self.pwd_entry = ctk.CTkEntry(out_frame, font=("Consolas", 15, "bold"), justify="center", fg_color="transparent", border_width=0)
        self.pwd_entry.pack(fill="x", padx=10, pady=(6, 4))

        self.s_bar = ctk.CTkProgressBar(out_frame, height=6)
        self.s_bar.pack(fill="x", padx=12, pady=(0, 4))

        self.s_lbl = ctk.CTkLabel(out_frame, text="", font=FONT_SMALL, text_color=COLOR_TEXT_MUTED)
        self.s_lbl.pack(pady=(0, 6))

        # Przyciski Kopiuj / Nowe / Użyj
        btn_box = layout_frame(scroll)
        btn_box.pack(fill="x", pady=(0, 15))

        self.copy_btn = ctk.CTkButton(btn_box, text=_("Kopiuj do schowka"), fg_color=COLOR_PRIMARY, command=self._copy)
        self.copy_btn.pack(side="left", expand=True, fill="x", padx=(0, 4))

        ctk.CTkButton(btn_box, text=_("🔄 Nowe"), width=75, fg_color=COLOR_CARD_DARK, command=self._regenerate).pack(side="left", padx=4)

        if self.on_use_password:
            ctk.CTkButton(btn_box, text=_("Wstaw do wpisu"), fg_color=COLOR_SUCCESS, command=lambda: self.on_use_password(self.pwd_entry.get())).pack(side="left", padx=(4, 0))

        # Przełącznik trybu
        self._random_label = _("Losowe hasło")
        self.mode_btn = ctk.CTkSegmentedButton(scroll, values=[self._random_label, _("Fraza (Passphrase)")], command=self._mode_change)
        self.mode_btn.set(self._random_label)
        self.mode_btn.pack(fill="x", pady=(0, 15))

        # Opcje
        self.opts_box = ctk.CTkFrame(scroll, fg_color=COLOR_CARD_DARK, corner_radius=10)
        self.opts_box.pack(fill="x", ipady=8, padx=2)

        # Długość
        lh = layout_frame(self.opts_box)
        lh.pack(fill="x", padx=15, pady=(8, 2))
        ctk.CTkLabel(lh, text=_("Długość hasła:"), font=FONT_BODY_BOLD).pack(side="left")
        self.len_lbl = ctk.CTkLabel(lh, text="20", font=FONT_BODY_BOLD, text_color=COLOR_PRIMARY_LIGHT)
        self.len_lbl.pack(side="right")

        self.len_slider = ctk.CTkSlider(self.opts_box, from_=8, to=64, number_of_steps=56, command=self._on_slider)
        self.len_slider.set(20)
        self.len_slider.pack(fill="x", padx=15, pady=(0, 12))

        # Checkboxy
        self.c_up = ctk.BooleanVar(value=True)
        self.c_lo = ctk.BooleanVar(value=True)
        self.c_dg = ctk.BooleanVar(value=True)
        self.c_sy = ctk.BooleanVar(value=True)
        self.c_am = ctk.BooleanVar(value=True)

        ctk.CTkCheckBox(self.opts_box, text=_("Wielkie litery (A-Z)"), variable=self.c_up, command=self._regenerate).pack(anchor="w", padx=15, pady=3)
        ctk.CTkCheckBox(self.opts_box, text=_("Małe litery (a-z)"), variable=self.c_lo, command=self._regenerate).pack(anchor="w", padx=15, pady=3)
        ctk.CTkCheckBox(self.opts_box, text=_("Cyfry (0-9)"), variable=self.c_dg, command=self._regenerate).pack(anchor="w", padx=15, pady=3)
        ctk.CTkCheckBox(self.opts_box, text=_("Znaki specjalne (!@#$%^&*)"), variable=self.c_sy, command=self._regenerate).pack(anchor="w", padx=15, pady=3)
        ctk.CTkCheckBox(self.opts_box, text=_("Unikaj mylących znaków (0, O, 1, l, I)"), variable=self.c_am, command=self._regenerate).pack(anchor="w", padx=15, pady=3)

    def _mode_change(self, v):
        self._mode = "random" if v == self._random_label else "passphrase"
        self._regenerate()

    def _on_slider(self, val):
        self.len_lbl.configure(text=str(int(val)))
        self._regenerate()

    def _regenerate(self):
        if self._mode == "random":
            pwd = generate_password(
                length=int(self.len_slider.get()),
                use_upper=self.c_up.get(), use_lower=self.c_lo.get(),
                use_digits=self.c_dg.get(), use_symbols=self.c_sy.get(),
                avoid_ambiguous=self.c_am.get()
            )
        else:
            pwd = generate_passphrase(word_count=5, separator="-", capitalize=True, include_number=True)

        self.pwd_entry.delete(0, "end")
        self.pwd_entry.insert(0, pwd)

        eval_res = evaluate_password_strength(pwd)
        self.s_bar.set(eval_res["score"] / 4.0)
        self.s_bar.configure(progress_color=eval_res["color"])
        self.s_lbl.configure(text=_("{label} ({entropy} bitów entropii)", label=_(eval_res['label']), entropy=eval_res['entropy']), text_color=eval_res["color"])

    def _copy(self):
        pwd = self.pwd_entry.get()
        if pwd:
            SecureClipboard.copy(pwd, timeout_seconds=30)
            self.copy_btn.configure(text=_("Skopiowano! (30s)"), fg_color=COLOR_SUCCESS)
            self.after(2000, lambda: self.copy_btn.configure(text=_("Kopiuj do schowka"), fg_color=COLOR_PRIMARY))


# =====================================================================
# 3. CENTRUM AUDYTU BEZPIECZEŃSTWA (AUDIT DRAWER VIEW)
# =====================================================================
class AuditDrawerView(ctk.CTkFrame):
    def __init__(self, parent, vault: Vault, on_fix_entry: Optional[Callable[[str], None]] = None,
                 on_report: Optional[Callable[[AuditReport], None]] = None,
                 on_settings_changed: Optional[Callable[[], None]] = None):
        super().__init__(parent, fg_color="transparent")
        self.pack(fill="both", expand=True)
        self.vault = vault
        self.on_fix_entry = on_fix_entry
        self.on_report = on_report  # tryb serwerowy: zbiorczy wynik trafia do raportu firmy
        self.on_settings_changed = on_settings_changed
        self._report: Optional[AuditReport] = None

        self._build_ui()
        self._start_audit()

    def _build_ui(self):
        self.scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.scroll.pack(fill="both", expand=True)

        # Karta wyniku
        self.score_card = ctk.CTkFrame(self.scroll, fg_color=COLOR_CARD_DARK, corner_radius=12)
        self.score_card.pack(fill="x", pady=(0, 15), ipady=6)

        inner = layout_frame(self.score_card)
        inner.pack(fill="x", padx=15, pady=8)

        self.score_lbl = ctk.CTkLabel(inner, text="--", font=("Segoe UI", 32, "bold"), text_color=COLOR_SUCCESS)
        self.score_lbl.pack(side="left", padx=(0, 12))

        col = layout_frame(inner)
        col.pack(side="left", fill="x", expand=True)

        self.score_title = ctk.CTkLabel(col, text=_("Trwa skanowanie sejfu..."), font=FONT_SUBTITLE, text_color=COLOR_TEXT_PRIMARY, anchor="w")
        self.score_title.pack(anchor="w")

        self.score_desc = ctk.CTkLabel(col, text=_("Weryfikacja wycieków Have I Been Pwned metodą k-Anonymity..."), font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, anchor="w")
        self.score_desc.pack(anchor="w")

        self.scan_bar = ctk.CTkProgressBar(self.scroll, height=5)
        self.scan_bar.pack(fill="x", pady=(0, 12))
        self.scan_bar.set(0)

        self.monitor_sw = ctk.CTkSwitch(self.scroll, text=_("Monitoruj wycieki automatycznie (raz dziennie, z powiadomieniem)"),
                                        command=self._toggle_monitoring)
        if self.vault.settings.get(WATCH_CONSENT_KEY):
            self.monitor_sw.select()
        self.monitor_sw.pack(anchor="w", pady=(0, 12))

        # Kontener na listę uwag
        ctk.CTkLabel(self.scroll, text=_("Wykryte uwagi bezpieczeństwa:"), font=FONT_BODY_BOLD).pack(anchor="w", pady=(0, 6))
        self.issues_container = layout_frame(self.scroll)
        self.issues_container.pack(fill="both", expand=True)

    def _toggle_monitoring(self):
        self.vault.settings[WATCH_CONSENT_KEY] = bool(self.monitor_sw.get())
        if self.on_settings_changed:
            self.on_settings_changed()

    def _start_audit(self):
        self.scan_bar.set(0)

        def _progress(done: int, total: int, title: str):
            try:
                self.after(0, lambda: self.scan_bar.winfo_exists() and self.scan_bar.set(done / max(total, 1)))
            except Exception:
                pass

        run_in_background(self, lambda: run_vault_audit(self.vault, check_hibp=True, progress_callback=_progress), self._on_done)

    def _on_done(self, report):
        if isinstance(report, Exception):
            self.score_title.configure(text=_("Audyt nie powiódł się"))
            self.score_desc.configure(text=str(report))
            return
        self._report = report
        if self.on_report:
            self.on_report(report)
        self.scan_bar.set(1.0)
        self.score_lbl.configure(text=f"{report.score}/100", text_color=report.rating_color)
        self.score_title.configure(text=_("Stan sejfu: {rating}", rating=_(report.rating_label)))
        desc = (_n(report.total_entries, "Przeanalizowano {n} wpis.", "Przeanalizowano {n} wpisy.",
                   "Przeanalizowano {n} wpisów.") + " "
                + _n(len(report.issues), "Wykryto {n} uwagę.", "Wykryto {n} uwagi.", "Wykryto {n} uwag."))
        if report.hibp_failures:
            desc += "\n" + _n(report.hibp_failures, "⚠️ Nie udało się sprawdzić {n} hasła w HIBP (brak połączenia?).",
                              "⚠️ Nie udało się sprawdzić {n} haseł w HIBP (brak połączenia?).",
                              "⚠️ Nie udało się sprawdzić {n} haseł w HIBP (brak połączenia?).")
        self.score_desc.configure(text=desc, justify="left")

        for w in self.issues_container.winfo_children():
            w.destroy()

        if not report.issues:
            card = ctk.CTkFrame(self.issues_container, fg_color=COLOR_CARD_DARK, corner_radius=10)
            card.pack(fill="x", pady=20, ipady=20)
            if report.total_entries == 0:
                ctk.CTkLabel(card, text=_("Sejf jest pusty – dodaj wpisy, aby przeprowadzić audyt."), font=FONT_SUBTITLE, text_color=COLOR_TEXT_MUTED).pack(pady=4)
                return
            ctk.CTkLabel(card, text="🎉", font=("Segoe UI", 36)).pack()
            ctk.CTkLabel(card, text=_("Brak zagrożeń w Twoim sejfie!"), font=FONT_SUBTITLE, text_color=COLOR_SUCCESS).pack(pady=4)
            ctk.CTkLabel(card, text=_("Wszystkie hasła są silne, unikalne i bezpieczne."), font=FONT_SMALL, text_color=COLOR_TEXT_MUTED).pack()
            return

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for issue in sorted(report.issues, key=lambda i: severity_order.get(i.severity, 9)):
            card = ctk.CTkFrame(self.issues_container, fg_color=COLOR_CARD_DARK, corner_radius=8)
            card.pack(fill="x", pady=4)

            row = layout_frame(card)
            row.pack(fill="x", padx=12, pady=10)

            col = layout_frame(row)
            col.pack(side="left", fill="x", expand=True)

            sev_color = COLOR_DANGER if issue.severity == "critical" else (COLOR_WARNING if issue.severity == "high" else COLOR_PRIMARY_LIGHT)
            ctk.CTkLabel(col, text=f"{issue.entry_title} — {issue.title}", font=FONT_BODY_BOLD, text_color=sev_color, anchor="w").pack(anchor="w")
            ctk.CTkLabel(col, text=issue.description, font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, anchor="w", wraplength=340, justify="left").pack(anchor="w")

            if self.on_fix_entry:
                ctk.CTkButton(
                    row,
                    text=_("Napraw 🔧"),
                    width=85,
                    height=28,
                    fg_color=COLOR_PANEL_DARK,
                    hover_color=COLOR_CARD_HOVER,
                    command=lambda eid=issue.entry_id: self.on_fix_entry(eid)
                ).pack(side="right", padx=(8, 0))


# =====================================================================
# 4. CENTRUM KOPII ZAPASOWYCH I CHMURY (BACKUP DRAWER VIEW)
# =====================================================================
class BackupDrawerView(ctk.CTkFrame):
    # (klucz, nagłówek, tekst przycisku logowania, podpowiedź folderu synchronizacji)
    CLOUDS = [
        ("onedrive", "☁️ Microsoft OneDrive", _("Zaloguj przez Microsoft"), _("np. C:\\Users\\...\\OneDrive")),
        ("google_drive", _("🟢 Dysk Google"), _("Zaloguj przez Google"), _("np. G:\\Mój dysk")),
        ("dropbox", "📦 Dropbox", _("Zaloguj przez Dropbox"), _("np. C:\\Users\\...\\Dropbox")),
    ]

    def __init__(self, parent, vault: Vault, vault_file_path: str, on_saved: Optional[Callable[[], None]] = None):
        super().__init__(parent, fg_color="transparent")
        self.pack(fill="both", expand=True)
        self.vault = vault
        self.vault_file_path = vault_file_path
        self.on_saved = on_saved
        self.mgr = BackupManager()
        self._action_buttons: List[ctk.CTkButton] = []
        self._cloud: Dict[str, Dict[str, Any]] = {}

        self._build_ui()
        self._load()

    # ------------------------------------------------------------- budowa UI
    def _dest(self) -> Dict[str, Any]:
        return self.vault.settings.setdefault("backup_destinations", {})

    def _action_button(self, parent, **kwargs) -> ctk.CTkButton:
        btn = ctk.CTkButton(parent, **kwargs)
        self._action_buttons.append(btn)
        return btn

    def _build_ui(self):
        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.pack(fill="both", expand=True)

        self.auto_b_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(scroll, text=_("Automatyczny backup przy każdym zapisie sejfu"), variable=self.auto_b_var, font=FONT_BODY_BOLD).pack(anchor="w", pady=(0, 15))

        # Kopia lokalna / USB
        c1 = ctk.CTkFrame(scroll, fg_color=COLOR_CARD_DARK, corner_radius=10)
        c1.pack(fill="x", pady=6, ipady=6)
        ctk.CTkLabel(c1, text=_("💾 Kopia lokalna / Nośnik USB"), font=FONT_SUBTITLE, text_color=COLOR_TEXT_PRIMARY).pack(anchor="w", padx=15, pady=(8, 2))
        r1 = layout_frame(c1)
        r1.pack(fill="x", padx=15, pady=4)
        self.local_dir_e = ctk.CTkEntry(r1, placeholder_text=_("Ścieżka do katalogu na kopie..."))
        self.local_dir_e.pack(side="left", expand=True, fill="x", padx=(0, 6))
        ctk.CTkButton(r1, text=_("Wybierz..."), width=80, fg_color=COLOR_PANEL_DARK, command=lambda: self._browse_into(self.local_dir_e, _("Katalog kopii lokalnej"))).pack(side="left")
        b1 = layout_frame(c1)
        b1.pack(fill="x", padx=15, pady=(4, 8))
        self._action_button(b1, text=_("Utwórz kopię teraz"), fg_color=COLOR_PRIMARY, command=lambda: self._run_backup("local")).pack(side="left")

        # Chmury z logowaniem w przeglądarce
        for key, title, login_text, folder_hint in self.CLOUDS:
            self._build_cloud_card(scroll, key, title, login_text, folder_hint)

        # WebDAV
        c2 = ctk.CTkFrame(scroll, fg_color=COLOR_CARD_DARK, corner_radius=10)
        c2.pack(fill="x", pady=6, ipady=6)
        ctk.CTkLabel(c2, text="🌐 WebDAV (Nextcloud / ownCloud / Synology)", font=FONT_SUBTITLE, text_color=COLOR_TEXT_PRIMARY).pack(anchor="w", padx=15, pady=(8, 2))
        self.webdav_url_e = ctk.CTkEntry(c2, placeholder_text="https://cloud.example.com/remote.php/dav/files/user/")
        self.webdav_url_e.pack(fill="x", padx=15, pady=4)
        w_auth = layout_frame(c2)
        w_auth.pack(fill="x", padx=15, pady=4)
        self.webdav_user_e = ctk.CTkEntry(w_auth, placeholder_text=_("Login / Użytkownik"))
        self.webdav_user_e.pack(side="left", expand=True, fill="x", padx=(0, 4))
        self.webdav_pwd_e = ctk.CTkEntry(w_auth, show="•", placeholder_text=_("Hasło / Token aplikacji"))
        self.webdav_pwd_e.pack(side="left", expand=True, fill="x", padx=(4, 0))
        b2 = layout_frame(c2)
        b2.pack(fill="x", padx=15, pady=(4, 8))
        self._action_button(b2, text=_("Testuj"), width=75, fg_color=COLOR_PANEL_DARK, command=lambda: self._test("webdav")).pack(side="left", padx=(0, 6))
        self._action_button(b2, text=_("Wyślij kopię na WebDAV"), fg_color=COLOR_PRIMARY, command=lambda: self._run_backup("webdav")).pack(side="left")

        # Konfiguracja aplikacji OAuth (Client ID)
        self._build_oauth_config_card(scroll)

        # Pasek akcji
        bar = ctk.CTkFrame(self, fg_color=COLOR_CARD_DARK, corner_radius=8, height=50)
        bar.pack(fill="x", side="bottom", pady=(5, 0))
        self._action_button(bar, text=_("🚀 Kopia na wszystkich platformach"), fg_color=COLOR_PRIMARY, command=self._run_all).pack(side="left", padx=10, pady=8)
        ctk.CTkButton(bar, text=_("Zapisz ustawienia"), fg_color=COLOR_SUCCESS, command=self._save_settings).pack(side="right", padx=10, pady=8)

    def _build_cloud_card(self, parent, key: str, title: str, login_text: str, folder_hint: str):
        card = ctk.CTkFrame(parent, fg_color=COLOR_CARD_DARK, corner_radius=10)
        card.pack(fill="x", pady=6, ipady=6)

        head = layout_frame(card)
        head.pack(fill="x", padx=15, pady=(8, 2))
        ctk.CTkLabel(head, text=title, font=FONT_SUBTITLE, text_color=COLOR_TEXT_PRIMARY).pack(side="left")
        status = ctk.CTkLabel(head, text="", font=FONT_SMALL, text_color=COLOR_TEXT_MUTED)
        status.pack(side="right")

        row = layout_frame(card)
        row.pack(fill="x", padx=15, pady=4)
        login_btn = ctk.CTkButton(row, text=login_text, fg_color=COLOR_PRIMARY, hover_color=COLOR_PRIMARY_HOVER, command=lambda: self._login_or_logout(key))
        login_btn.pack(side="left", padx=(0, 6))
        self._action_button(row, text=_("Testuj"), width=70, fg_color=COLOR_PANEL_DARK, command=lambda: self._test(key)).pack(side="left", padx=(0, 6))
        self._action_button(row, text=_("Wyślij kopię"), width=100, fg_color=COLOR_PANEL_DARK, command=lambda: self._run_backup(key)).pack(side="left")

        ctk.CTkLabel(card, text=_("…lub zamiast logowania: folder synchronizacji na tym komputerze"), font=FONT_SMALL, text_color=COLOR_TEXT_MUTED).pack(anchor="w", padx=15, pady=(4, 0))
        f_row = layout_frame(card)
        f_row.pack(fill="x", padx=15, pady=(2, 8))
        folder_e = ctk.CTkEntry(f_row, placeholder_text=folder_hint)
        folder_e.pack(side="left", expand=True, fill="x", padx=(0, 6))
        ctk.CTkButton(f_row, text=_("Wybierz..."), width=80, fg_color=COLOR_PANEL_DARK, command=lambda: self._browse_into(folder_e, f"Folder: {title}")).pack(side="left")

        self._cloud[key] = {"status": status, "login_btn": login_btn, "login_text": login_text, "folder_e": folder_e, "cancel": None}

    def _build_oauth_config_card(self, parent):
        card = ctk.CTkFrame(parent, fg_color=COLOR_CARD_DARK, corner_radius=10)
        card.pack(fill="x", pady=6, ipady=6)
        head = layout_frame(card)
        head.pack(fill="x", padx=15, pady=(8, 2))
        ctk.CTkLabel(head, text=_("⚙️ Konfiguracja logowania do chmury"), font=FONT_SUBTITLE, text_color=COLOR_TEXT_PRIMARY).pack(side="left")
        self._oauth_toggle_btn = ctk.CTkButton(head, text=_("Pokaż"), width=70, height=26, fg_color=COLOR_PANEL_DARK, command=self._toggle_oauth_config)
        self._oauth_toggle_btn.pack(side="right")
        ctk.CTkLabel(
            card,
            text=_("Jednorazowo: identyfikatory aplikacji zarejestrowanej u dostawcy (Client ID)."),
            font=FONT_SMALL, text_color=COLOR_TEXT_MUTED
        ).pack(anchor="w", padx=15)

        self._oauth_card = card
        self._oauth_body = None
        self._oauth_entries: Dict[str, Dict[str, ctk.CTkEntry]] = {}

    def _build_oauth_body(self):
        """Pola Client ID – budowane dopiero przy pierwszym rozwinięciu karty (rzadko używane, a kosztowne)."""
        self._oauth_body = layout_frame(self._oauth_card)
        fields = [
            ("onedrive", _("Microsoft – Identyfikator aplikacji (klienta)"), False),
            ("google_drive", "Google – Client ID", True),
            ("dropbox", "Dropbox – App key", False),
        ]
        for key, label, with_secret in fields:
            client = oauth.get_client_config(key)
            ctk.CTkLabel(self._oauth_body, text=label, font=FONT_BODY_BOLD).pack(anchor="w", pady=(8, 2))
            id_e = ctk.CTkEntry(self._oauth_body, placeholder_text="Client ID")
            if client.get("client_id"):
                id_e.insert(0, client["client_id"])
            id_e.pack(fill="x")
            entries = {"id": id_e}
            if with_secret:
                sec_e = ctk.CTkEntry(self._oauth_body, show="•", placeholder_text=_("Client Secret (Google wymaga go także dla aplikacji desktopowych)"))
                if client.get("client_secret"):
                    sec_e.insert(0, client["client_secret"])
                sec_e.pack(fill="x", pady=(4, 0))
                entries["secret"] = sec_e
            self._oauth_entries[key] = entries

        btns = layout_frame(self._oauth_body)
        btns.pack(fill="x", pady=(10, 4))
        ctk.CTkButton(btns, text=_("Zapisz identyfikatory"), fg_color=COLOR_SUCCESS, command=self._save_oauth_clients).pack(side="left")
        ctk.CTkButton(btns, text=_("❓ Jak uzyskać Client ID"), fg_color=COLOR_PANEL_DARK, command=self._show_oauth_help).pack(side="left", padx=6)

    def _toggle_oauth_config(self, force_open: bool = False):
        if self._oauth_body is None:
            self._build_oauth_body()
        if self._oauth_body.winfo_ismapped() and not force_open:
            self._oauth_body.pack_forget()
            self._oauth_toggle_btn.configure(text=_("Pokaż"))
        else:
            self._oauth_body.pack(fill="x", padx=15, pady=(0, 8))
            self._oauth_toggle_btn.configure(text=_("Ukryj"))

    def _save_oauth_clients(self):
        try:
            for key, entries in self._oauth_entries.items():
                oauth.save_client_config(key, entries["id"].get(), entries["secret"].get() if "secret" in entries else "")
        except OSError as e:
            messagebox.showerror(_("Błąd"), _("Nie udało się zapisać konfiguracji: {error}", error=e))
            return
        messagebox.showinfo(_("Zapisano"), _("Identyfikatory aplikacji zostały zapisane. Możesz się teraz zalogować."))

    def _show_oauth_help(self):
        messagebox.showinfo(
            _("Jak uzyskać Client ID"),
            _("Każdy dostawca wymaga jednorazowej rejestracji aplikacji (bezpłatnie):\n\n"
              "MICROSOFT (OneDrive)\n"
              "1. portal.azure.com → Rejestracje aplikacji → Nowa rejestracja\n"
              "2. Obsługiwane konta: dowolny katalog organizacyjny + osobiste konta Microsoft\n"
              "3. Identyfikator URI przekierowania: platforma 'Klient publiczny/natywny', adres http://localhost\n"
              "4. Skopiuj 'Identyfikator aplikacji (klienta)'\n\n"
              "GOOGLE (Dysk Google)\n"
              "1. console.cloud.google.com → nowy projekt → włącz 'Google Drive API'\n"
              "2. Ekran zgody OAuth: typ Zewnętrzny, dodaj swój e-mail jako użytkownika testowego\n"
              "3. Dane logowania → Utwórz identyfikator klienta OAuth → typ 'Aplikacja komputerowa'\n"
              "4. Skopiuj Client ID oraz Client Secret\n\n"
              "DROPBOX\n"
              "1. dropbox.com/developers/apps → Create app → Scoped access → App folder\n"
              "2. Permissions: files.content.write, files.content.read, account_info.read\n"
              "3. Settings → Redirect URIs: {redirect_uri}\n"
              "4. Skopiuj 'App key'", redirect_uri=oauth.redirect_uri('dropbox'))
        )

    # ------------------------------------------------------------- stan
    def _browse_into(self, entry: ctk.CTkEntry, title: str):
        d = filedialog.askdirectory(title=title)
        if d:
            entry.delete(0, "end")
            entry.insert(0, d)

    def _load(self):
        b_dest = self._dest()
        self.auto_b_var.set(self.vault.settings.get("auto_backup_on_save", True))

        def _fill(widget, value):
            # Wstawianie pustego tekstu kasuje placeholder CTkEntry
            if value:
                widget.insert(0, value)

        _fill(self.local_dir_e, (b_dest.get("local") or {}).get("folder_path", ""))
        wd = b_dest.get("webdav", {})
        _fill(self.webdav_url_e, wd.get("url", ""))
        _fill(self.webdav_user_e, wd.get("username", ""))
        _fill(self.webdav_pwd_e, wd.get("password", ""))
        for key, *_unused in self.CLOUDS:
            _fill(self._cloud[key]["folder_e"], (b_dest.get(key) or {}).get("folder_path", ""))
            self._refresh_cloud_status(key)

    def _refresh_cloud_status(self, key: str):
        w = self._cloud[key]
        if w["cancel"] is not None:
            return  # trwa logowanie
        cfg = self._dest().get(key) or {}
        if oauth.is_connected(cfg):
            account = (cfg.get("oauth") or {}).get("account") or _("połączono")
            w["status"].configure(text=f"✅ {account}", text_color=COLOR_SUCCESS)
            w["login_btn"].configure(text=_("Wyloguj"), fg_color=COLOR_PANEL_DARK, state="normal")
        else:
            w["status"].configure(text=_("Nie połączono"), text_color=COLOR_TEXT_MUTED)
            w["login_btn"].configure(text=w["login_text"], fg_color=COLOR_PRIMARY, state="normal")

    def _apply_settings(self) -> None:
        """Przepisuje wartości z formularza do ustawień sejfu i zapisuje sejf (bez komunikatu)."""
        self.vault.settings["auto_backup_on_save"] = self.auto_b_var.get()
        dest = self._dest()

        local = dest.setdefault("local", {})
        local["folder_path"] = self.local_dir_e.get().strip()
        local.setdefault("max_backups", 15)

        webdav = dest.setdefault("webdav", {})
        webdav.update({
            "enabled": bool(self.webdav_url_e.get().strip()),
            "url": self.webdav_url_e.get().strip(),
            "username": self.webdav_user_e.get().strip(),
            "password": self.webdav_pwd_e.get().strip()
        })
        webdav.setdefault("remote_folder", "KeyStead-Backups")

        for key, *_unused in self.CLOUDS:
            cfg = dest.setdefault(key, {})
            cfg["folder_path"] = self._cloud[key]["folder_e"].get().strip()
            cfg["enabled"] = bool(cfg["folder_path"] or oauth.is_connected(cfg))

        if self.on_saved:
            self.on_saved()

    def _save_settings(self):
        self._apply_settings()
        messagebox.showinfo(_("Zapisano"), _("Ustawienia kopii zapasowych zostały pomyślnie zapisane."))

    def _set_busy(self, busy: bool):
        for btn in self._action_buttons:
            if btn.winfo_exists():
                btn.configure(state="disabled" if busy else "normal")

    def _persist_runtime(self, key: str, cfg: Dict[str, Any], original: Optional[Dict[str, Any]] = None):
        """Zapisuje w sejfie tokeny odświeżone podczas operacji w tle."""
        if merge_runtime_state(self._dest(), {key: cfg}, {key: original} if original is not None else None) \
                and self.on_saved:
            self.on_saved()

    # ------------------------------------------------------------- logowanie
    def _login_or_logout(self, key: str):
        w = self._cloud[key]
        if w["cancel"] is not None:
            w["cancel"].set()  # przycisk działa jako _("Anuluj") podczas logowania
            return

        cfg = self._dest().setdefault(key, {})
        if oauth.is_connected(cfg):
            if messagebox.askyesno(_("Wylogowanie"), _("Odłączyć to konto? Automatyczne kopie do tej chmury zostaną wstrzymane.")):
                old_tokens = dict(cfg.get("oauth") or {})
                # Unieważnij token także po stronie dostawcy (w tle, bez blokowania UI)
                threading.Thread(target=oauth.revoke, args=(key, old_tokens), daemon=True).start()
                if key == "onedrive":
                    messagebox.showinfo(
                        _("Wylogowano"),
                        _("Microsoft nie pozwala aplikacjom unieważnić dostępu automatycznie.\n"
                          "Aby całkowicie odebrać dostęp: account.microsoft.com → Prywatność → Aplikacje i usługi.")
                    )
                cfg["oauth"] = {}
                cfg.pop("api_token", None)
                cfg.pop("folder_id", None)
                cfg["enabled"] = bool(cfg.get("folder_path"))
                if self.on_saved:
                    self.on_saved()
                self._refresh_cloud_status(key)
            return

        if not oauth.is_client_configured(key):
            self._toggle_oauth_config(force_open=True)
            messagebox.showwarning(
                _("Brak identyfikatora aplikacji"),
                _("Aby logować się w przeglądarce, wpisz najpierw Client ID w sekcji "
                  "'Konfiguracja logowania do chmury' (na dole panelu) i kliknij 'Zapisz identyfikatory'.\n\n"
                  "Instrukcję znajdziesz pod przyciskiem '❓ Jak uzyskać Client ID'.")
            )
            return

        cancel = threading.Event()
        w["cancel"] = cancel
        w["login_btn"].configure(text=_("Anuluj logowanie"), fg_color=COLOR_DANGER)
        w["status"].configure(text=_("⏳ Dokończ logowanie w przeglądarce..."), text_color=COLOR_WARNING)
        provider = self.mgr.get_provider(key)

        def _work():
            tokens = oauth.login(key, cancel_event=cancel)
            try:
                tokens["account"] = provider.fetch_account_name(tokens["access_token"])
            except Exception:
                tokens["account"] = ""
            return tokens

        def _done(res):
            w["cancel"] = None
            if isinstance(res, Exception):
                self._refresh_cloud_status(key)
                if not cancel.is_set():
                    messagebox.showerror(_("Logowanie nieudane"), str(res))
                return
            cfg = self._dest().setdefault(key, {})
            cfg["oauth"] = res
            cfg.pop("folder_id", None)
            cfg["enabled"] = True
            if self.on_saved:
                self.on_saved()
            self._refresh_cloud_status(key)
            messagebox.showinfo(_("Połączono"), _("Zalogowano: {account}.\nKopie będą wysyłane do tej chmury.",
                                                   account=res.get('account') or _("konto połączone")))

        run_in_background(self, _work, _done)

    # ------------------------------------------------------------- operacje
    def _test(self, key: str):
        self._apply_settings()
        cfg = copy.deepcopy(self._dest().get(key, {}))
        original = copy.deepcopy(cfg)
        if key == "webdav" and not cfg.get("url"):
            messagebox.showerror(_("Brak konfiguracji"), _("Podaj adres serwera WebDAV."))
            return
        self._set_busy(True)

        def _done(res):
            self._set_busy(False)
            if isinstance(res, Exception):
                messagebox.showerror(_("Test połączenia"), str(res))
                return
            self._persist_runtime(key, cfg, original)
            ok, msg = res
            (messagebox.showinfo if ok else messagebox.showerror)(_("Test połączenia"), msg)

        run_in_background(self, lambda: self.mgr.test_provider(key, cfg), _done)

    def _run_backup(self, p_key: str):
        self._apply_settings()
        cfg = copy.deepcopy(self._dest().get(p_key, {}))
        original = copy.deepcopy(cfg)
        if not self.mgr.get_provider(p_key).is_configured(cfg):
            messagebox.showerror(_("Brak konfiguracji"), _("Zaloguj się lub uzupełnij najpierw dane tej lokalizacji kopii."))
            return
        vault_path = self.vault_file_path
        self._set_busy(True)

        def _work():
            with vault_snapshot(vault_path) as snapshot:
                return self.mgr.backup_to_provider(p_key, snapshot, cfg)

        def _done(status):
            self._set_busy(False)
            if isinstance(status, Exception):
                messagebox.showerror(_("Błąd"), _("Nie udało się utworzyć kopii:\n{error}", error=status))
                return
            self._persist_runtime(p_key, cfg, original)
            if status.success:
                messagebox.showinfo(_("Kopia utworzona"), _("Pomyślnie utworzono kopię:\n{path}", path=status.destination_path))
            else:
                messagebox.showerror(_("Błąd"), _("Nie udało się utworzyć kopii:\n{error}", error=status.error_message))

        run_in_background(self, _work, _done)

    def _run_all(self):
        self._apply_settings()
        dest = copy.deepcopy(self._dest())
        original = copy.deepcopy(dest)
        vault_path = self.vault_file_path
        self._set_busy(True)

        def _work():
            with vault_snapshot(vault_path) as snapshot:
                return self.mgr.backup_to_all_configured(snapshot, dest)

        def _done(res):
            self._set_busy(False)
            if isinstance(res, Exception):
                messagebox.showerror(_("Kopie zapasowe"), _("Błąd: {error}", error=res))
                return
            if merge_runtime_state(self._dest(), dest, original) and self.on_saved:
                self.on_saved()
            if not res:
                messagebox.showwarning(_("Kopie zapasowe"), _("Nie skonfigurowano żadnej lokalizacji kopii zapasowych."))
                return
            ok_cnt = sum(1 for r in res if r.success)
            lines = [f"{'✅' if r.success else '❌'} {r.provider_name}" + ("" if r.success else f": {r.error_message}") for r in res]
            messagebox.showinfo(_("Kopie zapasowe"), _n(len(res), "Utworzono kopie na {ok} z {n} platformy.", "Utworzono kopie na {ok} z {n} platform.",
                                                       "Utworzono kopie na {ok} z {n} platform.", ok=ok_cnt)
                                + "\n\n" + "\n".join(lines))

        run_in_background(self, _work, _done)


# =====================================================================
# 5. KREATOR IMPORTU (IMPORT DRAWER VIEW)
# =====================================================================
class ImportDrawerView(ctk.CTkFrame):
    def __init__(self, parent, vault: Vault, on_done: Optional[Callable[[int], None]] = None):
        super().__init__(parent, fg_color="transparent")
        self.pack(fill="both", expand=True)
        self.vault = vault
        self.on_done = on_done
        self._analysis_result = None

        self._build_ui()

    def _build_ui(self):
        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.pack(fill="both", expand=True)

        ctk.CTkLabel(scroll, text=_("Wybierz źródłowy menedżer haseł:"), font=FONT_BODY_BOLD).pack(anchor="w", pady=(0, 4))
        self._auto_label = _("(Auto-detekcja) Wykryj automatycznie")
        imps = [self._auto_label] + [i.name for i in get_available_importers()]
        self.imp_combo = ctk.CTkComboBox(scroll, values=imps)
        self.imp_combo.set(imps[0])
        self.imp_combo.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(scroll, text=_("Plik z danymi haseł:"), font=FONT_BODY_BOLD).pack(anchor="w", pady=(0, 4))
        fb = layout_frame(scroll)
        fb.pack(fill="x", pady=(0, 10))
        self.file_e = ctk.CTkEntry(fb, placeholder_text=_("Wskaż plik..."))
        self.file_e.pack(side="left", expand=True, fill="x", padx=(0, 6))
        ctk.CTkButton(fb, text=_("Wybierz..."), width=80, fg_color=COLOR_CARD_DARK, command=self._browse).pack(side="left")

        # Hasło / plik klucza do KeePass
        self.pwd_e = ctk.CTkEntry(scroll, show="•", placeholder_text=_("Hasło do bazy (tylko KeePass .kdbx)..."))
        self.pwd_e.pack(fill="x", pady=(0, 6))

        kb = layout_frame(scroll)
        kb.pack(fill="x", pady=(0, 12))
        self.keyfile_e = ctk.CTkEntry(kb, placeholder_text=_("Opcjonalny plik klucza KeePass..."))
        self.keyfile_e.pack(side="left", expand=True, fill="x", padx=(0, 6))
        ctk.CTkButton(kb, text=_("Klucz..."), width=80, fg_color=COLOR_CARD_DARK, command=self._browse_keyfile).pack(side="left")

        # Strategia duplikatów
        ctk.CTkLabel(scroll, text=_("Gdy wpis już istnieje w sejfie (ten sam tytuł, login i URL):"), font=FONT_BODY_BOLD).pack(anchor="w", pady=(0, 4))
        self._strategies = {
            _("Pomiń istniejące wpisy"): STRATEGY_SKIP,
            _("Zaktualizuj istniejące wpisy"): STRATEGY_UPDATE,
            _("Dodaj wszystkie jako nowe"): STRATEGY_ADD_ALL
        }
        self.strategy_combo = ctk.CTkComboBox(scroll, values=list(self._strategies.keys()), state="readonly")
        self.strategy_combo.set(_("Pomiń istniejące wpisy"))
        self.strategy_combo.pack(fill="x", pady=(0, 12))

        # Analizuj
        self.analyze_btn = ctk.CTkButton(scroll, text=_("🔍 Analizuj plik"), fg_color=COLOR_PRIMARY, command=self._analyze)
        self.analyze_btn.pack(fill="x", pady=(0, 12))

        # Podgląd
        self.preview_box = ctk.CTkFrame(scroll, fg_color=COLOR_CARD_DARK, corner_radius=8)
        self.preview_box.pack(fill="both", expand=True, pady=(0, 12), ipady=6)

        self.preview_lbl = ctk.CTkLabel(self.preview_box, text=_("Wybierz plik i kliknij 'Analizuj plik'."), font=FONT_SMALL, text_color=COLOR_TEXT_MUTED)
        self.preview_lbl.pack(padx=10, pady=8)

        # Przycisk importu
        self.import_btn = ctk.CTkButton(scroll, text=_("📥 Zaimportuj znalezione wpisy"), fg_color=COLOR_SUCCESS, state="disabled", command=self._execute_import)
        self.import_btn.pack(fill="x", pady=(5, 10))

        # Porządkowanie wpisów już zapisanych w sejfie (np. po wcześniejszym imporcie)
        changes = untidy_entries(self.vault)
        if changes:
            card = ctk.CTkFrame(scroll, fg_color=COLOR_CARD_DARK, corner_radius=8)
            card.pack(fill="x", pady=(6, 10), ipady=6)
            ctk.CTkLabel(card, text=_("🧹 Porządkowanie wpisów"), font=FONT_BODY_BOLD).pack(anchor="w", padx=12, pady=(8, 2))
            ctk.CTkLabel(card, text=(_n(len(changes), "{n} wpis ma w loginie nazwę strony (np. „fotka.com, jan”) albo tytuł „--”. ",
                                        "{n} wpisy mają w loginie nazwę strony (np. „fotka.com, jan”) albo tytuł „--”. ",
                                        "{n} wpisów ma w loginie nazwę strony (np. „fotka.com, jan”) albo tytuł „--”. ")
                                     + _("Login zostanie skrócony do samej nazwy użytkownika, a tytuł zastąpiony adresem strony.")),
                         font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, wraplength=420, justify="left").pack(anchor="w", padx=12)
            ctk.CTkButton(card, text=_n(len(changes), "Popraw {n} wpis", "Popraw {n} wpisy", "Popraw {n} wpisów"), fg_color=COLOR_PRIMARY,
                          command=self._tidy_existing).pack(anchor="w", padx=12, pady=(8, 4))

    def _browse(self):
        p = filedialog.askopenfilename(
            title=_("Wybierz plik haseł"),
            filetypes=[(_("Obsługiwane bazy"), "*.json;*.csv;*.kdbx;*.1pux;*.zip;*.xml"), (_("Wszystkie"), "*.*")]
        )
        if p:
            self.file_e.delete(0, "end")
            self.file_e.insert(0, p)
            imp = detect_importer(p)
            if imp:
                self.imp_combo.set(imp.name)

    def _browse_keyfile(self):
        p = filedialog.askopenfilename(title=_("Wybierz plik klucza KeePass"))
        if p:
            self.keyfile_e.delete(0, "end")
            self.keyfile_e.insert(0, p)

    def _analyze(self):
        f = self.file_e.get().strip()
        if not f or not os.path.exists(f):
            messagebox.showerror(_("Błąd"), _("Plik nie istnieje."))
            return

        choice = self.imp_combo.get()
        name = None if choice == self._auto_label else choice
        pwd = self.pwd_e.get() or None
        keyfile = self.keyfile_e.get().strip() or None
        if keyfile and not os.path.isfile(keyfile):
            messagebox.showerror(_("Błąd"), _("Wskazany plik klucza nie istnieje."))
            return

        self.analyze_btn.configure(text=_("Przetwarzanie..."), state="disabled")
        self.import_btn.configure(state="disabled")

        def _ui(res):
            self.analyze_btn.configure(text=_("🔍 Analizuj plik"), state="normal")
            if isinstance(res, Exception):
                self._analysis_result = None
                self.preview_lbl.configure(text=_("Błąd:\n{error}", error=res), text_color=COLOR_DANGER)
                return
            self._analysis_result = res
            if res.items:
                cats = ", ".join(_(c) for c in res.categories_found[:6]) + ("..." if len(res.categories_found) > 6 else "")
                text = _("Sukces ({format})\nZnaleziono wpisów: {count}\nKategorie: {categories}",
                         format=res.source_format, count=len(res.items), categories=cats)
                if res.errors:
                    text += "\n\n" + _("Ostrzeżenia:") + "\n" + "\n".join(res.errors[:5])
                self.preview_lbl.configure(text=text, text_color=COLOR_SUCCESS, justify="left", wraplength=420)
                self.import_btn.configure(state="normal")
            else:
                err = "\n".join(res.errors) if res.errors else _("Nie odnaleziono wpisów.")
                self.preview_lbl.configure(text=_("Błąd:\n{error}", error=err), text_color=COLOR_DANGER, justify="left", wraplength=420)

        run_in_background(self, lambda: run_import(f, importer_name=name, password=pwd, keyfile_path=keyfile), _ui)

    def _tidy_existing(self):
        changes = untidy_entries(self.vault)
        if not changes:
            return
        sample = "\n".join(f"• {e.title} / {e.username}  →  {t} / {u}" for e, t, u in changes[:6])
        more = "\n" + _n(len(changes) - 6, "… i {n} inny", "… i {n} inne", "… i {n} innych") if len(changes) > 6 else ""
        question = _n(len(changes), "Poprawić {n} wpis?", "Poprawić {n} wpisy?", "Poprawić {n} wpisów?")
        if not messagebox.askyesno(_("Porządkowanie wpisów"), f"{question}\n\n{sample}{more}"):
            return
        count = tidy_vault(self.vault)
        messagebox.showinfo(_("Porządkowanie wpisów"), _("Poprawiono wpisów: {count}", count=count))
        if self.on_done:
            self.on_done(count)

    def _execute_import(self):
        if not self._analysis_result or not self._analysis_result.items:
            return

        strategy = self._strategies.get(self.strategy_combo.get(), STRATEGY_SKIP)
        try:
            stats = apply_import(self.vault, self._analysis_result.items, strategy)
        except Exception as e:
            messagebox.showerror(_("Import przerwany"), _("Nie udało się zaimportować danych: {error}", error=e))
            return
        self._analysis_result = None
        self.import_btn.configure(state="disabled")

        messagebox.showinfo(
            _("Import zakończony"),
            _("Dodano nowych wpisów: {added}\nZaktualizowano: {updated}\nPominięto duplikatów: {skipped}",
              added=stats['added'], updated=stats['updated'], skipped=stats['skipped'])
        )

        # Eksporty CSV/JSON/XML/1PUX zawierają hasła otwartym tekstem – nie zostawiaj ich na dysku
        source = self.file_e.get().strip()
        if source and os.path.isfile(source) and is_plaintext_export(source):
            if messagebox.askyesno(
                _("Usunąć plik eksportu?"),
                _("Plik {name} zawiera wszystkie hasła NIEZASZYFROWANE.\n\n"
                  "Zalecamy jego bezpieczne usunięcie (nadpisanie i skasowanie). Usunąć teraz?",
                  name=os.path.basename(source)),
                icon="warning"
            ):
                try:
                    secure_delete_file(source)
                    self.file_e.delete(0, "end")
                except OSError as e:
                    messagebox.showerror(_("Błąd"), _("Nie udało się usunąć pliku: {error}\nUsuń go ręcznie i opróżnij Kosz systemu.", error=e))

        if self.on_done:
            self.on_done(stats["added"] + stats["updated"])


# =====================================================================
# 6. USTAWIENIA SEJFU (SETTINGS DRAWER VIEW)
# =====================================================================
class SettingsDrawerView(ctk.CTkFrame):
    def __init__(
        self,
        parent,
        vault: Vault,
        current_password: str,
        vault_file_path: str,
        keyfile_bytes: Optional[bytes] = None,
        on_pwd_changed: Optional[Callable[[str], None]] = None,
        on_saved: Optional[Callable[[], None]] = None,
        password_saver: Optional[Callable[[str], None]] = None,
        policy: Optional[Dict[str, Any]] = None,
        security_options: Optional[Dict[str, Any]] = None,
        on_open_about: Optional[Callable[[], None]] = None,
        on_open_plugins: Optional[Callable[[], None]] = None
    ):
        super().__init__(parent, fg_color="transparent")
        self.pack(fill="both", expand=True)
        self.on_open_about = on_open_about
        self.on_open_plugins = on_open_plugins
        self.security = security_options or {}
        self.vault = vault
        self.current_password = current_password
        self.vault_file_path = vault_file_path
        self.keyfile_bytes = keyfile_bytes
        self.on_pwd_changed = on_pwd_changed
        self.on_saved = on_saved
        # Tryb serwerowy podaje własny sposób zapisu (przez kolejkę synchronizacji)
        self.password_saver = password_saver
        self.policy = policy or {}
        # Podpisy z ui/policy.py tłumaczone raz – ta sama lista służy do wyświetlania i do odczytu wartości
        self._lock_choices = [(_(label), minutes) for label, minutes in lock_choices(self.policy)]
        self._clip_choices = [(_(label), seconds) for label, seconds in clipboard_choices(self.policy)]

        self._build_ui()

    def _build_ui(self):
        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.pack(fill="both", expand=True)

        # Język interfejsu (ustawienie tego komputera, nie sejfu)
        lang = ctk.CTkFrame(scroll, fg_color=COLOR_CARD_DARK, corner_radius=10)
        lang.pack(fill="x", pady=6, ipady=6)
        row = layout_frame(lang)
        row.pack(fill="x", padx=15, pady=8)
        ctk.CTkLabel(row, text=_("🌐 Język / Language"), font=FONT_SUBTITLE, text_color=COLOR_TEXT_PRIMARY).pack(side="left")
        self.lang_menu = LanguageMenu(row, on_change=self._language_changed, width=140, height=28)
        self.lang_menu.pack(side="right")

        # Blokada i schowek
        c1 = ctk.CTkFrame(scroll, fg_color=COLOR_CARD_DARK, corner_radius=10)
        c1.pack(fill="x", pady=6, ipady=6)
        ctk.CTkLabel(c1, text=_("⏱️ Blokada i Schowek"), font=FONT_SUBTITLE, text_color=COLOR_TEXT_PRIMARY).pack(anchor="w", padx=15, pady=(8, 4))

        if self.policy:
            ctk.CTkLabel(c1, text=_("🏢 Część opcji ogranicza polityka bezpieczeństwa Twojej firmy."), font=FONT_SMALL,
                         text_color=COLOR_TEXT_ACCENT).pack(anchor="w", padx=15, pady=(0, 6))

        ctk.CTkLabel(c1, text=_("Automatyczna blokada sejfu przy bezczynności:")).pack(anchor="w", padx=15)
        self.lock_cb = ctk.CTkComboBox(c1, values=[label for label, _unused in self._lock_choices], state="readonly")
        cur_min = effective_auto_lock(int(self.vault.settings.get("auto_lock_minutes", 5) or 0), self.policy)
        self.lock_cb.set(next((l for l, m in self._lock_choices if m == cur_min), self._lock_choices[0][0]))
        self.lock_cb.pack(anchor="w", padx=15, pady=(2, 8))

        ctk.CTkLabel(c1, text=_("Czas czyszczenia schowka:")).pack(anchor="w", padx=15)
        self.clip_cb = ctk.CTkComboBox(c1, values=[label for label, _unused in self._clip_choices], state="readonly")
        cur_sec = effective_clipboard(int(self.vault.settings.get("clipboard_clear_seconds", 30) or 0), self.policy)
        self.clip_cb.set(next((l for l, s in self._clip_choices if s == cur_sec), self._clip_choices[0][0]))
        self.clip_cb.pack(anchor="w", padx=15, pady=(2, 10))

        self.session_lock_sw = ctk.CTkSwitch(c1, text=_("Blokuj sejf razem z komputerem (Win+L, wylogowanie)"))
        if self.vault.settings.get("lock_on_session_lock", True):
            self.session_lock_sw.select()
        self.session_lock_sw.pack(anchor="w", padx=15, pady=(0, 8))

        self.icons_sw = ctk.CTkSwitch(c1, text=_("Pokazuj ikony stron przy wpisach"))
        if self.vault.settings.get("site_icons", True):
            self.icons_sw.select()
        icons_blocked = (self.policy or {}).get("allow_site_icons", True) is False
        if icons_blocked:
            self.icons_sw.configure(state="disabled")
        self.icons_sw.pack(anchor="w", padx=15, pady=(0, 2))
        ctk.CTkLabel(c1, text=(_("Wyłączone przez politykę firmy.") if icons_blocked else
                               _("Ikony są pobierane bezpośrednio ze stron (jak w przeglądarce) – bez pośredników, "
                                 "którzy poznaliby listę Twoich kont. Adresy z sieci lokalnej są pomijane.")),
                     font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, wraplength=440, justify="left").pack(anchor="w", padx=15, pady=(0, 10))

        if self.on_open_plugins:
            self._build_plugins_card(scroll)

        if self.security:
            self._build_security_card(scroll)
        if self.security.get("recovery"):
            self._build_recovery_card(scroll)

        # Zmiana hasła głównego
        c2 = ctk.CTkFrame(scroll, fg_color=COLOR_CARD_DARK, corner_radius=10)
        c2.pack(fill="x", pady=6, ipady=6)
        ctk.CTkLabel(c2, text=_("🔑 Zmiana Hasła Głównego"), font=FONT_SUBTITLE, text_color=COLOR_TEXT_PRIMARY).pack(anchor="w", padx=15, pady=(8, 4))

        self.cur_p = ctk.CTkEntry(c2, show="•", placeholder_text=_("Aktualne hasło..."))
        self.cur_p.pack(fill="x", padx=15, pady=3)
        self.new_p = ctk.CTkEntry(c2, show="•", placeholder_text=_("Nowe hasło (min. 8 znaków)..."))
        self.new_p.pack(fill="x", padx=15, pady=3)
        self.cnf_p = ctk.CTkEntry(c2, show="•", placeholder_text=_("Potwierdź nowe hasło..."))
        self.cnf_p.pack(fill="x", padx=15, pady=3)

        ctk.CTkButton(c2, text=_("Zmień hasło główne"), fg_color=COLOR_PRIMARY, command=self._change_pwd).pack(anchor="w", padx=15, pady=(6, 8))

        # O programie i autorze
        if self.on_open_about:
            c3 = ctk.CTkFrame(scroll, fg_color=COLOR_CARD_DARK, corner_radius=10)
            c3.pack(fill="x", pady=6, ipady=6)
            row = layout_frame(c3)
            row.pack(fill="x", padx=15, pady=8)
            ctk.CTkLabel(row, text=f"ℹ️ KeyStead Manager {APP_VERSION}", font=FONT_SUBTITLE,
                         text_color=COLOR_TEXT_PRIMARY).pack(side="left")
            ctk.CTkButton(row, text=_("O programie i autorze"), width=160, fg_color=COLOR_PANEL_DARK,
                          command=self.on_open_about).pack(side="right")

        # Zapisz
        bar = ctk.CTkFrame(self, fg_color=COLOR_CARD_DARK, corner_radius=8, height=50)
        bar.pack(fill="x", side="bottom", pady=(5, 0))
        ctk.CTkButton(bar, text=_("Zapisz ustawienia"), fg_color=COLOR_SUCCESS, command=self._save).pack(side="right", padx=10, pady=8)

    def _language_changed(self, code: str):
        if messagebox.askyesno("KeyStead Manager", _("Aby zmienić język, program uruchomi się ponownie, a sejf zostanie "
                                                     "zablokowany. Kontynuować?"), parent=self.winfo_toplevel()):
            self.winfo_toplevel().restart_app()
        else:
            save_language(current_language())  # wybór cofnięty – zostaje dotychczasowy język
            self.lang_menu.set(LANGUAGES[current_language()])

    def _build_plugins_card(self, parent):
        from core.plugins import PLUGINS, enabled_set
        card = ctk.CTkFrame(parent, fg_color=COLOR_CARD_DARK, corner_radius=10)
        card.pack(fill="x", pady=6, ipady=6)
        row = layout_frame(card)
        row.pack(fill="x", padx=15, pady=(8, 2))
        ctk.CTkLabel(row, text=_("🧩 Wtyczki"), font=FONT_SUBTITLE, text_color=COLOR_TEXT_PRIMARY).pack(side="left")
        ctk.CTkButton(row, text=_("Zarządzaj wtyczkami"), width=160, fg_color=COLOR_PRIMARY,
                      command=self.on_open_plugins).pack(side="right")
        on = len(enabled_set(self.vault.settings, self.policy))
        ready = sum(1 for p in PLUGINS if p.ready)
        ctk.CTkLabel(card, text=_("Włączone: {on} z {total}. Dodatkowe funkcje: przycisk „Połącz” (RDP, SSH, WinBox), "
                                  "klucze SSH, YubiKey, data ważności hasła, kody QR, szablony wpisów i inne.",
                                  on=on, total=ready),
                     font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, wraplength=440, justify="left"
                     ).pack(anchor="w", padx=15, pady=(0, 8))

    def _build_security_card(self, parent):
        """Windows Hello i globalne skróty klawiszowe (ustawienia tego komputera, nie sejfu)."""
        sec = self.security
        card = ctk.CTkFrame(parent, fg_color=COLOR_CARD_DARK, corner_radius=10)
        card.pack(fill="x", pady=6, ipady=6)
        ctk.CTkLabel(card, text=_("🔐 Windows Hello i skróty"), font=FONT_SUBTITLE,
                     text_color=COLOR_TEXT_PRIMARY).pack(anchor="w", padx=15, pady=(8, 4))

        self.hello_sw = ctk.CTkSwitch(card, text=_("Odblokowuj odciskiem palca, twarzą lub PIN-em Windows"),
                                      command=self._toggle_hello)
        if sec.get("hello_enabled"):
            self.hello_sw.select()
        self.hello_sw.pack(anchor="w", padx=15, pady=(2, 2))
        if not sec.get("hello_available"):
            hint, state = _("Windows Hello nie jest skonfigurowane na tym komputerze (Ustawienia Windows → Konta → "
                            "Opcje logowania → PIN lub odcisk palca)."), "disabled"
        elif not sec.get("hello_allowed"):
            hint, state = _("Wyłączone przez politykę bezpieczeństwa Twojej firmy."), "disabled"
        else:
            hint, state = _n(sec.get('hello_days', 14),
                             "Hasło główne będzie potrzebne raz na {n} dzień. Dane szybkiego "
                             "odblokowania chroni moduł bezpieczeństwa (TPM) tego komputera.",
                             "Hasło główne będzie potrzebne raz na {n} dni. Dane szybkiego "
                             "odblokowania chroni moduł bezpieczeństwa (TPM) tego komputera.",
                             "Hasło główne będzie potrzebne raz na {n} dni. Dane szybkiego "
                             "odblokowania chroni moduł bezpieczeństwa (TPM) tego komputera."), "normal"
        self.hello_sw.configure(state=state)
        ctk.CTkLabel(card, text=hint, font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, wraplength=440,
                     justify="left").pack(anchor="w", padx=15, pady=(0, 10))

        hk = sec.get("hotkeys") or {}
        self.hotkeys_sw = ctk.CTkSwitch(card, text=_("Globalne skróty klawiszowe (działają w każdym programie)"))
        if hk.get("enabled", True):
            self.hotkeys_sw.select()
        self.hotkeys_sw.pack(anchor="w", padx=15, pady=(2, 6))
        registered = sec.get("hotkeys_registered") or {}
        self._hotkey_entries = {}
        for key, label in (("search", _("Szybkie wyszukiwanie (Enter kopiuje hasło)")),
                           ("autotype", _("Autotype – wpisz login i hasło w aktywne okno"))):
            row = layout_frame(card)
            row.pack(fill="x", padx=15, pady=2)
            entry = ctk.CTkEntry(row, width=170)
            entry.insert(0, hk.get(key, ""))
            entry.pack(side="left")
            note = label
            if hk.get("enabled", True) and key in registered and not registered[key]:
                note += _("  ⚠️ skrót zajęty przez inny program")
            if key == "autotype" and not sec.get("autotype_allowed", True):
                note += _("  (wyłączone przez politykę firmy)")
            ctk.CTkLabel(row, text=note, font=FONT_SMALL, text_color=COLOR_TEXT_MUTED).pack(side="left", padx=8)
            self._hotkey_entries[key] = entry
        ctk.CTkLabel(card, text=_("Autotype dopasowuje wpis do tytułu okna (nazwa wpisu lub domena strony), a w przeglądarce "
                                  "do prawdziwego adresu strony – na stronie z innym adresem niczego nie wpisze bez "
                                  "potwierdzenia. Dodatkowe strony logowania wpisu podasz w polu „Autotype adresy”. "
                                  "Własną kolejność wpisywania ustawisz w polu niestandardowym „Sekwencja autotype”, "
                                  "np. {USERNAME}{TAB}{PASSWORD}{TAB}{TOTP}{ENTER}."),
                     font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, wraplength=440, justify="left"
                     ).pack(anchor="w", padx=15, pady=(6, 8))

    def _build_recovery_card(self, parent):
        rec = self.security["recovery"]
        card = ctk.CTkFrame(parent, fg_color=COLOR_CARD_DARK, corner_radius=10)
        card.pack(fill="x", pady=6, ipady=6)
        ctk.CTkLabel(card, text=_("🔑 Odzyskiwanie dostępu"), font=FONT_SUBTITLE,
                     text_color=COLOR_TEXT_PRIMARY).pack(anchor="w", padx=15, pady=(8, 4))
        status = _("✅ ustawiony") if rec.get("has_code") else _("brak")
        ctk.CTkLabel(card, text=_("Osobisty kod odzyskiwania: {status}", status=status), font=FONT_BODY).pack(anchor="w", padx=15)
        ctk.CTkLabel(card, text=_("Kod pozwala ustawić nowe hasło główne, gdy je zapomnisz. Pokazywany jest tylko raz – "
                                  "zapisz go poza komputerem. Utworzenie nowego kodu unieważnia poprzedni."),
                     font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, wraplength=440, justify="left").pack(anchor="w", padx=15)
        row = layout_frame(card)
        row.pack(fill="x", padx=15, pady=8)
        ctk.CTkButton(row, text=_("Utwórz nowy kod") if rec.get("has_code") else _("Utwórz kod odzyskiwania"),
                      fg_color=COLOR_PRIMARY, command=rec["on_create"]).pack(side="left")
        if rec.get("has_code"):
            ctk.CTkButton(row, text=_("Usuń kod"), fg_color=COLOR_PANEL_DARK, command=rec["on_remove"]).pack(side="left", padx=8)
        if rec.get("org_key_id"):
            org = _("🏢 Odzyskiwanie przez firmę: włączone (odcisk klucza {fingerprint})", fingerprint=rec['org_key_id'])
        elif rec.get("org_policy"):
            org = _("🏢 Odzyskiwanie przez firmę: zostanie włączone przy najbliższej synchronizacji")
        else:
            org = _("🏢 Odzyskiwanie przez firmę: wyłączone")
        ctk.CTkLabel(card, text=org, font=FONT_SMALL, text_color=COLOR_TEXT_MUTED).pack(anchor="w", padx=15)
        ctk.CTkButton(card, text=_("Narzędzia administratora firmy…"), height=26, font=FONT_SMALL, fg_color="transparent",
                      hover_color=COLOR_PANEL_DARK, command=rec["on_admin_tools"]).pack(anchor="w", padx=10, pady=(4, 8))

    def _toggle_hello(self):
        handler = self.security.get("on_hello_toggle")
        if handler:
            handler(bool(self.hello_sw.get()))

    def _save(self):
        self.vault.settings["auto_lock_minutes"] = dict(self._lock_choices).get(self.lock_cb.get(), self._lock_choices[0][1])
        self.vault.settings["clipboard_clear_seconds"] = dict(self._clip_choices).get(self.clip_cb.get(), self._clip_choices[0][1])
        self.vault.settings["lock_on_session_lock"] = bool(self.session_lock_sw.get())
        icons_changed = bool(self.icons_sw.get()) != bool(self.vault.settings.get("site_icons", True))
        self.vault.settings["site_icons"] = bool(self.icons_sw.get())
        if self.security.get("on_hotkeys_save"):
            prefs = {"enabled": bool(self.hotkeys_sw.get()),
                     **{k: e.get().strip() for k, e in self._hotkey_entries.items()}}
            try:
                registered = self.security["on_hotkeys_save"](prefs)
            except ValueError as e:
                messagebox.showerror(_("Skróty klawiszowe"), _("Nieprawidłowy skrót: {error}\nPrzykład: Ctrl+Shift+Space", error=e))
                return
            busy = [k for k, ok in (registered or {}).items() if not ok]
            if prefs["enabled"] and busy:
                messagebox.showwarning(_("Skróty klawiszowe"), _("Niektóre skróty są zajęte przez inny program – "
                                                             "wybierz inną kombinację klawiszy."))
        if self.on_saved:
            self.on_saved()
        if icons_changed and self.security.get("on_icons_changed"):
            self.security["on_icons_changed"]()
        messagebox.showinfo(_("Zapisano"), _("Ustawienia zostały zapisane."))

    def _change_pwd(self):
        if not hmac.compare_digest(self.cur_p.get().encode("utf-8"), self.current_password.encode("utf-8")):
            messagebox.showerror(_("Błąd"), _("Aktualne hasło jest niepoprawne."))
            return
        np = self.new_p.get()
        if np != self.cnf_p.get():
            messagebox.showerror(_("Błąd"), _("Nowe hasła nie są identyczne."))
            return
        allowed, policy_msg = check_master_password(np)
        if not allowed:
            messagebox.showerror(_("Zbyt słabe hasło główne"), policy_msg)
            return
        required = min_master_score(self.policy)
        if required and evaluate_password_strength(np)["score"] < required:
            messagebox.showerror(
                _("Wymaganie firmy"),
                _("Polityka bezpieczeństwa firmy wymaga hasła głównego o sile co najmniej: „{level}”.",
                  level=_(SCORE_LABELS[required]))
            )
            return
        if policy_msg and not required and not messagebox.askyesno(_("Średnio silne hasło główne"), policy_msg + "\n\n" + _("Użyć mimo to?"), icon="warning"):
            return
        try:
            self.vault.settings.pop("force_password_change", None)  # hasło tymczasowe od administratora zmienione
            if self.password_saver:
                self.password_saver(np)  # zapis + powiadomienie o zmianie hasła
            else:
                # Plik-klucz (jeśli był używany) pozostaje drugim składnikiem zabezpieczenia
                save_vault(self.vault, self.vault_file_path, np, self.keyfile_bytes)
                if self.on_pwd_changed:
                    self.on_pwd_changed(np)
            self.current_password = np
            messagebox.showinfo(_("Sukces"), _("Hasło główne zostało zmienione!"))
            self.cur_p.delete(0, "end")
            self.new_p.delete(0, "end")
            self.cnf_p.delete(0, "end")
        except Exception as e:
            messagebox.showerror(_("Błąd"), str(e))


# =====================================================================
# 7. SYNCHRONIZACJA Z SERWEREM (SYNC DRAWER VIEW)
# =====================================================================
def _format_time(value) -> str:
    """ISO (UTC) lub znacznik czasu → czas lokalny 'dd.mm.rrrr gg:mm'."""
    if not value:
        return "—"
    try:
        if isinstance(value, (int, float)):
            dt = datetime.fromtimestamp(value)
        else:
            dt = datetime.fromisoformat(value).astimezone()
        return dt.strftime("%d.%m.%Y %H:%M")
    except (ValueError, OSError):
        return str(value)


class SyncDrawerView(ctk.CTkFrame):
    STATE_LABELS = {
        "synced": ("🟢", _("Zsynchronizowano"), COLOR_SUCCESS),
        "syncing": ("🔄", _("Synchronizacja w toku"), COLOR_PRIMARY_LIGHT),
        "pending": ("🔄", _("Zapisywanie zmian"), COLOR_PRIMARY_LIGHT),
        "offline": ("🟠", _("Brak połączenia z serwerem"), COLOR_WARNING),
        "conflict": ("⚠️", _("Konflikt wersji"), COLOR_DANGER),
        "error": ("⚠️", _("Wymaga uwagi"), COLOR_DANGER),
    }

    def __init__(self, parent, session, on_vault_replaced: Callable[[Vault, str], None], on_sync_now: Optional[Callable[..., None]] = None):
        super().__init__(parent, fg_color="transparent")
        self.pack(fill="both", expand=True)
        self.session = session
        self.on_vault_replaced = on_vault_replaced
        self.on_sync_now = on_sync_now
        self._shown_state = None

        self.scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.scroll.pack(fill="both", expand=True)

        # Karta stanu
        card = ctk.CTkFrame(self.scroll, fg_color=COLOR_CARD_DARK, corner_radius=12)
        card.pack(fill="x", pady=(0, 12), ipady=6)
        head = layout_frame(card)
        head.pack(fill="x", padx=15, pady=(10, 2))
        self.state_lbl = ctk.CTkLabel(head, text="", font=FONT_SUBTITLE, anchor="w")
        self.state_lbl.pack(side="left")
        self.sync_btn = ctk.CTkButton(head, text=_("🔄 Synchronizuj teraz"), width=150, fg_color=COLOR_PRIMARY, command=self._sync_now)
        self.sync_btn.pack(side="right")
        self.message_lbl = ctk.CTkLabel(card, text="", font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, anchor="w", justify="left", wraplength=480)
        self.message_lbl.pack(anchor="w", padx=15, pady=(0, 6))

        self.details = layout_frame(card)
        self.details.pack(fill="x", padx=15, pady=(0, 8))

        # Rozwiązywanie konfliktu (pokazywane tylko w razie potrzeby)
        self.conflict_card = ctk.CTkFrame(self.scroll, fg_color=COLOR_CARD_DARK, corner_radius=12, border_width=1, border_color=COLOR_DANGER)
        ctk.CTkLabel(self.conflict_card, text=_("Którą wersję zachować?"), font=FONT_SUBTITLE, text_color=COLOR_TEXT_PRIMARY).pack(anchor="w", padx=15, pady=(10, 2))
        ctk.CTkLabel(
            self.conflict_card,
            text=_("Sejf zmieniono na innym urządzeniu, a na tym komputerze są zmiany, których serwer jeszcze nie ma.\n"
                   "Niezależnie od wyboru, druga wersja zostaje w historii serwera i można ją później przywrócić."),
            font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, justify="left", wraplength=480
        ).pack(anchor="w", padx=15, pady=(0, 8))
        btns = layout_frame(self.conflict_card)
        btns.pack(fill="x", padx=15, pady=(0, 12))
        self.use_server_btn = ctk.CTkButton(btns, text=_("⬇️ Pobierz wersję z serwera"), fg_color=COLOR_PANEL_DARK, command=self._use_server)
        self.use_server_btn.pack(side="left", padx=(0, 6))
        self.keep_local_btn = ctk.CTkButton(btns, text=_("⬆️ Zachowaj moją wersję"), fg_color=COLOR_DANGER, command=self._keep_local)
        self.keep_local_btn.pack(side="left")

        # Historia wersji
        self.history_head = layout_frame(self.scroll)
        self.history_head.pack(fill="x", pady=(4, 4))
        ctk.CTkLabel(self.history_head, text=_("Historia wersji na serwerze"), font=FONT_BODY_BOLD).pack(side="left")
        ctk.CTkButton(self.history_head, text=_("Odśwież"), width=70, height=24, fg_color=COLOR_PANEL_DARK, command=self._load_history).pack(side="right")
        self.history_box = layout_frame(self.scroll)
        self.history_box.pack(fill="x")

        self._refresh_status()
        self._load_history()
        self._tick()

    # ------------------------------------------------------------ stan
    def _tick(self):
        if self.winfo_exists():
            self._refresh_status()
            self.after(1000, self._tick)

    def _refresh_status(self):
        st = self.session.status()
        icon, label, color = self.STATE_LABELS.get(st.state, ("☁️", st.state, COLOR_TEXT_PRIMARY))
        self.state_lbl.configure(text=f"{icon}  {label}", text_color=color)
        self.message_lbl.configure(text=st.message)

        signature = (st.state, st.local_version, st.last_sync, (st.remote_meta or {}).get("version"))
        if signature == self._shown_state:
            return
        self._shown_state = signature

        for w in self.details.winfo_children():
            w.destroy()
        remote = st.remote_meta or {}
        rows = [
            (_("Serwer"), self.session.profile.url),
            (_("To urządzenie"), self.session.profile.device_name or "—"),
            (_("Wersja na tym komputerze"), f"v{st.local_version}" + (_("  (niewysłane zmiany)") if st.pending else "")),
            (_("Wersja na serwerze"), f"v{remote['version']} · {_format_time(remote.get('updated_at'))} · {remote.get('updated_by', '?')}" if remote else "—"),
            (_("Ostatnia synchronizacja"), _format_time(st.last_sync)),
        ]
        for key, value in rows:
            r = layout_frame(self.details)
            r.pack(fill="x", pady=1)
            ctk.CTkLabel(r, text=f"{key}:", font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, width=170, anchor="w").pack(side="left")
            ctk.CTkLabel(r, text=value, font=FONT_SMALL, text_color=COLOR_TEXT_PRIMARY, anchor="w").pack(side="left")

        if st.state in ("conflict", "error"):
            self.conflict_card.pack(fill="x", pady=(0, 12), before=self.history_head)
        else:
            self.conflict_card.pack_forget()

    def _busy(self, busy: bool):
        for b in (self.sync_btn, self.use_server_btn, self.keep_local_btn):
            if b.winfo_exists():
                b.configure(state="disabled" if busy else "normal")

    # ------------------------------------------------------------ akcje
    def _sync_now(self):
        if not self.on_sync_now:
            return
        self._busy(True)

        def _finished():
            if self.winfo_exists():
                self._busy(False)
                self._refresh_status()
                self._load_history()
        self.on_sync_now(on_finished=_finished)

    def _use_server(self):
        if not messagebox.askyesno(_("Pobierz wersję z serwera"), _("Zmiany z tego komputera, których nie ma na serwerze, zostaną odrzucone. Kontynuować?")):
            return
        self._busy(True)

        def _done(res):
            self._busy(False)
            if isinstance(res, Exception):
                messagebox.showerror(_("Synchronizacja"), str(res))
            else:
                self.on_vault_replaced(res, _("⬇️ Wczytano wersję z serwera"))
        run_in_background(self, self.session.resolve_use_server, _done)

    def _keep_local(self):
        if not messagebox.askyesno(_("Zachowaj moją wersję"), _("Wersja z tego komputera zastąpi wersję na serwerze (poprzednia zostanie w historii). Kontynuować?")):
            return
        self._busy(True)

        def _done(res):
            self._busy(False)
            if isinstance(res, Exception):
                messagebox.showerror(_("Synchronizacja"), str(res))
            self._refresh_status()
            self._load_history()
        run_in_background(self, self.session.resolve_keep_local, _done)

    def _load_history(self):
        for w in self.history_box.winfo_children():
            w.destroy()
        ctk.CTkLabel(self.history_box, text=_("Wczytywanie..."), font=FONT_SMALL, text_color=COLOR_TEXT_MUTED).pack(anchor="w")

        def _done(res):
            for w in self.history_box.winfo_children():
                w.destroy()
            if isinstance(res, Exception):
                ctk.CTkLabel(self.history_box, text=_("Nie udało się pobrać historii: {error}", error=res), font=FONT_SMALL, text_color=COLOR_WARNING, wraplength=480, justify="left").pack(anchor="w")
                return
            current = (self.session.status().remote_meta or {}).get("version")
            for item in res:
                row = ctk.CTkFrame(self.history_box, fg_color=COLOR_CARD_DARK, corner_radius=8)
                row.pack(fill="x", pady=2)
                is_current = item["version"] == current
                text = f"v{item['version']}   {_format_time(item.get('updated_at'))}   ·   {item.get('updated_by', '?')}"
                ctk.CTkLabel(row, text=text, font=FONT_BODY_BOLD if is_current else FONT_BODY,
                             text_color=COLOR_SUCCESS if is_current else COLOR_TEXT_PRIMARY).pack(side="left", padx=12, pady=6)
                if is_current:
                    ctk.CTkLabel(row, text=_("bieżąca"), font=FONT_SMALL, text_color=COLOR_TEXT_MUTED).pack(side="right", padx=12)
                else:
                    ctk.CTkButton(row, text=_("Przywróć"), width=80, height=26, fg_color=COLOR_PANEL_DARK,
                                  command=lambda v=item["version"]: self._restore(v)).pack(side="right", padx=8)
        run_in_background(self, self.session.history, _done)

    def _restore(self, version: int):
        if not messagebox.askyesno(
            _("Przywróć wersję"),
            _("Przywrócić sejf do wersji v{version}?\n\nZostanie ona zapisana jako nowa, najnowsza wersja – "
              "obecna wersja pozostanie w historii.", version=version)
        ):
            return
        self._busy(True)

        def _done(res):
            self._busy(False)
            if isinstance(res, Exception):
                messagebox.showerror(_("Przywracanie wersji"), str(res))
            else:
                self.on_vault_replaced(res, _("⏪ Przywrócono wersję v{version}", version=version))
        run_in_background(self, lambda: self.session.restore_version(version), _done)
