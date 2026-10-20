"""
Kreator Pierwszego Uruchomienia (Onboarding & First-Run Wizard).
Prowadzi użytkownika krok po kroku przez pierwsze utworzenie sejfu,
zasady bezpieczeństwa, wybór kopii zapasowej oraz ewentualny import danych.
"""

import os
import json
from typing import Optional, Callable, Dict, Any
import customtkinter as ctk
from tkinter import filedialog, messagebox

from core.i18n import N_, _, _n
from core.vault import Vault, VaultEntry
from core.storage import save_vault
from core.generator import evaluate_password_strength, generate_passphrase, check_master_password
from importers import run_import
from ui.theme import (FONT_FAMILY, 
    FONT_TITLE_HERO, FONT_TITLE, FONT_SUBTITLE, FONT_BODY, FONT_BODY_BOLD, FONT_SMALL,
    COLOR_PRIMARY, COLOR_PRIMARY_HOVER, COLOR_CARD_DARK, COLOR_CARD_HOVER,
    COLOR_PANEL_DARK, COLOR_BORDER, COLOR_SUCCESS, COLOR_SUCCESS_HOVER, COLOR_DANGER, COLOR_WARNING,
    COLOR_TEXT_PRIMARY, COLOR_TEXT_MUTED, COLOR_TEXT_ACCENT
)

from core.paths import CONFIG_FILE, ensure_app_dir  # noqa: E402


def is_first_run() -> bool:
    """Sprawdza czy aplikacja jest uruchamiana po raz pierwszy."""
    if not os.path.exists(CONFIG_FILE):
        return True
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return not data.get("first_run_completed", False)
    except Exception:
        return True


def mark_first_run_completed() -> None:
    """Oznacza pierwsze uruchomienie jako zakończone."""
    try:
        data = {}
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        data["first_run_completed"] = True
        ensure_app_dir()
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception:
        pass


class OnboardingWizard(ctk.CTkToplevel):
    def __init__(
        self,
        parent,
        on_vault_ready: Callable[[Vault, str, str, Optional[bytes]], None],
        on_import_requested: Optional[Callable[[], None]] = None
    ):
        super().__init__(parent)
        self.on_vault_ready = on_vault_ready
        self.on_import_requested = on_import_requested

        self.title(_("Witaj w KeyStead Manager - Przewodnik Pierwszego Uruchomienia"))
        self.geometry("760x780")
        self.minsize(700, 680)

        self.transient(parent)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        # grab_set na CTkToplevel musi poczekać, aż okno będzie widoczne
        self.after(150, self._safe_grab)

        # Stan kreatora
        self.current_step = 1
        self.flow_mode = "new"  # 'new' lub 'import'

        # Dane konfiguracyjne sejfu
        self.vault_name = _("Mój Główny Sejf")
        default_dir = os.path.join(os.path.expanduser("~"), "Documents")
        self.vault_file_path = os.path.join(default_dir, _("MojSejf.vault"))
        self.master_password = ""
        self.keyfile_bytes: Optional[bytes] = None
        self.created_vault: Optional[Vault] = None

        self._build_ui()
        self._show_step(1)

    def _safe_grab(self):
        try:
            if self.winfo_exists():
                self.grab_set()
                self.focus_force()
        except Exception:
            pass

    def _on_close(self):
        """Zamknięcie kreatora krzyżykiem – nie pokazuj go automatycznie przy kolejnym starcie."""
        mark_first_run_completed()
        self.grab_release()
        self.destroy()

    def _build_ui(self):
        self.main_container = ctk.CTkFrame(self, fg_color="transparent")
        self.main_container.pack(fill="both", expand=True, padx=30, pady=25)

        # 1. Pasek wskaźnika kroków (Step Indicator)
        self.step_indicator_frame = ctk.CTkFrame(self.main_container, fg_color=COLOR_PANEL_DARK, corner_radius=12, height=55)
        self.step_indicator_frame.pack(fill="x", pady=(0, 20))

        self.step_labels = []
        steps = [
            ("1", _("Powitanie")),
            ("2", _("Twój Sejf")),
            ("3", _("Kopie Zapasowe")),
            ("4", _("Gotowe!"))
        ]

        steps_box = ctk.CTkFrame(self.step_indicator_frame, fg_color="transparent")
        steps_box.pack(expand=True, pady=10)

        for idx, (num, name) in enumerate(steps):
            col = ctk.CTkFrame(steps_box, fg_color="transparent")
            col.pack(side="left", padx=15)

            badge = ctk.CTkLabel(
                col,
                text=f"  {num}  ",
                font=FONT_BODY_BOLD,
                fg_color=COLOR_PRIMARY if idx == 0 else COLOR_CARD_DARK,
                text_color="#ffffff",
                corner_radius=12
            )
            badge.pack(side="left", padx=(0, 6))

            lbl = ctk.CTkLabel(
                col,
                text=name,
                font=FONT_BODY_BOLD if idx == 0 else FONT_BODY,
                text_color=COLOR_TEXT_PRIMARY if idx == 0 else COLOR_TEXT_MUTED
            )
            lbl.pack(side="left")

            self.step_labels.append({"badge": badge, "label": lbl})

            if idx < len(steps) - 1:
                arrow = ctk.CTkLabel(steps_box, text="➔", font=FONT_SMALL, text_color=COLOR_BORDER)
                arrow.pack(side="left", padx=5)

        # 2. Główny kontener na treść kroków
        self.step_content_frame = ctk.CTkFrame(self.main_container, fg_color=COLOR_PANEL_DARK, corner_radius=14)
        self.step_content_frame.pack(fill="both", expand=True, pady=(0, 15))

        # 3. Pasek przycisków nawigacji na dole
        self.bottom_nav = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.bottom_nav.pack(fill="x")

        self.back_btn = ctk.CTkButton(
            self.bottom_nav,
            text=_("🠔 Wstecz"),
            width=110,
            fg_color=COLOR_CARD_DARK,
            hover_color=COLOR_CARD_HOVER,
            command=self._prev_step
        )
        self.back_btn.pack(side="left")

        self.next_btn = ctk.CTkButton(
            self.bottom_nav,
            text=_("Dalej ➔"),
            width=130,
            fg_color=COLOR_PRIMARY,
            hover_color=COLOR_PRIMARY_HOVER,
            command=self._next_step
        )
        self.next_btn.pack(side="right")

    def _update_indicators(self, step_num: int):
        for idx, item in enumerate(self.step_labels):
            if idx + 1 == step_num:
                item["badge"].configure(fg_color=COLOR_PRIMARY)
                item["label"].configure(text_color=COLOR_TEXT_PRIMARY, font=FONT_BODY_BOLD)
            elif idx + 1 < step_num:
                item["badge"].configure(fg_color=COLOR_SUCCESS)
                item["label"].configure(text_color=COLOR_TEXT_MUTED, font=FONT_BODY)
            else:
                item["badge"].configure(fg_color=COLOR_CARD_DARK)
                item["label"].configure(text_color=COLOR_TEXT_MUTED, font=FONT_BODY)

    def _show_step(self, step: int):
        self.current_step = step
        self._update_indicators(step)

        for w in self.step_content_frame.winfo_children():
            w.destroy()

        if step == 1:
            self._render_step_1()
            self.back_btn.pack_forget()
            self.next_btn.configure(text=_("Dalej ➔"), fg_color=COLOR_PRIMARY)
        elif step == 2:
            self.back_btn.pack(side="left")
            self._render_step_2()
            self.next_btn.configure(text=_("Utwórz i szyfruj ➔"), fg_color=COLOR_PRIMARY)
        elif step == 3:
            self.back_btn.pack(side="left")
            self._render_step_3()
            self.next_btn.configure(text=_("Zapisz i kontynuuj ➔"), fg_color=COLOR_PRIMARY)
        elif step == 4:
            self.back_btn.pack_forget()
            self._render_step_4()
            self.next_btn.configure(text=_("Otwórz mój sejf 🚀"), fg_color=COLOR_SUCCESS, hover_color=COLOR_SUCCESS_HOVER)

    # ----------------- KROK 1: POWITANIE -----------------
    def _render_step_1(self):
        container = ctk.CTkScrollableFrame(self.step_content_frame, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=30, pady=25)

        # Hero Banner
        ctk.CTkLabel(container, text="🛡️", font=(FONT_FAMILY, 48)).pack(pady=(10, 5))
        ctk.CTkLabel(container, text=_("Witaj w KeyStead Manager!"), font=FONT_TITLE_HERO, text_color=COLOR_TEXT_PRIMARY).pack(pady=(0, 4))
        ctk.CTkLabel(
            container,
            text=_("Twój nowy, profesjonalny menedżer haseł chroniony kryptografią wojskowej klasy."),
            font=FONT_BODY,
            text_color=COLOR_TEXT_MUTED
        ).pack(pady=(0, 20))

        # 3 Karty korzyści
        features_box = ctk.CTkFrame(container, fg_color=COLOR_CARD_DARK, corner_radius=10)
        features_box.pack(fill="x", pady=(0, 20), ipady=8, padx=5)

        feat_list = [
            ("🔐", _("Architektura Zero-Knowledge"), _("Twoje hasła są szyfrowane lokalnie (Argon2id + AES-256-GCM). Nikt poza Tobą nie ma do nich dostępu.")),
            ("🚨", _("Aktywny Monitor Wycieków (HIBP)"), _("Baza wycieków danych sprawdzana metodą k-Anonymity – dowiesz się, czy Twoje konta są zagrożone.")),
            ("☁️", _("Wieloplatformowe Kopie Zapasowe"), _("Zaszyfrowane kopie zapasowe mogą automatycznie trafiać na WebDAV/Nextcloud, Google Drive, OneDrive lub USB."))
        ]

        for icon, title, desc in feat_list:
            row = ctk.CTkFrame(features_box, fg_color="transparent")
            row.pack(fill="x", padx=15, pady=8)
            ctk.CTkLabel(row, text=icon, font=(FONT_FAMILY, 24)).pack(side="left", padx=(0, 12))
            text_col = ctk.CTkFrame(row, fg_color="transparent")
            text_col.pack(side="left", fill="x", expand=True)
            ctk.CTkLabel(text_col, text=title, font=FONT_SUBTITLE, text_color=COLOR_TEXT_PRIMARY, anchor="w").pack(anchor="w")
            ctk.CTkLabel(text_col, text=desc, font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, anchor="w", wraplength=480, justify="left").pack(anchor="w")

        # Pytanie o tryb startu
        ctk.CTkLabel(container, text=_("Jak chcesz rozpocząć?"), font=FONT_SUBTITLE, text_color=COLOR_TEXT_PRIMARY).pack(anchor="w", pady=(10, 8))

        self.mode_var = ctk.StringVar(value="new")

        # Wybór A: Nowy sejf
        card_a = ctk.CTkFrame(container, fg_color=COLOR_CARD_HOVER, corner_radius=10, border_width=1, border_color=COLOR_PRIMARY)
        card_a.pack(fill="x", pady=5)
        row_a = ctk.CTkFrame(card_a, fg_color="transparent")
        row_a.pack(fill="x", padx=15, pady=12)

        self.radio_new = ctk.CTkRadioButton(
            row_a,
            text="",
            variable=self.mode_var,
            value="new",
            command=self._on_mode_select
        )
        self.radio_new.pack(side="left", padx=(0, 10))

        col_a = ctk.CTkFrame(row_a, fg_color="transparent")
        col_a.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(col_a, text=_("🌟 Utwórz nowy sejf od podstaw (Zalecane)"), font=FONT_BODY_BOLD, text_color=COLOR_TEXT_PRIMARY, anchor="w").pack(anchor="w")
        ctk.CTkLabel(col_a, text=_("Stworzymy bezpieczną bazę haseł i ustawimy Twoje hasło główne."), font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, anchor="w").pack(anchor="w")

        # Wybór B: Import z innego menedżera
        card_b = ctk.CTkFrame(container, fg_color=COLOR_CARD_DARK, corner_radius=10)
        card_b.pack(fill="x", pady=5)
        row_b = ctk.CTkFrame(card_b, fg_color="transparent")
        row_b.pack(fill="x", padx=15, pady=12)

        self.radio_import = ctk.CTkRadioButton(
            row_b,
            text="",
            variable=self.mode_var,
            value="import",
            command=self._on_mode_select
        )
        self.radio_import.pack(side="left", padx=(0, 10))

        col_b = ctk.CTkFrame(row_b, fg_color="transparent")
        col_b.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(col_b, text=_("📥 Przechodzę z innego menedżera (Import danych)"), font=FONT_BODY_BOLD, text_color=COLOR_TEXT_PRIMARY, anchor="w").pack(anchor="w")
        ctk.CTkLabel(col_b, text=_("Zaimportuj hasła z Bitwarden, KeePass (.kdbx), 1Password, LastPass lub przeglądarki Chrome/Firefox."), font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, anchor="w").pack(anchor="w")

    def _on_mode_select(self):
        self.flow_mode = self.mode_var.get()

    # ----------------- KROK 2: TWÓJ SEJF -----------------
    def _render_step_2(self):
        container = ctk.CTkScrollableFrame(self.step_content_frame, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=30, pady=20)

        ctk.CTkLabel(container, text=_("Krok 2: Tworzenie i zabezpieczenie sejfu"), font=FONT_TITLE, text_color=COLOR_TEXT_PRIMARY).pack(anchor="w", pady=(0, 4))
        ctk.CTkLabel(
            container,
            text=_("Wybierz nazwę sejfu oraz silne hasło główne (Master Password)."),
            font=FONT_BODY,
            text_color=COLOR_TEXT_MUTED
        ).pack(anchor="w", pady=(0, 15))

        # Ważna informacja o haśle
        tip_box = ctk.CTkFrame(container, fg_color=COLOR_CARD_DARK, corner_radius=8, border_width=1, border_color=COLOR_PRIMARY)
        tip_box.pack(fill="x", pady=(0, 15), ipady=6, padx=2)
        ctk.CTkLabel(
            tip_box,
            text=_("💡 PAMIĘTAJ: Hasło główne to jedyny klucz do Twoich danych.\nZ powodu szyfrowania Zero-Knowledge nie ma opcji 'Przypomnij hasło'!\nWybierz hasło, które zapamiętasz lub zapisz je w bezpiecznym miejscu offline."),
            font=FONT_SMALL,
            text_color=COLOR_TEXT_ACCENT,
            justify="left"
        ).pack(anchor="w", padx=12, pady=6)

        # Nazwa sejfu
        ctk.CTkLabel(container, text=_("Nazwa sejfu:"), font=FONT_BODY_BOLD).pack(anchor="w", pady=(2, 2))
        self.vault_name_input = ctk.CTkEntry(container, placeholder_text=_("Mój Główny Sejf"))
        self.vault_name_input.insert(0, self.vault_name)
        self.vault_name_input.pack(fill="x", pady=(0, 10))

        # Lokalizacja pliku
        ctk.CTkLabel(container, text=_("Lokalizacja pliku bazy (.vault):"), font=FONT_BODY_BOLD).pack(anchor="w", pady=(2, 2))
        file_box = ctk.CTkFrame(container, fg_color="transparent")
        file_box.pack(fill="x", pady=(0, 12))

        self.vault_path_input = ctk.CTkEntry(file_box)
        self.vault_path_input.insert(0, self.vault_file_path)
        self.vault_path_input.pack(side="left", expand=True, fill="x", padx=(0, 8))

        ctk.CTkButton(file_box, text=_("Zmień..."), width=80, fg_color=COLOR_CARD_DARK, command=self._browse_save_path).pack(side="left")

        # Hasło główne
        ctk.CTkLabel(container, text=_("Hasło główne do sejfu (Master Password) *:"), font=FONT_BODY_BOLD).pack(anchor="w", pady=(4, 2))
        pwd_box = ctk.CTkFrame(container, fg_color="transparent")
        pwd_box.pack(fill="x", pady=(0, 4))

        self.pwd1_input = ctk.CTkEntry(pwd_box, show="•", placeholder_text=_("Wpisz silne hasło główne..."))
        self.pwd1_input.pack(side="left", expand=True, fill="x", padx=(0, 8))
        self.pwd1_input.bind("<KeyRelease>", self._on_wizard_pwd_typed)

        ctk.CTkButton(
            pwd_box,
            text=_("🎲 Podpowiedź frazy"),
            width=135,
            fg_color=COLOR_CARD_DARK,
            command=self._suggest_passphrase
        ).pack(side="left")

        self.pwd_bar = ctk.CTkProgressBar(container, height=6)
        self.pwd_bar.pack(fill="x", pady=(2, 2))
        self.pwd_bar.set(0)

        self.pwd_hint_lbl = ctk.CTkLabel(container, text="", font=FONT_SMALL, text_color=COLOR_TEXT_MUTED)
        self.pwd_hint_lbl.pack(anchor="w", pady=(0, 8))

        # Powtórz hasło
        ctk.CTkLabel(container, text=_("Powtórz hasło główne *:"), font=FONT_BODY_BOLD).pack(anchor="w", pady=(2, 2))
        self.pwd2_input = ctk.CTkEntry(container, show="•", placeholder_text=_("Wpisz hasło ponownie..."))
        self.pwd2_input.pack(fill="x", pady=(0, 15))

    def _browse_save_path(self):
        p = filedialog.asksaveasfilename(
            title=_("Wybierz lokalizację pliku sejfu"),
            defaultextension=".vault",
            filetypes=[(_("Plik Sejfu"), "*.vault")]
        )
        if p:
            self.vault_path_input.delete(0, "end")
            self.vault_path_input.insert(0, p)
            self.vault_file_path = p

    def _suggest_passphrase(self):
        phrase = generate_passphrase(word_count=6, separator="-", capitalize=True, include_number=True)
        self.pwd1_input.delete(0, "end")
        self.pwd1_input.insert(0, phrase)
        self.pwd2_input.delete(0, "end")
        self.pwd2_input.insert(0, phrase)
        self._on_wizard_pwd_typed()
        messagebox.showinfo(_("Wygenerowano zapamiętywalne hasło"), _("Wstawiono silne hasło wielowyrazowe:\n\n{phrase}\n\nZapisz je w bezpiecznym miejscu!", phrase=phrase), parent=self)

    def _on_wizard_pwd_typed(self, event=None):
        pwd = self.pwd1_input.get()
        if not pwd:
            self.pwd_bar.set(0)
            self.pwd_hint_lbl.configure(text="")
            return

        eval_res = evaluate_password_strength(pwd)
        self.pwd_bar.set(eval_res["score"] / 4.0)
        self.pwd_bar.configure(progress_color=eval_res["color"])
        self.pwd_hint_lbl.configure(
            text=_("Siła: {label} ({entropy} bitów entropii)", label=eval_res["label"], entropy=eval_res["entropy"]),
            text_color=eval_res["color"]
        )

    # ----------------- KROK 3: KOPIE ZAPASOWE -----------------
    def _render_step_3(self):
        container = ctk.CTkScrollableFrame(self.step_content_frame, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=30, pady=20)

        ctk.CTkLabel(container, text=_("Krok 3: Ochrona i Kopie Zapasowe (Chmura / USB)"), font=FONT_TITLE, text_color=COLOR_TEXT_PRIMARY).pack(anchor="w", pady=(0, 4))
        ctk.CTkLabel(
            container,
            text=_("Kopie zapasowe są w pełni szyfrowane (AES-256-GCM). Możesz je bezpiecznie przechowywać w chmurze."),
            font=FONT_BODY,
            text_color=COLOR_TEXT_MUTED
        ).pack(anchor="w", pady=(0, 15))

        # Automatyczny backup checkbox
        self.auto_backup_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            container,
            text=_("Automatycznie twórz kopie zapasowe przy każdym zapisie sejfu"),
            font=FONT_BODY_BOLD,
            variable=self.auto_backup_var
        ).pack(anchor="w", pady=(0, 12))

        # Kopia lokalna / USB
        local_card = ctk.CTkFrame(container, fg_color=COLOR_CARD_DARK, corner_radius=10)
        local_card.pack(fill="x", pady=6, ipady=4)

        ctk.CTkLabel(local_card, text=_("💾 Kopia lokalna / Dysk USB (Zalecane na start):"), font=FONT_BODY_BOLD).pack(anchor="w", padx=12, pady=(6, 2))
        l_row = ctk.CTkFrame(local_card, fg_color="transparent")
        l_row.pack(fill="x", padx=12, pady=(0, 8))

        default_backup_dir = os.path.join(os.path.expanduser("~"), "Documents", _("KopieSejfu"))
        self.local_backup_input = ctk.CTkEntry(l_row, placeholder_text=_("np. D:\\Kopie lub pendrive USB..."))
        self.local_backup_input.insert(0, default_backup_dir)
        self.local_backup_input.pack(side="left", expand=True, fill="x", padx=(0, 8))

        ctk.CTkButton(l_row, text=_("Wybierz..."), width=80, fg_color=COLOR_PANEL_DARK, command=self._browse_backup_dir).pack(side="left")

        # Inne chmury info
        cloud_card = ctk.CTkFrame(container, fg_color=COLOR_CARD_DARK, corner_radius=10)
        cloud_card.pack(fill="x", pady=6, ipady=6)

        ctk.CTkLabel(cloud_card, text=_("☁️ Integracja z Chmurą (WebDAV, Google Drive, OneDrive, Dropbox):"), font=FONT_BODY_BOLD).pack(anchor="w", padx=12, pady=(6, 2))
        ctk.CTkLabel(
            cloud_card,
            text=_("Po wejściu do sejfu możesz w każdej chwili skonfigurować automatyczną wysyłkę do Nextcloud, Synology NAS, Dysku Google lub OneDrive klikając przycisk '☁️ Kopie i Chmura'."),
            font=FONT_SMALL,
            text_color=COLOR_TEXT_MUTED,
            wraplength=480,
            justify="left"
        ).pack(anchor="w", padx=12, pady=(0, 6))

        # Czas automatycznej blokady
        lock_box = ctk.CTkFrame(container, fg_color=COLOR_CARD_DARK, corner_radius=10)
        lock_box.pack(fill="x", pady=6, ipady=4)

        ctk.CTkLabel(lock_box, text=_("🔒 Automatyczna blokada sejfu przy braku aktywności:"), font=FONT_BODY_BOLD).pack(anchor="w", padx=12, pady=(6, 2))
        # Etykiety tłumaczone raz – wybór mapowany z powrotem na minuty po tej samej etykiecie
        self.autolock_options = {
            _("1 minuta"): 1, _("5 minut (Zalecane)"): 5, _("10 minut"): 10,
            _("15 minut"): 15, _("30 minut"): 30, _("Nigdy"): 0,
        }
        self.autolock_combo = ctk.CTkComboBox(
            lock_box,
            values=list(self.autolock_options),
            width=240
        )
        self.autolock_combo.set(_("5 minut (Zalecane)"))
        self.autolock_combo.pack(anchor="w", padx=12, pady=(0, 8))

    def _browse_backup_dir(self):
        d = filedialog.askdirectory(title=_("Wybierz katalog na kopie zapasowe"))
        if d:
            self.local_backup_input.delete(0, "end")
            self.local_backup_input.insert(0, d)

    # ----------------- KROK 4: GOTOWE -----------------
    def _render_step_4(self):
        container = ctk.CTkScrollableFrame(self.step_content_frame, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=30, pady=25)

        ctk.CTkLabel(container, text="🎉", font=(FONT_FAMILY, 48)).pack(pady=(10, 5))
        ctk.CTkLabel(container, text=_("Gratulacje! Twój sejf jest gotowy."), font=FONT_TITLE_HERO, text_color=COLOR_SUCCESS).pack(pady=(0, 4))
        ctk.CTkLabel(
            container,
            text=_("Wszystkie parametry zostały skonfigurowane, a baza została pomyślnie zaszyfrowana."),
            font=FONT_BODY,
            text_color=COLOR_TEXT_MUTED
        ).pack(pady=(0, 20))

        if self.flow_mode == "import":
            ctk.CTkLabel(
                container,
                text=_("📥 Po otwarciu sejfu automatycznie uruchomi się Kreator Importu."),
                font=FONT_BODY_BOLD,
                text_color=COLOR_TEXT_ACCENT
            ).pack(pady=(0, 15))

        summary_box = ctk.CTkFrame(container, fg_color=COLOR_CARD_DARK, corner_radius=10)
        summary_box.pack(fill="x", pady=(0, 20), ipady=8, padx=5)

        ctk.CTkLabel(summary_box, text=_("📌 Szybkie wskazówki na start:"), font=FONT_SUBTITLE, text_color=COLOR_TEXT_PRIMARY).pack(anchor="w", padx=15, pady=(8, 6))

        tips = [
            (_("➕ Dodawanie wpisów:"), _("Kliknij '+ Nowy Wpis' w górnym menu, aby zapisać login, hasło, stronę i klucz 2FA.")),
            (_("📋 Bezpieczny schowek:"), _("Kopiowanie hasła automatycznie usuwa je ze schowka systemowego po 30 sekundach.")),
            (_("🛡️ Audyt Wycieków:"), _("Uruchamiaj regularnie przycisk '🛡️ Audyt Wycieków', aby dowiedzieć się czy Twoje hasła nie pojawiły się w publicznych bazach.")),
            (_("📥 Import z innych menedżerów:"), _("W menu '📥 Import' możesz w każdej chwili przenieść całą bazę z Bitwarden, KeePass, 1Password lub Chrome."))
        ]

        for k, v in tips:
            row = ctk.CTkFrame(summary_box, fg_color="transparent")
            row.pack(fill="x", padx=15, pady=4)
            ctk.CTkLabel(row, text=k, font=FONT_BODY_BOLD, text_color=COLOR_TEXT_ACCENT).pack(side="left")
            ctk.CTkLabel(row, text=f" {v}", font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, wraplength=380, justify="left").pack(side="left")

    # ----------------- NAWIGACJA WIZARDA -----------------
    def _prev_step(self):
        if self.current_step > 1:
            self._show_step(self.current_step - 1)

    def _next_step(self):
        if self.current_step == 1:
            self._show_step(2)

        elif self.current_step == 2:
            # Weryfikacja kroku 2
            v_name = self.vault_name_input.get().strip() or _("Mój Główny Sejf")
            v_path = self.vault_path_input.get().strip()
            p1 = self.pwd1_input.get()
            p2 = self.pwd2_input.get()

            if not v_path:
                messagebox.showerror(_("Błąd"), _("Podaj ścieżkę do pliku sejfu."), parent=self)
                return

            if not v_path.lower().endswith(".vault"):
                v_path += ".vault"

            allowed, policy_msg = check_master_password(p1)
            if not allowed:
                messagebox.showerror(_("Zbyt słabe hasło główne"), policy_msg, parent=self)
                return

            if p1 != p2:
                messagebox.showerror(_("Błąd"), _("Wprowadzone hasła różnią się od siebie."), parent=self)
                return

            if policy_msg and not messagebox.askyesno(_("Średnio silne hasło główne"), policy_msg + "\n\n" + _("Użyć mimo to?"), icon="warning", parent=self):
                return

            if os.path.exists(v_path) and not messagebox.askyesno(
                _("Plik już istnieje"),
                _("Plik {path} już istnieje.\n\nNadpisanie go NIEODWRACALNIE usunie zapisany w nim sejf. Kontynuować?", path=v_path),
                icon="warning",
                parent=self
            ):
                return

            self.vault_name = v_name
            self.vault_file_path = v_path
            self.master_password = p1

            # Utwórz sejf
            self.created_vault = Vault(name=self.vault_name)

            self._show_step(3)

        elif self.current_step == 3:
            # Zastosuj ustawienia kopii i autolock
            backup_dir = self.local_backup_input.get().strip()
            lock_choice = self.autolock_combo.get()
            lock_min = self.autolock_options.get(lock_choice, 5)

            self.created_vault.settings["auto_lock_minutes"] = lock_min
            self.created_vault.settings["auto_backup_on_save"] = self.auto_backup_var.get()
            if backup_dir:
                self.created_vault.settings["backup_destinations"]["local"] = {
                    "folder_path": backup_dir,
                    "max_backups": 15
                }

            # Zapisz sejf fizycznie na dysku
            try:
                save_vault(self.created_vault, self.vault_file_path, self.master_password)
                mark_first_run_completed()
            except Exception as e:
                messagebox.showerror(_("Błąd zapisu sejfu"), _("Nie udało się zapisać sejfu na dysku: {error}", error=e), parent=self)
                return

            self._show_step(4)

        elif self.current_step == 4:
            # Najpierw zamykamy kreator, dopiero potem przełączamy widok aplikacji
            vault = self.created_vault
            password = self.master_password
            path = self.vault_file_path
            keyfile = self.keyfile_bytes
            wants_import = self.flow_mode == "import"
            on_ready = self.on_vault_ready
            on_import = self.on_import_requested

            self.grab_release()
            self.destroy()

            if on_ready and vault:
                on_ready(vault, password, path, keyfile)
                if wants_import and on_import:
                    on_import()
