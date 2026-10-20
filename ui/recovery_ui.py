"""
Odzyskiwanie dostępu w aplikacji:
- osobisty kod odzyskiwania (pokazywany raz, do zapisania/wydruku),
- „Nie pamiętam hasła” na ekranie logowania (kod odzyskiwania → nowe hasło główne),
- narzędzia administratora firmy: klucz odzyskiwania firmy i odzyskanie dostępu użytkownika (plik z panelu).
"""

import base64
import json
import os
from datetime import datetime, timezone
from typing import Callable, Optional

import customtkinter as ctk
from tkinter import filedialog, messagebox

from core.crypto import (CryptoError, generate_org_keypair, load_org_private_key, seal, unseal_with_org_key)
from core.i18n import N_, _, _n
from core.generator import check_master_password, evaluate_password_strength, generate_password
from ui.theme import (FONT_MONO, COLOR_CARD_DARK, COLOR_DANGER, COLOR_PANEL_DARK, COLOR_PRIMARY, COLOR_SUCCESS, COLOR_TEXT_MUTED,
                      COLOR_TEXT_PRIMARY, FONT_BODY, FONT_SMALL, FONT_SUBTITLE, FONT_TITLE)

FORCE_CHANGE_KEY = "force_password_change"


class _Modal(ctk.CTkToplevel):
    def __init__(self, master, title: str, width: int = 520, height: int = 360):
        super().__init__(master)
        self.title(title)
        self.geometry(f"{width}x{height}")
        self.resizable(False, False)
        self.transient(master.winfo_toplevel())
        self.result = None
        self.after(120, self._grab)

    def _grab(self):
        try:
            self.grab_set()
            self.focus_force()
        except Exception:
            pass

    def wait(self):
        self.wait_window(self)
        return self.result


class RecoveryCodeDialog(_Modal):
    """Kod odzyskiwania pokazywany jeden raz – zamknięcie dopiero po potwierdzeniu, że został zapisany."""

    def __init__(self, master, code: str, vault_name: str):
        super().__init__(master, _("Kod odzyskiwania"), 560, 400)
        self.code = code
        ctk.CTkLabel(self, text=_("🔑 Twój kod odzyskiwania"), font=FONT_TITLE).pack(anchor="w", padx=20, pady=(16, 4))
        ctk.CTkLabel(self, text=_("Pozwala odzyskać dostęp do sejfu, gdy zapomnisz hasła głównego. Pokazujemy go tylko teraz – "
                                  "zapisz go lub wydrukuj i przechowuj poza komputerem (np. w sejfie domowym)."),
                     font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, wraplength=510, justify="left").pack(anchor="w", padx=20)
        box = ctk.CTkFrame(self, fg_color=COLOR_PANEL_DARK, corner_radius=10)
        box.pack(fill="x", padx=20, pady=14)
        ctk.CTkLabel(box, text=code, font=(FONT_MONO, 20, "bold"), text_color=COLOR_SUCCESS).pack(pady=14)
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", padx=20)
        ctk.CTkButton(row, text=_("Kopiuj"), width=90, fg_color=COLOR_CARD_DARK, command=self._copy).pack(side="left")
        ctk.CTkButton(row, text=_("Zapisz do pliku…"), width=130, fg_color=COLOR_CARD_DARK,
                      command=lambda: self._save(vault_name)).pack(side="left", padx=8)
        self.ok_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(self, text=_("Zapisałem kod w bezpiecznym miejscu"), variable=self.ok_var,
                        command=self._toggle).pack(anchor="w", padx=20, pady=(16, 6))
        self.done_btn = ctk.CTkButton(self, text=_("Gotowe"), state="disabled", fg_color=COLOR_PRIMARY, command=self._done)
        self.done_btn.pack(anchor="e", padx=20, pady=(4, 12))
        self.protocol("WM_DELETE_WINDOW", self._close_attempt)

    def _copy(self):
        self.clipboard_clear()
        self.clipboard_append(self.code)

    def _save(self, vault_name: str):
        path = filedialog.asksaveasfilename(title=_("Zapisz kod odzyskiwania"), defaultextension=".txt",
                                            initialfile=_("KeyStead - kod odzyskiwania.txt"), parent=self)
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(_("KeyStead Manager – kod odzyskiwania sejfu „{vault}”\n"
                          "Utworzono: {created}\n\n{code}\n\n"
                          "Przechowuj ten plik poza komputerem (pendrive w szufladzie, wydruk). "
                          "Każdy, kto ma ten kod i plik sejfu, może ustawić nowe hasło główne.\n",
                          vault=vault_name, created=f"{datetime.now():%Y-%m-%d %H:%M}", code=self.code))

    def _toggle(self):
        self.done_btn.configure(state="normal" if self.ok_var.get() else "disabled")

    def _close_attempt(self):
        if self.ok_var.get() or messagebox.askyesno(_("Kod odzyskiwania"), _("Na pewno zamknąć bez zapisania kodu? "
                                                                            "Nie będzie można go wyświetlić ponownie."), parent=self):
            self._done()

    def _done(self):
        self.result = True
        self.destroy()


class EmergencyCardDialog(_Modal):
    """Opcje karty awaryjnej (PDF): nowy kod odzyskiwania na karcie, miejsce na ręczne wpisanie hasła głównego."""

    def __init__(self, master, has_recovery: bool):
        super().__init__(master, _("Karta awaryjna"), 560, 400)
        ctk.CTkLabel(self, text=_("🖨 Karta awaryjna"), font=FONT_TITLE).pack(anchor="w", padx=20, pady=(16, 4))
        ctk.CTkLabel(self, text=_("Jedna kartka A4 z tym, czego Ty lub bliscy potrzebujecie, żeby dostać się do sejfu: "
                                  "gdzie jest sejf, co jest potrzebne do otwarcia i co zrobić po zapomnieniu hasła. "
                                  "Wydrukuj ją i schowaj w bezpiecznym miejscu."),
                     font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, wraplength=510, justify="left").pack(anchor="w", padx=20)
        self.new_code = ctk.BooleanVar(value=not has_recovery)
        ctk.CTkCheckBox(self, text=_("Utwórz nowy kod odzyskiwania i umieść go na karcie"),
                        variable=self.new_code).pack(anchor="w", padx=20, pady=(16, 2))
        ctk.CTkLabel(self, text=(_("Dotychczasowy kod przestanie działać – zostanie ten z karty.") if has_recovery else
                                 _("Sejf nie ma jeszcze kodu odzyskiwania – zalecamy go utworzyć.")),
                     font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, wraplength=490, justify="left").pack(anchor="w", padx=48)
        self.password_box = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(self, text=_("Dodaj pole na ręczne wpisanie hasła głównego"),
                        variable=self.password_box).pack(anchor="w", padx=20, pady=(12, 2))
        ctk.CTkLabel(self, text=_("KeyStead nigdy nie drukuje hasła głównego – możesz je dopisać długopisem."),
                     font=FONT_SMALL, text_color=COLOR_TEXT_MUTED).pack(anchor="w", padx=48)
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=(20, 12), side="bottom")
        ctk.CTkButton(row, text=_("Anuluj"), width=90, fg_color=COLOR_CARD_DARK, command=self.destroy).pack(side="right")
        ctk.CTkButton(row, text=_("Zapisz PDF…"), width=130, fg_color=COLOR_PRIMARY,
                      command=self._ok).pack(side="right", padx=8)

    def _ok(self):
        self.result = {"new_code": bool(self.new_code.get()), "password_box": bool(self.password_box.get())}
        self.destroy()


class PasswordPrompt(_Modal):
    """Pojedyncze pole z hasłem (np. potwierdzenie hasła głównego, hasło do klucza firmy) albo kod odzyskiwania."""

    def __init__(self, master, title: str, prompt: str, secret: bool = True):
        super().__init__(master, title, 460, 210)
        ctk.CTkLabel(self, text=prompt, font=FONT_BODY, wraplength=420, justify="left").pack(anchor="w", padx=20, pady=(18, 8))
        self.entry = ctk.CTkEntry(self, show="•" if secret else "", height=36)
        self.entry.pack(fill="x", padx=20)
        self.entry.bind("<Return>", lambda e: self._ok())
        ctk.CTkButton(self, text="OK", fg_color=COLOR_PRIMARY, command=self._ok).pack(anchor="e", padx=20, pady=16)
        self.after(200, self.entry.focus_set)

    def _ok(self):
        self.result = self.entry.get()
        self.destroy()


class NewPasswordDialog(_Modal):
    """Nowe hasło główne (po odzyskaniu dostępu) – z kontrolą siły jak przy zmianie hasła."""

    def __init__(self, master, min_score: int = 0, intro: str = ""):
        super().__init__(master, _("Nowe hasło główne"), 480, 330)
        self.min_score = min_score
        ctk.CTkLabel(self, text=_("🔑 Ustaw nowe hasło główne"), font=FONT_SUBTITLE).pack(anchor="w", padx=20, pady=(16, 4))
        if intro:
            ctk.CTkLabel(self, text=intro, font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, wraplength=430,
                         justify="left").pack(anchor="w", padx=20)
        self.p1 = ctk.CTkEntry(self, show="•", placeholder_text=_("Nowe hasło główne..."), height=34)
        self.p1.pack(fill="x", padx=20, pady=(12, 4))
        self.p2 = ctk.CTkEntry(self, show="•", placeholder_text=_("Powtórz hasło..."), height=34)
        self.p2.pack(fill="x", padx=20, pady=4)
        self.err = ctk.CTkLabel(self, text="", text_color=COLOR_DANGER, font=FONT_SMALL, wraplength=430)
        self.err.pack(anchor="w", padx=20)
        ctk.CTkButton(self, text=_("Ustaw hasło"), fg_color=COLOR_SUCCESS, command=self._ok).pack(anchor="e", padx=20, pady=10)
        self.p2.bind("<Return>", lambda e: self._ok())
        self.after(200, self.p1.focus_set)

    def _ok(self):
        p1, p2 = self.p1.get(), self.p2.get()
        if p1 != p2:
            self.err.configure(text=_("Hasła nie są identyczne."))
            return
        allowed, msg = check_master_password(p1)
        if not allowed:
            self.err.configure(text=msg)
            return
        if self.min_score and evaluate_password_strength(p1)["score"] < self.min_score:
            self.err.configure(text=_("Polityka firmy wymaga silniejszego hasła głównego."))
            return
        self.result = p1
        self.destroy()


# --------------------------------------------------------------------- narzędzia administratora firmy
class AdminRecoveryTools(ctk.CTkFrame):
    """Panel w szufladzie: klucz odzyskiwania firmy i odzyskanie dostępu użytkownika (plik .ksrecovery z panelu)."""

    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent")
        self.pack(fill="both", expand=True)
        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.pack(fill="both", expand=True)

        c1 = ctk.CTkFrame(scroll, fg_color=COLOR_CARD_DARK, corner_radius=10)
        c1.pack(fill="x", pady=6, ipady=6)
        ctk.CTkLabel(c1, text=_("🔑 Klucz odzyskiwania firmy"), font=FONT_SUBTITLE).pack(anchor="w", padx=15, pady=(8, 2))
        ctk.CTkLabel(c1, text=_("Tworzy parę kluczy. Klucz PRYWATNY zapisz w bezpiecznym miejscu (zaszyfrowany hasłem) – "
                                "bez niego nie odzyskasz dostępu żadnemu pracownikowi. Klucz PUBLICZNY wklej w panelu serwera: "
                                "Ustawienia → Odzyskiwanie dostępu."),
                     font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, wraplength=470, justify="left").pack(anchor="w", padx=15)
        ctk.CTkButton(c1, text=_("Utwórz klucz odzyskiwania firmy…"), fg_color=COLOR_PRIMARY,
                      command=self._create_key).pack(anchor="w", padx=15, pady=10)
        self.pub_box = ctk.CTkTextbox(c1, height=70, font=(FONT_MONO, 12))
        self.pub_info = ctk.CTkLabel(c1, text="", font=FONT_SMALL, text_color=COLOR_SUCCESS, wraplength=470, justify="left")

        c2 = ctk.CTkFrame(scroll, fg_color=COLOR_CARD_DARK, corner_radius=10)
        c2.pack(fill="x", pady=6, ipady=6)
        ctk.CTkLabel(c2, text=_("🔑 Odzyskaj dostęp użytkownika"), font=FONT_SUBTITLE).pack(anchor="w", padx=15, pady=(8, 2))
        ctk.CTkLabel(c2, text=_("1. W panelu serwera (karta użytkownika) pobierz pakiet odzyskiwania.  2. Wybierz go tutaj razem "
                                "z plikiem klucza firmy.  3. Wgraj w panelu plik wyniku i przekaż użytkownikowi hasło tymczasowe."),
                     font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, wraplength=470, justify="left").pack(anchor="w", padx=15)
        ctk.CTkButton(c2, text=_("Odzyskaj dostęp użytkownika…"), fg_color=COLOR_PRIMARY,
                      command=self._recover_user).pack(anchor="w", padx=15, pady=10)
        self.result_info = ctk.CTkLabel(c2, text="", font=FONT_BODY, text_color=COLOR_TEXT_PRIMARY, wraplength=470,
                                        justify="left")
        self.result_info.pack(anchor="w", padx=15, pady=(0, 6))

    def _create_key(self):
        p1 = PasswordPrompt(self, _("Hasło do klucza firmy"), _("Ustaw hasło chroniące klucz prywatny (min. 12 znaków):")).wait()
        if not p1:
            return
        p2 = PasswordPrompt(self, _("Hasło do klucza firmy"), _("Powtórz hasło:")).wait()
        if p1 != p2:
            messagebox.showerror(_("Klucz firmy"), _("Hasła nie są identyczne."))
            return
        try:
            public, key_file = generate_org_keypair(p1)
        except CryptoError as e:
            messagebox.showerror(_("Klucz firmy"), str(e))
            return
        path = filedialog.asksaveasfilename(title=_("Zapisz klucz prywatny odzyskiwania firmy"), defaultextension=".ksorgkey",
                                            initialfile=_("KeyStead - klucz odzyskiwania firmy.ksorgkey"),
                                            filetypes=[(_("Klucz odzyskiwania KeyStead"), "*.ksorgkey")])
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump(key_file, f, indent=2)
        self.pub_box.pack(fill="x", padx=15, pady=(0, 6))
        self.pub_box.delete("1.0", "end")
        self.pub_box.insert("1.0", public)
        self.pub_info.configure(text=_("✅ Zapisano klucz prywatny. Odcisk klucza: {key_id}\n"
                                       "Skopiuj powyższy klucz publiczny do panelu serwera. Zrób kopię pliku klucza!",
                                       key_id=key_file["key_id"]))
        self.pub_info.pack(anchor="w", padx=15, pady=(0, 8))

    def _recover_user(self):
        pkg_path = filedialog.askopenfilename(title=_("Pakiet odzyskiwania z panelu serwera"),
                                              filetypes=[(_("Pakiet odzyskiwania"), "*.ksrecovery"), (_("Wszystkie pliki"), "*.*")])
        if not pkg_path:
            return
        key_path = filedialog.askopenfilename(title=_("Plik klucza odzyskiwania firmy"),
                                              filetypes=[(_("Klucz odzyskiwania KeyStead"), "*.ksorgkey"), (_("Wszystkie pliki"), "*.*")])
        if not key_path:
            return
        passphrase = PasswordPrompt(self, _("Klucz firmy"), _("Hasło do klucza odzyskiwania firmy:")).wait()
        if not passphrase:
            return
        try:
            with open(pkg_path, "r", encoding="utf-8") as f:
                package = json.load(f)
            with open(key_path, "r", encoding="utf-8") as f:
                key_file = json.load(f)
            result, temp_password = build_recovery_result(package, key_file, passphrase)
        except (OSError, ValueError, KeyError, CryptoError) as e:
            messagebox.showerror(_("Odzyskiwanie dostępu"), str(e))
            return
        out = filedialog.asksaveasfilename(title=_("Zapisz wynik do wgrania w panelu"), defaultextension=".ksreset",
                                           initialfile=_("wynik-{user}.ksreset", user=package.get("user", _("uzytkownik"))),
                                           filetypes=[(_("Wynik odzyskiwania"), "*.ksreset")])
        if not out:
            return
        with open(out, "w", encoding="utf-8") as f:
            json.dump(result, f)
        self.result_info.configure(text=_("✅ Gotowe dla: {user}\n"
                                          "Hasło tymczasowe:  {password}\n"
                                          "Wgraj plik wyniku w panelu serwera i przekaż hasło użytkownikowi (np. telefonicznie). "
                                          "Przy odblokowaniu aplikacja wymusi ustawienie nowego hasła.",
                                          user=package.get("display_name") or package.get("user"), password=temp_password))


def build_recovery_result(package: dict, key_file: dict, passphrase: str):
    """Pakiet z panelu + klucz firmy → (wynik do wgrania w panelu, hasło tymczasowe)."""
    if package.get("type") != "keystead-recovery-package":
        raise CryptoError(_("To nie jest pakiet odzyskiwania z panelu KeyStead."))
    private = load_org_private_key(key_file, passphrase)
    plaintext, ring = unseal_with_org_key(base64.b64decode(package["blob"], validate=True), private)
    data = json.loads(plaintext.decode("utf-8"))
    settings = data.setdefault("settings", {})
    settings[FORCE_CHANGE_KEY] = True                 # aplikacja wymusi ustawienie własnego hasła
    data["revision"] = int(data.get("revision", 0) or 0) + 1  # nowa treść – nie „podsunięta stara wersja”
    temp_password = generate_password(length=16, use_symbols=False)
    blob = seal(json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8"), temp_password, None, ring)
    result = {"type": "keystead-recovery-result", "version": 1, "user": package["user"],
              "base_version": int(package["vault_version"]),
              "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "blob": base64.b64encode(blob).decode("ascii")}
    return result, temp_password
