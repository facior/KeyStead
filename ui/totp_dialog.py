"""
Okna 2FA użytkownika przy dołączaniu urządzenia do serwera firmy:
- ask_code: kod z aplikacji uwierzytelniającej (kolejne urządzenia),
- setup: konfiguracja 2FA przy pierwszym urządzeniu (klucz do wpisania + potwierdzenie kodem).
"""

from typing import Optional

import customtkinter as ctk

from core.i18n import N_, _, _n
from ui.theme import (FONT_MONO, COLOR_CARD_DARK, COLOR_PRIMARY, COLOR_PRIMARY_HOVER, COLOR_TEXT_MUTED, FONT_BODY, FONT_BODY_BOLD,
                      FONT_SMALL, FONT_SUBTITLE)


class TotpDialog(ctk.CTkToplevel):
    def __init__(self, parent, title: str):
        super().__init__(parent)
        self.title(title)
        self.resizable(False, False)
        self.transient(parent.winfo_toplevel())
        self.result: Optional[str] = None
        self.protocol("WM_DELETE_WINDOW", self._cancel)
        self.body = ctk.CTkFrame(self, fg_color="transparent")
        self.body.pack(fill="both", expand=True, padx=22, pady=18)

    def _code_row(self):
        self.code_entry = ctk.CTkEntry(self.body, placeholder_text="000000", font=(FONT_MONO, 18, "bold"),
                                       justify="center", width=180)
        self.code_entry.pack(pady=(4, 10))
        self.code_entry.bind("<Return>", lambda e: self._ok())
        row = ctk.CTkFrame(self.body, fg_color="transparent")
        row.pack(fill="x")
        ctk.CTkButton(row, text=_("Anuluj"), fg_color=COLOR_CARD_DARK, width=100, command=self._cancel).pack(side="left")
        ctk.CTkButton(row, text=_("Potwierdź"), fg_color=COLOR_PRIMARY, hover_color=COLOR_PRIMARY_HOVER, width=120,
                      command=self._ok).pack(side="right")

    def _ok(self):
        code = self.code_entry.get().strip().replace(" ", "")
        if code.isdigit() and len(code) == 6:
            self.result = code
            self.destroy()
        else:
            self.code_entry.configure(border_color="#f43f5e")

    def _cancel(self):
        self.result = None
        self.destroy()

    def _run(self) -> Optional[str]:
        self.update_idletasks()
        self.after(100, lambda: self.winfo_exists() and (self.grab_set(), self.code_entry.focus_set()))
        self.wait_window()
        return self.result

    @classmethod
    def ask_code(cls, parent, message: str) -> Optional[str]:
        dlg = cls(parent, _("Kod 2FA"))
        ctk.CTkLabel(dlg.body, text=_("🔐 Wymagany kod 2FA"), font=FONT_SUBTITLE).pack(anchor="w")
        ctk.CTkLabel(dlg.body, text=message + "\n\n" + _("Wpisz 6-cyfrowy kod z aplikacji uwierzytelniającej:"),
                     font=FONT_BODY, wraplength=360, justify="left").pack(anchor="w", pady=(4, 6))
        dlg._code_row()
        return dlg._run()

    @classmethod
    def setup(cls, parent, secret: str, uri: str) -> Optional[str]:
        dlg = cls(parent, _("Włącz logowanie dwuskładnikowe"))
        ctk.CTkLabel(dlg.body, text=_("🔐 Twoja firma wymaga 2FA"), font=FONT_SUBTITLE).pack(anchor="w")
        ctk.CTkLabel(
            dlg.body,
            text=_("1. Otwórz aplikację uwierzytelniającą (Google Authenticator, Microsoft Authenticator, Aegis…).\n"
                   "2. Wybierz „Dodaj konto” → „Wpisz klucz ręcznie” i wpisz poniższy klucz.\n"
                   "3. Wpisz 6-cyfrowy kod, który pokaże aplikacja."),
            font=FONT_BODY, wraplength=420, justify="left").pack(anchor="w", pady=(4, 8))
        ctk.CTkLabel(dlg.body, text=_("Klucz:"), font=FONT_BODY_BOLD).pack(anchor="w")
        key = ctk.CTkEntry(dlg.body, width=420, font=(FONT_MONO, 14))
        key.insert(0, " ".join(secret[i:i + 4] for i in range(0, len(secret), 4)))
        key.configure(state="readonly")
        key.pack(pady=(2, 6))
        ctk.CTkLabel(dlg.body, text=_("Link do aplikacji (jeśli obsługuje wklejanie otpauth://):"),
                     font=FONT_SMALL, text_color=COLOR_TEXT_MUTED).pack(anchor="w")
        link = ctk.CTkEntry(dlg.body, width=420, font=FONT_SMALL)
        link.insert(0, uri)
        link.configure(state="readonly")
        link.pack(pady=(2, 10))
        ctk.CTkLabel(dlg.body, text=_("Kod z aplikacji:"), font=FONT_BODY_BOLD).pack(anchor="w")
        dlg._code_row()
        return dlg._run()
