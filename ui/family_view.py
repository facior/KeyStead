"""
Wtyczka „Udostępnianie domownikom”: wizytówka, lista domowników, odbieranie paczek i wysyłanie wpisów.
"""

import os
from tkinter import filedialog, messagebox
from typing import Callable

import customtkinter as ctk

from core import family_share as fs
from core.i18n import _
from core.vault import Vault, VaultEntry
from ui.drawer_views import layout_frame
from ui.plugin_dialogs import _Dialog
from ui.theme import (COLOR_CARD_DARK, COLOR_PANEL_DARK, COLOR_PRIMARY, COLOR_SUCCESS, COLOR_TEXT_ACCENT,
                      COLOR_TEXT_MUTED, COLOR_TEXT_PRIMARY, FONT_BODY, FONT_BODY_BOLD, FONT_SMALL,
                      FONT_SUBTITLE)

CARD_EXT, PACKAGE_EXT = ".kscard", ".ksshare"
QR_LIMIT = 2000  # dłuższy tekst nie zmieści się czytelnie w kodzie QR


def _clipboard_text(widget) -> str:
    try:
        return widget.clipboard_get()
    except Exception:
        return ""


def _read_file(widget, title: str, ext: str) -> str:
    path = filedialog.askopenfilename(title=title, parent=widget.winfo_toplevel(),
                                      filetypes=[(_("Pliki KeyStead"), f"*{ext}"), (_("Wszystkie pliki"), "*")])
    if not path:
        return ""
    try:
        if os.path.getsize(path) > fs.MAX_PACKAGE_CHARS:
            raise ValueError(_("Plik jest zbyt duży."))
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except (OSError, UnicodeDecodeError, ValueError) as e:
        messagebox.showerror(title, str(e), parent=widget.winfo_toplevel())
        return ""


def _qr_text(widget) -> str:
    """Tekst z kodu QR na obrazku w schowku (np. zrzut Win+Shift+S zdjęcia wizytówki z telefonu)."""
    from PIL import Image, ImageGrab
    from core import qr
    image = ImageGrab.grabclipboard()
    if not isinstance(image, Image.Image):
        messagebox.showinfo(_("Kod QR"), _("W schowku nie ma obrazka. Zrób zrzut kodu QR klawiszami Win+Shift+S "
                                           "i kliknij ponownie."), parent=widget.winfo_toplevel())
        return ""
    codes = [c for c in qr.read_codes(image) if c.startswith((fs.CONTACT_PREFIX, fs.PACKAGE_PREFIX))]
    if not codes:
        messagebox.showwarning(_("Kod QR"), _("Na obrazku nie ma kodu QR z KeyStead."), parent=widget.winfo_toplevel())
        return ""
    return codes[0]


def _save_text(widget, title: str, text: str, filename: str, ext: str) -> str:
    safe = "".join(c for c in filename if c not in '<>:"/\\|?*')[:80]
    path = filedialog.asksaveasfilename(title=title, defaultextension=ext, initialfile=safe + ext,
                                        filetypes=[(_("Pliki KeyStead"), f"*{ext}")], parent=widget.winfo_toplevel())
    if path:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    return path


class FamilyDrawerView(ctk.CTkFrame):
    def __init__(self, parent, vault: Vault, on_saved: Callable[[], None], on_received: Callable[[VaultEntry], None],
                 copy_text: Callable[[str], None]):
        super().__init__(parent, fg_color="transparent")
        self.pack(fill="both", expand=True)
        self.vault, self.on_saved, self.on_received, self.copy_text = vault, on_saved, on_received, copy_text
        self.scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.scroll.pack(fill="both", expand=True)
        self.render()

    def _card(self, title: str, text: str = ""):
        card = ctk.CTkFrame(self.scroll, fg_color=COLOR_CARD_DARK, corner_radius=10)
        card.pack(fill="x", pady=5, ipady=4)
        ctk.CTkLabel(card, text=title, font=FONT_SUBTITLE, text_color=COLOR_TEXT_PRIMARY).pack(anchor="w", padx=14, pady=(10, 2))
        if text:
            ctk.CTkLabel(card, text=text, font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, wraplength=440,
                         justify="left").pack(anchor="w", padx=14, pady=(0, 4))
        return card

    def render(self):
        for w in self.scroll.winfo_children():
            w.destroy()
        created = not isinstance(self.vault.settings.get(fs.IDENTITY_KEY), dict)
        ident = fs.identity(self.vault.settings, self.vault.name)
        if created:
            self.on_saved()  # nowa para kluczy musi trafić do zaszyfrowanego sejfu od razu

        # --- Odbierz
        card = self._card(_("📥 Odbierz wpis od domownika"),
                          _("Wklej paczkę, którą dostałeś (tekst zaczynający się od „ksshare1:”), wczytaj plik albo "
                            "zrób zrzut kodu QR."))
        row = layout_frame(card)
        row.pack(fill="x", padx=14, pady=(2, 10))
        for label, source in ((_("📋 Wklej"), "clipboard"), (_("📂 Z pliku…"), "file"), (_("📷 Z kodu QR"), "qr")):
            ctk.CTkButton(row, text=label, width=110, height=28, font=FONT_SMALL,
                          fg_color=COLOR_PRIMARY if source == "clipboard" else COLOR_PANEL_DARK,
                          command=lambda s=source: self._receive(s)).pack(side="left", padx=(0, 6))

        # --- Moja wizytówka
        card = self._card(_("📇 Moja wizytówka"),
                          _("Daj ją domownikom – dzięki niej mogą wysyłać Ci hasła, które otworzy tylko Twój sejf. "
                            "Wizytówka nie zawiera żadnych haseł."))
        name_row = layout_frame(card)
        name_row.pack(fill="x", padx=14, pady=2)
        ctk.CTkLabel(name_row, text=_("Twoje imię:"), font=FONT_BODY).pack(side="left")
        self.name_entry = ctk.CTkEntry(name_row, width=200)
        self.name_entry.insert(0, ident.get("name") or self.vault.name)
        self.name_entry.pack(side="left", padx=8)
        ctk.CTkLabel(card, text=_("Odcisk: {fp}", fp=fs.fingerprint(fs._unb64(ident["public"]))), font=FONT_BODY_BOLD,
                     text_color=COLOR_TEXT_ACCENT).pack(anchor="w", padx=14, pady=(4, 2))
        row = layout_frame(card)
        row.pack(fill="x", padx=14, pady=(4, 10))
        ctk.CTkButton(row, text=_("📋 Kopiuj wizytówkę"), width=150, height=28, font=FONT_SMALL, fg_color=COLOR_PRIMARY,
                      command=lambda: self.copy_text(self._my_card())).pack(side="left")
        ctk.CTkButton(row, text=_("💾 Zapisz plik…"), width=110, height=28, font=FONT_SMALL, fg_color=COLOR_PANEL_DARK,
                      command=lambda: _save_text(self, _("Zapisz wizytówkę"), self._my_card(),
                                                 _("Wizytówka KeyStead"), CARD_EXT)).pack(side="left", padx=6)
        ctk.CTkButton(row, text=_("🔳 Kod QR"), width=90, height=28, font=FONT_SMALL, fg_color=COLOR_PANEL_DARK,
                      command=lambda: TextQrDialog(self, _("Moja wizytówka"), self._my_card(),
                                                   _("Domownik robi zdjęcie / zrzut tego kodu i wczytuje go w swoim "
                                                     "KeyStead (Domownicy → Dodaj → Z kodu QR)."))).pack(side="left")

        # --- Domownicy
        people = fs.contacts(self.vault.settings)
        card = self._card(_("👪 Domownicy ({count})", count=len(people)),
                          _("Dodaj wizytówkę domownika. Porównajcie odciski (np. przez telefon) – wtedy masz pewność, "
                            "że to naprawdę jego klucz."))
        for c in people:
            r = layout_frame(card)
            r.pack(fill="x", padx=14, pady=1)
            ctk.CTkLabel(r, text=f"👤 {c.name}", font=FONT_BODY_BOLD).pack(side="left")
            ctk.CTkLabel(r, text=f"  {c.fingerprint}", font=FONT_SMALL, text_color=COLOR_TEXT_MUTED).pack(side="left")
            ctk.CTkButton(r, text=_("Usuń"), width=60, height=24, font=FONT_SMALL, fg_color=COLOR_PANEL_DARK,
                          command=lambda p=c.public, n=c.name: self._remove(p, n)).pack(side="right")
        row = layout_frame(card)
        row.pack(fill="x", padx=14, pady=(6, 10))
        ctk.CTkLabel(row, text=_("Dodaj:"), font=FONT_BODY).pack(side="left", padx=(0, 6))
        for label, source in ((_("📋 Wklej"), "clipboard"), (_("📂 Z pliku…"), "file"), (_("📷 Z kodu QR"), "qr")):
            ctk.CTkButton(row, text=label, width=100, height=28, font=FONT_SMALL, fg_color=COLOR_PANEL_DARK,
                          command=lambda s=source: self._add_contact(s)).pack(side="left", padx=(0, 6))

    def _my_card(self) -> str:
        name = self.name_entry.get().strip()
        before = fs.identity(self.vault.settings).get("name")
        card = fs.my_card(self.vault.settings, name or self.vault.name)
        if fs.identity(self.vault.settings).get("name") != before:
            self.on_saved()
        return card

    def _text_from(self, source: str, ext: str) -> str:
        if source == "clipboard":
            return _clipboard_text(self)
        if source == "file":
            return _read_file(self, _("Wybierz plik"), ext)
        return _qr_text(self)

    def _add_contact(self, source: str):
        text = self._text_from(source, CARD_EXT)
        if not text:
            return
        try:
            contact = fs.parse_card(text)
        except fs.ShareError as e:
            messagebox.showerror(_("Wizytówka"), str(e), parent=self.winfo_toplevel())
            return
        if not messagebox.askyesno(_("Nowy domownik"), _("Dodać „{name}”?\n\nOdcisk klucza: {fp}\nPorównaj go z odciskiem "
                                                           "widocznym w KeyStead tej osoby.", name=contact.name,
                                                           fp=contact.fingerprint), parent=self.winfo_toplevel()):
            return
        if not fs.add_contact(self.vault.settings, contact):
            messagebox.showinfo(_("Wizytówka"), _("To Twoja własna wizytówka."), parent=self.winfo_toplevel())
            return
        self.on_saved()
        self.render()

    def _remove(self, public: str, name: str):
        if messagebox.askyesno(_("Domownicy"), _("Usunąć „{name}” z domowników? Hasła już wysłane zostają u tej osoby.",
                                                name=name), parent=self.winfo_toplevel()):
            fs.remove_contact(self.vault.settings, public)
            self.on_saved()
            self.render()

    def _receive(self, source: str):
        text = self._text_from(source, PACKAGE_EXT)
        if not text:
            return
        try:
            received = fs.open_package(self.vault.settings, text)
        except fs.ShareError as e:
            messagebox.showerror(_("Odbierz wpis"), str(e), parent=self.winfo_toplevel())
            return
        title = received.payload.get("title") or _("Bez tytułu")
        update = received.share_id in (self.vault.settings.get(fs.RECEIVED_KEY) or {})
        if received.known_sender is not None:
            who = _("Od: {name} ✓ (domownik)", name=received.known_sender.name)
            question = _("{who}\nWpis: {title}\n\n{action}", who=who, title=title,
                         action=_("Zaktualizować wpis w sejfie?") if update else _("Dodać ten wpis do sejfu?"))
            icon = "question"
        else:
            question = _("⚠️ Nadawca NIE jest na liście domowników.\nPodaje się za: „{name}” · odcisk {fp}\nWpis: {title}\n\n"
                         "Dodaj wpis tylko, jeśli wiesz, kto go wysłał.", name=received.sender_name or "?",
                         fp=fs.fingerprint(fs._unb64(received.sender_public)), title=title)
            icon = "warning"
        if not messagebox.askyesno(_("Odbierz wpis"), question, icon=icon, parent=self.winfo_toplevel()):
            return
        entry = fs.apply_received(self.vault.settings, self.vault, received)
        self.on_saved()
        self.on_received(entry)


class SendShareDialog(_Dialog):
    """Udostępnij wpis domownikowi: paczka jako tekst, plik albo kod QR."""

    def __init__(self, master, vault: Vault, entry: VaultEntry, sender_name: str, copy_text: Callable[[str], None],
                 on_sent: Callable[[], None]):
        super().__init__(master, _("Udostępnij – {title}", title=entry.title))
        self.vault, self.entry, self.sender_name = vault, entry, sender_name
        self.copy_text, self.on_sent = copy_text, on_sent
        self.people = fs.contacts(vault.settings)
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(padx=16, pady=12, fill="both", expand=True)
        if not self.people:
            ctk.CTkLabel(body, text=_("Nie masz jeszcze domowników. Otwórz „👪 Domownicy” i dodaj wizytówkę osoby, "
                                      "której chcesz wysłać hasło."), wraplength=380, justify="left").pack(anchor="w")
            ctk.CTkButton(body, text=_("Zamknij"), command=self.destroy, fg_color=COLOR_CARD_DARK).pack(anchor="e", pady=(12, 0))
            self.center_on(master)
            return
        ctk.CTkLabel(body, text=_("Komu wysłać „{title}”?", title=entry.title), font=FONT_BODY_BOLD).pack(anchor="w")
        names = [p.name for p in self.people]
        self.person = ctk.CTkComboBox(body, values=names, state="readonly", command=lambda _v: self._hint())
        self.person.set(names[0])
        self.person.pack(fill="x", pady=(4, 6))
        self.hint = ctk.CTkLabel(body, text="", font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, wraplength=380, justify="left")
        self.hint.pack(anchor="w")
        self.notes = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(body, text=_("Dołącz notatki wpisu"), variable=self.notes).pack(anchor="w", pady=(6, 2))
        ctk.CTkLabel(body, text=_("Paczkę wyślij czymkolwiek (Messenger, e-mail, SMS, pendrive) – otworzy ją tylko "
                                  "KeyStead tej osoby."), font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, wraplength=380,
                     justify="left").pack(anchor="w", pady=(6, 6))
        row = ctk.CTkFrame(body, fg_color="transparent")
        row.pack(fill="x")
        ctk.CTkButton(row, text=_("📋 Kopiuj paczkę"), width=130, fg_color=COLOR_PRIMARY,
                      command=lambda: self._send("copy")).pack(side="left")
        ctk.CTkButton(row, text=_("💾 Plik…"), width=80, fg_color=COLOR_PANEL_DARK,
                      command=lambda: self._send("file")).pack(side="left", padx=6)
        ctk.CTkButton(row, text=_("🔳 Kod QR"), width=90, fg_color=COLOR_PANEL_DARK,
                      command=lambda: self._send("qr")).pack(side="left")
        self.status = ctk.CTkLabel(body, text="", font=FONT_SMALL, text_color=COLOR_SUCCESS, wraplength=380, justify="left")
        self.status.pack(anchor="w", pady=(8, 0))
        ctk.CTkButton(body, text=_("Zamknij"), width=90, fg_color=COLOR_CARD_DARK, command=self.destroy).pack(anchor="e", pady=(10, 0))
        self._hint()
        self.center_on(master)

    def _contact(self) -> fs.Contact:
        return next(p for p in self.people if p.name == self.person.get())

    def _hint(self):
        contact = self._contact()
        before = next((i for i in fs.shared_with(self.vault.settings, self.entry.id) if i.get("public") == contact.public), None)
        self.hint.configure(text=_("Wysłano już wcześniej – nowa paczka zaktualizuje wpis u tej osoby.") if before else
                            _("Odcisk klucza: {fp}", fp=contact.fingerprint))

    def _send(self, how: str):
        contact = self._contact()
        share_id = fs.share_id_for(self.vault.settings, self.entry.id, contact)
        package = fs.seal_package(self.vault.settings, self.sender_name, contact,
                                  fs.entry_payload(self.entry, include_notes=bool(self.notes.get())), share_id)
        if how == "copy":
            self.copy_text(package)
            done = _("Skopiowano – wklej paczkę w wiadomości do: {name}.", name=contact.name)
        elif how == "file":
            if not _save_text(self, _("Zapisz paczkę"), package, _("Hasło dla {name} – {title}", name=contact.name,
                                                                    title=self.entry.title), PACKAGE_EXT):
                return
            done = _("Zapisano plik – wyślij go do: {name}.", name=contact.name)
        else:
            if len(package) > QR_LIMIT:
                messagebox.showinfo(_("Kod QR"), _("Ten wpis jest za długi na kod QR – użyj „Kopiuj paczkę” albo pliku "
                                                   "(np. bez notatek)."), parent=self)
                return
            TextQrDialog(self, _("Paczka dla: {name}", name=contact.name), package,
                         _("Domownik robi zrzut tego kodu i wczytuje go: Domownicy → Odbierz → Z kodu QR."))
            done = _("Pokazano kod QR dla: {name}.", name=contact.name)
        fs.remember_sent(self.vault.settings, self.entry.id, contact, share_id)
        self.on_sent()
        self.status.configure(text=done)
        self._hint()


class TextQrDialog(_Dialog):
    """Kod QR z tekstem (wizytówka albo paczka)."""

    def __init__(self, master, title: str, text: str, hint: str):
        from core import qr
        super().__init__(master, title)
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(padx=16, pady=12)
        ctk.CTkLabel(body, text=title, font=FONT_SUBTITLE).pack()
        img = qr.make_image(text, scale=4)
        size = min(380, img.width)
        self._image = ctk.CTkImage(light_image=img, dark_image=img, size=(size, size))
        ctk.CTkLabel(body, text="", image=self._image).pack(pady=8)
        ctk.CTkLabel(body, text=hint, font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, wraplength=360,
                     justify="left").pack()
        ctk.CTkButton(body, text=_("Zamknij"), fg_color=COLOR_CARD_DARK, command=self.destroy).pack(pady=(8, 0))
        self.center_on(master)
