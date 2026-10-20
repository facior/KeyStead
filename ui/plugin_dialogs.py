"""
Okna wtyczek: hasło jako kod QR, wybrane znaki hasła i pływający panel z ulubionymi wpisami.
"""

import tkinter as tk
from typing import Callable, List, Optional

import customtkinter as ctk

from core import qr
from core.i18n import N_, _, _n
from core.totp_service import get_current_totp
from core.vault import Vault, VaultEntry
from ui.flat_button import FlatButton
from ui.theme import (FONT_FAMILY, FONT_MONO, COLOR_CARD_DARK, COLOR_PANEL_DARK, COLOR_PRIMARY, COLOR_SUCCESS, COLOR_TEXT_MUTED,
                      COLOR_TEXT_PRIMARY, COLOR_WARNING, FONT_BODY, FONT_BODY_BOLD, FONT_SMALL, FONT_SUBTITLE)

# Kolorowe hasło: cyfry i znaki specjalne wyróżnione (wtyczka „Kolorowe hasło”)
DIGIT_COLOR = "#60a5fa"
SYMBOL_COLOR = "#f59e0b"


def char_kind(ch: str) -> str:
    if ch.isdigit():
        return "digit"
    if ch.isalpha():
        return "letter"
    return "symbol"


def exclude_from_capture(window) -> None:
    """Okno z hasłem niewidoczne na zrzutach ekranu i w nagraniach (Windows 10 2004+). Bez efektu, gdy niedostępne."""
    try:
        import ctypes
        hwnd = ctypes.windll.user32.GetParent(window.winfo_id()) or window.winfo_id()
        ctypes.windll.user32.SetWindowDisplayAffinity(hwnd, 0x11)  # WDA_EXCLUDEFROMCAPTURE
    except Exception:
        pass


class _Dialog(ctk.CTkToplevel):
    def __init__(self, master, title: str):
        super().__init__(master)
        self.title(title)
        self.resizable(False, False)
        self.transient(master.winfo_toplevel())
        self.configure(fg_color=COLOR_PANEL_DARK)
        self.bind("<Escape>", lambda e: self.destroy())
        self.after(50, lambda: self.winfo_exists() and exclude_from_capture(self))

    def center_on(self, master):
        self.update_idletasks()
        top = master.winfo_toplevel()
        x = top.winfo_rootx() + (top.winfo_width() - self.winfo_width()) // 2
        y = top.winfo_rooty() + (top.winfo_height() - self.winfo_height()) // 3
        self.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        self.lift()
        self.focus_force()


class QrDialog(_Dialog):
    """Hasło (albo dane Wi-Fi) jako kod QR. Zamyka się samo – kod na ekranie to hasło na widoku."""
    LIFETIME = 60

    def __init__(self, master, entry: VaultEntry):
        super().__init__(master, _("Kod QR – {title}", title=entry.title))
        self._remaining = self.LIFETIME
        self._choices = []
        wifi = qr.wifi_payload(entry)
        if wifi:
            self._choices.append((_("Połącz z Wi-Fi"), wifi))
        if entry.password:
            self._choices.append((_("Samo hasło"), entry.password))

        body = ctk.CTkFrame(self, fg_color=COLOR_PANEL_DARK)
        body.pack(padx=18, pady=14)
        ctk.CTkLabel(body, text=entry.title, font=FONT_SUBTITLE, text_color=COLOR_TEXT_PRIMARY).pack()
        if len(self._choices) > 1:
            self.mode = ctk.CTkSegmentedButton(body, values=[label for label, _v in self._choices], command=self._show)
            self.mode.set(self._choices[0][0])
            self.mode.pack(pady=(6, 0))
        self.image_lbl = ctk.CTkLabel(body, text="")
        self.image_lbl.pack(pady=10)
        self.hint_lbl = ctk.CTkLabel(body, text="", font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, wraplength=300)
        self.hint_lbl.pack()
        self.timer_lbl = ctk.CTkLabel(body, text="", font=FONT_SMALL, text_color=COLOR_WARNING)
        self.timer_lbl.pack(pady=(4, 0))
        ctk.CTkButton(body, text=_("Zamknij"), fg_color=COLOR_CARD_DARK, command=self.destroy).pack(pady=(8, 0))

        self._show(self._choices[0][0])
        self._tick()
        self.center_on(master)

    def _show(self, label: str):
        payload = dict(self._choices)[label]
        img = qr.make_image(payload, scale=6)
        size = min(320, img.width)
        self._image = ctk.CTkImage(light_image=img, dark_image=img, size=(size, size))
        self.image_lbl.configure(image=self._image)
        self.hint_lbl.configure(text=_("Zeskanuj aparatem telefonu – telefon połączy się z siecią.")
                                if payload.startswith("WIFI:") else
                                _("Zeskanuj aparatem telefonu lub aplikacją do kodów QR, żeby przenieść hasło."))

    def _tick(self):
        if not self.winfo_exists():
            return
        if self._remaining <= 0:
            self.destroy()
            return
        self.timer_lbl.configure(text=_("Okno zamknie się za {seconds} s", seconds=self._remaining))
        self._remaining -= 1
        self.after(1000, self._tick)


class PickCharsDialog(_Dialog):
    """Wybrane znaki hasła (np. „podaj 3., 5. i 8. znak”) – reszta hasła pozostaje ukryta."""
    PER_ROW = 10

    def __init__(self, master, entry: VaultEntry, on_copy: Callable[[str, str], None]):
        super().__init__(master, _("Wybrane znaki – {title}", title=entry.title))
        self.password = entry.password
        self.on_copy = on_copy
        self.selected: List[int] = []
        self._buttons = []

        body = ctk.CTkFrame(self, fg_color=COLOR_PANEL_DARK)
        body.pack(padx=16, pady=12)
        ctk.CTkLabel(body, text=_("Kliknij numery znaków, o które prosi strona (np. 3, 5 i 8)."),
                     font=FONT_BODY, text_color=COLOR_TEXT_PRIMARY).pack(anchor="w")
        ctk.CTkLabel(body, text=_n(len(self.password), "Hasło ma {n} znak. Pozostałe znaki nie są pokazywane.",
                                   "Hasło ma {n} znaki. Pozostałe znaki nie są pokazywane.",
                                   "Hasło ma {n} znaków. Pozostałe znaki nie są pokazywane."),
                     font=FONT_SMALL, text_color=COLOR_TEXT_MUTED).pack(anchor="w", pady=(0, 6))

        grid = tk.Frame(body, bg=COLOR_PANEL_DARK)
        grid.pack(anchor="w")
        for i in range(len(self.password)):
            btn = ctk.CTkButton(grid, text=str(i + 1), width=40, height=40, font=FONT_BODY_BOLD,
                                fg_color=COLOR_CARD_DARK, command=lambda n=i: self._toggle(n))
            btn.grid(row=i // self.PER_ROW, column=i % self.PER_ROW, padx=2, pady=2)
            self._buttons.append(btn)

        type_row = tk.Frame(body, bg=COLOR_PANEL_DARK)
        type_row.pack(fill="x", pady=(8, 0))
        ctk.CTkLabel(type_row, text=_("albo wpisz numery:"), font=FONT_SMALL, text_color=COLOR_TEXT_MUTED).pack(side="left")
        self.numbers_entry = ctk.CTkEntry(type_row, width=140, placeholder_text="3, 5, 8")
        self.numbers_entry.pack(side="left", padx=6)
        self.numbers_entry.bind("<KeyRelease>", self._typed)

        self.result_lbl = ctk.CTkLabel(body, text="", font=(FONT_MONO, 22, "bold"), text_color=COLOR_SUCCESS)
        self.result_lbl.pack(anchor="w", pady=(10, 0))
        self.detail_lbl = ctk.CTkLabel(body, text="", font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, justify="left")
        self.detail_lbl.pack(anchor="w")

        actions = tk.Frame(body, bg=COLOR_PANEL_DARK)
        actions.pack(fill="x", pady=(10, 0))
        ctk.CTkButton(actions, text=_("Kopiuj wybrane znaki"), fg_color=COLOR_PRIMARY, command=self._copy).pack(side="left")
        ctk.CTkButton(actions, text=_("Wyczyść"), fg_color=COLOR_CARD_DARK, width=80,
                      command=lambda: self._set_selection([])).pack(side="left", padx=6)
        ctk.CTkButton(actions, text=_("Zamknij"), fg_color=COLOR_CARD_DARK, width=80, command=self.destroy).pack(side="right")
        self._render()
        self.center_on(master)

    def _toggle(self, index: int):
        sel = list(self.selected)
        if index in sel:
            sel.remove(index)
        else:
            sel.append(index)
        self._set_selection(sel)
        self.numbers_entry.delete(0, "end")
        self.numbers_entry.insert(0, ", ".join(str(i + 1) for i in self.selected))

    def _typed(self, event=None):
        numbers = []
        for part in self.numbers_entry.get().replace(";", ",").replace(" ", ",").split(","):
            if part.strip().isdigit():
                n = int(part) - 1
                if 0 <= n < len(self.password) and n not in numbers:
                    numbers.append(n)
        self._set_selection(numbers)

    def _set_selection(self, indexes: List[int]):
        self.selected = sorted(indexes)
        self._render()

    def _render(self):
        for i, btn in enumerate(self._buttons):
            on = i in self.selected
            btn.configure(text=f"{i + 1}\n{self._shown(self.password[i])}" if on else str(i + 1),
                          fg_color=COLOR_PRIMARY if on else COLOR_CARD_DARK, height=48 if on else 40)
        chars = [self._shown(self.password[i]) for i in self.selected]
        self.result_lbl.configure(text="  ".join(chars) if chars else "—")
        self.detail_lbl.configure(text="\n".join(_("{n}. znak: {char}", n=i + 1, char=self._shown(self.password[i]))
                                                 for i in self.selected))

    @staticmethod
    def _shown(ch: str) -> str:
        return "␣" if ch == " " else ch

    def _copy(self):
        if not self.selected:
            return
        self.on_copy("".join(self.password[i] for i in self.selected), _("Skopiowano wybrane znaki!"))


class PhoneHandoffDialog(_Dialog):
    """Hasło na telefon przez Wi-Fi: kod QR z adresem w sieci lokalnej, odliczanie, stan odbioru."""

    def __init__(self, master, entry: VaultEntry, poster: Callable[[Callable[[], None]], None]):
        from core.phone_handoff import HandoffError, HandoffServer, LIFETIME_SECONDS
        super().__init__(master, _("Hasło na telefon – {title}", title=entry.title))
        self._remaining = LIFETIME_SECONDS
        self.server = None
        body = ctk.CTkFrame(self, fg_color=COLOR_PANEL_DARK)
        body.pack(padx=18, pady=14)
        ctk.CTkLabel(body, text=_("📱 Zeskanuj kod aparatem telefonu"), font=FONT_SUBTITLE,
                     text_color=COLOR_TEXT_PRIMARY).pack()
        try:
            # Wątki serwera nie mogą wołać Tk – wyniki przechodzą przez kolejkę wątku interfejsu (poster)
            self.server = HandoffServer(entry.title, entry.password,
                                        on_fetched=lambda: poster(self._fetched),
                                        on_closed=lambda reason: poster(lambda: self._closed(reason))).start()
        except (HandoffError, OSError) as e:
            ctk.CTkLabel(body, text=_("Nie udało się uruchomić: {error}", error=e), font=FONT_BODY,
                         text_color=COLOR_WARNING, wraplength=320).pack(pady=12)
            ctk.CTkButton(body, text=_("Zamknij"), fg_color=COLOR_CARD_DARK, command=self.destroy).pack(pady=(4, 0))
            self.center_on(master)
            return
        img = qr.make_image(self.server.url, scale=6)
        self._image = ctk.CTkImage(light_image=img, dark_image=img, size=(min(300, img.width),) * 2)
        ctk.CTkLabel(body, text="", image=self._image).pack(pady=10)
        ctk.CTkLabel(body, text=_("Telefon musi być w tej samej sieci Wi-Fi co komputer. Hasło przejdzie zaszyfrowane – "
                                  "klucz jest tylko w tym kodzie. Przy pierwszym użyciu Windows może zapytać o zgodę "
                                  "na dostęp do sieci – kliknij „Zezwól”."),
                     font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, wraplength=320, justify="left").pack()
        self.status_lbl = ctk.CTkLabel(body, text="", font=FONT_BODY_BOLD, text_color=COLOR_WARNING)
        self.status_lbl.pack(pady=(8, 0))
        ctk.CTkButton(body, text=_("Zamknij"), fg_color=COLOR_CARD_DARK, command=self.destroy).pack(pady=(8, 0))
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self._tick()
        self.center_on(master)

    def _tick(self):
        if not self.winfo_exists() or self.server is None or self.server.fetched:
            return
        if self._remaining <= 0:
            return
        self.status_lbl.configure(text=_("Czekam na telefon… {seconds} s", seconds=self._remaining))
        self._remaining -= 1
        self.after(1000, self._tick)

    def _fetched(self):
        if self.winfo_exists():
            self.status_lbl.configure(text=_("✓ Telefon odebrał hasło"), text_color=COLOR_SUCCESS)
            self.after(2500, lambda: self.winfo_exists() and self.destroy())

    def _closed(self, reason: str):
        if self.winfo_exists() and reason in ("timeout", "attack"):
            self.status_lbl.configure(text=_("Czas minął – kod przestał działać.") if reason == "timeout" else
                                      _("Wykryto podejrzane próby w sieci – udostępnianie przerwane."),
                                      text_color=COLOR_WARNING)

    def destroy(self):
        if self.server is not None:
            self.server.on_closed = None
            self.server.close()
        super().destroy()


class SecureSendDialog(_Dialog):
    """Jednorazowy link do hasła: wybór pól, ważność, opcjonalne hasło do linku; lista wysłanych linków."""
    STATES = {"active": N_("czeka na otwarcie"), "opened": N_("✓ otwarty"), "revoked": N_("odwołany"),
              "burned": N_("zablokowany (błędne hasła)"), "expired": N_("wygasł"), "unknown": "…"}

    def __init__(self, master, entry: VaultEntry, session, settings, run_in_background, on_sent):
        from core import secure_send
        super().__init__(master, _("Bezpieczny link – {title}", title=entry.title))
        self.entry, self.session, self.settings = entry, session, settings
        self.run_in_background, self.on_sent = run_in_background, on_sent
        self.secure_send = secure_send

        body = ctk.CTkFrame(self, fg_color=COLOR_PANEL_DARK)
        body.pack(padx=16, pady=12, fill="both", expand=True)
        ctk.CTkLabel(body, text=_("Link otworzy się tylko raz, potem znika z serwera. Treść jest zaszyfrowana – "
                                  "serwer jej nie zna."), font=FONT_SMALL, text_color=COLOR_TEXT_MUTED,
                     wraplength=420, justify="left").pack(anchor="w")

        ctk.CTkLabel(body, text=_("Co wysłać:"), font=FONT_BODY_BOLD).pack(anchor="w", pady=(10, 2))
        self.include = {}
        row = tk.Frame(body, bg=COLOR_PANEL_DARK)
        row.pack(anchor="w")
        for key, label, default in (("title", _("Nazwa"), True), ("username", _("Login"), True),
                                    ("password", _("Hasło"), True), ("url", _("Adres"), True),
                                    ("notes", _("Notatka"), False)):
            value = getattr(entry, key)
            var = ctk.BooleanVar(value=default and bool(value))
            cb = ctk.CTkCheckBox(row, text=label, variable=var, width=70)
            if not value:
                cb.configure(state="disabled")
            cb.pack(side="left", padx=(0, 6))
            self.include[key] = var

        ctk.CTkLabel(body, text=_("Link ważny przez:"), font=FONT_BODY_BOLD).pack(anchor="w", pady=(10, 2))
        self._expiry = {_(label): hours for hours, label in secure_send.EXPIRY_CHOICES}
        self.expiry = ctk.CTkSegmentedButton(body, values=list(self._expiry))
        self.expiry.set(_("1 dzień"))
        self.expiry.pack(anchor="w")

        ctk.CTkLabel(body, text=_("Hasło do linku (opcjonalne):"), font=FONT_BODY_BOLD).pack(anchor="w", pady=(10, 2))
        self.password = ctk.CTkEntry(body, width=240, show="•", placeholder_text=_("przekaż je osobno, np. SMS-em"))
        self.password.pack(anchor="w")

        self.create_btn = ctk.CTkButton(body, text=_("✉ Utwórz link"), fg_color=COLOR_PRIMARY, command=self._create)
        self.create_btn.pack(anchor="w", pady=(12, 4))
        self.result = tk.Frame(body, bg=COLOR_PANEL_DARK)
        self.result.pack(fill="x")
        self.status_lbl = ctk.CTkLabel(body, text="", font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, wraplength=420,
                                       justify="left")
        self.status_lbl.pack(anchor="w")

        ctk.CTkLabel(body, text=_("Wysłane linki"), font=FONT_BODY_BOLD).pack(anchor="w", pady=(12, 2))
        self.sent_box = tk.Frame(body, bg=COLOR_PANEL_DARK)
        self.sent_box.pack(fill="x")
        ctk.CTkButton(body, text=_("Zamknij"), fg_color=COLOR_CARD_DARK, width=90, command=self.destroy).pack(anchor="e", pady=(10, 0))
        self._render_sent(None)
        self._refresh_states()
        self.center_on(master)

    def _create(self):
        include = {k: bool(v.get()) for k, v in self.include.items()}
        payload = self.secure_send.payload_from_entry(self.entry, include)
        if not any(k in payload for k in ("username", "password", "notes", "url")):
            self.status_lbl.configure(text=_("Zaznacz, co wysłać."), text_color=COLOR_WARNING)
            return
        hours, password = self._expiry[self.expiry.get()], self.password.get()
        self.create_btn.configure(state="disabled", text=_("Tworzenie linku…"))
        client = self.session.client

        def _work():
            sealed = self.secure_send.seal(payload, password)
            info = client.create_share(sealed.ciphertext, sealed.iv, sealed.proof, hours, bool(password))
            return sealed, info

        self.run_in_background(_work, self._created)

    def _created(self, result):
        if not self.winfo_exists():
            return
        self.create_btn.configure(state="normal", text=_("✉ Utwórz link"))
        if isinstance(result, Exception):
            self.status_lbl.configure(text=_("Nie udało się: {error}", error=result), text_color=COLOR_WARNING)
            return
        sealed, info = result
        base = info.get("public_url") or self.session.profile.url
        url = self.secure_send.link(base, info["id"], sealed.link_key)
        self.secure_send.remember_sent(self.settings, info, self.entry.title)
        self.on_sent()
        for w in self.result.winfo_children():
            w.destroy()
        field = ctk.CTkEntry(self.result, width=330)
        field.insert(0, url)
        field.configure(state="readonly")
        field.pack(side="left", fill="x", expand=True)
        self.link_entry = field
        self.copy_btn = ctk.CTkButton(self.result, text=_("Kopiuj link"), width=90, fg_color=COLOR_SUCCESS,
                                      command=lambda: self._copy(url))
        self.copy_btn.pack(side="left", padx=(6, 0))
        hint = _("Wyślij link odbiorcy. Działa jeden raz i wygasa za: {expiry}.", expiry=self.expiry.get())
        if self.password.get():
            hint += " " + _("Hasło do linku przekaż innym kanałem (SMS, telefon) – nie w tej samej wiadomości.")
        if not info.get("public_url"):
            hint += " " + _("Uwaga: link zadziała tylko tam, gdzie widać serwer {url}.", url=self.session.profile.url)
        self.status_lbl.configure(text=hint, text_color=COLOR_TEXT_MUTED)
        self._refresh_states()

    def _copy(self, url: str):
        from ui.clipboard import SecureClipboard
        SecureClipboard.copy(url, timeout_seconds=300)  # link z kluczem – schowek czyszczony po 5 minutach
        self.copy_btn.configure(text=_("✓ Skopiowano"))

    def _refresh_states(self):
        client = self.session.client
        self.run_in_background(lambda: {i["id"]: i for i in client.list_shares()},
                               lambda r: self.winfo_exists() and self._render_sent(r if isinstance(r, dict) else None))

    def _render_sent(self, states):
        for w in self.sent_box.winfo_children():
            w.destroy()
        sent = self.secure_send.sent_list(self.settings)[:8]
        if not sent:
            ctk.CTkLabel(self.sent_box, text=_("Brak"), font=FONT_SMALL, text_color=COLOR_TEXT_MUTED).pack(anchor="w")
            return
        from datetime import datetime
        for item in sent:
            row = tk.Frame(self.sent_box, bg=COLOR_PANEL_DARK)
            row.pack(fill="x", pady=1)
            info = (states or {}).get(item["id"])
            state = info["state"] if info else "expired" if states is not None else "unknown"
            when = datetime.fromtimestamp(item.get("created") or 0).strftime("%d.%m %H:%M")
            ctk.CTkLabel(row, text=f"{when}  {item['title']}  –  {_(self.STATES.get(state, state))}", font=FONT_SMALL,
                         text_color=COLOR_SUCCESS if state == "opened" else COLOR_TEXT_PRIMARY).pack(side="left")
            if state == "active":
                ctk.CTkButton(row, text=_("Odwołaj"), width=70, height=22, font=FONT_SMALL, fg_color=COLOR_CARD_DARK,
                              command=lambda sid=item["id"]: self._revoke(sid)).pack(side="right")

    def _revoke(self, share_id: str):
        client = self.session.client
        self.run_in_background(lambda: client.revoke_share(share_id), lambda _r: self._refresh_states())


class FloatingPanel(ctk.CTkToplevel):
    """Małe okno zawsze na wierzchu: ulubione wpisy i wyszukiwarka, kopiowanie jednym kliknięciem."""
    MAX_ROWS = 30

    def __init__(self, master, vault_getter: Callable[[], Vault], copy: Callable[[str], int],
                 on_select: Callable[[str], None]):
        super().__init__(master)
        self.vault_getter = vault_getter
        self.copy = copy  # kopiuje do schowka (z automatycznym czyszczeniem), zwraca czas czyszczenia w sekundach
        self.on_select = on_select
        self._message_job: Optional[str] = None
        self.title(_("KeyStead – panel"))
        self.attributes("-topmost", True)
        self.configure(fg_color=COLOR_PANEL_DARK)
        self.minsize(280, 260)
        width, height = 310, 430
        x = self.winfo_screenwidth() - width - 30
        y = max(30, self.winfo_screenheight() - height - 90)
        self.geometry(f"{width}x{height}+{x}+{y}")

        top = tk.Frame(self, bg=COLOR_PANEL_DARK)
        top.pack(fill="x", padx=8, pady=(8, 4))
        self.search = ctk.CTkEntry(top, placeholder_text=_("🔍 Szukaj..."), height=30)
        self.search.pack(fill="x")
        self.search.bind("<KeyRelease>", lambda e: self._schedule_refresh())
        self.info_lbl = ctk.CTkLabel(self, text="", font=FONT_SMALL, text_color=COLOR_TEXT_MUTED)
        self.info_lbl.pack(anchor="w", padx=10)
        self.list_frame = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.list_frame.pack(fill="both", expand=True, padx=4, pady=(0, 6))
        self._refresh_job: Optional[str] = None
        self.refresh()

    def _schedule_refresh(self):
        if self._refresh_job:
            self.after_cancel(self._refresh_job)
        self._refresh_job = self.after(150, self.refresh)

    def refresh(self):
        self._refresh_job = None
        if not self.winfo_exists():
            return
        vault = self.vault_getter()
        query = self.search.get().strip()
        if query:
            entries = vault.search(query=query)
            info = _("Wyniki wyszukiwania")
        else:
            entries = vault.search(favorite_only=True)
            info = _("⭐ Ulubione") if entries else _("Brak ulubionych – wpisz nazwę, aby wyszukać.")
        self.info_lbl.configure(text=info, text_color=COLOR_TEXT_MUTED)
        for w in self.list_frame.winfo_children():
            w.destroy()
        for e in entries[:self.MAX_ROWS]:
            self._row(e)

    def _row(self, entry: VaultEntry):
        row = tk.Frame(self.list_frame, bg=COLOR_CARD_DARK)
        row.pack(fill="x", pady=2, padx=2)
        title = tk.Label(row, text=entry.title, bg=COLOR_CARD_DARK, fg=COLOR_TEXT_PRIMARY, anchor="w",
                         font=(FONT_FAMILY, 10, "bold"), cursor="hand2")
        title.pack(side="top", fill="x", padx=8, pady=(4, 0))
        title.bind("<Button-1>", lambda e, eid=entry.id: self.on_select(eid))
        acts = tk.Frame(row, bg=COLOR_CARD_DARK)
        acts.pack(side="top", fill="x", padx=6, pady=(0, 5))
        eid = entry.id
        if entry.username:
            FlatButton(acts, text=_("👤 Login"), width=70, height=24, font=FONT_SMALL, fg_color=COLOR_PANEL_DARK,
                       command=lambda: self._copy_field(eid, "username")).pack(side="left", padx=2)
        if entry.password:
            FlatButton(acts, text=_("🔑 Hasło"), width=72, height=24, font=FONT_SMALL, fg_color=COLOR_PRIMARY,
                       command=lambda: self._copy_field(eid, "password")).pack(side="left", padx=2)
        if entry.totp_secret:
            FlatButton(acts, text="2FA", width=46, height=24, font=FONT_SMALL, fg_color=COLOR_SUCCESS,
                       command=lambda: self._copy_field(eid, "totp")).pack(side="left", padx=2)

    def _copy_field(self, entry_id: str, what: str):
        entry = self.vault_getter().get_entry(entry_id)  # aktualne dane (wpis mógł się zmienić)
        if entry is None:
            self.refresh()
            return
        if what == "username":
            text, message = entry.username, _("✓ Login skopiowany: {title}", title=entry.title)
        elif what == "password":
            text, message = entry.password, _("✓ Hasło skopiowane: {title}", title=entry.title)
        else:
            text, message = get_current_totp(entry.totp_secret), _("✓ Kod 2FA skopiowany: {title}", title=entry.title)
            if not text:
                return
        seconds = self.copy(text)
        if seconds:
            message += " " + _("(schowek wyczyści się za {seconds} s)", seconds=seconds)
        self.info_lbl.configure(text=message, text_color=COLOR_SUCCESS)
        if self._message_job:
            self.after_cancel(self._message_job)
        self._message_job = self.after(3000, self._restore_info)

    def _restore_info(self):
        self._message_job = None
        if self.winfo_exists():
            self.info_lbl.configure(text_color=COLOR_TEXT_MUTED)
            self.refresh()
