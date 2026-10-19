"""
Centrum ratunkowe: mapa domina kont (które skrzynki e-mail otwierają które konta) i kreator
„Ktoś przejął moje konto!” z listą kroków do odhaczania.
"""

import tkinter as tk
from typing import Callable, Dict, List, Optional, Set

import customtkinter as ctk

from core import domino, rescue
from core.generator import generate_password
from core.i18n import _, _n
from core.vault import Vault, VaultEntry
from ui.drawer_views import layout_frame
from ui.theme import (COLOR_CARD_DARK, COLOR_DANGER, COLOR_PANEL_DARK, COLOR_PRIMARY, COLOR_SUCCESS, COLOR_TEXT_ACCENT,
                      COLOR_TEXT_MUTED, COLOR_TEXT_PRIMARY, COLOR_WARNING, FONT_BODY, FONT_BODY_BOLD, FONT_SMALL,
                      FONT_SUBTITLE, FONT_TITLE)

TILE_COLORS = {"bank": "#ef4444", "gov": "#f59e0b", "shop": "#3b82f6", "social": "#a855f7", "crypto": "#14b8a6",
               None: "#64748b"}


def risk_look(risk: int):
    return {3: (_("PILNE"), COLOR_DANGER), 2: (_("do poprawy"), COLOR_WARNING),
            1: (_("sprawdź"), COLOR_WARNING), 0: (_("dobrze"), COLOR_SUCCESS)}[max(0, min(3, risk))]


class RescueDrawerView(ctk.CTkFrame):
    DOMINO, RESCUE = "domino", "rescue"

    def __init__(self, parent, vault: Vault, breached_ids: Set[str], on_select_entry: Callable[[str], None],
                 on_save: Callable[[], None], copy_secret: Callable[[str], None], open_url: Callable[[str], None],
                 start_entry_id: Optional[str] = None, on_emergency_card: Optional[Callable[[], None]] = None):
        super().__init__(parent, fg_color="transparent")
        self.pack(fill="both", expand=True)
        self.vault, self.breached = vault, breached_ids
        self.on_select_entry, self.on_save = on_select_entry, on_save
        self.copy_secret, self.open_url = copy_secret, open_url
        self.on_emergency_card = on_emergency_card
        self.keys = domino.analyze(vault.entries.values(), breached_ids)
        self._new_password: Optional[str] = None

        self._tabs = {_("🧩 Mapa domina"): self.DOMINO, _("🚨 Ktoś przejął konto"): self.RESCUE}
        self.tabs = ctk.CTkSegmentedButton(self, values=list(self._tabs), command=self._switch)
        self.tabs.pack(fill="x", pady=(0, 8))
        self.body = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.body.pack(fill="both", expand=True)
        if start_entry_id and vault.get_entry(start_entry_id):
            self.show_rescue(start_entry_id)
        else:
            self.tabs.set(_("🧩 Mapa domina"))
            self._render_domino()

    # ----------------------------------------------------------------- pomocnicze
    def _clear(self):
        for w in self.body.winfo_children():
            w.destroy()
        self.body._parent_canvas.yview_moveto(0)

    def _card(self):
        card = ctk.CTkFrame(self.body, fg_color=COLOR_CARD_DARK, corner_radius=10)
        card.pack(fill="x", pady=5, ipady=4)
        return card

    def _label(self, parent, text, font=FONT_SMALL, color=COLOR_TEXT_MUTED, pady=(0, 2)):
        lbl = ctk.CTkLabel(parent, text=text, font=font, text_color=color, wraplength=440, justify="left", anchor="w")
        lbl.pack(anchor="w", fill="x", padx=14, pady=pady)
        return lbl

    def _switch(self, label: str):
        if self._tabs.get(label) == self.DOMINO:
            self._render_domino()
        else:
            self._render_rescue_picker()

    # ----------------------------------------------------------------- mapa domina
    def _render_domino(self):
        self._clear()
        intro = self._card()
        self._label(intro, _("🧩 Twoje cyfrowe domino"), FONT_SUBTITLE, COLOR_TEXT_PRIMARY, (10, 2))
        self._label(intro, _("Większość serwisów pozwala zresetować hasło przez e-mail. Kto przejmie skrzynkę, przejmie "
                             "też konta założone na ten adres. Oto Twoje skrzynki – od najbardziej zagrożonej."))
        if self.on_emergency_card:
            row = layout_frame(intro)
            row.pack(fill="x", padx=14, pady=(2, 8))
            ctk.CTkButton(row, text=_("🖨 Karta awaryjna (PDF)"), height=26, font=FONT_SMALL, fg_color=COLOR_SUCCESS,
                          command=self.on_emergency_card).pack(side="left")
            ctk.CTkLabel(row, text=_("wszystko, czego bliscy potrzebują, by dostać się do sejfu"), font=FONT_SMALL,
                         text_color=COLOR_TEXT_MUTED).pack(side="left", padx=8)
        if not self.keys:
            self._label(intro, _("Nie znaleziono adresów e-mail w loginach. Dopisz do wpisów pole „E-mail” albo użyj "
                                 "adresu jako loginu, żeby zobaczyć mapę."), FONT_BODY, COLOR_TEXT_PRIMARY, (6, 8))
            return
        top = self.keys[0]
        self._label(intro, _("Najważniejsza: {email} – od niej zależy {count}.", email=top.email,
                             count=_n(len(top.dependents), "{n} konto", "{n} konta", "{n} kont")),
                    FONT_BODY_BOLD, COLOR_TEXT_ACCENT, (4, 8))
        for key in self.keys:
            self._render_key(key)
        without = sum(1 for e in self.vault.entries.values() if not domino.entry_emails(e) and e.username)
        if without:
            note = self._card()
            self._label(note, _n(without, "{n} wpis ma login, który nie jest adresem e-mail – dopisz w nim pole „E-mail”, "
                                          "jeśli wiesz, na jaki adres założono konto.",
                                 "{n} wpisy mają login, który nie jest adresem e-mail – dopisz w nich pole „E-mail”, "
                                 "jeśli wiesz, na jaki adres założono konta.",
                                 "{n} wpisów ma login, który nie jest adresem e-mail – dopisz w nich pole „E-mail”, "
                                 "jeśli wiesz, na jaki adres założono konta."), pady=(8, 8))

    def _render_key(self, key: domino.Key):
        card = self._card()
        head = layout_frame(card)
        head.pack(fill="x", padx=14, pady=(8, 2))
        ctk.CTkLabel(head, text=f"📧 {key.email}", font=FONT_BODY_BOLD, text_color=COLOR_TEXT_PRIMARY).pack(side="left")
        label, color = risk_look(key.risk)
        ctk.CTkLabel(head, text=f"  {label}  ", font=FONT_SMALL, fg_color=color, text_color="#ffffff",
                     corner_radius=6).pack(side="right")
        count = len(key.dependents)
        self._label(card, _("Od tej skrzynki zależy {count}", count=_n(count, "{n} konto", "{n} konta", "{n} kont")),
                    FONT_SUBTITLE, COLOR_TEXT_PRIMARY, (2, 2))
        if key.important:
            parts = [f"{_(domino.IMPORTANT[k][0])}: {v}" for k, v in sorted(key.important.items(), key=lambda kv: -kv[1])]
            self._label(card, _("w tym ważne – {list}", list=", ".join(parts)), FONT_SMALL, COLOR_TEXT_ACCENT)
        if count:
            self._tiles(card, key)
            names = [e.title for e in sorted(key.dependents, key=lambda e: (domino.importance(e) is None, e.title.lower()))]
            shown = ", ".join(names[:6]) + (_(" i {n} innych", n=len(names) - 6) if len(names) > 6 else "")
            self._label(card, shown)
        for problem in key.problems:
            self._label(card, f"⚠️ {_(problem)}", FONT_SMALL, COLOR_DANGER if key.risk >= 2 else COLOR_WARNING)
        if not key.problems and key.mailbox is not None:
            self._label(card, _("✓ Skrzynka dobrze zabezpieczona (2FA, silne, unikalne hasło)."), FONT_SMALL, COLOR_SUCCESS)
        row = layout_frame(card)
        row.pack(fill="x", padx=14, pady=(6, 8))
        if key.mailbox is not None:
            ctk.CTkButton(row, text=_("Otwórz wpis skrzynki"), height=26, width=150, font=FONT_SMALL,
                          fg_color=COLOR_PANEL_DARK, command=lambda: self.on_select_entry(key.mailbox.id)).pack(side="left")
            ctk.CTkButton(row, text=_("🚨 Co jeśli ją przejmą?"), height=26, width=160, font=FONT_SMALL,
                          fg_color=COLOR_DANGER, command=lambda: self.show_rescue(key.mailbox.id)).pack(side="left", padx=6)
        _sessions, twofa = domino.security_pages(key.provider_host)
        if twofa and domino.PROBLEM_NO_2FA in key.problems:
            ctk.CTkButton(row, text=_("Włącz 2FA ↗"), height=26, width=100, font=FONT_SMALL, fg_color=COLOR_PRIMARY,
                          command=lambda u=twofa: self.open_url(u)).pack(side="left", padx=6)

    def _tiles(self, card, key: domino.Key):
        """Kostki domina: każde zależne konto to kostka (kolor = rodzaj ważnego konta)."""
        deps = sorted(key.dependents, key=lambda e: (domino.importance(e) is None, domino.importance(e) or ""))[:40]
        size, gap = 14, 4
        canvas = tk.Canvas(card, height=size + 8, highlightthickness=0, bd=0, bg=card._apply_appearance_mode(COLOR_CARD_DARK))
        canvas.pack(anchor="w", padx=14, pady=(2, 2), fill="x")
        for i, e in enumerate(deps):
            x0 = i * (size + gap)
            canvas.create_rectangle(x0, 4, x0 + size, 4 + size, fill=TILE_COLORS.get(domino.importance(e)), width=0)

    # ----------------------------------------------------------------- „Ktoś przejął moje konto”
    def _entries_sorted(self) -> List[VaultEntry]:
        return sorted(self.vault.entries.values(), key=lambda e: e.title.lower())

    def _render_rescue_picker(self, selected: Optional[VaultEntry] = None):
        self._clear()
        intro = self._card()
        self._label(intro, _("🚨 Ktoś przejął moje konto!"), FONT_SUBTITLE, COLOR_TEXT_PRIMARY, (10, 2))
        self._label(intro, _("Spokojnie – przejdziemy przez to krok po kroku. Wybierz konto, które zostało przejęte "
                             "(albo co do którego masz podejrzenia)."))
        entries = self._entries_sorted()
        self._choices = {}
        for e in entries:
            label = f"{e.title}  ·  {e.username}" if e.username else e.title
            while label in self._choices:
                label += " "
            self._choices[label] = e
        combo = ctk.CTkComboBox(intro, values=list(self._choices) or [_("(brak wpisów)")], state="readonly",
                                command=lambda v: self.show_rescue(self._choices[v].id) if v in self._choices else None)
        combo.pack(fill="x", padx=14, pady=(4, 10))
        combo.set(next((k for k, v in self._choices.items() if v is selected), _("— wybierz konto —")))
        cases = [self.vault.get_entry(i) for i in rescue.open_cases(self.vault.settings)]
        cases = [c for c in cases if c is not None and c is not selected]
        if cases:
            self._label(intro, _("Rozpoczęte wcześniej: {list}", list=", ".join(c.title for c in cases)), pady=(0, 8))
        return intro

    def show_rescue(self, entry_id: str):
        entry = self.vault.get_entry(entry_id)
        if entry is None:
            return
        self.tabs.set(_("🚨 Ktoś przejął konto"))
        self._new_password = None
        self._render_rescue_picker(entry)
        box_key = domino.mailbox_key(entry, self.keys)
        if box_key is not None and box_key.dependents:
            warn = self._card()
            self._label(warn, _("⚠️ To skrzynka e-mail – od niej zależy {count}. Działaj szybko: napastnik może "
                                "resetować hasła tych kont.",
                                count=_n(len(box_key.dependents), "{n} konto", "{n} konta", "{n} kont")),
                        FONT_BODY_BOLD, COLOR_DANGER, (8, 8))
        steps = rescue.build_steps(entry, list(self.vault.entries.values()), self.keys)
        state = rescue.progress(self.vault.settings, entry.id)
        self._progress_lbl = self._label(self._card(), "", FONT_BODY_BOLD, COLOR_TEXT_ACCENT, (8, 8))
        self._steps, self._entry = steps, entry
        for number, step in enumerate(steps, 1):
            self._render_step(number, step, state)
        end = layout_frame(self.body)
        end.pack(fill="x", pady=(8, 4))
        ctk.CTkButton(end, text=_("Zakończ i wyczyść postęp"), fg_color=COLOR_PANEL_DARK, height=28,
                      command=lambda: self._finish(entry)).pack(side="right")
        self._update_progress()

    def _render_step(self, number: int, step: rescue.Step, state: Dict):
        card = self._card()
        var = ctk.BooleanVar(value=step.id in state["done"])
        ctk.CTkCheckBox(card, text=f"{number}. {step.title}", variable=var, font=FONT_BODY_BOLD,
                        command=lambda: self._toggle(step.id, var.get())).pack(anchor="w", padx=14, pady=(8, 2))
        self._label(card, step.text, pady=(0, 4))
        if step.kind == "password":
            row = layout_frame(card)
            row.pack(fill="x", padx=14, pady=(2, 4))
            save_btn = ctk.CTkButton(row, text=_("💾 Zapisz nowe hasło we wpisie"), height=26, font=FONT_SMALL,
                                     fg_color=COLOR_SUCCESS, state="disabled")
            ctk.CTkButton(row, text=_("⚡ Wygeneruj i skopiuj nowe hasło"), height=26, font=FONT_SMALL,
                          fg_color=COLOR_PRIMARY, command=lambda: self._generate(save_btn)).pack(side="left")
            save_btn.configure(command=lambda: self._save_password(var, step.id, save_btn))
            save_btn.pack(side="left", padx=6)
        if step.links:
            row = layout_frame(card)
            row.pack(fill="x", padx=14, pady=(2, 6))
            for label, url in step.links:
                ctk.CTkButton(row, text=f"{label} ↗", height=26, font=FONT_SMALL, fg_color=COLOR_PANEL_DARK,
                              command=lambda u=url: self.open_url(u)).pack(side="left", padx=(0, 6))
        if step.kind == "entries":
            for e in step.entries:
                row = layout_frame(card)
                row.pack(fill="x", padx=24, pady=1)
                sub = ctk.BooleanVar(value=e.id in state["entries_done"])
                important = domino.importance(e)
                title = e.title + (f"  ({_(domino.IMPORTANT[important][0])})" if important else "")
                ctk.CTkCheckBox(row, text=title, variable=sub, font=FONT_SMALL,
                                command=lambda i=e.id, v=sub: self._toggle(i, v.get(), "entries_done")).pack(side="left")
                url = domino.change_password_url(e)
                if url:
                    ctk.CTkButton(row, text=_("Zmień hasło ↗"), width=100, height=22, font=FONT_SMALL,
                                  fg_color=COLOR_PANEL_DARK, command=lambda u=url: self.open_url(u)).pack(side="right")
            ctk.CTkLabel(card, text="", height=4).pack()

    def _toggle(self, item_id: str, done: bool, sub: str = "done"):
        rescue.set_done(self.vault.settings, self._entry.id, item_id, done, sub)
        self.on_save()
        self._update_progress()

    def _update_progress(self):
        state = rescue.progress(self.vault.settings, self._entry.id)
        done = sum(1 for s in self._steps if s.id in state["done"])
        text = _("Zrobione: {done} z {total}", done=done, total=len(self._steps))
        if done == len(self._steps):
            text += "  ·  " + _("✓ Wszystkie kroki wykonane – konto jest bezpieczne.")
        self._progress_lbl.configure(text=text)

    def _generate(self, save_btn):
        self._new_password = generate_password(length=20, avoid_ambiguous=True)
        self.copy_secret(self._new_password)
        save_btn.configure(state="normal")

    def _save_password(self, var, step_id: str, save_btn):
        if not self._new_password:
            return
        self._entry.update(password=self._new_password)  # stare hasło trafia do historii wpisu
        self._new_password = None
        save_btn.configure(state="disabled", text=_("✓ Zapisano"))
        var.set(True)
        self._toggle(step_id, True)

    def _finish(self, entry: VaultEntry):
        rescue.clear(self.vault.settings, entry.id)
        self.on_save()
        self._render_rescue_picker()
