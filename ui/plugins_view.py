"""
Ustawienia → Wtyczki: lista wbudowanych wtyczek z włącznikami i opisami oraz ustawienia programów dla „Połącz”.
"""

import os
from typing import Any, Callable, Dict, Optional

import customtkinter as ctk
from tkinter import filedialog, messagebox

from core import connect
from core.i18n import _
from core.plugins import PLUGINS, blocked_by_policy, options, set_choices, set_options, user_choices
from core.vault import Vault
from ui.drawer_views import layout_frame
from ui.theme import (COLOR_CARD_DARK, COLOR_PANEL_DARK, COLOR_SUCCESS, COLOR_TEXT_ACCENT, COLOR_TEXT_MUTED,
                      COLOR_TEXT_PRIMARY, COLOR_WARNING, FONT_BODY, FONT_BODY_BOLD, FONT_SMALL)

# Programy, które „Połącz” może uruchamiać – (klucz w ustawieniach, nazwa)
CONNECT_PROGRAMS = (("putty", "PuTTY"), ("winbox", "WinBox"), ("anydesk", "AnyDesk"), ("teamviewer", "TeamViewer"))


class PluginsDrawerView(ctk.CTkFrame):
    def __init__(self, parent, vault: Vault, policy: Optional[Dict[str, Any]] = None,
                 on_saved: Optional[Callable[[], None]] = None,
                 agent_status: Optional[Callable[[], Dict[str, str]]] = None,
                 yubikey_actions: Optional[Dict[str, Callable]] = None):
        super().__init__(parent, fg_color="transparent")
        self.pack(fill="both", expand=True)
        self.vault = vault
        self.policy = policy or {}
        self.on_saved = on_saved
        self._switches: Dict[str, ctk.CTkSwitch] = {}
        self._connect_prefs = connect.load_prefs()
        self._program_labels: Dict[str, ctk.CTkLabel] = {}
        self.agent_status = agent_status
        self.yubikey_actions = yubikey_actions or {}
        self._build_ui()

    def _build_ui(self):
        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.pack(fill="both", expand=True)

        intro = ctk.CTkFrame(scroll, fg_color=COLOR_CARD_DARK, corner_radius=10)
        intro.pack(fill="x", pady=6, ipady=4)
        ctk.CTkLabel(intro, text=_("Wtyczki to dodatkowe funkcje, które włączasz według potrzeb. Są wbudowane w "
                                   "KeyStead – nic nie jest pobierane z internetu i żaden obcy program nie ma dostępu "
                                   "do sejfu. Wybór zapisuje się w sejfie, więc obowiązuje na wszystkich Twoich "
                                   "komputerach."),
                     font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, wraplength=450, justify="left"
                     ).pack(anchor="w", padx=15, pady=8)

        chosen = user_choices(self.vault.settings)
        for plugin in PLUGINS:
            card = ctk.CTkFrame(scroll, fg_color=COLOR_CARD_DARK, corner_radius=10)
            card.pack(fill="x", pady=4, ipady=4)
            head = layout_frame(card)
            head.pack(fill="x", padx=15, pady=(8, 2))
            switch = ctk.CTkSwitch(head, text=f"{plugin.icon}  {_(plugin.name)}", font=FONT_BODY_BOLD,
                                   text_color=COLOR_TEXT_PRIMARY)
            switch.pack(side="left")
            blocked = blocked_by_policy(self.policy, plugin.id)
            if chosen.get(plugin.id) and plugin.ready and not blocked:
                switch.select()
            if not plugin.ready:
                switch.configure(state="disabled")
                ctk.CTkLabel(head, text=_("🔜 w przygotowaniu"), font=FONT_SMALL, text_color=COLOR_WARNING).pack(side="right")
            elif blocked:
                switch.configure(state="disabled")
                ctk.CTkLabel(head, text=_("🏢 zablokowane przez firmę"), font=FONT_SMALL,
                             text_color=COLOR_TEXT_ACCENT).pack(side="right")
            else:
                self._switches[plugin.id] = switch
            ctk.CTkLabel(card, text=_(plugin.description), font=FONT_SMALL, text_color=COLOR_TEXT_MUTED,
                         wraplength=450, justify="left").pack(anchor="w", padx=15, pady=(0, 6))
            if plugin.id == "connect" and plugin.id in self._switches:
                self._build_connect_options(card)
            if plugin.id == "ssh_agent" and plugin.id in self._switches:
                self._build_agent_options(card)
            if plugin.id == "yubikey" and plugin.id in self._switches and self.yubikey_actions:
                self._build_yubikey_options(card)

        bar = ctk.CTkFrame(self, fg_color=COLOR_CARD_DARK, corner_radius=8, height=50)
        bar.pack(fill="x", side="bottom", pady=(5, 0))
        ctk.CTkButton(bar, text=_("Zapisz wtyczki"), fg_color=COLOR_SUCCESS, command=self._save).pack(side="right", padx=10, pady=8)

    def _build_connect_options(self, card):
        box = ctk.CTkFrame(card, fg_color=COLOR_PANEL_DARK, corner_radius=8)
        box.pack(fill="x", padx=15, pady=(2, 8))
        ctk.CTkLabel(box, text=_("Programy na tym komputerze"), font=FONT_BODY_BOLD).pack(anchor="w", padx=10, pady=(6, 2))

        row = layout_frame(box)
        row.pack(fill="x", padx=10, pady=2)
        ctk.CTkLabel(row, text=_("SSH otwieraj w:"), font=FONT_BODY).pack(side="left")
        self._ssh_choices = {_("OpenSSH (okno konsoli)"): "openssh", "PuTTY": "putty"}
        self.ssh_menu = ctk.CTkSegmentedButton(row, values=list(self._ssh_choices))
        self.ssh_menu.set(next(k for k, v in self._ssh_choices.items()
                               if v == self._connect_prefs.get("ssh_client", "openssh")))
        self.ssh_menu.pack(side="left", padx=8)

        for key, name in CONNECT_PROGRAMS:
            r = layout_frame(box)
            r.pack(fill="x", padx=10, pady=2)
            ctk.CTkLabel(r, text=f"{name}:", font=FONT_BODY, width=90, anchor="w").pack(side="left")
            ctk.CTkButton(r, text=_("Wskaż…"), width=70, height=24, font=FONT_SMALL, fg_color=COLOR_CARD_DARK,
                          command=lambda k=key, n=name: self._pick_program(k, n)).pack(side="right")
            lbl = ctk.CTkLabel(r, text="", font=FONT_SMALL, anchor="w", justify="left", wraplength=260)
            lbl.pack(side="left", fill="x", expand=True, padx=6)
            self._program_labels[key] = lbl
            self._show_program(key)
        ctk.CTkLabel(box, text=_("Pulpit zdalny i OpenSSH są wbudowane w Windows. Przy SSH hasło trafia do schowka – "
                                 "wklej je prawym przyciskiem myszy, gdy konsola o nie zapyta."),
                     font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, wraplength=430, justify="left"
                     ).pack(anchor="w", padx=10, pady=(4, 8))

    def _build_agent_options(self, card):
        box = ctk.CTkFrame(card, fg_color=COLOR_PANEL_DARK, corner_radius=8)
        box.pack(fill="x", padx=15, pady=(2, 8))
        self.agent_confirm_sw = ctk.CTkSwitch(box, text=_("Pytaj o zgodę przy każdym użyciu klucza"))
        if options(self.vault.settings, "ssh_agent").get("confirm"):
            self.agent_confirm_sw.select()
        self.agent_confirm_sw.pack(anchor="w", padx=10, pady=(8, 2))
        ctk.CTkLabel(box, text=_("Bez tej opcji KeyStead tylko pokazuje powiadomienie, który program użył klucza."),
                     font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, wraplength=430, justify="left"
                     ).pack(anchor="w", padx=10)
        status = self.agent_status() if self.agent_status else {}
        texts = {
            "openssh": {"running": _("✓ ssh, scp, ssh-add (Windows OpenSSH): działa"),
                        "busy": _("⚠️ Windows OpenSSH: kanał zajęty – działa usługa „OpenSSH Authentication Agent”. "
                                  "Wyłącz ją w Usługach Windows, żeby ssh brał klucze z KeyStead."),
                        "stopped": _("Windows OpenSSH: włączy się po zapisaniu wtyczek")},
            "pageant": {"running": _("✓ PuTTY, WinSCP, TortoiseGit (Pageant): działa"),
                        "busy": _("⚠️ PuTTY: działa już Pageant – zamknij go, żeby PuTTY brał klucze z KeyStead."),
                        "stopped": _("PuTTY/Pageant: włączy się po zapisaniu wtyczek")},
        }
        for channel in ("openssh", "pageant"):
            state = status.get(channel, "stopped")
            text = texts[channel].get(state, _("⚠️ Nie udało się uruchomić ({channel}).", channel=channel))
            ctk.CTkLabel(box, text=text, font=FONT_SMALL, wraplength=430, justify="left",
                         text_color=COLOR_SUCCESS if state == "running" else
                         COLOR_WARNING if state == "busy" else COLOR_TEXT_MUTED).pack(anchor="w", padx=10, pady=(4, 0))
        ctk.CTkLabel(box, text=_("Git dla Windows ma własne ssh – aby używał kluczy z KeyStead, wpisz raz w konsoli:\n"
                                 "git config --global core.sshCommand C:/Windows/System32/OpenSSH/ssh.exe"),
                     font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, wraplength=430, justify="left"
                     ).pack(anchor="w", padx=10, pady=(6, 8))

    def _build_yubikey_options(self, card):
        self._yk_box = ctk.CTkFrame(card, fg_color=COLOR_PANEL_DARK, corner_radius=8)
        self._yk_box.pack(fill="x", padx=15, pady=(2, 8))
        self._render_yubikey()

    def _render_yubikey(self):
        box = self._yk_box
        for w in box.winfo_children():
            w.destroy()
        state = self.yubikey_actions["state"]()
        if state.get("enabled"):
            ctk.CTkLabel(box, text=_("✓ Ten sejf jest zabezpieczony YubiKey."), font=FONT_BODY_BOLD,
                         text_color=COLOR_SUCCESS).pack(anchor="w", padx=10, pady=(8, 2))
            ctk.CTkButton(box, text=_("Wyłącz YubiKey"), width=140, fg_color=COLOR_CARD_DARK,
                          command=lambda: self.yubikey_actions["disable"](on_done=self._yubikey_changed)
                          ).pack(anchor="w", padx=10, pady=(4, 8))
            return
        ctk.CTkLabel(box, text=_("Sejf nie jest jeszcze zabezpieczony YubiKey."), font=FONT_BODY,
                     text_color=COLOR_TEXT_PRIMARY).pack(anchor="w", padx=10, pady=(8, 2))
        ctk.CTkLabel(box, text=_("Przygotowanie klucza (raz): zainstaluj YubiKey Manager, wybierz Applications → OTP → "
                                 "Long Touch (slot 2) → Configure → Challenge-response → Generate → Finish. "
                                 "Potem kliknij przycisk poniżej i dotknij klucza."),
                     font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, wraplength=430, justify="left").pack(anchor="w", padx=10)
        if not state.get("recovery"):
            ctk.CTkLabel(box, text=_("⚠️ Najpierw utwórz kod odzyskiwania (Ustawienia → Odzyskiwanie dostępu) – "
                                     "to jedyne wyjście, gdy zgubisz YubiKey."),
                         font=FONT_SMALL, text_color=COLOR_WARNING, wraplength=430, justify="left"
                         ).pack(anchor="w", padx=10, pady=(4, 0))
        ctk.CTkButton(box, text=_("🔑 Zabezpiecz sejf YubiKey"), width=200, fg_color=COLOR_SUCCESS,
                      command=lambda: self.yubikey_actions["enable"](on_done=self._yubikey_changed),
                      state="normal" if state.get("recovery") and state.get("library") else "disabled"
                      ).pack(anchor="w", padx=10, pady=(6, 8))

    def _yubikey_changed(self):
        if self.winfo_exists():
            self._render_yubikey()

    def _show_program(self, key: str):
        path = connect.find_program(key, self._connect_prefs)
        self._program_labels[key].configure(
            text=os.path.basename(path) + "  ✓" if path else _("nie znaleziono"),
            text_color=COLOR_SUCCESS if path else COLOR_TEXT_MUTED)

    def _pick_program(self, key: str, name: str):
        path = filedialog.askopenfilename(title=_("Wskaż program {name}", name=name),
                                          filetypes=[(_("Programy"), "*.exe")], parent=self.winfo_toplevel())
        if path:
            self._connect_prefs[key] = os.path.normpath(path)
            self._show_program(key)

    def _save(self):
        set_choices(self.vault.settings, {pid: bool(sw.get()) for pid, sw in self._switches.items()})
        if hasattr(self, "agent_confirm_sw"):
            set_options(self.vault.settings, "ssh_agent", {"confirm": bool(self.agent_confirm_sw.get())})
        if hasattr(self, "ssh_menu"):
            self._connect_prefs["ssh_client"] = self._ssh_choices.get(self.ssh_menu.get(), "openssh")
            try:
                connect.save_prefs(self._connect_prefs)
            except OSError as e:
                messagebox.showerror(_("Błąd"), str(e), parent=self.winfo_toplevel())
                return
        if self.on_saved:
            self.on_saved()
        messagebox.showinfo(_("Zapisano"), _("Ustawienia wtyczek zostały zapisane."), parent=self.winfo_toplevel())
