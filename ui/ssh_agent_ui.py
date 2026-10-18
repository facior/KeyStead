"""
Wtyczka „Klucze SSH w sejfie” w aplikacji: uruchamia agenta SSH, gdy sejf jest otwarty, i dostarcza mu klucze.

Klucze z wpisów są odczytywane w tle (klucz z hasłem to Argon2/bcrypt – nawet sekunda na klucz) i zapamiętywane,
więc kolejne zapisy sejfu przeliczają tylko zmienione wpisy. Agent wywołuje `_on_use` ze swojego wątku – zgoda
lub powiadomienie idą przez kolejkę wątku interfejsu (post_to_ui).
"""

import threading
from typing import Dict, List, Optional, Tuple

from tkinter import messagebox

from core import plugins, ssh_keys
from core.i18n import _
from core.ssh_agent import AgentService

PLUGIN_ID = "ssh_agent"
CONFIRM_TIMEOUT = 60


class AgentController:
    def __init__(self, view):
        self.view = view
        self.service: Optional[AgentService] = None
        self.keys: Tuple[ssh_keys.AgentKey, ...] = ()
        self.errors: Dict[str, str] = {}
        self._cache: Dict[tuple, object] = {}   # (id wpisu, tekst klucza, hasło) -> AgentKey albo komunikat błędu
        self._generation = 0
        self._lock = threading.Lock()
        self._poster = None  # funkcja przekazująca zadanie do wątku interfejsu – ustalana w wątku interfejsu

    # ----------------------------------------------------------------- stan
    @property
    def enabled(self) -> bool:
        return self.view.plugin_on(PLUGIN_ID)

    def status(self) -> Dict[str, str]:
        return self.service.status() if self.service else {"openssh": "stopped", "pageant": "stopped"}

    def key_for(self, entry_id: str) -> Optional[ssh_keys.AgentKey]:
        return next((k for k in self.keys if k.entry_id == entry_id), None)

    # ----------------------------------------------------------------- cykl życia
    def sync(self):
        """Włącza albo wyłącza agenta zgodnie z wtyczką (po otwarciu sejfu, zmianie wtyczek lub polityki)."""
        # Wątki agenta nie mogą wołać Tk – kanał do wątku interfejsu bierzemy teraz (jesteśmy w wątku interfejsu)
        self._poster = getattr(self.view.winfo_toplevel(), "post_to_ui", None) or (lambda f: self.view.after(0, f))
        if self.enabled:
            if self.service is None:
                self.service = AgentService(lambda: self.keys, self._on_use)
                self.service.start()
            self.refresh_keys()
        else:
            self.stop()

    def stop(self):
        service, self.service = self.service, None
        self.keys = ()
        self._generation += 1
        if service is not None:
            service.stop()

    def refresh_keys(self):
        if self.service is None:
            return
        snapshot = [(e.id, e.title, ssh_keys.entry_key_text(e), e.password)
                    for e in self.view.vault.entries.values() if ssh_keys.field_name(e)]
        self._generation += 1
        generation = self._generation
        threading.Thread(target=self._load, args=(snapshot, generation), daemon=True, name="ssh-keys").start()

    def _load(self, snapshot, generation):
        keys: List[ssh_keys.AgentKey] = []
        errors: Dict[str, str] = {}
        for entry_id, title, text, password in snapshot:
            cache_key = (entry_id, text, password)
            with self._lock:
                cached = self._cache.get(cache_key)
            if cached is None:
                try:
                    cached = ssh_keys.load_key(text, password)
                    cached.entry_id, cached.entry_title = entry_id, title
                    cached.comment = cached.comment or title
                except ssh_keys.SshKeyError as e:
                    cached = str(e)
                except Exception as e:  # uszkodzony wpis nie może zatrzymać agenta
                    cached = _("Nie udało się odczytać klucza SSH: {error}", error=e)
                with self._lock:
                    self._cache[cache_key] = cached
            if isinstance(cached, str):
                errors[entry_id] = cached
            else:
                cached.entry_title = title
                keys.append(cached)
        with self._lock:
            live = {(eid, text, pw) for eid, _t, text, pw in snapshot}
            self._cache = {k: v for k, v in self._cache.items() if k in live}
        if generation != self._generation or self.service is None:
            return  # w międzyczasie zablokowano sejf albo wczytano nowszy stan
        self.keys, self.errors = tuple(keys), errors
        self._post(self.view.on_ssh_keys_loaded)

    # ----------------------------------------------------------------- użycie klucza (wątek agenta)
    def _post(self, fn):
        try:
            if self._poster is not None:
                self._poster(fn)
        except Exception:
            pass

    def _confirm_required(self) -> bool:
        return bool(plugins.options(self.view.vault.settings, PLUGIN_ID).get("confirm"))

    def _on_use(self, key: ssh_keys.AgentKey, client: str) -> bool:
        if self.service is None:
            return False
        program = client or _("nieznany program")
        if not self._confirm_required():
            self._post(lambda: self.view.winfo_exists() and self.view.show_toast(
                _("🗝️ {program} użył klucza „{title}”", program=program, title=key.entry_title)))
            return True
        answer = {"ok": False}
        done = threading.Event()

        def _ask():
            try:
                answer["ok"] = self.view.winfo_exists() and messagebox.askyesno(
                    _("Użycie klucza SSH"),
                    _("Program {program} chce użyć klucza SSH „{title}” ({fingerprint}).\n\nZezwolić?",
                      program=program, title=key.entry_title, fingerprint=key.fingerprint()),
                    parent=self.view.winfo_toplevel())
            finally:
                done.set()
        self._post(_ask)
        done.wait(CONFIRM_TIMEOUT)
        return bool(answer["ok"]) and self.service is not None
