"""
Ochrona przed podsunięciem przez serwer starszej wersji sejfu (replay): licznik zapisów w zaszyfrowanej
treści, odrzucenie starszej zawartości, świadome przyjęcie przez „Pobierz wersję z serwera”.
"""

import os
import shutil
import tempfile
import unittest

from core.crypto import encrypt_payload
from core.vault import Vault, VaultEntry
from sync.profile import ServerProfile
from sync.session import ERROR, SYNCED, SyncSession

PASSWORD = "haslo-glowne-123"


def blob_for(title: str, revision: int) -> bytes:
    vault = Vault("Test")
    vault.revision = revision
    vault.add_entry(VaultEntry(title=title, password=title))
    return encrypt_payload(vault.to_json().encode(), PASSWORD)


class FakeClient:
    """Serwer pod kontrolą testu: przechowuje wersje i może podsunąć dowolną starą jako „nową”."""

    def __init__(self):
        self.versions = {}
        self.current = 0

    def publish(self, blob):
        self.current += 1
        self.versions[self.current] = blob
        return self.current

    def meta(self):
        return {"exists": bool(self.current), "server_id": "srv1", "device": "PC",
                "meta": {"version": self.current, "updated_by": "Laptop"} if self.current else None}

    def download(self, version=None):
        v = version or self.current
        return self.versions[v], v

    def upload(self, blob, base):
        assert base == self.current
        return {"version": self.publish(blob)}


class TestRollbackProtection(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.client = FakeClient()
        self.client.publish(blob_for("stare hasło (wyciekło)", 1))
        self.client.publish(blob_for("NOWE hasło", 2))
        profile = ServerProfile(url="https://s", token="t", cache_dir=self.tmp)
        self.session = SyncSession(profile, client=self.client)

    def tearDown(self):
        self.session.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def titles(self, vault):
        return [e.title for e in vault.entries.values()]

    def test_replayed_old_version_rejected_on_poll(self):
        vault = self.session.open(PASSWORD)
        self.assertEqual(self.titles(vault), ["NOWE hasło"])
        self.assertEqual(self.session.max_revision, 2)
        # serwer podsuwa starą treść jako wersję 3 „z urządzenia Laptop”
        self.client.publish(self.client.versions[1])
        self.assertIsNone(self.session.poll())
        self.assertEqual(self.session.state, ERROR)
        self.assertIn("STARSZĄ", self.session.message)

    def test_replay_rejected_when_opening(self):
        self.session.open(PASSWORD)
        self.client.publish(self.client.versions[1])
        again = SyncSession(ServerProfile(url="https://s", token="t", cache_dir=self.tmp, server_id="srv1"),
                            client=self.client)
        try:
            vault = again.open(PASSWORD)
            self.assertEqual(self.titles(vault), ["NOWE hasło"])  # własna, nowsza kopia
            self.assertEqual(again.state, ERROR)
        finally:
            again.close()

    def test_newer_version_accepted_and_user_can_accept_older_explicitly(self):
        self.session.open(PASSWORD)
        self.client.publish(blob_for("jeszcze nowsze", 3))
        update = self.session.poll()
        self.assertEqual(self.titles(update.vault), ["jeszcze nowsze"])
        self.session.adopt(update).result()
        self.assertEqual(self.session.state, SYNCED)
        # świadoma decyzja: administrator przywrócił starą wersję na prośbę użytkownika
        self.client.publish(self.client.versions[1])
        self.assertIsNone(self.session.poll())
        vault = self.session.resolve_use_server()
        self.assertEqual(self.titles(vault), ["stare hasło (wyciekło)"])
        self.assertEqual(self.session.max_revision, 1)
        self.assertEqual(self.session.next_revision(vault.revision), 2)

    def test_restore_from_history_gets_new_revision(self):
        self.session.open(PASSWORD)
        vault = self.session.restore_version(1)
        self.assertEqual(self.titles(vault), ["stare hasło (wyciekło)"])
        self.assertGreater(vault.revision, 2)  # inne urządzenia przyjmą ją jako zwykłą zmianę

    def test_login_after_password_change_on_other_device(self):
        """Lokalna kopia zaszyfrowana starym hasłem nie może blokować logowania nowym hasłem."""
        self.session.open(PASSWORD)  # kopia lokalna – stare hasło, revision 2
        vault = Vault("Test")
        vault.revision = 3
        vault.add_entry(VaultEntry(title="po zmianie hasła", password="x"))
        self.client.publish(encrypt_payload(vault.to_json().encode(), "NOWE-haslo-456"))
        again = SyncSession(ServerProfile(url="https://s", token="t", cache_dir=self.tmp, server_id="srv1"),
                            client=self.client)
        try:
            opened = again.open("NOWE-haslo-456")
            self.assertEqual(self.titles(opened), ["po zmianie hasła"])
            self.assertEqual(again.state, SYNCED)
        finally:
            again.close()

    def test_revision_survives_roundtrip(self):
        v = Vault("x")
        v.revision = 7
        self.assertEqual(Vault.from_json(v.to_json()).revision, 7)
        self.assertEqual(Vault.from_dict({"name": "stary format"}).revision, 0)


if __name__ == "__main__":
    unittest.main()
