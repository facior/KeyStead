"""
Zabezpieczenia kopii zapasowych i logowania OAuth: strona zwrotna bez wstrzykiwania HTML, ignorowanie
obcych żądań, zmiana konta w trakcie backupu, rotacja ograniczona do kopii danego sejfu.
"""

import os
import shutil
import socket
import tempfile
import threading
import time
import unittest
import urllib.request

from backups import oauth
from backups.local_backup import LocalBackupProvider
from backups.manager import merge_runtime_state


class TestOAuthCallback(unittest.TestCase):
    def _run_wait(self, state="dobry-state"):
        cancel = threading.Event()
        box = {}

        def target():
            try:
                box["result"] = oauth._wait_for_redirect("127.0.0.1", state, cancel)
            except Exception as e:
                box["error"] = e
        t = threading.Thread(target=target, daemon=True)
        t.start()
        deadline = time.time() + 5
        while time.time() < deadline:  # czekamy, aż serwer zacznie przyjmować połączenia
            try:
                socket.create_connection(("127.0.0.1", oauth.REDIRECT_PORT), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        return t, cancel, box

    def _get(self, query):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{oauth.REDIRECT_PORT}/?{query}", timeout=3) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, ""

    def test_foreign_requests_ignored_and_error_escaped(self):
        t, cancel, box = self._run_wait()
        try:
            status, _ = self._get("code=x&state=zly")  # obca strona – nie przerywa logowania
            self.assertEqual(status, 400)
            self.assertTrue(t.is_alive())
            status, page = self._get("state=dobry-state&error=x&error_description=%3Cscript%3Ealert(1)%3C/script%3E")
            self.assertEqual(status, 200)
            self.assertNotIn("<script>", page)
            self.assertIn("&lt;script&gt;", page)
        finally:
            cancel.set()
            t.join(5)

    def test_hanging_connection_does_not_block_cancel(self):
        t, cancel, box = self._run_wait()
        s = socket.create_connection(("127.0.0.1", oauth.REDIRECT_PORT))
        s.sendall(b"GET /?co")  # niedokończone żądanie
        try:
            cancel.set()
            t.join(8)
            self.assertFalse(t.is_alive())
        finally:
            s.close()


class TestMergeRuntimeState(unittest.TestCase):
    def test_account_switch_during_backup_keeps_new_account(self):
        original = {"google_drive": {"oauth": {"refresh_token": "KONTO-A"}, "folder_id": "fA"}}
        worker = {"google_drive": {"oauth": {"refresh_token": "KONTO-A-odswiezony"}, "folder_id": "fA"}}
        live = {"google_drive": {"oauth": {"refresh_token": "KONTO-B"}, "folder_id": "fB"}}
        self.assertFalse(merge_runtime_state(live, worker, original))
        self.assertEqual(live["google_drive"]["oauth"]["refresh_token"], "KONTO-B")

    def test_refreshed_token_saved_when_account_unchanged(self):
        original = {"google_drive": {"oauth": {"refresh_token": "A"}}}
        worker = {"google_drive": {"oauth": {"refresh_token": "A2"}, "folder_id": "f"}}
        live = {"google_drive": {"oauth": {"refresh_token": "A"}}}
        self.assertTrue(merge_runtime_state(live, worker, original))
        self.assertEqual(live["google_drive"]["oauth"]["refresh_token"], "A2")


class TestLocalRotation(unittest.TestCase):
    def test_rotation_only_touches_this_vault(self):
        tmp = tempfile.mkdtemp()
        try:
            dest = os.path.join(tmp, "usb")
            os.makedirs(dest)
            foreign = [os.path.join(dest, n) for n in ("a_backup_X_backup_20240101_000000.vault",
                                                       "a_backup_notatki.vault")]
            for p in foreign:
                open(p, "wb").write(b"inny sejf")
            src = os.path.join(tmp, "a.vault")
            open(src, "wb").write(b"SECVAULT" + b"0" * 100)
            for i in range(3):
                open(os.path.join(dest, f"a_backup_2024010{i + 1}_000000.vault"), "wb").write(b"x")
            LocalBackupProvider()._rotate_backups(dest, "a", 1)
            for p in foreign:
                self.assertTrue(os.path.exists(p), p)
            own = [n for n in os.listdir(dest) if n.startswith("a_backup_2024")]
            self.assertEqual(len(own), 1)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
