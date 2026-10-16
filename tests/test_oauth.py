"""
Testy logowania OAuth do chmur (PKCE + loopback), odświeżania tokenów
oraz wysyłki kopii z użyciem tokenu – bez prawdziwej sieci.
"""

import base64
import hashlib
import os
import shutil
import tempfile
import threading
import time
import unittest
import urllib.request
from unittest import mock
from urllib.parse import parse_qs, urlparse

from backups import oauth, merge_runtime_state
from backups.onedrive_backup import OneDriveBackupProvider


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text

    def json(self):
        return self._payload


class OAuthTestBase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        patcher = mock.patch.object(oauth, "CONFIG_FILE", os.path.join(self.temp_dir, "cfg.json"))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(shutil.rmtree, self.temp_dir, True)


class TestOAuthLogin(OAuthTestBase):
    def test_login_requires_client_id(self):
        with self.assertRaises(oauth.OAuthError):
            oauth.login("onedrive", open_browser=lambda url: None)

    def test_full_pkce_login_flow(self):
        oauth.save_client_config("onedrive", "test-client-id")
        seen = {}

        def fake_browser(url):
            params = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
            seen["auth"] = params

            def _redirect():
                urllib.request.urlopen(f"{params['redirect_uri']}?code=AUTH_CODE&state={params['state']}").read()
            threading.Thread(target=_redirect, daemon=True).start()

        def fake_post(url, data=None, timeout=None):
            seen["token_request"] = data
            return FakeResponse(payload={"access_token": "AT", "refresh_token": "RT", "expires_in": 3600})

        with mock.patch.object(oauth.requests, "post", side_effect=fake_post):
            tokens = oauth.login("onedrive", open_browser=fake_browser)

        self.assertEqual(tokens["access_token"], "AT")
        self.assertEqual(tokens["refresh_token"], "RT")
        auth = seen["auth"]
        self.assertEqual(auth["client_id"], "test-client-id")
        self.assertEqual(auth["code_challenge_method"], "S256")
        self.assertIn("offline_access", auth["scope"])

        # Weryfikator PKCE musi odpowiadać wysłanemu wcześniej wyzwaniu
        verifier = seen["token_request"]["code_verifier"]
        expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        self.assertEqual(auth["code_challenge"], expected)
        self.assertEqual(seen["token_request"]["code"], "AUTH_CODE")
        self.assertNotIn("client_secret", seen["token_request"])

    def test_wrong_state_is_rejected(self):
        """Odpowiedź z obcym `state` jest ignorowana (400) – nie da się nią ani zalogować, ani przerwać logowania."""
        oauth.save_client_config("dropbox", "app-key")
        cancel = threading.Event()
        statuses = []

        def attack(redirect):
            try:
                urllib.request.urlopen(f"{redirect}?code=X&state=ATAK").read()
            except urllib.error.HTTPError as e:
                statuses.append(e.code)
            cancel.set()

        def fake_browser(url):
            params = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
            threading.Thread(target=attack, args=(params["redirect_uri"],), daemon=True).start()

        with self.assertRaisesRegex(oauth.OAuthError, "anulowane"):
            oauth.login("dropbox", cancel_event=cancel, open_browser=fake_browser)
        self.assertEqual(statuses, [400])

    def test_cancel_stops_waiting(self):
        oauth.save_client_config("dropbox", "app-key")
        cancel = threading.Event()
        threading.Timer(0.5, cancel.set).start()
        start = time.time()
        with self.assertRaises(oauth.OAuthError):
            oauth.login("dropbox", cancel_event=cancel, open_browser=lambda url: None)
        self.assertLess(time.time() - start, 5)

    def test_google_requires_secret(self):
        oauth.save_client_config("google_drive", "gid")
        self.assertFalse(oauth.is_client_configured("google_drive"))
        oauth.save_client_config("google_drive", "gid", "gsecret")
        self.assertTrue(oauth.is_client_configured("google_drive"))


class TestTokenRefresh(OAuthTestBase):
    def test_valid_token_is_reused(self):
        cfg = {"oauth": {"access_token": "AT", "refresh_token": "RT", "expires_at": time.time() + 600}}
        with mock.patch.object(oauth.requests, "post") as post:
            self.assertEqual(oauth.get_access_token("onedrive", cfg), "AT")
            post.assert_not_called()

    def test_expired_token_is_refreshed_and_stored(self):
        oauth.save_client_config("dropbox", "app-key")
        cfg = {"oauth": {"access_token": "OLD", "refresh_token": "RT", "expires_at": 0, "account": "jan@x.pl"}}
        with mock.patch.object(oauth.requests, "post", return_value=FakeResponse(payload={"access_token": "NEW", "expires_in": 14400})):
            self.assertEqual(oauth.get_access_token("dropbox", cfg), "NEW")
        self.assertEqual(cfg["oauth"]["refresh_token"], "RT")  # Dropbox nie zwraca nowego refresh tokenu
        self.assertEqual(cfg["oauth"]["account"], "jan@x.pl")

    def test_revoked_refresh_token_raises(self):
        oauth.save_client_config("onedrive", "cid")
        cfg = {"oauth": {"access_token": "OLD", "refresh_token": "RT", "expires_at": 0}}
        with mock.patch.object(oauth.requests, "post", return_value=FakeResponse(400, {"error": "invalid_grant"})):
            with self.assertRaises(oauth.OAuthError):
                oauth.get_access_token("onedrive", cfg)

    def test_not_connected_returns_none(self):
        self.assertIsNone(oauth.get_access_token("onedrive", {"oauth": {}}))


class TestCloudUploadWithOAuth(OAuthTestBase):
    def test_onedrive_upload_uses_bearer_token(self):
        vault_file = os.path.join(self.temp_dir, "Sejf.vault")
        with open(vault_file, "wb") as f:
            f.write(b"SECVAULT-encrypted")
        cfg = {"oauth": {"access_token": "AT", "refresh_token": "RT", "expires_at": time.time() + 600}}

        with mock.patch("backups.onedrive_backup.requests.put", return_value=FakeResponse(201)) as put:
            status = OneDriveBackupProvider().upload_backup(vault_file, cfg)

        self.assertTrue(status.success, status.error_message)
        url = put.call_args.args[0]
        self.assertIn("/me/drive/root:/KeyStead-Backups/Sejf_backup_", url)
        self.assertEqual(put.call_args.kwargs["headers"]["Authorization"], "Bearer AT")


class TestMergeRuntimeState(unittest.TestCase):
    def test_refreshed_tokens_are_copied_back(self):
        target = {"onedrive": {"oauth": {"access_token": "OLD", "refresh_token": "RT"}}}
        source = {"onedrive": {"oauth": {"access_token": "NEW", "refresh_token": "RT2"}, "folder_id": "F1"}}
        self.assertTrue(merge_runtime_state(target, source))
        self.assertEqual(target["onedrive"]["oauth"]["access_token"], "NEW")
        self.assertEqual(target["onedrive"]["folder_id"], "F1")

    def test_logout_during_backup_is_respected(self):
        target = {"onedrive": {"oauth": {}}}
        source = {"onedrive": {"oauth": {"access_token": "NEW", "refresh_token": "RT"}}}
        self.assertFalse(merge_runtime_state(target, source))
        self.assertEqual(target["onedrive"]["oauth"], {})


if __name__ == "__main__":
    unittest.main()
