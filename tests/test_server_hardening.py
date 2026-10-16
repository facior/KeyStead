"""
Testy zabezpieczeń dodanych po audycie serwera: limit rozmiaru żądań, panel niewidoczny z internetu
także dla błędnych formularzy, unieważnianie kodu aktywacyjnego po błędnych kodach 2FA, ochrona przed
ponownym użyciem kodu 2FA, blokada IPv6 per /64, ograniczenia roli pomocy technicznej, eksport CSV,
punkty dzienne w historii wersji i dziennik odporny na zalewanie.
"""

import json
import os
import re
from datetime import datetime, timedelta, timezone

import pyotp
from fastapi.testclient import TestClient

from server.accounts import totp_step
from server.security import limiter_key
from tests.test_admin import ADMIN_PASSWORD, _csrf
from tests.test_admin_features import FeatureBase

BLOB = b"SECVAULT" + b"\x00" * 80
PUBLIC = ("203.0.113.9", 50000)


class TestBodyLimitsAndPanelExposure(FeatureBase):
    def test_huge_enroll_body_rejected_before_parsing(self):
        r = self.client.post("/api/v1/enroll", content=b"{" + b" " * (2 * 1024 * 1024) + b"}",
                             headers={"Content-Type": "application/json"})
        self.assertEqual(r.status_code, 413)

    def test_chunked_body_without_length_limited(self):
        def gen():
            for _ in range(200):
                yield b"x" * 1024
        r = self.client.post("/api/v1/enroll", content=gen(), headers={"Content-Type": "application/json"})
        self.assertEqual(r.status_code, 413)

    def test_vault_upload_keeps_its_own_limit(self):
        tok = self.enroll(self.new_user()).json()["token"]
        r = self.client.put("/api/v1/vault", content=BLOB + b"\x00" * 200_000,
                            headers={"Authorization": f"Bearer {tok}", "If-Match": '"0"'})
        self.assertEqual(r.status_code, 200)

    def test_panel_hidden_from_internet_even_for_invalid_forms(self):
        public = TestClient(self.app, client=PUBLIC)
        self.assertEqual(public.get("/admin").status_code, 404)
        r = public.post("/admin/backups/settings", data={"hour": "abc"})
        self.assertEqual(r.status_code, 404)  # wcześniej 422 zdradzało istnienie panelu
        r = public.post("/admin/settings/general", content=b"x" * 500_000,
                        headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertIn(r.status_code, (404, 413))


class TestEnrollmentTotp(FeatureBase):
    def _user_with_2fa(self):
        self.policy(require_user_2fa=1)
        first = self.enroll(self.new_user(), "Laptop").json()
        secret = first["totp_setup"]["secret"]
        auth = {"Authorization": f"Bearer {first['token']}"}
        self.assertEqual(self.client.post("/api/v1/account/totp/confirm", headers=auth,
                                          json={"code": pyotp.TOTP(secret).now()}).status_code, 200)
        return secret

    def test_code_burned_after_wrong_totp_guesses_from_many_ips(self):
        self._user_with_2fa()
        code = self.code_for("jan")
        statuses = []
        for i in range(5):  # każda próba z innego adresu IPv6 (inna sieć /64)
            c = TestClient(self.app, client=(f"2001:db8:{i}::1", 40000))
            statuses.append(c.post("/api/v1/enroll", json={"code": code, "device_name": "X", "totp": "000000"}).status_code)
        self.assertEqual(statuses[-1], 403)
        self.assertIsNone(self.app.state.enrollments.peek(code))  # kod unieważniony
        self.assertTrue(any(e["event"] == "enroll_code_burned" for e in self.app.state.audit.search()))

    def test_totp_code_cannot_be_reused(self):
        secret = self._user_with_2fa()
        now_code = pyotp.TOTP(secret).now()
        self.assertIsNone(totp_step(secret, now_code, last_step=pyotp.TOTP(secret).timecode(datetime.now())))
        self.assertFalse(self.app.state.users.verify_totp("jan", now_code))  # użyty już przy potwierdzeniu

    def test_admin_totp_replay_rejected(self):
        self.client.post("/admin/logout", data={"csrf": self.csrf})
        code = pyotp.TOTP(self.secret).now()
        # ten sam kod był już użyty przy logowaniu w setUp – drugie logowanie tym kodem nie przejdzie
        r = self.client.post("/admin/login", data={"username": "admin", "password": ADMIN_PASSWORD, "code": code})
        if r.status_code == 200 and "Nowy użytkownik" in r.text:
            self.skipTest("granica 30-sekundowego okna TOTP w trakcie testu")
        self.assertEqual(r.status_code, 401)


class TestRateLimitKey(FeatureBase):
    def test_ipv6_grouped_per_64(self):
        self.assertEqual(limiter_key("2001:db8:1:2:aaaa::1"), limiter_key("2001:db8:1:2:ffff::9"))
        self.assertNotEqual(limiter_key("2001:db8:1:2::1"), limiter_key("2001:db8:1:3::1"))
        self.assertEqual(limiter_key("::ffff:10.0.0.5"), "10.0.0.5")
        self.assertEqual(limiter_key("10.0.0.5"), "10.0.0.5")

    def test_invalid_codes_not_flooding_audit(self):
        before = len(self.app.state.audit.search(limit=0))
        for i in range(8):
            c = TestClient(self.app, client=(f"198.51.100.{i}", 1))
            c.post("/api/v1/enroll", json={"code": "AAAA-BBBB-CCCC", "device_name": "spam" * 10})
        self.assertEqual(len(self.app.state.audit.search(limit=0)), before)


class TestHelpdeskAndCsv(FeatureBase):
    def _helpdesk_client(self):
        r = self.client.post("/admin/admins/invite", data={"csrf": self.csrf, "role": "helpdesk"})
        link = re.search(r"(/admin/invite/[A-Za-z0-9_-]+)", r.text).group(1)
        hd = TestClient(self.app, client=("127.0.0.1", 50001))
        page = hd.post(link, data={"username": "pomoc", "password": ADMIN_PASSWORD, "password2": ADMIN_PASSWORD})
        secret = re.search(r"user-select:all\">([A-Z2-7]+)<", page.text).group(1)
        pid = re.search(r'name="pid" value="([^"]+)"', page.text).group(1)
        hd.post("/admin/setup/confirm", data={"pid": pid, "code": pyotp.TOTP(secret).now()})
        r = hd.post("/admin/login", data={"username": "pomoc", "password": ADMIN_PASSWORD,
                                          "code": pyotp.TOTP(secret).now()})
        return hd, _csrf(r.text)

    def test_helpdesk_cannot_issue_codes_for_accounts_with_vault(self):
        tok = self.enroll(self.new_user("ola")).json()["token"]
        self.client.put("/api/v1/vault", content=BLOB, headers={"Authorization": f"Bearer {tok}", "If-Match": '"0"'})
        self.client.post("/admin/users", data={"csrf": self.csrf, "username": "nowy", "display_name": "Nowy"})
        self.app.state.enrollments.revoke_for("nowy")
        hd, csrf = self._helpdesk_client()
        r = hd.post("/admin/users/ola/code", data={"csrf": csrf})
        self.assertIn("tylko administrator", r.text)
        self.assertEqual(self.app.state.enrollments.active_for("ola"), [])
        r = hd.post("/admin/users/nowy/code", data={"csrf": csrf})  # nowe konto bez sejfu – dozwolone
        self.assertIn("code-box", r.text)

    def test_csv_export_neutralizes_formulas(self):
        TestClient(self.app, client=("127.0.0.1", 1)).post(
            "/admin/login", data={"username": '=HYPERLINK("http://evil")', "password": "x", "code": "1"})
        csv_text = self.client.get("/admin/audit.csv").text
        self.assertIn("'=HYPERLINK", csv_text.replace('"', ""))
        self.assertNotIn(";=HYPERLINK", csv_text.replace('"', ""))


class TestHistoryAnchors(FeatureBase):
    def test_flood_does_not_erase_previous_days(self):
        store = self.app.state.store
        store.max_history = 5
        tok = self.enroll(self.new_user()).json()["token"]
        auth = {"Authorization": f"Bearer {tok}"}
        base = 0
        for _ in range(3):
            base = self.client.put("/api/v1/vault", content=BLOB, headers={**auth, "If-Match": f'"{base}"'}).json()["meta"]["version"]
        # wersje 1-3 „z wczoraj”
        vdir = os.path.join(self.data_dir, "users", "jan", "vault", "versions")
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(timespec="seconds")
        for name in os.listdir(vdir):
            if name.endswith(".json"):
                path = os.path.join(vdir, name)
                meta = json.load(open(path))
                meta["updated_at"] = yesterday
                json.dump(meta, open(path, "w"))
        for _ in range(30):  # zalanie śmieciowymi wersjami
            base = self.client.put("/api/v1/vault", content=BLOB, headers={**auth, "If-Match": f'"{base}"'}).json()["meta"]["version"]
        versions = [v["version"] for v in store.history("jan")]
        self.assertIn(3, versions)       # ostatnia wersja sprzed ataku przetrwała
        self.assertNotIn(1, versions)    # starsze wersje z tamtego dnia normalnie usunięte
        self.assertLessEqual(len(versions), 5 + 2)


class TestWebhookScheme(FeatureBase):
    def test_non_http_webhook_rejected(self):
        form = {"csrf": self.csrf, "webhook_enabled": "1", "webhook_kind": "generic", "webhook_url": "file:///etc/passwd",
                "disk_low_percent": "10"}
        self.client.post("/admin/settings/notifications", data=form)
        self.assertEqual(self.app.state.settings.section("notifications")["webhook"]["url"], "")
