"""Raport PDF w panelu: generowanie, polskie znaki, trend z dziennych podsumowań, uprawnienia."""

import os
import tempfile
import unittest

from server.report_pdf import ReportHistory, build_pdf, org_summary
from tests.test_admin_features import FeatureBase


class TestReportPdf(unittest.TestCase):
    def rows(self):
        return [
            {"user_id": "jan", "name": "Jan Kowalski – księgowość", "disabled": False, "devices": 2, "active_24h": 1,
             "has_2fa": True, "report": {"score": 62, "breached": 2, "weak": 3, "reused": 1, "stale": 4,
                                         "received_at": "2026-10-15T10:00:00+00:00"}},
            {"user_id": "ola", "name": "Ola Żółwińska", "disabled": True, "devices": 0, "active_24h": 0,
             "has_2fa": False, "report": None},
        ]

    def test_summary(self):
        s = org_summary(self.rows())
        self.assertEqual((s["users"], s["active_users"], s["reports"], s["avg_score"], s["breached"]), (2, 1, 1, 62, 2))

    def test_pdf_generated_with_trend(self):
        history = [{"date": f"2026-10-{d:02d}", "avg_score": 50 + d} for d in range(1, 16)]
        data = build_pdf("Kowalski Sp. z o.o.", self.rows(), history, "1.5.0")
        self.assertTrue(data.startswith(b"%PDF-"))
        self.assertGreater(len(data), 3000)
        self.assertNotIn(b"tajne", data)

    def test_pdf_with_no_data(self):
        self.assertTrue(build_pdf("", [], []).startswith(b"%PDF-"))

    def test_history_one_entry_per_day(self):
        h = ReportHistory(tempfile.mkdtemp())
        h.record({"avg_score": 50}, day="2026-10-01")
        h.record({"avg_score": 70}, day="2026-10-01")
        h.record({"avg_score": 80}, day="2026-10-02")
        self.assertEqual([(d["date"], d["avg_score"]) for d in h.load()], [("2026-10-01", 70), ("2026-10-02", 80)])


class TestReportPdfRoute(FeatureBase):
    def test_download_from_panel(self):
        tok = self.enroll(self.new_user()).json()["token"]
        self.client.post("/api/v1/report", headers={"Authorization": f"Bearer {tok}"},
                         json={"score": 77, "total": 10, "breached": 1})
        page = self.client.get("/admin/reports").text
        self.assertIn("Pobierz raport PDF", page)
        r = self.client.get("/admin/reports.pdf")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers["content-type"], "application/pdf")
        self.assertTrue(r.content.startswith(b"%PDF-"))
        self.assertTrue(os.path.exists(os.path.join(self.data_dir, "report_history.json")))
        self.assertTrue(any(e["event"] == "report_pdf_downloaded" for e in self.app.state.audit.search()))

    def test_background_snapshot_daily(self):
        tasks = self.app.state.ctx.tasks
        tasks.run_once()
        tasks.run_once()  # drugi raz tego samego dnia – bez duplikatu
        self.assertEqual(len(self.app.state.ctx.report_history.load()), 1)


if __name__ == "__main__":
    unittest.main()
