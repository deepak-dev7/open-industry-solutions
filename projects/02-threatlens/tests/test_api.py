"""End-to-end FastAPI integration tests for ThreatLens SOC Workbench API."""

from __future__ import annotations

import io
import shutil
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from threatlens.api import create_app


class ThreatLensAPITestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_api_threatlens.db"
        self.app = create_app(db_path=self.db_path)
        self.client = TestClient(self.app)

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_frontend_static_and_security_headers(self) -> None:
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("ThreatLens", resp.text)
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
        self.assertIn("default-src 'self'", resp.headers.get("Content-Security-Policy", ""))

        self.assertEqual(self.client.get("/static/styles.css").status_code, 200)
        self.assertEqual(self.client.get("/static/app.js").status_code, 200)

        health = self.client.get("/api/health")
        self.assertEqual(health.status_code, 200)
        data = health.json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["service"], "ThreatLens")
        self.assertEqual(data["database"], "ok")

    def test_scenarios_listing_and_ingestion(self) -> None:
        scenarios_resp = self.client.get("/api/scenarios")
        self.assertEqual(scenarios_resp.status_code, 200)
        scenarios = scenarios_resp.json().get("scenarios", [])
        self.assertGreaterEqual(len(scenarios), 5)
        keys = [s["key"] for s in scenarios]
        self.assertIn("brute_force", keys)
        self.assertIn("impossible_travel", keys)

        # Ingest brute force scenario
        ingest_resp = self.client.post("/api/ingest/scenario", json={"scenario_key": "brute_force"})
        self.assertEqual(ingest_resp.status_code, 200)
        result = ingest_resp.json()
        self.assertGreater(result["events_count"], 0)
        self.assertGreater(result["incidents_count"], 0)
        self.assertEqual(result["detected_format"], "syslog")

    def test_incident_lifecycle_triage_and_export(self) -> None:
        # Ingest impossible travel attack scenario
        self.client.post("/api/ingest/scenario", json={"scenario_key": "impossible_travel"})

        # List incidents
        inc_resp = self.client.get("/api/incidents")
        self.assertEqual(inc_resp.status_code, 200)
        incidents = inc_resp.json().get("incidents", [])
        self.assertGreater(len(incidents), 0)
        incident_id = incidents[0]["id"]

        # Get detail
        detail_resp = self.client.get(f"/api/incidents/{incident_id}")
        self.assertEqual(detail_resp.status_code, 200)
        detail = detail_resp.json()
        self.assertEqual(detail["id"], incident_id)
        self.assertIn("events", detail)

        # Triage incident
        triage_resp = self.client.patch(
            f"/api/incidents/{incident_id}",
            json={"status": "investigating", "analyst_notes": "Adversary session revoked in Okta."},
        )
        self.assertEqual(triage_resp.status_code, 200)
        self.assertEqual(triage_resp.json()["status"], "investigating")

        # Export JSON
        export_json = self.client.get(f"/api/incidents/{incident_id}/export?format=json")
        self.assertEqual(export_json.status_code, 200)
        self.assertIn(incident_id, export_json.text)

        # Export CSV
        export_csv = self.client.get(f"/api/incidents/{incident_id}/export?format=csv")
        self.assertEqual(export_csv.status_code, 200)
        self.assertIn("EventType", export_csv.text)

        # Export Markdown
        export_md = self.client.get(f"/api/incidents/{incident_id}/export?format=markdown")
        self.assertEqual(export_md.status_code, 200)
        self.assertIn("Security Incident Forensic Report", export_md.text)

    def test_raw_text_ingest_and_event_search(self) -> None:
        raw_log = """
Nov 13 03:00:01 bastion sshd[9012]: Failed password for invalid user analyst from 185.220.101.5 port 51222 ssh2
Nov 13 03:00:05 bastion sshd[9014]: Failed password for invalid user analyst from 185.220.101.5 port 51224 ssh2
"""
        resp = self.client.post(
            "/api/ingest/text",
            json={"text": raw_log, "filename": "bastion_auth.log", "format_hint": "syslog"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["events_count"], 2)

        # Search events
        events_resp = self.client.get("/api/events?username=analyst")
        self.assertEqual(events_resp.status_code, 200)
        events = events_resp.json().get("events", [])
        self.assertEqual(len(events), 2)

    def test_file_upload_ingest(self) -> None:
        csv_content = b"timestamp,username,source_ip,status,event_type,target_host\n2026-11-13T01:00:00Z,operator,198.51.100.40,success,login_success,core-db\n"
        resp = self.client.post(
            "/api/ingest/upload",
            files={"file": ("audit.csv", io.BytesIO(csv_content), "text/csv")},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["events_count"], 1)
        self.assertEqual(data["filename"], "audit.csv")

    def test_ioc_and_settings_and_audit_endpoints(self) -> None:
        # Add IOC
        ioc_resp = self.client.post(
            "/api/ioc",
            json={
                "ioc_type": "ip",
                "indicator": "198.51.100.99",
                "threat_type": "Command and Control",
                "severity": "critical",
                "description": "Known malicious beacon",
            },
        )
        self.assertEqual(ioc_resp.status_code, 200)
        ioc_id = ioc_resp.json()["id"]

        # List IOCs
        iocs_list = self.client.get("/api/ioc").json()["iocs"]
        self.assertTrue(any(i["indicator"] == "198.51.100.99" for i in iocs_list))

        # Delete IOC
        del_resp = self.client.delete(f"/api/ioc/{ioc_id}")
        self.assertEqual(del_resp.status_code, 200)

        # Get settings
        settings = self.client.get("/api/settings").json()
        self.assertIn("brute_force_threshold", settings)

        # Update settings
        settings["brute_force_threshold"] = 7
        update_resp = self.client.put("/api/settings", json=settings)
        self.assertEqual(update_resp.status_code, 200)
        self.assertEqual(update_resp.json()["brute_force_threshold"], 7)

        # Check audit logs
        audit_resp = self.client.get("/api/audit-logs")
        self.assertEqual(audit_resp.status_code, 200)
        logs = audit_resp.json().get("logs", [])
        self.assertGreater(len(logs), 0)


if __name__ == "__main__":
    unittest.main()
