"""End-to-end FastAPI + SQLite tests for the CodeGuard web workbench."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from codeguard.api import create_app


class CodeGuardWebAppTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name).resolve()
        self.db_path = self.root / "test_codeguard.db"
        self.client = TestClient(create_app(db_path=self.db_path))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_frontend_static_assets_and_security_headers(self) -> None:
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("CodeGuard", resp.text)
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
        self.assertIn("script-src 'self'", resp.headers.get("Content-Security-Policy", ""))

        self.assertEqual(self.client.get("/static/styles.css").status_code, 200)
        self.assertEqual(self.client.get("/static/app.js").status_code, 200)

        health = self.client.get("/api/health")
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json()["database"], "ok")

    def test_path_scan_persistence_dashboard_triage_export_and_delete(self) -> None:
        project_dir = self.root / "sample_repo"
        project_dir.mkdir()
        (project_dir / "app.py").write_text(
            'import os\nos.system("id")\nimport hashlib\nhashlib.md5(b"x")\n',
            encoding="utf-8",
        )

        scan_resp = self.client.post(
            "/api/scans/path",
            json={"path": str(project_dir), "fail_on": "high"},
        )
        self.assertEqual(scan_resp.status_code, 200)
        scan = scan_resp.json()
        self.assertTrue(scan["failed"])
        self.assertEqual(scan["findings_count"], 2)
        self.assertEqual(scan["high_count"], 1)
        self.assertEqual(scan["medium_count"], 1)

        dash = self.client.get("/api/dashboard").json()
        self.assertEqual(dash["total_scans"], 1)
        self.assertEqual(dash["open_findings"], 2)

        filtered = self.client.get(f"/api/scans/{scan['id']}?severity=high").json()
        self.assertEqual(len(filtered["findings"]), 1)
        finding_id = filtered["findings"][0]["id"]

        triage = self.client.patch(
            f"/api/findings/{finding_id}",
            json={"status": "acknowledged"},
        )
        self.assertEqual(triage.status_code, 200)
        self.assertEqual(triage.json()["status"], "acknowledged")

        dash_after = self.client.get("/api/dashboard").json()
        self.assertEqual(dash_after["open_findings"], 1)

        sarif_resp = self.client.get(f"/api/scans/{scan['id']}/export?format=sarif")
        self.assertEqual(sarif_resp.status_code, 200)
        self.assertIn('"version": "2.1.0"', sarif_resp.text)

        html_resp = self.client.get(f"/api/scans/{scan['id']}/export?format=html")
        self.assertEqual(html_resp.status_code, 200)
        self.assertIn("CodeGuard Security", html_resp.text)

        del_resp = self.client.delete(f"/api/scans/{scan['id']}")
        self.assertEqual(del_resp.status_code, 200)
        self.assertEqual(self.client.get(f"/api/scans/{scan['id']}").status_code, 404)

    def test_upload_scan_and_traversal_blocking(self) -> None:
        resp = self.client.post(
            "/api/scans/upload",
            json={
                "folder_name": "demo-app",
                "fail_on": "high",
                "files": [
                    {"path": "demo-app/main.py", "content": 'eval("1+1")\n'},
                    {"path": "demo-app/clean.py", "content": "x = 42\n"},
                ],
            },
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["files_scanned"], 2)
        self.assertEqual(data["findings_count"], 1)
        self.assertEqual(data["findings"][0]["rule_id"], "CG-PY-001")

        bad = self.client.post(
            "/api/scans/upload",
            json={
                "folder_name": "bad",
                "files": [{"path": "../escape.py", "content": "x = 1\n"}],
            },
        )
        self.assertEqual(bad.status_code, 400)
        self.assertIn("traversal", bad.json()["detail"].lower())

        logs = self.client.get("/api/audit-logs").json()["logs"]
        actions = [entry["action"] for entry in logs]
        self.assertIn("scan_upload", actions)

    def test_browse_and_approved_roots_enforcement(self) -> None:
        allowed_dir = self.root / "approved"
        forbidden_dir = self.root / "forbidden"
        (allowed_dir / "sub").mkdir(parents=True)
        forbidden_dir.mkdir()

        put_resp = self.client.put(
            "/api/settings",
            json={
                "fail_on": "high",
                "max_file_size_kb": 1024,
                "entropy_threshold": 4.2,
                "disabled_rules": [],
                "ignore_paths": [".git/**"],
                "allowlist_patterns": [],
                "allowed_roots": [str(allowed_dir)],
            },
        )
        self.assertEqual(put_resp.status_code, 200)

        browse_ok = self.client.get("/api/browse")
        self.assertEqual(browse_ok.status_code, 200)
        self.assertEqual(browse_ok.json()["directories"][0]["name"], "sub")

        browse_denied = self.client.get(f"/api/browse?path={forbidden_dir}")
        self.assertEqual(browse_denied.status_code, 403)

        scan_denied = self.client.post("/api/scans/path", json={"path": str(forbidden_dir)})
        self.assertEqual(scan_denied.status_code, 403)

    def test_rules_filter_and_settings_validation(self) -> None:
        rules = self.client.get("/api/rules?severity=critical").json()["rules"]
        self.assertTrue(all(r["severity"] == "critical" for r in rules))

        bad_settings = self.client.put(
            "/api/settings",
            json={
                "fail_on": "high",
                "max_file_size_kb": 1024,
                "entropy_threshold": 4.2,
                "allowlist_patterns": ["[unclosed"],
            },
        )
        self.assertEqual(bad_settings.status_code, 422)


if __name__ == "__main__":
    unittest.main()
