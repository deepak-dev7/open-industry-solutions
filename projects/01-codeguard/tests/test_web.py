"""Tests for the CodeGuard local web UI server and JSON/upload scan endpoints."""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from codeguard.web import create_server


class WebUiTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.server = create_server(host="127.0.0.1", port=0)
        self.port = self.server.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def _post_json(self, path: str, payload: dict[str, object]) -> tuple[int, dict[str, object]]:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_serves_html_and_rules_endpoint(self) -> None:
        with urllib.request.urlopen(f"{self.base_url}/", timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            html = resp.read().decode("utf-8")
            self.assertIn("CodeGuard", html)
            self.assertIn("webkitdirectory", html)

        with urllib.request.urlopen(f"{self.base_url}/api/rules", timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            body = json.loads(resp.read().decode("utf-8"))
            self.assertGreaterEqual(len(body["rules"]), 14)

    def test_scan_path_endpoint_finds_issues_and_handles_missing_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sample.py").write_text('eval("1+1")\n', encoding="utf-8")

            status, body = self._post_json("/api/scan-path", {"path": str(root), "fail_on": "high"})
            self.assertEqual(status, 200)
            self.assertTrue(body["failed"])
            self.assertEqual(body["summary"]["findings_count"], 1)
            self.assertEqual(body["findings"][0]["rule_id"], "CG-PY-001")
            self.assertIn("2.1.0", str(body["sarif"]))

        missing_status, missing_body = self._post_json(
            "/api/scan-path", {"path": "Z:/definitely/does/not/exist/codeguard"}
        )
        self.assertEqual(missing_status, 400)
        self.assertIn("does not exist", str(missing_body["error"]))

    def test_scan_upload_endpoint_scans_files_and_blocks_traversal(self) -> None:
        status, body = self._post_json(
            "/api/scan-upload",
            {
                "fail_on": "high",
                "files": [
                    {"path": "my-app/app.py", "content": 'import os\nos.system("id")\n'},
                    {"path": "my-app/clean.py", "content": "x = 1\n"},
                ],
            },
        )
        self.assertEqual(status, 200)
        self.assertTrue(body["failed"])
        self.assertEqual(body["summary"]["files_scanned"], 2)
        self.assertEqual(body["findings"][0]["rule_id"], "CG-PY-002")
        self.assertEqual(body["findings"][0]["file_path"], "my-app/app.py")

        bad_status, bad_body = self._post_json(
            "/api/scan-upload",
            {
                "fail_on": "high",
                "files": [{"path": "../escape.py", "content": "x = 1\n"}],
            },
        )
        self.assertEqual(bad_status, 400)
        self.assertIn("traversal", str(bad_body["error"]).lower())


if __name__ == "__main__":
    unittest.main()
