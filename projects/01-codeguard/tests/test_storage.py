"""Unit tests for CodeGuard SQLite storage layer."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from codeguard.models import Finding, ScanResult, Severity
from codeguard.storage import CodeGuardStore


class CodeGuardStoreTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.store = CodeGuardStore(db_path=Path(self._tmp.name) / "codeguard.db")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_persists_scan_findings_triage_settings_and_audit(self) -> None:
        self.assertTrue(self.store.check_health())

        finding = Finding(
            rule_id="CG-PY-001",
            rule_name="Dynamic Code Execution",
            severity=Severity.HIGH,
            category="python-security",
            cwe="CWE-95",
            file_path="app.py",
            line=10,
            column=5,
            message="Avoid eval().",
            remediation="Use ast.literal_eval().",
            snippet="eval(x)",
        )
        scan_result = ScanResult(
            root="/tmp/demo",
            files_scanned=3,
            files_skipped=1,
            suppressed_count=0,
            findings=[finding],
        )

        saved = self.store.save_scan(
            source_type="path",
            target_label="/tmp/demo",
            result=scan_result,
            fail_on=Severity.HIGH,
            duration_ms=25,
            sarif_json='{"version":"2.1.0"}',
        )
        self.assertTrue(saved["failed"])
        self.assertEqual(saved["findings_count"], 1)
        finding_id = saved["findings"][0]["id"]

        updated = self.store.update_finding_status(finding_id, "acknowledged")
        self.assertIsNotNone(updated)
        self.assertEqual(updated["status"], "acknowledged")

        dash = self.store.get_dashboard_stats()
        self.assertEqual(dash["total_scans"], 1)
        self.assertEqual(dash["open_findings"], 0)

        new_settings = self.store.update_settings({"fail_on": "medium", "max_file_size_kb": 512})
        self.assertEqual(new_settings["fail_on"], "medium")
        self.assertEqual(new_settings["max_file_size_kb"], 512)

        self.store.log_audit("scan_path", "/tmp/demo", "failed_gate", "findings=1")
        logs = self.store.list_audit_logs()
        self.assertEqual(logs[0]["action"], "scan_path")

        self.assertTrue(self.store.delete_scan(saved["id"]))
        self.assertIsNone(self.store.get_scan(saved["id"]))


if __name__ == "__main__":
    unittest.main()
