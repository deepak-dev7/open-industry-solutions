"""Tests for JSON/SARIF formatters and end-to-end CLI execution including Git --staged."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from codeguard.cli import main


class FormattersAndCliTestCase(unittest.TestCase):
    def test_cli_scan_sarif_and_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text('import os\nos.system("id")\n', encoding="utf-8")
            sarif_out = root / "report.sarif"

            prev_cwd = Path.cwd()
            try:
                os.chdir(root)
                stdout_buf = io.StringIO()
                with redirect_stdout(stdout_buf):
                    exit_code = main(
                        ["scan", ".", "--format", "sarif", "--output", str(sarif_out), "--fail-on", "high"]
                    )
            finally:
                os.chdir(prev_cwd)

            self.assertEqual(exit_code, 1)
            self.assertTrue(sarif_out.is_file())
            sarif = json.loads(sarif_out.read_text(encoding="utf-8"))
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertEqual(sarif["runs"][0]["tool"]["driver"]["name"], "CodeGuard")
            results = sarif["runs"][0]["results"]
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["ruleId"], "CG-PY-002")
            self.assertEqual(
                results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                "app.py",
            )

    def test_cli_rules_json_and_init(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg_path = root / ".codeguard.toml"

            stdout_buf = io.StringIO()
            with redirect_stdout(stdout_buf):
                rc_rules = main(["rules", "--format", "json"])
            self.assertEqual(rc_rules, 0)
            rules = json.loads(stdout_buf.getvalue())
            self.assertGreaterEqual(len(rules), 10)

            stdout_buf = io.StringIO()
            with redirect_stdout(stdout_buf):
                rc_init = main(["init", "--path", str(cfg_path)])
            self.assertEqual(rc_init, 0)
            self.assertTrue(cfg_path.is_file())

            stderr_buf = io.StringIO()
            with redirect_stderr(stderr_buf):
                rc_init_again = main(["init", "--path", str(cfg_path)])
            self.assertEqual(rc_init_again, 2)

    def test_cli_staged_git_diff_integration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "-b", "main"], cwd=root, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True, capture_output=True)
            subprocess.run(
                ["git", "config", "user.email", "test@example.com"],
                cwd=root,
                check=True,
                capture_output=True,
            )

            unstaged_bad = root / "unstaged.py"
            unstaged_bad.write_text('eval("1+1")\n', encoding="utf-8")

            staged_ok = root / "clean.py"
            staged_ok.write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")
            subprocess.run(["git", "add", "clean.py"], cwd=root, check=True, capture_output=True)

            prev_cwd = Path.cwd()
            try:
                os.chdir(root)
                stdout_buf = io.StringIO()
                with redirect_stdout(stdout_buf):
                    rc = main(["scan", "--staged", "--format", "json"])
            finally:
                os.chdir(prev_cwd)

            self.assertEqual(rc, 0)
            data = json.loads(stdout_buf.getvalue())
            self.assertEqual(data["summary"]["files_scanned"], 1)
            self.assertEqual(data["summary"]["findings_count"], 0)


if __name__ == "__main__":
    unittest.main()
