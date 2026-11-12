"""Tests for cross-language rules, inline suppressions, and TOML configuration."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from codeguard.config import load_config
from codeguard.models import CodeGuardConfig, Severity
from codeguard.scanner import scan_paths


class GeneralAndSuppressionTestCase(unittest.TestCase):
    def test_detects_github_actions_js_and_shell_issues(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wf = root / ".github" / "workflows" / "ci.yml"
            wf.parent.mkdir(parents=True)
            wf.write_text("name: CI\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n", encoding="utf-8")

            js = root / "web.js"
            js.write_text("function render(x) { el.innerHTML = x; }\n", encoding="utf-8")

            sh = root / "install.sh"
            sh.write_text("#!/usr/bin/env bash\ncurl -sSL https://example.com/install.sh | bash\n", encoding="utf-8")

            result = scan_paths(root=root, targets=[root], config=CodeGuardConfig())
            rule_ids = {f.rule_id for f in result.findings}
            self.assertEqual(rule_ids, {"CG-CFG-001", "CG-JS-001", "CG-SH-001"})

    def test_inline_suppression_same_line_and_next_line(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            py = root / "suppressed.py"
            py.write_text(
                'eval("1+1")  # codeguard: ignore[CG-PY-001]\n'
                "# codeguard: ignore[CG-PY-007]\n"
                "import tempfile\n"
                "x = tempfile.mktemp()\n"
                "y = tempfile.mktemp()\n",
                encoding="utf-8",
            )
            # Only line 2 suppression applies to line 3 (import), not line 4; verify exact behavior:
            py.write_text(
                "import tempfile\n"
                'eval("1+1")  # codeguard: ignore[CG-PY-001]\n'
                "# codeguard: ignore[CG-PY-007]\n"
                "x = tempfile.mktemp()\n"
                "y = tempfile.mktemp()\n",
                encoding="utf-8",
            )
            result = scan_paths(root=root, targets=[root], config=CodeGuardConfig())
            self.assertEqual(result.suppressed_count, 2)
            self.assertEqual(len(result.findings), 1)
            self.assertEqual(result.findings[0].line, 5)
            self.assertEqual(result.findings[0].rule_id, "CG-PY-007")

    def test_toml_config_ignores_paths_and_disables_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg_file = root / ".codeguard.toml"
            cfg_file.write_text(
                '[codeguard]\n'
                'fail_on = "critical"\n'
                'ignore_paths = ["ignored/**"]\n'
                'disabled_rules = ["CG-PY-001"]\n',
                encoding="utf-8",
            )
            (root / "ignored").mkdir()
            (root / "ignored" / "bad.py").write_text('eval("1+1")\n', encoding="utf-8")
            (root / "main.py").write_text('eval("1+1")\n', encoding="utf-8")

            cfg = load_config(config_path=None, root=root)
            self.assertEqual(cfg.fail_on, Severity.CRITICAL)
            result = scan_paths(root=root, targets=[root], config=cfg)
            self.assertEqual(result.findings, [])

    def test_skips_binary_and_oversized_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "binary.bin").write_bytes(b"\x00\x01\x02\x03")
            (root / "large.py").write_text("x = 1\n" * 400, encoding="utf-8")

            cfg = CodeGuardConfig(max_file_size_kb=1)
            result = scan_paths(root=root, targets=[root], config=cfg)
            self.assertEqual(result.files_scanned, 0)
            self.assertEqual(result.files_skipped, 2)


if __name__ == "__main__":
    unittest.main()
