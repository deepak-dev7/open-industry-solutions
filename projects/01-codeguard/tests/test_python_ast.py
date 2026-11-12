"""Tests for Python AST static security and quality rules."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from codeguard.rules.python_ast import scan_python_ast


class PythonAstRulesTestCase(unittest.TestCase):
    def test_detects_all_unsafe_python_patterns(self) -> None:
        code = """
import hashlib
import os
import pickle
import ssl
import subprocess
import tempfile
import yaml

def run_risky(user_input, cursor, requests):
    eval(user_input)
    os.system("ls -la")
    subprocess.run("echo hi", shell=True)
    pickle.loads(b"data")
    yaml.load("a: 1")
    hashlib.md5(b"pw")
    requests.get("https://example.com", verify=False)
    ssl._create_unverified_context()
    tempfile.mktemp()
    cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
"""
        findings, err = scan_python_ast("risky.py", code)
        self.assertIsNone(err)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("CG-PY-001", rule_ids)
        self.assertEqual(rule_ids.count("CG-PY-002"), 2)
        self.assertIn("CG-PY-003", rule_ids)
        self.assertIn("CG-PY-004", rule_ids)
        self.assertIn("CG-PY-005", rule_ids)
        self.assertEqual(rule_ids.count("CG-PY-006"), 2)
        self.assertIn("CG-PY-007", rule_ids)
        self.assertIn("CG-PY-008", rule_ids)

    def test_allows_safe_python_patterns(self) -> None:
        code = """
import ast
import hashlib
import subprocess
import tempfile
import yaml

def run_safe(raw, cursor, requests):
    ast.literal_eval("[1, 2, 3]")
    subprocess.run(["echo", "hi"], shell=False, check=True)
    yaml.safe_load("a: 1")
    yaml.load("a: 1", Loader=yaml.SafeLoader)
    hashlib.md5(b"cache-key", usedforsecurity=False)
    hashlib.sha256(b"secure")
    requests.get("https://example.com", verify=True, timeout=5)
    with tempfile.NamedTemporaryFile() as fh:
        fh.write(b"ok")
    cursor.execute("SELECT * FROM users WHERE name = ?", (raw,))
"""
        findings, err = scan_python_ast("safe.py", code)
        self.assertIsNone(err)
        self.assertEqual(findings, [])

    def test_handles_syntax_error_gracefully(self) -> None:
        findings, err = scan_python_ast("broken.py", "def broken(:\n  pass\n")
        self.assertEqual(findings, [])
        self.assertIsNotNone(err)
        self.assertIn("SyntaxError", err or "")


if __name__ == "__main__":
    unittest.main()
