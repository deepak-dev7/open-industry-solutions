"""Tests for secret detection, entropy checks, placeholder filtering, and redaction."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from codeguard.models import CodeGuardConfig, Severity
from codeguard.redaction import redact_secret
from codeguard.rules.secrets import scan_secrets, shannon_entropy


class SecretRulesTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.config = CodeGuardConfig()

    def test_redaction_masks_interior_of_secret(self) -> None:
        token = "ghp_" + "AbCdEfGhIjKlMnOpQrStUvWxYz123456"
        redacted = redact_secret(token)
        self.assertTrue(redacted.startswith("ghp_"))
        self.assertTrue(redacted.endswith("3456"))
        self.assertIn("****", redacted)
        self.assertNotIn("KlMnOp", redacted)

    def test_detects_provider_token_and_redacts_snippet(self) -> None:
        token = "ghp_" + "9xK2mP4qR7sT1vW3yZ5aB8cD0eF2gH4j"
        content = f'GITHUB_TOKEN = "{token}"\n'
        findings = scan_secrets("app.py", content, self.config)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "CG-SEC-001")
        self.assertEqual(finding.severity, Severity.CRITICAL)
        self.assertNotIn(token, finding.message)
        self.assertNotIn(token, finding.snippet)

    def test_detects_aws_access_key(self) -> None:
        aws_key = "AKIA" + "Z9X8C7V6B5N4M3K2"
        findings = scan_secrets("config.py", f'AWS_ID = "{aws_key}"\n', self.config)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "CG-SEC-001")
        self.assertNotIn(aws_key, findings[0].snippet)

    def test_detects_private_key_header(self) -> None:
        header = "-----" + "BEGIN RSA PRIVATE KEY" + "-----"
        findings = scan_secrets("key.pem", header + "\n", self.config)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "CG-SEC-002")
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_detects_high_entropy_secret_assignment(self) -> None:
        secret = "9fK$mP2@xQ7!vL4#" + "nZ8&bW5*cR1^tY6%"
        self.assertGreater(shannon_entropy(secret), self.config.entropy_threshold)
        findings = scan_secrets("settings.py", f'api_key = "{secret}"\n', self.config)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "CG-SEC-003")
        self.assertNotIn(secret, findings[0].snippet)

    def test_ignores_obvious_placeholders_and_low_entropy_values(self) -> None:
        content = (
            'api_key = "your_api_key_placeholder"\n'
            'password = "changeme_in_production"\n'
            'auth_token = "aaaaaaaaaaaaaaa"\n'
            'secret = "${MY_RUNTIME_SECRET}"\n'
        )
        findings = scan_secrets("settings.py", content, self.config)
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
