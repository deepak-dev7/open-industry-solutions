"""Unit tests for Threat Intelligence Indicators of Compromise (IOC) matching."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threatlens.ioc import IOCMatcher, IOCRecord
from threatlens.models import IncidentSeverity


class IOCTestCase(unittest.TestCase):
    def test_default_ioc_exact_ip_matching(self) -> None:
        matcher = IOCMatcher()
        match = matcher.match_ip("185.220.101.5")
        self.assertIsNotNone(match)
        self.assertEqual(match.threat_type, "tor_exit_node")
        self.assertEqual(match.severity, IncidentSeverity.CRITICAL)

    def test_cidr_subnet_matching(self) -> None:
        matcher = IOCMatcher()
        # 198.51.100.0/24 is configured as brute_force_botnet
        match = matcher.match_ip("198.51.100.42")
        self.assertIsNotNone(match)
        self.assertEqual(match.threat_type, "brute_force_botnet")

    def test_clean_ip_returns_none(self) -> None:
        matcher = IOCMatcher()
        self.assertIsNone(matcher.match_ip("8.8.8.8"))
        self.assertIsNone(matcher.match_ip("127.0.0.1"))

    def test_dynamic_add_ioc(self) -> None:
        matcher = IOCMatcher([])
        self.assertIsNone(matcher.match_ip("203.0.113.199"))

        matcher.add_record(
            IOCRecord(
                id=99,
                ioc_type="ip",
                indicator="203.0.113.199",
                threat_type="custom_threat",
                severity=IncidentSeverity.HIGH,
                description="Custom test indicator",
            )
        )
        match = matcher.match_ip("203.0.113.199")
        self.assertIsNotNone(match)
        self.assertEqual(match.threat_type, "custom_threat")


if __name__ == "__main__":
    unittest.main()
