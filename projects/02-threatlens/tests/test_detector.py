"""Unit tests for the ThreatLens correlation engine and MITRE ATT&CK rules."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threatlens.detector import ThreatDetector
from threatlens.models import IncidentSeverity, SecurityEvent, ThreatLensConfig


class DetectorTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.config = ThreatLensConfig(
            brute_force_threshold=4,
            brute_force_window_sec=300,
            spray_user_threshold=3,
            spray_window_sec=600,
            impossible_travel_max_kmh=800.0,
            work_hours_start=8,
            work_hours_end=19,
        )
        self.detector = ThreatDetector(config=self.config)

    def test_detect_brute_force_and_compromise(self) -> None:
        # 4 failed logins followed by success for admin from same IP
        events = [
            SecurityEvent("2026-11-13T01:00:00Z", "login_failed", "failure", "admin", "198.51.100.10"),
            SecurityEvent("2026-11-13T01:00:10Z", "login_failed", "failure", "admin", "198.51.100.10"),
            SecurityEvent("2026-11-13T01:00:20Z", "login_failed", "failure", "admin", "198.51.100.10"),
            SecurityEvent("2026-11-13T01:00:30Z", "login_failed", "failure", "admin", "198.51.100.10"),
            SecurityEvent("2026-11-13T01:00:45Z", "login_success", "success", "admin", "198.51.100.10"),
        ]
        incidents = self.detector.analyze(events)
        mitre_ids = [inc.mitre_id for inc in incidents]

        # Should detect Brute Force (T1110.001) and Account Compromise (T1078.002)
        self.assertIn("T1110.001", mitre_ids)
        self.assertIn("T1078.002", mitre_ids)

        # Critical compromise severity
        comp_inc = next(inc for inc in incidents if inc.mitre_id == "T1078.002")
        self.assertEqual(comp_inc.severity, IncidentSeverity.CRITICAL)
        self.assertEqual(comp_inc.risk_score, 95)

    def test_detect_password_spray(self) -> None:
        # Single IP attacking 3 distinct usernames
        events = [
            SecurityEvent("2026-11-13T09:00:00Z", "login_failed", "failure", "alice", "45.154.255.88"),
            SecurityEvent("2026-11-13T09:01:00Z", "login_failed", "failure", "bob", "45.154.255.88"),
            SecurityEvent("2026-11-13T09:02:00Z", "login_failed", "failure", "charlie", "45.154.255.88"),
        ]
        incidents = self.detector.analyze(events)
        spray_inc = next((inc for inc in incidents if inc.mitre_id == "T1110.003"), None)
        self.assertIsNotNone(spray_inc)
        self.assertEqual(spray_inc.severity, IncidentSeverity.HIGH)
        self.assertEqual(spray_inc.primary_ip, "45.154.255.88")

    def test_detect_impossible_travel(self) -> None:
        # User logging in from London then Tokyo 10 minutes later
        events = [
            SecurityEvent(
                timestamp="2026-11-13T10:00:00Z",
                event_type="login_success",
                status="success",
                username="sarah.chen",
                source_ip="192.0.2.10",
                geo_country="United Kingdom",
                geo_city="London",
                geo_lat=51.5074,
                geo_lon=-0.1278,
            ),
            SecurityEvent(
                timestamp="2026-11-13T10:10:00Z",
                event_type="login_success",
                status="success",
                username="sarah.chen",
                source_ip="203.0.113.20",
                geo_country="Japan",
                geo_city="Tokyo",
                geo_lat=35.6762,
                geo_lon=139.6503,
            ),
        ]
        incidents = self.detector.analyze(events)
        travel_inc = next((inc for inc in incidents if inc.mitre_id == "T1078"), None)
        self.assertIsNotNone(travel_inc)
        self.assertEqual(travel_inc.primary_user, "sarah.chen")
        self.assertIn("impossible velocity", travel_inc.analyst_notes.lower())

    def test_detect_after_hours_admin(self) -> None:
        # Root login at 03:00 UTC (outside 08:00 - 19:00)
        events = [
            SecurityEvent(
                timestamp="2026-11-13T03:15:00Z",
                event_type="login_success",
                status="success",
                username="root",
                source_ip="10.0.1.5",
            ),
        ]
        incidents = self.detector.analyze(events)
        after_inc = next((inc for inc in incidents if inc.mitre_id == "T1078.004"), None)
        self.assertIsNotNone(after_inc)
        self.assertEqual(after_inc.primary_user, "root")

    def test_clean_traffic_yields_no_incidents(self) -> None:
        # Normal midday user logins
        events = [
            SecurityEvent("2026-11-13T11:00:00Z", "login_success", "success", "dev1", "10.0.1.1"),
            SecurityEvent("2026-11-13T11:05:00Z", "login_success", "success", "dev2", "10.0.1.2"),
        ]
        incidents = self.detector.analyze(events)
        self.assertEqual(len(incidents), 0)


if __name__ == "__main__":
    unittest.main()
