"""Unit tests for ThreatLens SQLite storage layer."""

from __future__ import annotations

import unittest
import uuid
from pathlib import Path
import tempfile
import shutil

from threatlens.models import Incident, IncidentSeverity, IncidentStatus, SecurityEvent
from threatlens.storage import ThreatLensStore


class StorageTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_threatlens.db"
        self.store = ThreatLensStore(self.db_path)

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_schema_init_and_health_check(self) -> None:
        self.assertTrue(self.store.check_health())
        # Default IOC records seeded
        iocs = self.store.list_iocs()
        self.assertGreater(len(iocs), 0)

    def test_save_and_retrieve_ingest_batch(self) -> None:
        events = [
            SecurityEvent(
                timestamp="2026-11-13T02:00:00Z",
                event_type="login_failed",
                status="failure",
                username="alice",
                source_ip="185.220.101.5",
                target_host="bastion",
                geo_country="Germany",
                geo_city="Frankfurt",
                geo_lat=50.11,
                geo_lon=8.68,
                raw_message="failed login test",
            ),
            SecurityEvent(
                timestamp="2026-11-13T02:00:05Z",
                event_type="login_success",
                status="success",
                username="alice",
                source_ip="185.220.101.5",
                target_host="bastion",
                geo_country="Germany",
                geo_city="Frankfurt",
                geo_lat=50.11,
                geo_lon=8.68,
                raw_message="accepted login test",
            ),
        ]

        inc_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        incident = Incident(
            id=inc_id,
            title="Credential Compromise Detected",
            severity=IncidentSeverity.CRITICAL,
            mitre_id="T1078",
            mitre_name="Valid Accounts",
            risk_score=95,
            primary_ip="185.220.101.5",
            primary_user="alice",
            event_count=2,
            first_seen="2026-11-13T02:00:00Z",
            last_seen="2026-11-13T02:00:05Z",
            status=IncidentStatus.NEW,
        )

        source_id = self.store.save_ingest_batch(
            filename="auth.log",
            fmt="syslog",
            events=events,
            incidents=[incident],
            duration_ms=45,
        )

        self.assertTrue(bool(source_id))

        # Check incidents
        incidents = self.store.list_incidents()
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["id"], incident.id)
        self.assertEqual(incidents[0]["severity"], "critical")
        self.assertEqual(incidents[0]["status"], "new")

        # Check single incident detail
        inc_detail = self.store.get_incident(incident.id)
        self.assertIsNotNone(inc_detail)
        self.assertEqual(inc_detail["title"], "Credential Compromise Detected")

        # Check search events
        ev_list = self.store.search_events(limit=10)
        self.assertEqual(len(ev_list), 2)

    def test_incident_status_update_and_audit_trail(self) -> None:
        inc_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        incident = Incident(
            id=inc_id,
            title="Brute Force Attempt",
            severity=IncidentSeverity.HIGH,
            mitre_id="T1110.001",
            mitre_name="Password Guessing",
            risk_score=75,
            primary_ip="198.51.100.10",
            primary_user="root",
            event_count=1,
            first_seen="2026-11-13T02:00:00Z",
            last_seen="2026-11-13T02:00:10Z",
            status=IncidentStatus.NEW,
        )
        self.store.save_ingest_batch("sample.log", "syslog", [], [incident], 10)

        # Update status
        updated = self.store.update_incident(
            incident.id,
            status="investigating",
            notes="Assigned to L2 analyst; blocking IP on edge firewall.",
        )
        self.assertIsNotNone(updated)
        self.assertEqual(updated["status"], "investigating")
        self.assertIn("blocking IP", updated["analyst_notes"])

        # Log audit action
        self.store.log_audit("update_incident", incident.id, "success", "Assigned to L2 analyst")

        # Check audit log
        logs = self.store.list_audit_logs()
        self.assertGreater(len(logs), 0)
        action_names = [l["action"] for l in logs]
        self.assertIn("update_incident", action_names)

    def test_ioc_management(self) -> None:
        initial_count = len(self.store.list_iocs())
        new_ioc = self.store.add_ioc(
            ioc_type="ip",
            indicator="198.51.100.250",
            threat_type="APT C2 Server",
            severity="critical",
            description="Active C2 beacon test",
        )
        self.assertEqual(new_ioc["indicator"], "198.51.100.250")
        self.assertEqual(len(self.store.list_iocs()), initial_count + 1)

        # Delete IOC
        deleted = self.store.delete_ioc(new_ioc["id"])
        self.assertTrue(deleted)
        self.assertEqual(len(self.store.list_iocs()), initial_count)

    def test_dashboard_metrics(self) -> None:
        metrics = self.store.get_dashboard_metrics()
        self.assertIn("total_events", metrics)
        self.assertIn("total_incidents", metrics)
        self.assertIn("severity_breakdown", metrics)
        self.assertIn("top_attacker_ips", metrics)
        self.assertIn("top_targeted_accounts", metrics)


if __name__ == "__main__":
    unittest.main()
