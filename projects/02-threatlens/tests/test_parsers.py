"""Unit tests for multi-format log parsers (syslog, Windows Events, CloudTrail, CSV)."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threatlens.parsers import (
    auto_detect_and_parse,
    parse_cloud_audit_json,
    parse_generic_csv,
    parse_syslog_auth,
    parse_windows_event_json,
)


class ParsersTestCase(unittest.TestCase):
    def test_parse_syslog_auth(self) -> None:
        syslog_sample = """
Nov 13 02:14:10 edge-fw sshd[10411]: Failed password for invalid user admin from 198.51.100.22 port 41212 ssh2
Nov 13 02:14:40 edge-fw sshd[10427]: Accepted password for admin from 198.51.100.22 port 41232 ssh2
Nov 13 02:15:00 edge-fw sshd[10430]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.22  user=root
"""
        events = parse_syslog_auth(syslog_sample)
        self.assertEqual(len(events), 3)

        self.assertEqual(events[0].event_type, "login_failed")
        self.assertEqual(events[0].username, "admin")
        self.assertEqual(events[0].source_ip, "198.51.100.22")

        self.assertEqual(events[1].event_type, "login_success")
        self.assertEqual(events[1].username, "admin")

        self.assertEqual(events[2].event_type, "login_failed")
        self.assertEqual(events[2].username, "root")

    def test_parse_windows_event_json(self) -> None:
        records = [
            {
                "EventID": "4625",
                "TimeCreated": "2026-11-13T08:30:00Z",
                "TargetUserName": "finance_bob",
                "IpAddress": "185.220.101.5",
                "Computer": "DC01.corp.internal",
            },
            {
                "EventID": "4624",
                "TimeCreated": "2026-11-13T08:35:00Z",
                "TargetUserName": "finance_bob",
                "IpAddress": "185.220.101.5",
                "Computer": "DC01.corp.internal",
            },
            {
                "EventID": "4672",
                "TimeCreated": "2026-11-13T08:35:01Z",
                "TargetUserName": "finance_bob",
                "IpAddress": "185.220.101.5",
                "Computer": "DC01.corp.internal",
            },
        ]
        events = parse_windows_event_json(records)
        self.assertEqual(len(events), 3)
        self.assertEqual(events[0].event_type, "login_failed")
        self.assertEqual(events[1].event_type, "login_success")
        self.assertEqual(events[2].event_type, "privilege_escalation")

    def test_parse_cloud_audit_json(self) -> None:
        records = [
            {
                "eventTime": "2026-11-13T10:00:00Z",
                "eventName": "ConsoleLogin",
                "userIdentity": {"userName": "lead_engineer"},
                "sourceIPAddress": "192.0.2.14",
                "errorCode": "FailedAuthentication",
            },
            {
                "eventTime": "2026-11-13T10:01:00Z",
                "eventName": "ConsoleLogin",
                "userIdentity": {"userName": "lead_engineer"},
                "sourceIPAddress": "192.0.2.14",
            },
        ]
        events = parse_cloud_audit_json(records)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].status, "failure")
        self.assertEqual(events[1].status, "success")

    def test_parse_generic_csv(self) -> None:
        csv_data = """timestamp,username,source_ip,event_type,status
2026-11-13T04:00:00Z,operator,45.154.255.88,login_failed,failure
2026-11-13T04:01:00Z,operator,45.154.255.88,login_success,success
"""
        events = parse_generic_csv(csv_data)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].username, "operator")
        self.assertEqual(events[0].source_ip, "45.154.255.88")

    def test_auto_detect_and_parse(self) -> None:
        # JSON auto-detection
        json_text = json.dumps([
            {"timestamp": "2026-11-13T00:00:00Z", "username": "alice", "source_ip": "1.2.3.4", "event_type": "login_failed", "status": "failure"}
        ])
        events, fmt = auto_detect_and_parse(json_text)
        self.assertEqual(fmt, "json")
        self.assertEqual(len(events), 1)


if __name__ == "__main__":
    unittest.main()
