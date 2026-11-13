"""Built-in synthetic security event scenarios for demonstration and automated testing."""

from __future__ import annotations

SCENARIOS: dict[str, dict[str, str]] = {
    "brute_force": {
        "title": "SSH Dictionary Brute Force & Account Compromise",
        "description": "7 rapid failed password attempts against user 'admin' from 198.51.100.22, followed by successful authentication.",
        "format": "syslog",
        "content": """Nov 13 02:14:10 edge-fw sshd[10411]: Failed password for invalid user admin from 198.51.100.22 port 41212 ssh2
Nov 13 02:14:14 edge-fw sshd[10412]: Failed password for invalid user admin from 198.51.100.22 port 41214 ssh2
Nov 13 02:14:19 edge-fw sshd[10415]: Failed password for invalid user admin from 198.51.100.22 port 41218 ssh2
Nov 13 02:14:23 edge-fw sshd[10418]: Failed password for invalid user admin from 198.51.100.22 port 41220 ssh2
Nov 13 02:14:28 edge-fw sshd[10421]: Failed password for invalid user admin from 198.51.100.22 port 41224 ssh2
Nov 13 02:14:32 edge-fw sshd[10424]: Failed password for invalid user admin from 198.51.100.22 port 41228 ssh2
Nov 13 02:14:40 edge-fw sshd[10427]: Accepted password for admin from 198.51.100.22 port 41232 ssh2
Nov 13 02:15:02 edge-fw sudo: admin : COMMAND=/bin/bash
""",
    },
    "password_spray": {
        "title": "Distributed Password Spray Across Multiple Corporate Accounts",
        "description": "Single external adversary targeting finance, engineering, and HR accounts with high-frequency credential tests.",
        "format": "syslog",
        "content": """Nov 13 09:30:05 sso-gw sshd[22010]: Failed password for alice from 45.154.255.88 port 51001 ssh2
Nov 13 09:30:15 sso-gw sshd[22014]: Failed password for bob from 45.154.255.88 port 51004 ssh2
Nov 13 09:30:24 sso-gw sshd[22018]: Failed password for charlie from 45.154.255.88 port 51008 ssh2
Nov 13 09:30:35 sso-gw sshd[22022]: Failed password for david from 45.154.255.88 port 51012 ssh2
Nov 13 09:30:46 sso-gw sshd[22026]: Failed password for emma from 45.154.255.88 port 51016 ssh2
Nov 13 09:30:57 sso-gw sshd[22030]: Failed password for frank from 45.154.255.88 port 51020 ssh2
""",
    },
    "impossible_travel": {
        "title": "Cross-Continent Impossible Travel Velocity Anomaly",
        "description": "User 'sarah.chen' authenticated successfully from London UK, followed 15 minutes later by a session from Tokyo Japan.",
        "format": "json",
        "content": """[
  {
    "timestamp": "2026-11-13T10:00:00Z",
    "event_type": "login_success",
    "status": "success",
    "username": "sarah.chen",
    "source_ip": "192.0.2.45",
    "target_host": "cloud-workspace",
    "geo_country": "United Kingdom",
    "geo_city": "London",
    "geo_lat": 51.5074,
    "geo_lon": -0.1278,
    "raw_message": "Okta SSO: Successful authentication for sarah.chen from London, UK"
  },
  {
    "timestamp": "2026-11-13T10:15:00Z",
    "event_type": "login_success",
    "status": "success",
    "username": "sarah.chen",
    "source_ip": "203.0.113.89",
    "target_host": "cloud-workspace",
    "geo_country": "Japan",
    "geo_city": "Tokyo",
    "geo_lat": 35.6762,
    "geo_lon": 139.6503,
    "raw_message": "Okta SSO: Successful authentication for sarah.chen from Tokyo, Japan"
  }
]""",
    },
    "after_hours_admin": {
        "title": "After-Hours Privileged Administrative Access via Tor Exit Node",
        "description": "Direct root login to a production database server at 03:22 AM UTC via a known Tor exit node IP.",
        "format": "syslog",
        "content": """Nov 13 03:22:15 prod-db-01 sshd[3301]: Accepted publickey for root from 185.220.101.5 port 55412 ssh2
Nov 13 03:22:18 prod-db-01 sudo: root : COMMAND=/usr/bin/cat /etc/shadow
""",
    },
    "clean_baseline": {
        "title": "Corporate Baseline Authentication Activity (Normal Operations)",
        "description": "Legitimate employee workday logins from office IP subnets with zero security policy alerts.",
        "format": "syslog",
        "content": """Nov 13 09:05:12 auth-server sshd[1101]: Accepted publickey for dev_john from 10.0.1.55 port 42100 ssh2
Nov 13 09:12:44 auth-server sshd[1105]: Accepted publickey for lead_dave from 10.0.1.72 port 42104 ssh2
Nov 13 09:20:10 auth-server sshd[1109]: Accepted publickey for sec_analyst from 10.0.2.14 port 42108 ssh2
Nov 13 10:04:19 auth-server sshd[1115]: Accepted password for eng_anna from 10.0.1.90 port 42112 ssh2
Nov 13 11:30:22 auth-server sshd[1122]: Accepted password for ops_mike from 10.0.3.11 port 42116 ssh2
""",
    },
}
