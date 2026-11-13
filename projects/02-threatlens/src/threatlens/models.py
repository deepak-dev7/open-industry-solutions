"""Data models for ThreatLens events, incidents, IOCs, and detection configurations."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class IncidentSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @classmethod
    def from_str(cls, val: str) -> IncidentSeverity:
        try:
            return cls(val.strip().lower())
        except ValueError:
            return cls.MEDIUM


class IncidentStatus(str, Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


@dataclass
class SecurityEvent:
    """Normalized security authentication or access event."""
    timestamp: str  # ISO-8601 UTC
    event_type: str  # login_failed, login_success, privilege_escalation, account_locked, session_start
    status: str      # failure, success, info
    username: str
    source_ip: str
    target_host: str = "auth-server"
    geo_country: str = "Unknown"
    geo_city: str = "Unknown"
    geo_lat: float | None = None
    geo_lon: float | None = None
    raw_message: str = ""
    event_id: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "status": self.status,
            "username": self.username,
            "source_ip": self.source_ip,
            "target_host": self.target_host,
            "geo_country": self.geo_country,
            "geo_city": self.geo_city,
            "geo_lat": self.geo_lat,
            "geo_lon": self.geo_lon,
            "raw_message": self.raw_message,
        }


@dataclass
class Incident:
    """A correlated security incident representing an attack campaign or anomaly."""
    id: str
    title: str
    severity: IncidentSeverity
    mitre_id: str
    mitre_name: str
    risk_score: int  # 0 to 100
    primary_ip: str
    primary_user: str
    event_count: int
    first_seen: str
    last_seen: str
    status: IncidentStatus = IncidentStatus.NEW
    analyst_notes: str = ""
    event_ids: list[int] = field(default_factory=list)
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "mitre_id": self.mitre_id,
            "mitre_name": self.mitre_name,
            "risk_score": self.risk_score,
            "primary_ip": self.primary_ip,
            "primary_user": self.primary_user,
            "event_count": self.event_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "status": self.status.value,
            "analyst_notes": self.analyst_notes,
            "event_ids": self.event_ids,
            "created_at": self.created_at,
        }


@dataclass
class ThreatLensConfig:
    """Detection engine threshold configuration."""
    brute_force_threshold: int = 5          # >= N failures for single user in window
    brute_force_window_sec: int = 300       # 5 minutes
    spray_user_threshold: int = 4           # >= N distinct users attacked by single IP
    spray_window_sec: int = 600             # 10 minutes
    impossible_travel_max_kmh: float = 850.0  # Speed threshold for impossible travel (commercial aircraft max)
    work_hours_start: int = 8               # 08:00
    work_hours_end: int = 19                # 19:00
    privileged_accounts: tuple[str, ...] = ("root", "admin", "administrator", "sysadmin", "deploy", "dbadmin")
