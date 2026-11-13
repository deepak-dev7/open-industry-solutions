"""Deterministic security event correlation and threat detection engine."""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Iterable

from threatlens.geo import calculate_velocity_kmh
from threatlens.ioc import IOCMatcher, IOCRecord
from threatlens.models import (
    Incident,
    IncidentSeverity,
    IncidentStatus,
    SecurityEvent,
    ThreatLensConfig,
)


def _parse_ts(ts_str: str) -> float:
    """Parse ISO timestamp to epoch seconds."""
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.timestamp()
    except Exception:
        return 0.0


def _hour_of_ts(ts_str: str) -> int:
    """Return UTC hour (0-23) of timestamp."""
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.hour
    except Exception:
        return 12


class ThreatDetector:
    """Stateful correlator evaluating security events against MITRE ATT&CK patterns."""

    def __init__(
        self,
        config: ThreatLensConfig | None = None,
        ioc_matcher: IOCMatcher | None = None,
    ) -> None:
        self.config = config or ThreatLensConfig()
        self.ioc_matcher = ioc_matcher or IOCMatcher()

    def analyze(self, events: list[SecurityEvent]) -> list[Incident]:
        """Correlate security events and generate deduplicated SecurityIncidents."""
        if not events:
            return []

        # Sort events chronologically
        sorted_events = sorted(events, key=lambda e: _parse_ts(e.timestamp))
        incidents: list[Incident] = []
        incident_keys: set[str] = set()

        # Grouping structures
        by_user = defaultdict(list)
        by_ip = defaultdict(list)

        for idx, ev in enumerate(sorted_events):
            # Stamp event with temporary sequence id if none exists
            if ev.event_id is None:
                ev.event_id = idx + 1

            by_user[ev.username].append(ev)
            by_ip[ev.source_ip].append(ev)

        # -------------------------------------------------------------
        # Rule 1: Brute Force (T1110.001) & Compromise Detection
        # Multiple failed logins against a single account within window
        # -------------------------------------------------------------
        for user, u_events in by_user.items():
            failed_window: list[SecurityEvent] = []
            for ev in u_events:
                ev_time = _parse_ts(ev.timestamp)
                if ev.status == "failure":
                    # Expire old events from window
                    failed_window = [
                        old for old in failed_window
                        if ev_time - _parse_ts(old.timestamp) <= self.config.brute_force_window_sec
                    ]
                    failed_window.append(ev)

                    if len(failed_window) >= self.config.brute_force_threshold:
                        key = f"brute_force:{user}:{failed_window[0].source_ip}"
                        if key not in incident_keys:
                            incident_keys.add(key)
                            incidents.append(
                                Incident(
                                    id=f"INC-{uuid.uuid4().hex[:8].upper()}",
                                    title=f"Brute Force Password Guessing on account '{user}'",
                                    severity=IncidentSeverity.HIGH,
                                    mitre_id="T1110.001",
                                    mitre_name="Brute Force: Password Guessing",
                                    risk_score=78,
                                    primary_ip=failed_window[0].source_ip,
                                    primary_user=user,
                                    event_count=len(failed_window),
                                    first_seen=failed_window[0].timestamp,
                                    last_seen=ev.timestamp,
                                    status=IncidentStatus.NEW,
                                    analyst_notes=(
                                        f"Observed {len(failed_window)} rapid failed login attempts "
                                        f"within {self.config.brute_force_window_sec}s window from "
                                        f"{failed_window[0].source_ip} ({failed_window[0].geo_city}, {failed_window[0].geo_country})."
                                    ),
                                    event_ids=[f.event_id for f in failed_window if f.event_id],
                                    created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                )
                            )

                elif ev.status == "success":
                    # Check if this success directly follows a brute-force cluster from the same IP (Compromise!)
                    recent_fails = [
                        old for old in failed_window
                        if old.source_ip == ev.source_ip and ev_time - _parse_ts(old.timestamp) <= self.config.brute_force_window_sec
                    ]
                    if len(recent_fails) >= 3:
                        comp_key = f"compromise:{user}:{ev.source_ip}"
                        if comp_key not in incident_keys:
                            incident_keys.add(comp_key)
                            all_ev_ids = [f.event_id for f in recent_fails if f.event_id] + ([ev.event_id] if ev.event_id else [])
                            incidents.append(
                                Incident(
                                    id=f"INC-{uuid.uuid4().hex[:8].upper()}",
                                    title=f"Potential Account Compromise: Multiple Failures Followed by Success on '{user}'",
                                    severity=IncidentSeverity.CRITICAL,
                                    mitre_id="T1078.002",
                                    mitre_name="Valid Accounts: Domain Accounts",
                                    risk_score=95,
                                    primary_ip=ev.source_ip,
                                    primary_user=user,
                                    event_count=len(all_ev_ids),
                                    first_seen=recent_fails[0].timestamp,
                                    last_seen=ev.timestamp,
                                    status=IncidentStatus.NEW,
                                    analyst_notes=(
                                        f"CRITICAL: Adversary at {ev.source_ip} succeeded in authenticating as '{user}' "
                                        f"after {len(recent_fails)} failed attempts. Immediate credential reset & session revocation recommended."
                                    ),
                                    event_ids=all_ev_ids,
                                    created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                )
                            )
                    # Reset failure window after success
                    failed_window = []

        # -------------------------------------------------------------
        # Rule 2: Password Spraying (T1110.003)
        # Single source IP attempting logins across >= N distinct users
        # -------------------------------------------------------------
        for ip, ip_events in by_ip.items():
            if ip in {"127.0.0.1", "::1"}:
                continue

            failed_ip_events = [e for e in ip_events if e.status == "failure"]
            if not failed_ip_events:
                continue

            # Check distinct users within window
            window_start = _parse_ts(failed_ip_events[0].timestamp)
            users_seen: set[str] = set()
            spray_events: list[SecurityEvent] = []

            for fev in failed_ip_events:
                t = _parse_ts(fev.timestamp)
                if t - window_start > self.config.spray_window_sec:
                    # Slide window
                    window_start = t
                    users_seen = {fev.username}
                    spray_events = [fev]
                else:
                    users_seen.add(fev.username)
                    spray_events.append(fev)

                if len(users_seen) >= self.config.spray_user_threshold:
                    key = f"password_spray:{ip}"
                    if key not in incident_keys:
                        incident_keys.add(key)
                        incidents.append(
                            Incident(
                                id=f"INC-{uuid.uuid4().hex[:8].upper()}",
                                title=f"Distributed Password Spray from IP {ip}",
                                severity=IncidentSeverity.HIGH,
                                mitre_id="T1110.003",
                                mitre_name="Brute Force: Password Spraying",
                                risk_score=85,
                                primary_ip=ip,
                                primary_user=f"{len(users_seen)} users (including {next(iter(users_seen))})",
                                event_count=len(spray_events),
                                first_seen=spray_events[0].timestamp,
                                last_seen=fev.timestamp,
                                status=IncidentStatus.NEW,
                                analyst_notes=(
                                    f"Source IP {ip} ({fev.geo_city}, {fev.geo_country}) targeted {len(users_seen)} distinct accounts "
                                    f"({', '.join(sorted(list(users_seen))[:5])}...) in a coordinated spray campaign."
                                ),
                                event_ids=[e.event_id for e in spray_events if e.event_id],
                                created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                            )
                        )

        # -------------------------------------------------------------
        # Rule 3: Impossible Travel / Geo-Velocity Anomaly (T1078)
        # Success or active events for same user from distant points at supersonic speed
        # -------------------------------------------------------------
        for user, u_events in by_user.items():
            for i in range(len(u_events) - 1):
                ev1 = u_events[i]
                ev2 = u_events[i + 1]

                # Only check if both events have valid coordinates and differing coordinates
                if (
                    ev1.geo_lat is not None and ev1.geo_lon is not None
                    and ev2.geo_lat is not None and ev2.geo_lon is not None
                    and (ev1.geo_lat != ev2.geo_lat or ev1.geo_lon != ev2.geo_lon)
                ):
                    t1 = _parse_ts(ev1.timestamp)
                    t2 = _parse_ts(ev2.timestamp)
                    dist_km, velocity_kmh = calculate_velocity_kmh(
                        ev1.geo_lat, ev1.geo_lon, t1,
                        ev2.geo_lat, ev2.geo_lon, t2,
                    )

                    if velocity_kmh > self.config.impossible_travel_max_kmh and dist_km > 500:
                        key = f"impossible_travel:{user}:{ev1.geo_city}:{ev2.geo_city}"
                        if key not in incident_keys:
                            incident_keys.add(key)
                            delta_min = max(1, int(abs(t2 - t1) / 60.0))
                            incidents.append(
                                Incident(
                                    id=f"INC-{uuid.uuid4().hex[:8].upper()}",
                                    title=f"Impossible Travel Anomaly for user '{user}'",
                                    severity=IncidentSeverity.HIGH,
                                    mitre_id="T1078",
                                    mitre_name="Valid Accounts: Impossible Travel Velocity",
                                    risk_score=82,
                                    primary_ip=ev2.source_ip,
                                    primary_user=user,
                                    event_count=2,
                                    first_seen=ev1.timestamp,
                                    last_seen=ev2.timestamp,
                                    status=IncidentStatus.NEW,
                                    analyst_notes=(
                                        f"Account '{user}' traversed {dist_km:.0f} km in {delta_min} minutes "
                                        f"({ev1.geo_city}, {ev1.geo_country} -> {ev2.geo_city}, {ev2.geo_country}) "
                                        f"implying an impossible velocity of {velocity_kmh:.0f} km/h."
                                    ),
                                    event_ids=[eid for eid in (ev1.event_id, ev2.event_id) if eid],
                                    created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                )
                            )

        # -------------------------------------------------------------
        # Rule 4: Privileged After-Hours Access (T1078.004)
        # Successful login for privileged account outside normal business hours
        # -------------------------------------------------------------
        for ev in sorted_events:
            if ev.status == "success" and ev.username.lower() in self.config.privileged_accounts:
                hour = _hour_of_ts(ev.timestamp)
                if hour < self.config.work_hours_start or hour >= self.config.work_hours_end:
                    key = f"after_hours:{ev.username}:{ev.timestamp[:13]}"
                    if key not in incident_keys:
                        incident_keys.add(key)
                        incidents.append(
                            Incident(
                                id=f"INC-{uuid.uuid4().hex[:8].upper()}",
                                title=f"After-Hours Privileged Access by '{ev.username}'",
                                severity=IncidentSeverity.MEDIUM,
                                mitre_id="T1078.004",
                                mitre_name="Valid Accounts: Cloud / System Accounts",
                                risk_score=60,
                                primary_ip=ev.source_ip,
                                primary_user=ev.username,
                                event_count=1,
                                first_seen=ev.timestamp,
                                last_seen=ev.timestamp,
                                status=IncidentStatus.NEW,
                                analyst_notes=(
                                    f"Privileged account '{ev.username}' logged into {ev.target_host} at {hour:02d}:00 UTC "
                                    f"from {ev.source_ip} ({ev.geo_city}, {ev.geo_country}) outside normal working hours."
                                ),
                                event_ids=[ev.event_id] if ev.event_id else [],
                                created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                            )
                        )

        # -------------------------------------------------------------
        # Rule 5: Threat Intel IOC Hit (T1071 / T1110)
        # Activity from known Tor exit nodes, botnet IPs, or malicious CIDRs
        # -------------------------------------------------------------
        for ev in sorted_events:
            ioc = self.ioc_matcher.match_ip(ev.source_ip)
            if ioc:
                key = f"ioc_hit:{ev.source_ip}"
                if key not in incident_keys:
                    incident_keys.add(key)
                    incidents.append(
                        Incident(
                            id=f"INC-{uuid.uuid4().hex[:8].upper()}",
                            title=f"Activity from Known Malicious Indicator: {ioc.threat_type} ({ev.source_ip})",
                            severity=ioc.severity,
                            mitre_id="T1071",
                            mitre_name="Application Layer Protocol: Anonymization / Malicious Infrastructure",
                            risk_score=92 if ioc.severity == IncidentSeverity.CRITICAL else 75,
                            primary_ip=ev.source_ip,
                            primary_user=ev.username,
                            event_count=1,
                            first_seen=ev.timestamp,
                            last_seen=ev.timestamp,
                            status=IncidentStatus.NEW,
                            analyst_notes=(
                                f"Traffic matched Threat Intelligence feed: {ioc.description}. "
                                f"Indicator: {ioc.indicator} ({ioc.threat_type}). Targeted user: '{ev.username}'."
                            ),
                            event_ids=[ev.event_id] if ev.event_id else [],
                            created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        )
                    )

        # Sort incidents by risk score descending
        incidents.sort(key=lambda inc: inc.risk_score, reverse=True)
        return incidents
