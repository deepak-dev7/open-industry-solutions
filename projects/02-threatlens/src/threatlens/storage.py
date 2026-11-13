"""SQLite persistence layer for ThreatLens logs, events, incidents, IOCs, and audit trails."""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from threatlens.ioc import DEFAULT_IOC_RECORDS, IOCRecord
from threatlens.models import (
    Incident,
    IncidentSeverity,
    IncidentStatus,
    SecurityEvent,
    ThreatLensConfig,
)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def default_db_path() -> Path:
    env_path = os.environ.get("THREATLENS_DB_PATH", "").strip()
    if env_path:
        return Path(env_path).expanduser().resolve()
    try:
        home_db = Path.home() / ".threatlens" / "threatlens.db"
        home_db.parent.mkdir(parents=True, exist_ok=True)
        return home_db.resolve()
    except (PermissionError, OSError):
        fallback_dir = Path.cwd() / ".threatlens"
        try:
            fallback_dir.mkdir(parents=True, exist_ok=True)
            return (fallback_dir / "threatlens.db").resolve()
        except (PermissionError, OSError):
            import tempfile
            return (Path(tempfile.gettempdir()) / "threatlens.db").resolve()


class ThreatLensStore:
    """Thread-safe SQLite storage for ThreatLens SOC workbench."""

    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = (db_path or default_db_path()).resolve()
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        except (PermissionError, OSError):
            pass
        self._init_schema()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA journal_mode = WAL;")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS log_sources (
                    id TEXT PRIMARY KEY,
                    filename TEXT NOT NULL,
                    format TEXT NOT NULL,
                    ingested_at TEXT NOT NULL,
                    event_count INTEGER NOT NULL,
                    duration_ms INTEGER NOT NULL,
                    status TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_id TEXT NOT NULL REFERENCES log_sources(id) ON DELETE CASCADE,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    username TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    target_host TEXT NOT NULL,
                    geo_country TEXT NOT NULL,
                    geo_city TEXT NOT NULL,
                    geo_lat REAL,
                    geo_lon REAL,
                    raw_message TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_events_ip ON events(source_ip);
                CREATE INDEX IF NOT EXISTS idx_events_user ON events(username);

                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    mitre_id TEXT NOT NULL,
                    mitre_name TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    primary_ip TEXT NOT NULL,
                    primary_user TEXT NOT NULL,
                    event_count INTEGER NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'new',
                    analyst_notes TEXT NOT NULL DEFAULT '',
                    event_ids_json TEXT NOT NULL DEFAULT '[]'
                );

                CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_incidents_sev ON incidents(severity);
                CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);

                CREATE TABLE IF NOT EXISTS ioc_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_type TEXT NOT NULL,
                    indicator TEXT NOT NULL UNIQUE,
                    threat_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    added_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS soc_audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    details TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS app_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )

            # Seed default IOC threat intelligence records if table is empty
            count = conn.execute("SELECT COUNT(*) AS c FROM ioc_records").fetchone()["c"]
            if count == 0:
                for rec in DEFAULT_IOC_RECORDS:
                    conn.execute(
                        """
                        INSERT INTO ioc_records (ioc_type, indicator, threat_type, severity, description, added_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (rec.ioc_type, rec.indicator, rec.threat_type, rec.severity.value, rec.description, rec.added_at),
                    )

    def check_health(self) -> bool:
        with self._connect() as conn:
            row = conn.execute("SELECT 1 AS ok").fetchone()
            return bool(row and row["ok"] == 1)

    def save_ingest_batch(
        self,
        filename: str,
        fmt: str,
        events: list[SecurityEvent],
        incidents: list[Incident],
        duration_ms: int,
    ) -> str:
        """Insert a batch of events and their correlated incidents atomically."""
        source_id = str(uuid.uuid4())
        now = utc_now_iso()

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO log_sources (id, filename, format, ingested_at, event_count, duration_ms, status)
                VALUES (?, ?, ?, ?, ?, ?, 'completed')
                """,
                (source_id, filename, fmt, now, len(events), duration_ms),
            )

            # Insert events and map them to their generated DB row IDs
            for ev in events:
                cur = conn.execute(
                    """
                    INSERT INTO events (
                        source_id, timestamp, event_type, status, username,
                        source_ip, target_host, geo_country, geo_city, geo_lat, geo_lon, raw_message
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        source_id, ev.timestamp, ev.event_type, ev.status, ev.username,
                        ev.source_ip, ev.target_host, ev.geo_country, ev.geo_city, ev.geo_lat, ev.geo_lon, ev.raw_message,
                    ),
                )
                ev.event_id = cur.lastrowid

            # Insert correlated incidents
            for inc in incidents:
                conn.execute(
                    """
                    INSERT INTO incidents (
                        id, created_at, title, severity, mitre_id, mitre_name, risk_score,
                        primary_ip, primary_user, event_count, first_seen, last_seen, status, analyst_notes, event_ids_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        event_count = excluded.event_count,
                        last_seen = excluded.last_seen,
                        event_ids_json = excluded.event_ids_json
                    """,
                    (
                        inc.id, now, inc.title, inc.severity.value, inc.mitre_id, inc.mitre_name, inc.risk_score,
                        inc.primary_ip, inc.primary_user, inc.event_count, inc.first_seen, inc.last_seen,
                        inc.status.value, inc.analyst_notes, json.dumps(inc.event_ids),
                    ),
                )

        return source_id

    def get_dashboard_metrics(self) -> dict[str, Any]:
        """Aggregate real-time metrics across all events and incidents."""
        with self._connect() as conn:
            ev_stats = conn.execute(
                """
                SELECT
                    COUNT(*) AS total_events,
                    COALESCE(SUM(CASE WHEN status = 'failure' THEN 1 ELSE 0 END), 0) AS failed_logins,
                    COALESCE(SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END), 0) AS successful_logins,
                    COUNT(DISTINCT source_ip) AS unique_ips,
                    COUNT(DISTINCT username) AS unique_users
                FROM events
                """
            ).fetchone()

            inc_stats = conn.execute(
                """
                SELECT
                    COUNT(*) AS total_incidents,
                    COALESCE(SUM(CASE WHEN status IN ('new', 'investigating') THEN 1 ELSE 0 END), 0) AS active_incidents,
                    COALESCE(SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END), 0) AS critical_count,
                    COALESCE(SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END), 0) AS high_count,
                    COALESCE(SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END), 0) AS medium_count,
                    COALESCE(SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END), 0) AS low_count
                FROM incidents
                """
            ).fetchone()

            top_ips = conn.execute(
                """
                SELECT source_ip, geo_country, geo_city, COUNT(*) as count
                FROM events
                WHERE status = 'failure'
                GROUP BY source_ip, geo_country, geo_city
                ORDER BY count DESC
                LIMIT 5
                """
            ).fetchall()

            top_users = conn.execute(
                """
                SELECT username, COUNT(*) as count
                FROM events
                WHERE status = 'failure'
                GROUP BY username
                ORDER BY count DESC
                LIMIT 5
                """
            ).fetchall()

            recent_incidents = conn.execute(
                """
                SELECT id, created_at, title, severity, mitre_id, risk_score, primary_ip, primary_user, status
                FROM incidents
                ORDER BY created_at DESC
                LIMIT 6
                """
            ).fetchall()

        return {
            "total_events": int(ev_stats["total_events"]) if ev_stats else 0,
            "failed_logins": int(ev_stats["failed_logins"]) if ev_stats else 0,
            "successful_logins": int(ev_stats["successful_logins"]) if ev_stats else 0,
            "unique_ips": int(ev_stats["unique_ips"]) if ev_stats else 0,
            "unique_users": int(ev_stats["unique_users"]) if ev_stats else 0,
            "total_incidents": int(inc_stats["total_incidents"]) if inc_stats else 0,
            "active_incidents": int(inc_stats["active_incidents"]) if inc_stats else 0,
            "severity_breakdown": {
                "critical": int(inc_stats["critical_count"]) if inc_stats else 0,
                "high": int(inc_stats["high_count"]) if inc_stats else 0,
                "medium": int(inc_stats["medium_count"]) if inc_stats else 0,
                "low": int(inc_stats["low_count"]) if inc_stats else 0,
            },
            "top_attacker_ips": [dict(r) for r in top_ips],
            "top_targeted_accounts": [dict(r) for r in top_users],
            "recent_incidents": [dict(r) for r in recent_incidents],
        }

    def list_incidents(
        self,
        severity: str = "",
        status: str = "",
        search: str = "",
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []

        if severity.strip():
            clauses.append("severity = ?")
            params.append(severity.strip().lower())
        if status.strip():
            clauses.append("status = ?")
            params.append(status.strip().lower())
        if search.strip():
            clauses.append("(title LIKE ? OR primary_ip LIKE ? OR primary_user LIKE ? OR mitre_id LIKE ?)")
            like = f"%{search.strip()}%"
            params.extend([like, like, like, like])

        where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        bounded = max(1, min(limit, 200))
        params.append(bounded)

        query = f"SELECT * FROM incidents {where_sql} ORDER BY risk_score DESC, created_at DESC LIMIT ?"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
            if not row:
                return None
            data = dict(row)
            event_ids_raw = data.get("event_ids_json") or "[]"
            if event_ids_raw and event_ids_raw != "[]":
                ev_rows = conn.execute(
                    "SELECT * FROM events WHERE id IN (SELECT value FROM json_each(?)) ORDER BY timestamp ASC",
                    (event_ids_raw,),
                ).fetchall()
                data["events"] = [dict(r) for r in ev_rows]
            else:
                data["events"] = []
            return data

    def update_incident(self, incident_id: str, status: str, notes: str | None = None) -> dict[str, Any] | None:
        with self._connect() as conn:
            if notes is not None:
                conn.execute(
                    "UPDATE incidents SET status = ?, analyst_notes = ? WHERE id = ?",
                    (status, notes, incident_id),
                )
            else:
                conn.execute("UPDATE incidents SET status = ? WHERE id = ?", (status, incident_id))
        return self.get_incident(incident_id)

    def delete_incident(self, incident_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM incidents WHERE id = ?", (incident_id,))
            return cur.rowcount > 0

    def search_events(
        self,
        username: str = "",
        ip: str = "",
        status: str = "",
        event_type: str = "",
        search: str = "",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []

        if username.strip():
            clauses.append("username LIKE ?")
            params.append(f"%{username.strip()}%")
        if ip.strip():
            clauses.append("source_ip LIKE ?")
            params.append(f"%{ip.strip()}%")
        if status.strip():
            clauses.append("status = ?")
            params.append(status.strip().lower())
        if event_type.strip():
            clauses.append("event_type = ?")
            params.append(event_type.strip().lower())
        if search.strip():
            clauses.append("(raw_message LIKE ? OR target_host LIKE ?)")
            like = f"%{search.strip()}%"
            params.extend([like, like])

        where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        bounded = max(1, min(limit, 300))
        params.append(bounded)

        query = f"SELECT * FROM events {where_sql} ORDER BY timestamp DESC, id DESC LIMIT ?"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def list_iocs(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM ioc_records ORDER BY added_at DESC, id DESC").fetchall()
        return [dict(r) for r in rows]

    def add_ioc(self, ioc_type: str, indicator: str, threat_type: str, severity: str, description: str) -> dict[str, Any]:
        now = utc_now_iso()
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO ioc_records (ioc_type, indicator, threat_type, severity, description, added_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(indicator) DO UPDATE SET
                    threat_type = excluded.threat_type,
                    severity = excluded.severity,
                    description = excluded.description
                """,
                (ioc_type, indicator.strip(), threat_type, severity, description, now),
            )
            row_id = cur.lastrowid
            row = conn.execute("SELECT * FROM ioc_records WHERE id = ?", (row_id,)).fetchone()
            return dict(row)

    def delete_ioc(self, ioc_id: int) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM ioc_records WHERE id = ?", (ioc_id,))
            return cur.rowcount > 0

    def get_settings(self) -> dict[str, Any]:
        defaults = {
            "brute_force_threshold": 5,
            "brute_force_window_sec": 300,
            "spray_user_threshold": 4,
            "spray_window_sec": 600,
            "impossible_travel_max_kmh": 850.0,
            "work_hours_start": 8,
            "work_hours_end": 19,
            "privileged_accounts": ["root", "admin", "administrator", "sysadmin", "deploy"],
        }
        with self._connect() as conn:
            rows = conn.execute("SELECT key, value FROM app_settings").fetchall()
        for r in rows:
            if r["key"] in defaults:
                defaults[r["key"]] = json.loads(r["value"])
        return defaults

    def update_settings(self, updates: dict[str, Any]) -> dict[str, Any]:
        now = utc_now_iso()
        with self._connect() as conn:
            for k, v in updates.items():
                conn.execute(
                    """
                    INSERT INTO app_settings (key, value, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET
                        value = excluded.value,
                        updated_at = excluded.updated_at
                    """,
                    (k, json.dumps(v), now),
                )
        return self.get_settings()

    def log_audit(self, action: str, target: str, outcome: str, details: str = "") -> None:
        now = utc_now_iso()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO soc_audit_logs (timestamp, action, target, outcome, details)
                VALUES (?, ?, ?, ?, ?)
                """,
                (now, action, target, outcome, details),
            )

    def list_audit_logs(self, limit: int = 40) -> list[dict[str, Any]]:
        bounded = max(1, min(limit, 200))
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM soc_audit_logs ORDER BY timestamp DESC, id DESC LIMIT ?",
                (bounded,),
            ).fetchall()
        return [dict(r) for r in rows]
