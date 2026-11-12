"""SQLite persistence layer for CodeGuard scans, findings, settings, and audit logs."""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from codeguard.models import CodeGuardConfig, ScanResult, Severity

DEFAULT_SETTINGS: dict[str, Any] = {
    "fail_on": "high",
    "max_file_size_kb": 1024,
    "entropy_threshold": 4.2,
    "disabled_rules": [],
    "ignore_paths": list(CodeGuardConfig().ignore_paths),
    "allowlist_patterns": ["EXAMPLE_KEY", "changeme"],
    "allowed_roots": [],
}


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def default_db_path() -> Path:
    """Resolve the SQLite database path from CODEGUARD_DB_PATH or user home."""
    env_path = os.environ.get("CODEGUARD_DB_PATH", "").strip()
    if env_path:
        return Path(env_path).expanduser().resolve()
    return (Path.home() / ".codeguard" / "codeguard.db").resolve()


class CodeGuardStore:
    """Thread-safe SQLite store for CodeGuard web application state."""

    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = (db_path or default_db_path()).resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
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
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    target_label TEXT NOT NULL,
                    fail_on TEXT NOT NULL,
                    failed INTEGER NOT NULL,
                    files_scanned INTEGER NOT NULL,
                    files_skipped INTEGER NOT NULL,
                    suppressed_count INTEGER NOT NULL,
                    findings_count INTEGER NOT NULL,
                    critical_count INTEGER NOT NULL,
                    high_count INTEGER NOT NULL,
                    medium_count INTEGER NOT NULL,
                    low_count INTEGER NOT NULL,
                    duration_ms INTEGER NOT NULL,
                    sarif_json TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);

                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    rule_id TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    category TEXT NOT NULL,
                    cwe TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    line INTEGER NOT NULL,
                    column INTEGER NOT NULL,
                    message TEXT NOT NULL,
                    remediation TEXT NOT NULL,
                    snippet TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open'
                );

                CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
                CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

                CREATE TABLE IF NOT EXISTS app_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    details TEXT NOT NULL
                );
                """
            )

    def check_health(self) -> bool:
        """Verify database connectivity."""
        with self._connect() as conn:
            row = conn.execute("SELECT 1 AS ok").fetchone()
            return bool(row and row["ok"] == 1)

    def get_settings(self) -> dict[str, Any]:
        """Return merged persisted settings with defaults."""
        merged = {
            k: list(v) if isinstance(v, list) else v for k, v in DEFAULT_SETTINGS.items()
        }
        with self._connect() as conn:
            rows = conn.execute("SELECT key, value FROM app_settings").fetchall()
        for row in rows:
            if row["key"] in merged:
                merged[row["key"]] = json.loads(row["value"])
        return merged

    def update_settings(self, updates: dict[str, Any]) -> dict[str, Any]:
        """Persist validated settings keys and return updated settings."""
        now = utc_now_iso()
        with self._connect() as conn:
            for key, value in updates.items():
                if key not in DEFAULT_SETTINGS:
                    continue
                conn.execute(
                    """
                    INSERT INTO app_settings (key, value, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET
                        value = excluded.value,
                        updated_at = excluded.updated_at
                    """,
                    (key, json.dumps(value), now),
                )
        return self.get_settings()

    def to_runtime_config(self) -> CodeGuardConfig:
        """Build a CodeGuardConfig instance from persisted settings."""
        s = self.get_settings()
        return CodeGuardConfig(
            ignore_paths=tuple(s["ignore_paths"]),
            disabled_rules=tuple(s["disabled_rules"]),
            allowlist_patterns=tuple(s["allowlist_patterns"]),
            fail_on=Severity.from_str(str(s["fail_on"])),
            max_file_size_kb=int(s["max_file_size_kb"]),
            entropy_threshold=float(s["entropy_threshold"]),
        )

    def log_audit(self, action: str, target: str, outcome: str, details: str = "") -> None:
        """Insert a security/operational audit log record."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_logs (created_at, action, target, outcome, details)
                VALUES (?, ?, ?, ?, ?)
                """,
                (utc_now_iso(), action, target, outcome, details),
            )

    def list_audit_logs(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return recent audit log entries."""
        bounded = max(1, min(limit, 200))
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, created_at, action, target, outcome, details
                FROM audit_logs
                ORDER BY id DESC
                LIMIT ?
                """,
                (bounded,),
            ).fetchall()
        return [dict(row) for row in rows]

    def save_scan(
        self,
        *,
        source_type: str,
        target_label: str,
        result: ScanResult,
        fail_on: Severity,
        duration_ms: int,
        sarif_json: str,
    ) -> dict[str, Any]:
        """Persist a completed scan and all findings, returning the stored record."""
        scan_id = str(uuid.uuid4())
        created_at = utc_now_iso()
        failed = 1 if result.should_fail(fail_on) else 0

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in result.findings:
            counts[finding.severity.label] += 1

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scans (
                    id, created_at, source_type, target_label, fail_on, failed,
                    files_scanned, files_skipped, suppressed_count, findings_count,
                    critical_count, high_count, medium_count, low_count, duration_ms, sarif_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    created_at,
                    source_type,
                    target_label,
                    fail_on.label,
                    failed,
                    result.files_scanned,
                    result.files_skipped,
                    result.suppressed_count,
                    len(result.findings),
                    counts["critical"],
                    counts["high"],
                    counts["medium"],
                    counts["low"],
                    duration_ms,
                    sarif_json,
                ),
            )
            conn.executemany(
                """
                INSERT INTO findings (
                    scan_id, rule_id, rule_name, severity, category, cwe,
                    file_path, line, column, message, remediation, snippet, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')
                """,
                [
                    (
                        scan_id,
                        f.rule_id,
                        f.rule_name,
                        f.severity.label,
                        f.category,
                        f.cwe,
                        f.file_path,
                        f.line,
                        f.column,
                        f.message,
                        f.remediation,
                        f.snippet,
                    )
                    for f in result.findings
                ],
            )

        record = self.get_scan(scan_id)
        if record is None:
            raise RuntimeError("Failed to reload newly saved scan.")
        return record

    def list_scans(
        self,
        *,
        search: str = "",
        status: str = "",
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """List persisted scans with optional search and pass/fail filter."""
        clauses: list[str] = []
        params: list[Any] = []

        if search.strip():
            clauses.append("target_label LIKE ?")
            params.append(f"%{search.strip()}%")
        if status == "pass":
            clauses.append("failed = 0")
        elif status == "fail":
            clauses.append("failed = 1")

        where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        bounded = max(1, min(limit, 200))
        params.append(bounded)

        query = (
            "SELECT id, created_at, source_type, target_label, fail_on, failed, "
            "files_scanned, files_skipped, suppressed_count, findings_count, "
            "critical_count, high_count, medium_count, low_count, duration_ms "
            f"FROM scans {where_sql} ORDER BY created_at DESC LIMIT ?"
        )
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        items = [dict(row) for row in rows]
        for item in items:
            item["failed"] = bool(item["failed"])
        return items

    def get_scan(
        self,
        scan_id: str,
        *,
        severity: str = "",
        rule_id: str = "",
        status: str = "",
        search: str = "",
    ) -> dict[str, Any] | None:
        """Fetch a scan record and its filtered findings."""
        with self._connect() as conn:
            scan_row = conn.execute(
                """
                SELECT id, created_at, source_type, target_label, fail_on, failed,
                       files_scanned, files_skipped, suppressed_count, findings_count,
                       critical_count, high_count, medium_count, low_count, duration_ms, sarif_json
                FROM scans WHERE id = ?
                """,
                (scan_id,),
            ).fetchone()
            if scan_row is None:
                return None

            clauses = ["scan_id = ?"]
            params: list[Any] = [scan_id]
            if severity.strip():
                clauses.append("severity = ?")
                params.append(severity.strip().lower())
            if rule_id.strip():
                clauses.append("rule_id = ?")
                params.append(rule_id.strip().upper())
            if status.strip():
                clauses.append("status = ?")
                params.append(status.strip().lower())
            if search.strip():
                clauses.append("(file_path LIKE ? OR message LIKE ? OR rule_id LIKE ?)")
                like = f"%{search.strip()}%"
                params.extend([like, like, like])

            finding_sql = (
                "SELECT id, scan_id, rule_id, rule_name, severity, category, cwe, "
                "file_path, line, column, message, remediation, snippet, status "
                f"FROM findings WHERE {' AND '.join(clauses)} "
                "ORDER BY file_path ASC, line ASC, column ASC, id ASC"
            )
            finding_rows = conn.execute(finding_sql, params).fetchall()

        data = dict(scan_row)
        data["failed"] = bool(data["failed"])
        data["findings"] = [dict(row) for row in finding_rows]
        return data

    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan and cascade-delete its findings."""
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            return cur.rowcount > 0

    def update_finding_status(self, finding_id: int, status: str) -> dict[str, Any] | None:
        """Update triage status of a finding."""
        if status not in {"open", "acknowledged", "false_positive"}:
            raise ValueError("Invalid finding status.")
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE findings SET status = ? WHERE id = ?",
                (status, finding_id),
            )
            if cur.rowcount == 0:
                return None
            row = conn.execute(
                """
                SELECT id, scan_id, rule_id, rule_name, severity, category, cwe,
                       file_path, line, column, message, remediation, snippet, status
                FROM findings WHERE id = ?
                """,
                (finding_id,),
            ).fetchone()
        return dict(row) if row else None

    def get_dashboard_stats(self) -> dict[str, Any]:
        """Compute aggregate metrics from persisted scans and findings."""
        with self._connect() as conn:
            totals = conn.execute(
                """
                SELECT
                    COUNT(*) AS total_scans,
                    COALESCE(SUM(files_scanned), 0) AS total_files_scanned,
                    COALESCE(SUM(findings_count), 0) AS total_findings,
                    COALESCE(SUM(CASE WHEN failed = 1 THEN 1 ELSE 0 END), 0) AS failed_scans
                FROM scans
                """
            ).fetchone()
            sev_rows = conn.execute(
                """
                SELECT severity, COUNT(*) AS count
                FROM findings
                WHERE status = 'open'
                GROUP BY severity
                """
            ).fetchall()
            open_row = conn.execute(
                "SELECT COUNT(*) AS count FROM findings WHERE status = 'open'"
            ).fetchone()
            top_rules = conn.execute(
                """
                SELECT rule_id, rule_name, severity, COUNT(*) AS count
                FROM findings
                GROUP BY rule_id, rule_name, severity
                ORDER BY count DESC, rule_id ASC
                LIMIT 6
                """
            ).fetchall()

        sev_map = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for row in sev_rows:
            if row["severity"] in sev_map:
                sev_map[row["severity"]] = int(row["count"])

        return {
            "total_scans": int(totals["total_scans"]) if totals else 0,
            "total_files_scanned": int(totals["total_files_scanned"]) if totals else 0,
            "total_findings": int(totals["total_findings"]) if totals else 0,
            "open_findings": int(open_row["count"]) if open_row else 0,
            "failed_scans": int(totals["failed_scans"]) if totals else 0,
            "severity_breakdown": sev_map,
            "top_rules": [dict(row) for row in top_rules],
            "recent_scans": self.list_scans(limit=6),
        }

