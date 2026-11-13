"""Authentication log parsers for syslog/auth.log, Windows Events, CloudTrail/Okta, and JSON/CSV."""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timezone
from typing import Iterator

from threatlens.geo import resolve_ip_geo
from threatlens.models import SecurityEvent

# Syslog date pattern e.g. "Nov 12 14:20:15" or ISO-8601 "2026-11-12T14:20:15+00:00"
SYSLOG_LINE_RE = re.compile(
    r"^(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>[^\s]+)\s+(?P<process>[A-Za-z0-9_\-\.\/]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<msg>.*)$"
)

ISO_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}")

# SSH Patterns
SSH_FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>[A-Za-z0-9_\-\.]+) from (?P<ip>[A-Fa-f0-9\.:]+) port \d+ ssh2"
)
SSH_ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>[A-Za-z0-9_\-\.]+) from (?P<ip>[A-Fa-f0-9\.:]+) port \d+ ssh2"
)
PAM_FAILURE_RE = re.compile(
    r"pam_unix\([A-Za-z0-9_\-]+:auth\): authentication failure;"
)
SUDO_PRIV_RE = re.compile(
    r"(?P<user>[A-Za-z0-9_\-\.]+)\s*:\s*COMMAND=(?P<cmd>.*)"
)

CURRENT_YEAR = 2026


def _parse_syslog_timestamp(month_str: str, day_str: str, time_str: str) -> str:
    """Convert syslog standard timestamp (Nov 12 14:02:10) to ISO-8601 UTC."""
    months = {
        "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
        "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
    }
    month = months.get(month_str[:3], 11)
    day = int(day_str)
    hour, minute, second = [int(p) for p in time_str.split(":")]
    dt = datetime(CURRENT_YEAR, month, day, hour, minute, second, tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalize_iso(ts_str: str) -> str:
    """Normalize variable ISO timestamps to canonical %Y-%m-%dT%H:%M:%SZ."""
    cleaned = ts_str.strip().replace(" ", "T")
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(cleaned)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_syslog_auth(text: str) -> list[SecurityEvent]:
    """Parse Linux auth.log / secure / syslog file content."""
    events: list[SecurityEvent] = []
    lines = text.splitlines()

    for line in lines:
        line_str = line.strip()
        if not line_str:
            continue

        match = SYSLOG_LINE_RE.match(line_str)
        if not match:
            # Check if line begins with ISO date
            parts = line_str.split(maxsplit=4)
            if len(parts) >= 5 and ISO_TIMESTAMP_RE.match(parts[0]):
                ts = _normalize_iso(parts[0])
                host = parts[1]
                msg = line_str[len(parts[0]) + len(parts[1]) + 2:].strip()
            else:
                continue
        else:
            ts = _parse_syslog_timestamp(match.group("month"), match.group("day"), match.group("time"))
            host = match.group("host")
            msg = match.group("msg")

        # 1. SSH Failed Login
        m_failed = SSH_FAILED_RE.search(msg)
        if m_failed:
            ip = m_failed.group("ip")
            user = m_failed.group("user")
            geo = resolve_ip_geo(ip)
            events.append(
                SecurityEvent(
                    timestamp=ts,
                    event_type="login_failed",
                    status="failure",
                    username=user,
                    source_ip=ip,
                    target_host=host,
                    geo_country=geo.country,
                    geo_city=geo.city,
                    geo_lat=geo.lat,
                    geo_lon=geo.lon,
                    raw_message=line_str,
                )
            )
            continue

        # 2. SSH Accepted Login
        m_accepted = SSH_ACCEPTED_RE.search(msg)
        if m_accepted:
            ip = m_accepted.group("ip")
            user = m_accepted.group("user")
            geo = resolve_ip_geo(ip)
            events.append(
                SecurityEvent(
                    timestamp=ts,
                    event_type="login_success",
                    status="success",
                    username=user,
                    source_ip=ip,
                    target_host=host,
                    geo_country=geo.country,
                    geo_city=geo.city,
                    geo_lat=geo.lat,
                    geo_lon=geo.lon,
                    raw_message=line_str,
                )
            )
            continue

        # 3. PAM authentication failure
        if PAM_FAILURE_RE.search(msg):
            m_user = re.search(r"\buser=(?P<user>[A-Za-z0-9_\-\.]+)", msg)
            m_ip = re.search(r"\brhost=(?P<ip>[A-Fa-f0-9\.:]+)", msg)
            user = m_user.group("user") if m_user else "unknown"
            ip = m_ip.group("ip") if m_ip else "127.0.0.1"
            geo = resolve_ip_geo(ip)
            events.append(
                SecurityEvent(
                    timestamp=ts,
                    event_type="login_failed",
                    status="failure",
                    username=user,
                    source_ip=ip,
                    target_host=host,
                    geo_country=geo.country,
                    geo_city=geo.city,
                    geo_lat=geo.lat,
                    geo_lon=geo.lon,
                    raw_message=line_str,
                )
            )
            continue

    return events


def parse_windows_event_json(data: list[dict[str, Any]] | dict[str, Any]) -> list[SecurityEvent]:
    """Parse Windows Security Event Log records (Event ID 4624, 4625, 4720, 4672)."""
    items = [data] if isinstance(data, dict) else data
    events: list[SecurityEvent] = []

    for item in items:
        event_id = str(item.get("EventID") or item.get("event_id") or "")
        ts_raw = item.get("TimeCreated") or item.get("timestamp") or item.get("TimeGenerated") or ""
        ts = _normalize_iso(str(ts_raw)) if ts_raw else datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        user_data = item.get("TargetUserName") or item.get("username") or item.get("TargetUser") or "unknown"
        ip_raw = item.get("IpAddress") or item.get("source_ip") or item.get("ClientAddress") or "127.0.0.1"
        host = item.get("Computer") or item.get("target_host") or "win-server"

        # Windows Event 4625: An account failed to log on
        if event_id in {"4625", "Event4625"}:
            geo = resolve_ip_geo(ip_raw)
            events.append(
                SecurityEvent(
                    timestamp=ts,
                    event_type="login_failed",
                    status="failure",
                    username=user_data,
                    source_ip=ip_raw,
                    target_host=host,
                    geo_country=geo.country,
                    geo_city=geo.city,
                    geo_lat=geo.lat,
                    geo_lon=geo.lon,
                    raw_message=f"Windows Event 4625: Logon failure for '{user_data}' from {ip_raw}",
                )
            )
        # Windows Event 4624: An account was successfully logged on
        elif event_id in {"4624", "Event4624"}:
            # Exclude service/machine account noise (SYSTEM, NETWORK SERVICE, etc.) if local logon type
            logon_type = str(item.get("LogonType") or "3")
            geo = resolve_ip_geo(ip_raw)
            events.append(
                SecurityEvent(
                    timestamp=ts,
                    event_type="login_success",
                    status="success",
                    username=user_data,
                    source_ip=ip_raw,
                    target_host=host,
                    geo_country=geo.country,
                    geo_city=geo.city,
                    geo_lat=geo.lat,
                    geo_lon=geo.lon,
                    raw_message=f"Windows Event 4624: Logon success for '{user_data}' (LogonType={logon_type})",
                )
            )
        # Windows Event 4672: Special privileges assigned to new logon (Privilege Escalation indicator)
        elif event_id in {"4672", "Event4672"}:
            geo = resolve_ip_geo(ip_raw)
            events.append(
                SecurityEvent(
                    timestamp=ts,
                    event_type="privilege_escalation",
                    status="info",
                    username=user_data,
                    source_ip=ip_raw,
                    target_host=host,
                    geo_country=geo.country,
                    geo_city=geo.city,
                    geo_lat=geo.lat,
                    geo_lon=geo.lon,
                    raw_message=f"Windows Event 4672: Administrator/Special privileges assigned to '{user_data}'",
                )
            )

    return events


def parse_cloud_audit_json(records: list[dict[str, Any]]) -> list[SecurityEvent]:
    """Parse AWS CloudTrail, Okta, or Azure AD JSON authentication logs."""
    events: list[SecurityEvent] = []

    for item in records:
        ts_raw = item.get("eventTime") or item.get("timestamp") or item.get("published") or ""
        ts = _normalize_iso(str(ts_raw)) if ts_raw else datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # CloudTrail format
        event_name = item.get("eventName") or item.get("event_type") or item.get("action") or ""
        identity = item.get("userIdentity") or {}
        username = (
            identity.get("userName")
            or item.get("username")
            or (item.get("actor") or {}).get("displayName")
            or "unknown"
        )
        ip = item.get("sourceIPAddress") or item.get("source_ip") or item.get("clientIp") or "127.0.0.1"
        error_code = item.get("errorCode") or item.get("outcome") or ""

        # Map to SecurityEvent
        is_failure = bool(error_code or "fail" in event_name.lower())
        status = "failure" if is_failure else "success"
        ev_type = "login_failed" if is_failure else "login_success"

        geo = resolve_ip_geo(ip)
        events.append(
            SecurityEvent(
                timestamp=ts,
                event_type=ev_type,
                status=status,
                username=username,
                source_ip=ip,
                target_host=str(item.get("recipientAccountId") or item.get("target") or "cloud-iam"),
                geo_country=geo.country,
                geo_city=geo.city,
                geo_lat=geo.lat,
                geo_lon=geo.lon,
                raw_message=f"Cloud Identity event: {event_name} user={username} ip={ip} status={status}",
            )
        )

    return events


def parse_generic_csv(text: str) -> list[SecurityEvent]:
    """Parse CSV logs with flexible column names (timestamp, username, ip, event_type, status)."""
    events: list[SecurityEvent] = []
    reader = csv.DictReader(io.StringIO(text))

    for row in reader:
        # Flexible key discovery
        ts_raw = row.get("timestamp") or row.get("time") or row.get("date") or ""
        ts = _normalize_iso(ts_raw) if ts_raw else datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        user = row.get("username") or row.get("user") or row.get("account") or "unknown"
        ip = row.get("source_ip") or row.get("ip") or row.get("client_ip") or "127.0.0.1"
        ev_type = row.get("event_type") or row.get("action") or "login_failed"
        status = row.get("status") or ("failure" if "fail" in ev_type.lower() else "success")
        host = row.get("target_host") or row.get("host") or "server"

        geo = resolve_ip_geo(ip)
        events.append(
            SecurityEvent(
                timestamp=ts,
                event_type=ev_type,
                status=status,
                username=user,
                source_ip=ip,
                target_host=host,
                geo_country=geo.country,
                geo_city=geo.city,
                geo_lat=geo.lat,
                geo_lon=geo.lon,
                raw_message=f"CSV record: user={user} ip={ip} type={ev_type} status={status}",
            )
        )

    return events


def auto_detect_and_parse(text: str, format_hint: str = "auto") -> tuple[list[SecurityEvent], str]:
    """Detect format and parse text into normalized SecurityEvent objects."""
    cleaned = text.strip()
    if not cleaned:
        return [], "empty"

    # Explicit format hint
    if format_hint == "syslog":
        return parse_syslog_auth(cleaned), "syslog"
    if format_hint == "csv":
        return parse_generic_csv(cleaned), "csv"

    # Try JSON detection
    if cleaned.startswith(("{", "[")):
        try:
            parsed_json = json.loads(cleaned)
            # Check if Windows Event format
            if isinstance(parsed_json, list) and any("EventID" in item for item in parsed_json if isinstance(item, dict)):
                return parse_windows_event_json(parsed_json), "windows_event"
            if isinstance(parsed_json, dict) and "EventID" in parsed_json:
                return parse_windows_event_json([parsed_json]), "windows_event"
            # Check CloudTrail format
            if isinstance(parsed_json, dict) and "Records" in parsed_json:
                return parse_cloud_audit_json(parsed_json["Records"]), "cloud_audit"
            if isinstance(parsed_json, list):
                # Check for standard SecurityEvent JSON format
                if any("username" in item and "source_ip" in item for item in parsed_json if isinstance(item, dict)):
                    res = []
                    for item in parsed_json:
                        if not isinstance(item, dict):
                            continue
                        ip = item.get("source_ip", "127.0.0.1")
                        geo = resolve_ip_geo(ip)
                        res.append(
                            SecurityEvent(
                                timestamp=_normalize_iso(str(item.get("timestamp", ""))),
                                event_type=str(item.get("event_type", "login_failed")),
                                status=str(item.get("status", "failure")),
                                username=str(item.get("username", "unknown")),
                                source_ip=ip,
                                target_host=str(item.get("target_host", "server")),
                                geo_country=str(item.get("geo_country") or geo.country),
                                geo_city=str(item.get("geo_city") or geo.city),
                                geo_lat=float(item.get("geo_lat") or geo.lat),
                                geo_lon=float(item.get("geo_lon") or geo.lon),
                                raw_message=str(item.get("raw_message", json.dumps(item))),
                            )
                        )
                    return res, "json"
                return parse_windows_event_json(parsed_json), "windows_event"
        except json.JSONDecodeError:
            pass

    # CSV detection
    if "," in cleaned.splitlines()[0] and any(h in cleaned.splitlines()[0].lower() for h in ("username", "user", "ip", "event_type")):
        return parse_generic_csv(cleaned), "csv"

    # Default to syslog / auth.log parser
    syslog_events = parse_syslog_auth(cleaned)
    if syslog_events:
        return syslog_events, "syslog"

    return [], "unknown"
