# ThreatLens Database Schema (SQLite)

ThreatLens persists ingested log sources, normalized security events, correlated security incidents, threat intelligence IOCs, and analyst audit actions in a local SQLite database (`~/.threatlens/threatlens.db` by default, configurable via `THREATLENS_DB_PATH`) using WAL mode and foreign-key constraints.

---

## Entity Relationship Summary

```text
log_sources (1) ───< events (N) >─── (M) incidents
ioc_records (standalone feed)
app_settings (key-value store)
soc_audit_logs (immutable analyst activity)
```

---

## Table Definitions

### `log_sources`
| Column | Type | Constraints | Description |
| --- | --- | --- | --- |
| `id` | `TEXT` | `PRIMARY KEY` | UUID4 identifier of the ingested log file or batch |
| `filename` | `TEXT` | `NOT NULL` | Original filename or simulation scenario title |
| `format` | `TEXT` | `NOT NULL` | `syslog`, `windows_event`, `cloud_audit`, `json`, `csv` |
| `ingested_at` | `TEXT` | `NOT NULL` | ISO-8601 UTC timestamp of ingestion |
| `event_count` | `INTEGER` | `NOT NULL` | Total parsed events |
| `duration_ms` | `INTEGER` | `NOT NULL` | Parse & analysis duration in milliseconds |
| `status` | `TEXT` | `NOT NULL` | `completed`, `error` |

### `events`
| Column | Type | Constraints | Description |
| --- | --- | --- | --- |
| `id` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Event row ID |
| `source_id` | `TEXT` | `NOT NULL REFERENCES log_sources(id) ON DELETE CASCADE` | Source batch ID |
| `timestamp` | `TEXT` | `NOT NULL` | ISO-8601 event occurrence time |
| `event_type` | `TEXT` | `NOT NULL` | `login_failed`, `login_success`, `privilege_escalation`, `account_locked`, `session_start` |
| `status` | `TEXT` | `NOT NULL` | `failure`, `success`, `info` |
| `username` | `TEXT` | `NOT NULL` | Targeted username or account identity |
| `source_ip` | `TEXT` | `NOT NULL` | Originating IPv4/IPv6 address |
| `target_host` | `TEXT` | `NOT NULL` | Targeted server, domain, or service |
| `geo_country` | `TEXT` | `NOT NULL DEFAULT 'Unknown'` | Country code or name |
| `geo_city` | `TEXT` | `NOT NULL DEFAULT 'Unknown'` | City name |
| `geo_lat` | `REAL` | `NULL` | Latitude coordinate for velocity analysis |
| `geo_lon` | `REAL` | `NULL` | Longitude coordinate for velocity analysis |
| `raw_message` | `TEXT` | `NOT NULL` | Unmodified log line or payload |

### `incidents`
| Column | Type | Constraints | Description |
| --- | --- | --- | --- |
| `id` | `TEXT` | `PRIMARY KEY` | Incident identifier (e.g. `INC-2026-0001` or UUID4) |
| `created_at` | `TEXT` | `NOT NULL` | Detection timestamp (ISO-8601 UTC) |
| `title` | `TEXT` | `NOT NULL` | Descriptive title (e.g. "Brute Force Attack on account 'admin'") |
| `severity` | `TEXT` | `NOT NULL` | `critical`, `high`, `medium`, `low` |
| `mitre_id` | `TEXT` | `NOT NULL` | Primary MITRE ATT&CK ID (e.g. `T1110.001`) |
| `mitre_name` | `TEXT` | `NOT NULL` | MITRE technique title (e.g. "Password Guessing") |
| `risk_score` | `INTEGER` | `NOT NULL` | Calculated score (0–100) |
| `primary_ip` | `TEXT` | `NOT NULL` | Adversary IP address |
| `primary_user` | `TEXT` | `NOT NULL` | Targeted username |
| `event_count` | `INTEGER` | `NOT NULL` | Number of correlated events |
| `first_seen` | `TEXT` | `NOT NULL` | Earliest event timestamp in incident |
| `last_seen` | `TEXT` | `NOT NULL` | Latest event timestamp in incident |
| `status` | `TEXT` | `NOT NULL DEFAULT 'new'` | `new`, `investigating`, `contained`, `resolved`, `false_positive` |
| `analyst_notes` | `TEXT` | `NOT NULL DEFAULT ''` | Forensic notes and remediation summary |
| `event_ids_json` | `TEXT` | `NOT NULL DEFAULT '[]'` | JSON list of associated event row IDs |

### `ioc_records`
| Column | Type | Constraints | Description |
| --- | --- | --- | --- |
| `id` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | IOC entry ID |
| `ioc_type` | `TEXT` | `NOT NULL` | `ip`, `cidr`, `user_agent`, `username` |
| `indicator` | `TEXT` | `NOT NULL UNIQUE` | Value (e.g. `185.220.101.5` or `198.51.100.0/24`) |
| `threat_type` | `TEXT` | `NOT NULL` | `tor_exit_node`, `brute_force_botnet`, `malicious_scanner`, `known_c2` |
| `severity` | `TEXT` | `NOT NULL` | `critical`, `high`, `medium` |
| `description` | `TEXT` | `NOT NULL` | Intelligence narrative |
| `added_at` | `TEXT` | `NOT NULL` | ISO-8601 UTC timestamp |

### `soc_audit_logs`
| Column | Type | Constraints | Description |
| --- | --- | --- | --- |
| `id` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Audit row ID |
| `timestamp` | `TEXT` | `NOT NULL` | ISO-8601 UTC timestamp |
| `action` | `TEXT` | `NOT NULL` | `ingest_logs`, `triage_incident`, `add_ioc`, `update_settings`, `export_report` |
| `target` | `TEXT` | `NOT NULL` | Affected entity or ID |
| `outcome` | `TEXT` | `NOT NULL` | `success`, `error` |
| `details` | `TEXT` | `NOT NULL` | Event metadata |
