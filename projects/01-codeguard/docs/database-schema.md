# CodeGuard Database Schema (SQLite)

CodeGuard persists scan runs, individual findings, runtime settings, and security audit events in a local SQLite database (`~/.codeguard/codeguard.db` by default, configurable via `CODEGUARD_DB_PATH`) using WAL mode and foreign-key enforcement.

---

## Tables

### `scans`
| Column | Type | Constraints | Description |
| --- | --- | --- | --- |
| `id` | `TEXT` | `PRIMARY KEY` | UUID4 scan identifier |
| `created_at` | `TEXT` | `NOT NULL` | ISO-8601 UTC timestamp |
| `source_type` | `TEXT` | `NOT NULL` | `path` or `upload` |
| `target_label` | `TEXT` | `NOT NULL` | Normalised path or uploaded folder label |
| `fail_on` | `TEXT` | `NOT NULL` | Effective fail threshold (`low`..`critical`) |
| `failed` | `INTEGER` | `NOT NULL` | `1` if findings >= `fail_on`, else `0` |
| `files_scanned` | `INTEGER` | `NOT NULL` | Count of scanned text files |
| `files_skipped` | `INTEGER` | `NOT NULL` | Count of ignored/binary/oversized files |
| `suppressed_count` | `INTEGER` | `NOT NULL` | Findings suppressed via config/inline |
| `findings_count` | `INTEGER` | `NOT NULL` | Total persisted findings |
| `critical_count` | `INTEGER` | `NOT NULL` | Count of `critical` findings |
| `high_count` | `INTEGER` | `NOT NULL` | Count of `high` findings |
| `medium_count` | `INTEGER` | `NOT NULL` | Count of `medium` findings |
| `low_count` | `INTEGER` | `NOT NULL` | Count of `low` findings |
| `duration_ms` | `INTEGER` | `NOT NULL` | Scan duration in milliseconds |
| `sarif_json` | `TEXT` | `NOT NULL` | Generated SARIF v2.1.0 JSON payload |

### `findings`
| Column | Type | Constraints | Description |
| --- | --- | --- | --- |
| `id` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Finding row ID |
| `scan_id` | `TEXT` | `NOT NULL, REFERENCES scans(id) ON DELETE CASCADE` | Parent scan ID |
| `rule_id` | `TEXT` | `NOT NULL` | Rule identifier (e.g. `CG-PY-002`) |
| `rule_name` | `TEXT` | `NOT NULL` | Rule title |
| `severity` | `TEXT` | `NOT NULL` | `critical`, `high`, `medium`, `low` |
| `category` | `TEXT` | `NOT NULL` | Rule category |
| `cwe` | `TEXT` | `NOT NULL` | CWE identifier |
| `file_path` | `TEXT` | `NOT NULL` | Relative POSIX path |
| `line` | `INTEGER` | `NOT NULL` | 1-based line number |
| `column` | `INTEGER` | `NOT NULL` | 1-based column number |
| `message` | `TEXT` | `NOT NULL` | Redacted finding description |
| `remediation` | `TEXT` | `NOT NULL` | Actionable remediation guidance |
| `snippet` | `TEXT` | `NOT NULL` | Redacted source line excerpt |
| `status` | `TEXT` | `NOT NULL DEFAULT 'open'` | `open`, `acknowledged`, or `false_positive` |

### `app_settings`
| Column | Type | Constraints | Description |
| --- | --- | --- | --- |
| `key` | `TEXT` | `PRIMARY KEY` | Setting key |
| `value` | `TEXT` | `NOT NULL` | JSON-encoded value |
| `updated_at` | `TEXT` | `NOT NULL` | ISO-8601 UTC timestamp |

### `audit_logs`
| Column | Type | Constraints | Description |
| --- | --- | --- | --- |
| `id` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Audit record ID |
| `created_at` | `TEXT` | `NOT NULL` | ISO-8601 UTC timestamp |
| `action` | `TEXT` | `NOT NULL` | Event type (`scan_path`, `scan_upload`, `finding_triage`, `settings_update`, `scan_delete`) |
| `target` | `TEXT` | `NOT NULL` | Resource or path affected |
| `outcome` | `TEXT` | `NOT NULL` | `success`, `failed_gate`, or `rejected` |
| `details` | `TEXT` | `NOT NULL` | Redacted summary metadata |

