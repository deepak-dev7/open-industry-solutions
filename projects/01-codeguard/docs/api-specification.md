# CodeGuard REST API Specification

Base URL (local default): `http://127.0.0.1:8765`

All endpoints validate inputs via Pydantic schemas, protect against path traversal, enforce request size limits, redact credential values, and record state-changing actions in `audit_logs`.

---

## Endpoints

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/api/health` | Service status, version, database connectivity, active rule count |
| `GET` | `/api/dashboard` | Aggregate scan metrics, severity counts, top rules, recent scans |
| `GET` | `/api/browse?path=<dir>` | Safe directory browser returning parent and subdirectories within approved roots |
| `POST` | `/api/scans/path` | Run static scan on an approved local directory/file path and persist results |
| `POST` | `/api/scans/upload` | Validate & scan uploaded folder files in an isolated temporary directory |
| `GET` | `/api/scans` | List persisted scan history with optional `search` and `status` (`pass`/`fail`) filters |
| `GET` | `/api/scans/{scan_id}` | Fetch scan details and filtered findings (`severity`, `rule_id`, `status`, `search`) |
| `DELETE` | `/api/scans/{scan_id}` | Delete a scan record and cascade-delete its findings |
| `GET` | `/api/scans/{scan_id}/export?format=json\|sarif\|html` | Download scan report in JSON, OASIS SARIF v2.1.0, or standalone HTML |
| `PATCH` | `/api/findings/{finding_id}` | Update triage status (`open`, `acknowledged`, `false_positive`) |
| `GET` | `/api/rules` | Searchable list of all built-in rules (`category`, `severity`, `search`) |
| `GET` | `/api/settings` | Retrieve persisted scanner settings and approved scan roots |
| `PUT` | `/api/settings` | Validate and persist scanner settings |
| `GET` | `/api/audit-logs` | Retrieve recent security & operational audit records |

