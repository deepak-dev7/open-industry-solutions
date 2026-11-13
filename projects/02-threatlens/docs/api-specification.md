# ThreatLens REST API Specification

Base URL: `http://127.0.0.1:8766`

All endpoints return JSON responses with standard HTTP status codes, enforce parameterised database interactions, and include security response headers (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, strict CSP).

---

## Endpoint Summary

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/api/health` | Service health status, database connectivity, and version metadata |
| `GET` | `/api/dashboard` | High-level SOC metrics, active incident counters, severity distribution, top IPs and accounts |
| `POST` | `/api/ingest/upload` | Upload and parse an authentication log file (`multipart/form-data`) |
| `POST` | `/api/ingest/text` | Ingest raw text log data directly with specified format (`syslog`, `windows_event`, `json`, `csv`) |
| `POST` | `/api/ingest/scenario` | Ingest a built-in synthetic attack scenario (`brute_force`, `password_spray`, `impossible_travel`, `after_hours_admin`, `clean_baseline`) |
| `GET` | `/api/incidents` | List correlated incidents with filters: `severity`, `status`, `search`, `page`, `limit` |
| `GET` | `/api/incidents/{incident_id}` | Fetch detailed incident view including timeline events, MITRE details, and analyst notes |
| `PATCH` | `/api/incidents/{incident_id}` | Update incident triage status (`investigating`, `contained`, `resolved`, `false_positive`) and notes |
| `GET` | `/api/incidents/{incident_id}/export` | Export incident report in `json`, `csv`, or `markdown` format |
| `GET` | `/api/events` | Search and filter raw security events (`username`, `ip`, `status`, `source_type`, `search`, `limit`) |
| `GET` | `/api/ioc` | List active Threat Intelligence Indicators of Compromise (IOCs) |
| `POST` | `/api/ioc` | Add a new custom IOC record (IP, CIDR, or threat category) |
| `DELETE` | `/api/ioc/{ioc_id}` | Remove an IOC record |
| `GET` | `/api/settings` | Get current detection thresholds (burst window, brute-force count, spray count, working hours) |
| `PUT` | `/api/settings` | Update detection parameters |
| `GET` | `/api/audit-logs` | Retrieve recent SOC analyst audit records |
