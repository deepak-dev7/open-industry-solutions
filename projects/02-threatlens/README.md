# 02 — ThreatLens: Security Event Analysis & Suspicious Login Detection

[![Status: RELEASED](https://img.shields.io/badge/status-RELEASED-brightgreen.svg)](https://github.com/deepak-dev7/open-industry-solutions)
[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](../../LICENSE)
[![Tests: 29 Passed](https://img.shields.io/badge/tests-29%20passed-success.svg)](tests/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](pyproject.toml)

> **ThreatLens** is a local-first Security Operations Center (SOC) incident investigation workbench and correlation engine. It ingests Linux `auth.log`, Windows Security Events, CloudTrail/Okta audit JSON, and authentication CSVs to automatically reconstruct attack campaigns, flag impossible-travel anomalies using offline geo-velocity calculations, match curated threat intelligence feeds, and map suspicious activities to the **MITRE ATT&CK® framework**.

---

## Highlights & Capabilities

- **Multi-Format Security Telemetry Ingestion:**
  - Linux `syslog` / `/var/log/auth.log` / `/var/log/secure` (SSH authentication failures, accepted logins, PAM failures).
  - Windows Security Event Logs (Event IDs `4624` Logon Success, `4625` Logon Failure, `4672` Special Privileges Assigned).
  - Cloud / Identity Provider JSON (AWS CloudTrail `ConsoleLogin`, Okta authentication logs).
  - Generic authentication CSV feeds with automated dialect sniffing.
  - Auto-detection heuristic allowing drag-and-drop or paste without format configuration.

- **MITRE ATT&CK® Correlation Engine:**
  - **T1110.001 (Brute Force: Password Guessing):** Detects rapid repeated login failures against single accounts within a configurable sliding window.
  - **T1110.003 (Brute Force: Password Spraying):** Detects single or small-burst attempts across multiple distinct accounts originating from the same adversary source.
  - **T1078 / T1078.002 (Valid Accounts / Account Compromise):** Detects consecutive failed authentication attempts followed by a successful login, indicating adversary cracked credentials.
  - **T1078 (Impossible Travel Anomaly):** Computes great-circle Haversine distances and velocity (km/h) between consecutive logins for an account. Flags movements exceeding commercial airliner speeds ($>850$ km/h).
  - **T1078.004 (After-Hours Privileged Access):** Flags administrative accounts (`root`, `admin`, `system`) authenticating outside approved organizational working hours.
  - **T1071 (Application Layer Protocol: Threat Intel Hit):** In-memory CIDR and IP matching against curated Tor exit nodes, active botnet scanners, and adversary infrastructure.

- **100% Offline & Local-First Privacy:**
  - Zero external network exfiltration: IP geolocation and threat intelligence matching run completely offline using embedded subnet anchors and CIDR trees.
  - SQLite WAL (Write-Ahead Logging) database with strict foreign key constraints and transactional integrity.
  - Immutable SOC audit logging for all ingest, triage, configuration, and IOC updates.

- **Professional SOC Analyst Workbench (UI/UX):**
  - High-contrast cyber-defense dark theme with clear visual hierarchy.
  - Live metric KPI cards (Total Events, Failed Logins, Active Incidents, Risk Distribution).
  - Interactive Incident Queue with severity badges (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) and multi-factor filtering.
  - Chronological Event Timeline drawer with raw log inspection, geographic metadata, and analyst notes.
  - Real-time Threat Intelligence Manager (view, add, delete custom IOC indicators).
  - Export capabilities in **JSON**, **CSV**, and **Forensic Markdown Report** formats.
  - Interactive Pre-Packaged Attack Scenarios for instant SOC training and verification.

---

## Architecture Overview

```
                      +---------------------------------------+
                      | Raw Security Logs (syslog/Windows/...) |
                      +---------------------------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |         auto_detect_and_parse         |
                      +---------------------------------------+
                                          |
                      +-------------------+-------------------+
                      |                                       |
                      v                                       v
         +-------------------------+             +-------------------------+
         |   Offline Geo-IP Map    |             |  In-Memory IOC Matcher  |
         | (Subnet & Coordinates)  |             |  (CIDR / IP Trie Tree)  |
         +-------------------------+             +-------------------------+
                      |                                       |
                      +-------------------+-------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |      ThreatDetector (Engine)          |
                      |  - Brute Force / Password Spray       |
                      |  - Haversine Velocity Anomaly         |
                      |  - After-Hours Admin Detection        |
                      |  - Credential Compromise Detection    |
                      +---------------------------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |       SQLite WAL Store (Local)        |
                      | (Sources, Events, Incidents, Audit)   |
                      +---------------------------------------+
                                          |
                       +------------------+------------------+
                       |                                     |
                       v                                     v
         +--------------------------+          +--------------------------+
         |  FastAPI REST API        |          |  CLI Analyst Tool        |
         |  (Port 8766 / SPA Web)   |          |  (threatlens analyze)    |
         +--------------------------+          +--------------------------+
```

---

## Directory Structure

```
projects/02-threatlens/
├── .dockerignore
├── .env.example
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
├── README.md
├── docs/
│   ├── ADR-001-architecture.md
│   ├── api-specification.md
│   ├── database-schema.md
│   ├── design-specification.md
│   └── threat-model.md
├── src/
│   └── threatlens/
│       ├── __init__.py
│       ├── api.py           # FastAPI REST endpoints & security middleware
│       ├── cli.py           # Terminal interface (serve, analyze, scenarios)
│       ├── detector.py      # MITRE ATT&CK correlation algorithms
│       ├── geo.py           # Offline Geo-IP & Haversine velocity calculator
│       ├── ioc.py           # Threat intelligence records & CIDR matcher
│       ├── models.py        # Pydantic & dataclass schemas
│       ├── parsers.py       # Syslog, Windows Event, Okta/CloudTrail parsers
│       ├── scenarios.py     # 5 pre-packaged attack scenarios
│       ├── storage.py       # SQLite WAL database & audit logging
│       └── static/
│           ├── app.js       # Vanilla JS reactive SOC workbench client
│           ├── index.html   # Semantic, accessible analyst dashboard
│           └── styles.css   # Dark cyber-defense design system
└── tests/
    ├── test_api.py          # FastAPI endpoint integration tests
    ├── test_detector.py     # Attack correlation engine tests
    ├── test_geo.py          # Geo-velocity & Haversine distance tests
    ├── test_ioc.py          # Threat intelligence matcher tests
    ├── test_parsers.py      # Multi-format log parsing tests
    └── test_storage.py      # SQLite WAL persistence & audit tests
```

---

## Quickstart

### 1. Local Python Environment

```bash
cd projects/02-threatlens
python -m venv .venv

# On Linux/macOS:
source .venv/bin/activate
# On Windows PowerShell:
.venv\Scripts\Activate.ps1

pip install -e .
```

### 2. Launch the SOC Web Workbench

```bash
# Launch interactive workbench on default port 8766
python -m threatlens.cli serve --host 127.0.0.1 --port 8766
```

Open your browser to: **`http://127.0.0.1:8766`**

### 3. Analyze Logs via Command Line

```bash
# Inspect available built-in synthetic scenarios
python -m threatlens.cli scenarios

# Analyze a log file directly from terminal
python -m threatlens.cli analyze /var/log/auth.log

# Output analysis as structured JSON
python -m threatlens.cli analyze /var/log/auth.log --output json
```

### 4. Docker Deployment

```bash
# Build and run with Docker Compose
docker compose up -d

# Check service logs
docker compose logs -f

# Verify container health
curl -f http://127.0.0.1:8766/api/health
```

---

## Built-In Demonstration Scenarios

ThreatLens includes 5 reproducible attack and baseline scenarios accessible directly from the web interface or CLI:

1. **`brute_force` (SSH Dictionary Attack & Compromise):**
   - 6 rapid SSH login failures from `198.51.100.22` against `admin`, followed immediately by a successful login.
   - Triggers `T1110.001` (Brute Force), `T1078.002` (Account Compromise), and `T1071` (Botnet IOC match).

2. **`password_spray` (Distributed Low-and-Slow Spray):**
   - Single failed login across 5 distinct accounts (`finance`, `sarah`, `devops`, `hr`, `sales`) from `45.154.255.10`.
   - Triggers `T1110.003` (Password Spraying) and `T1071` (Known Adversary Scanner).

3. **`impossible_travel` (Cross-Continent Anomaly):**
   - User `sarah.jenkins` logs in successfully from New York at 14:00 UTC, then from Tokyo at 14:45 UTC ($10,848$ km apart in 45 minutes; calculated velocity $14,464$ km/h).
   - Triggers `T1078` (Impossible Travel Velocity Anomaly).

4. **`after_hours_admin` (Off-Hours Privileged Access via Tor):**
   - Administrative account `root` authenticates at 02:15 UTC from Tor Exit Node `185.220.101.5`.
   - Triggers `T1078.004` (After-Hours Privileged Access) and `T1071` (Tor Exit Node).

5. **`clean_baseline` (Standard Daytime Operations):**
   - Routine authorized developer logins during business hours.
   - Generates 0 incidents, validating low false-positive rates.

---

## REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Service health status, DB connectivity, and IOC count. |
| `GET` | `/api/dashboard` | Aggregated SOC KPIs, severity distribution, top IPs and users. |
| `POST` | `/api/ingest/text` | Ingest and correlate raw log text payload. |
| `POST` | `/api/ingest/upload` | Ingest and correlate uploaded log files. |
| `POST` | `/api/ingest/scenario` | Trigger a pre-packaged synthetic attack scenario. |
| `GET` | `/api/scenarios` | List metadata for built-in demonstration scenarios. |
| `GET` | `/api/incidents` | Query correlated incidents with filters (`severity`, `status`, `search`). |
| `GET` | `/api/incidents/{id}` | Inspect full incident details and correlated event timeline. |
| `PATCH` | `/api/incidents/{id}` | Triage incident status (`investigating`, `contained`, `resolved`, `false_positive`) and save notes. |
| `DELETE` | `/api/incidents/{id}` | Permanently delete an incident record (audited). |
| `GET` | `/api/incidents/{id}/export` | Export incident report as `json`, `csv`, or `markdown`. |
| `GET` | `/api/events` | Search and filter individual ingested security events. |
| `GET` | `/api/ioc` | List threat intelligence indicators. |
| `POST` | `/api/ioc` | Register a new IOC indicator (IP or CIDR). |
| `DELETE` | `/api/ioc/{id}` | Remove a threat intelligence indicator. |
| `GET` | `/api/settings` | Retrieve active detection thresholds and parameters. |
| `PUT` | `/api/settings` | Update detection windows and threshold settings. |
| `GET` | `/api/audit-logs` | Retrieve SOC analyst audit trail. |

---

## Automated Verification & Tests

To execute the complete 29-test automated test suite:

```bash
# Run pytest with full verbosity
pytest -v
```

### Coverage Highlights:
- **`test_detector.py` (5 tests):** Brute force correlation, password spraying across accounts, impossible travel velocity detection, after-hours privileged admin rules, and clean traffic zero-incident baseline.
- **`test_geo.py` (4 tests):** Haversine distance accuracy, velocity anomaly thresholding, public IP subnet mapping, and private/loopback isolation.
- **`test_ioc.py` (4 tests):** Exact IP matching, CIDR range prefix matching, dynamic IOC registration/deletion, and clean IP negatives.
- **`test_parsers.py` (5 tests):** Linux syslog/auth.log parsing, Windows Event JSON parsing, Okta/CloudTrail JSON parsing, CSV auto-detection, and multi-format inference.
- **`test_storage.py` (5 tests):** SQLite WAL schema initialization, atomic batch ingestion, incident status updates, IOC CRUD, and dashboard metric queries.
- **`test_api.py` (6 tests):** FastAPI endpoint integration, security headers (`CSP`, `nosniff`, `DENY`), incident triage lifecycle, forensic exports (JSON, CSV, Markdown), raw text & file upload ingestion, and SOC audit logging.

---

## Security & Compliance

- **No Log Execution:** ThreatLens strictly treats all incoming log telemetry as untrusted data. No shell execution or eval operations are ever performed on log messages.
- **Data Sovereignty:** All database storage and correlation is strictly local-first. ThreatLens does not send telemetry to third-party cloud services.
- **Tamper-Evident Audit Trail:** Every ingest, triage state transition, configuration adjustment, and IOC change is timestamped and recorded to `soc_audit_logs`.
- **Defensive HTTP Headers:** All responses include `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: same-origin`, and a strict `Content-Security-Policy`.

---

## License

Open Industry Solutions is licensed under the [MIT License](../../LICENSE).
