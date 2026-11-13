# Changelog

All notable programme-level milestones and project releases for **Open Industry Solutions (OIS)** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and released solutions adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- **02 — ThreatLens v0.1.0 (`RELEASED`):** Developed full-stack SOC analyst incident investigation workbench and security event correlation engine (`projects/02-threatlens/`). Ingests Linux auth/syslog, Windows Security Events (4624/4625/4672), CloudTrail/Okta JSON, and CSVs. Offline Haversine geo-velocity anomaly detection, in-memory CIDR threat intelligence matcher, MITRE ATT&CK correlation engine (T1110.001 Brute Force, T1110.003 Password Spray, T1078.002 Account Compromise, T1078 Impossible Travel, T1078.004 After-Hours Admin, T1071 IOC hits), SQLite WAL storage, REST API (`src/threatlens/api.py`), dark cyber-defense SPA dashboard (`src/threatlens/static/`), CLI runner (`threatlens serve`, `threatlens analyze`, `threatlens scenarios`), 29 automated tests, Dockerfile and docker-compose.yml.
- **01 — CodeGuard v0.2.0 (`RELEASED`):** Completed full-stack local-first web application with FastAPI backend (`src/codeguard/api.py`), SQLite persistence (`src/codeguard/storage.py`), multi-view Light/Dark Web Workbench (`src/codeguard/static/`), interactive folder browser, finding triage, HTML/JSON/SARIF export, audit logging, Docker support (`Dockerfile`, `docker-compose.yml`), design/DB/API docs, 22 automated tests, and CI Docker verification.
- **01 — CodeGuard (`VERIFIED`):** Implemented zero-dependency Python 3.11+ static security and quality guardrail CLI (`src/codeguard/`), ADR-001, threat model, SARIF v2.1.0 / JSON / text formatters, Git `--staged` and `--diff` support, `.codeguard.toml` loader, 16 unit/integration tests, and CI self-scan in `.github/workflows/validate.yml`.
- Initialised the Open Industry Solutions (`open-industry-solutions`) workspace structure.
- Added governance documentation (`README.md`, `LICENSE`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`).
- Documented the 8 IT industry domains, 10 November 2026 problem statements, technology decision framework, and references in `research/`.
- Created project specification placeholders (`PLANNED` status) for Projects `01-codeguard` through `10-accesscheck`.
- Added programme architecture, project lifecycle & release criteria, security standards, engineering standards, and roadmap in `docs/`.
- Added monthly progress tracker in `progress/monthly-tracker.md`.
- Configured GitHub issue templates, pull request template, and CI validation workflow (`.github/workflows/validate.yml`).

