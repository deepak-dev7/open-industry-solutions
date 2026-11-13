# ADR-001: ThreatLens Architecture & Technology Selection

- **Status:** Accepted
- **Date:** 2026-11-13
- **Project:** 02-threatlens

---

## Context

Security Operations Centers (SOCs) and incident responders are inundated with heterogeneous authentication and security logs from Linux servers (`auth.log`/syslog), Windows domain controllers (Security Event Logs 4624/4625), and cloud identity providers (Okta, AWS CloudTrail, Azure AD). Manually reviewing these files or deploying massive enterprise SIEMs (Splunk, Elastic, Sentinel) for targeted triage is either too slow, too complex, or requires uploading sensitive internal network telemetry to third-party SaaS providers.

**ThreatLens** must provide a fast, local-first, self-hostable SOC telemetry analysis workbench capable of ingesting varied log formats, normalizing events into a vendor-neutral schema, executing deterministic behavioral and threat correlation rules, and presenting an actionable analyst triage interface with MITRE ATT&CK mapping.

---

## Decision

1. **Backend Framework & Language:** Python 3.11+ using **FastAPI** and **Uvicorn** for high-throughput, async REST API handling with strict Pydantic schemas.
2. **Deterministic Correlation Engine:**
   - Multi-format ingestion adapters: Linux PAM/OpenSSH `auth.log`, Windows Security Event XML/JSON (EventIDs 4624, 4625, 4720, 4672), AWS CloudTrail / Okta JSON logs, and generic CSV/JSON event streams.
   - Algorithmic detectors:
     - Sliding-window Brute Force detection (MITRE ATT&CK T1110.001).
     - Single-source Password Spray detection across multiple accounts (T1110.003).
     - Haversine-based Geo-Velocity Anomaly / Impossible Travel calculator (T1078).
     - After-Hours Privileged Administrative Access alerts (T1078.004).
     - Known Bad IP / Tor Exit Node / Botnet IOC matching (T1071).
     - Compromise detection: multiple failures followed immediately by success from the same actor.
3. **Storage & Persistence:** Local **SQLite** with WAL mode, foreign key enforcement, and indexes on timestamp, username, IP, and incident severity.
4. **Zero-Exfiltration Privacy:** All analysis, geo-velocity math, and IOC lookups run 100% locally on the host. Telemetry is never forwarded to external networks.
5. **Frontend Architecture:** Self-contained, responsive SOC Analyst Workbench built with vanilla ES6, semantic HTML5, and responsive cyber-defense CSS. Zero npm build bloat, instantly runnable offline and in air-gapped security environments.
6. **Port Allocation:** Port `8766` to allow concurrent operation with sibling projects.

---

## Alternatives Considered

- **ELK Stack / OpenSearch:** Powerful for petabyte-scale storage, but heavy (multiple gigabytes of RAM, JVM dependencies) and unsuitable for rapid local triage or single-binary air-gapped laptops.
- **Pure Regex Log Grep (Fail2ban style):** Inadequate for stateful correlation across time windows, geo-velocity calculation, or tracking multi-stage attack campaigns.

---

## Consequences

- **Positive:** Zero external infrastructure prerequisites; runs on standard analyst workstations; transparent deterministic correlation logic; instant export of incident reports in JSON, CSV, and Markdown.
- **Trade-off:** Geolocation lookup uses an embedded offline IP-to-coordinates database and synthetic reference table for privacy; high-volume streaming (>100k events/sec) will require batch chunking.
