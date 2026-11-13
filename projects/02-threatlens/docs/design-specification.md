# ThreatLens Design Specification & SOC Workbench UX

## 1. Industry Context & Operational Objectives

Modern threat actors routinely exploit identity as the primary perimeter. Credential stuffing botnets, distributed password spraying, and compromised privileged accounts represent the overwhelming majority of initial access vectors in enterprise breaches (MITRE ATT&CK T1078 and T1110).

**ThreatLens** provides security operations analysts with an intuitive, high-density incident workbench that transforms raw, unindexed log streams into correlated attack campaigns with clear risk severity, MITRE tactics, affected entities, and containment recommendations.

---

## 2. User Personas

| Persona | Role | Primary Workflow | Key Needs |
| --- | --- | --- | --- |
| **Tier-1 / Tier-2 SOC Analyst** | Triage incoming alerts and investigate suspicious authentication surges | Ingest log files $\to$ review high-severity incidents $\to$ inspect event timeline $\to$ confirm threat or tag false positive | Fast search, timeline visualization, raw log drill-down, MITRE context |
| **Incident Response (IR) Lead** | Lead containment and post-incident root cause forensics | Correlate multi-account compromise $\to$ trace malicious IPs $\to$ export executive incident summaries | Exportable JSON/CSV evidence, IOC match reporting, attack chain narrative |
| **Security Engineer / Sysadmin** | Harden authentication infrastructure and configure detection gates | Configure off-hours thresholds, manage custom IOC feeds, verify log parsing coverage | Ingestion diagnostics, customizable thresholds, zero-maintenance local runtime |

---

## 3. Visual Identity & Design System

- **Aesthetic:** High-density Cyber Defense & Security Operations Center (SOC) theme.
- **Color Palette:**
  - Canvas: Deep Void `#070b14` and Midnight Slate `#0d1322`
  - Panels & Surfaces: Dark Obsidian `#131b2e` with subtle cyber-cyan borders `#1e2942`
  - Threat Severity Tokens:
    - `CRITICAL`: Crimson Red `#ef4444` / `#991b1b` (e.g. Brute-Force Break-in, Known IOC)
    - `HIGH`: Amber Orange `#f97316` (e.g. Distributed Password Spray, Impossible Travel)
    - `MEDIUM`: Cyber Gold `#eab308` (e.g. Elevated failed login burst)
    - `LOW` / `INFO`: Electric Cyan `#06b6d4` / `#0284c7` (e.g. Off-hours login, single anomaly)
    - `RESOLVED` / `CLEAN`: Emerald Green `#10b981`
- **Typography:**
  - Headings & Labels: Clear sans-serif (`Inter`, `Segoe UI`, system font)
  - Raw Logs & Telemetry: High-readability monospace (`JetBrains Mono`, `Consolas`, `ui-monospace`)
- **Key Views:**
  1. **SOC Overview (Dashboard):** Threat posture, active incident counters, live severity breakdown, top targeted accounts, top adversary IPs, and recent alerts.
  2. **Log Ingest & Parser:** File upload (drag & drop), format selection (syslog `auth.log`, Windows Event JSON, Okta/CloudTrail, generic CSV/JSON), and one-click built-in attack simulation scenarios.
  3. **Incident Queue & Triage:** Filterable incident ledger by severity, status (`NEW`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `FALSE_POSITIVE`), affected entity, and attack technique.
  4. **Incident Detail & Forensic Timeline:** Deep dive into a correlated attack group, displaying temporal event progression, geo-velocity hops, raw log inspector, and triage notes.
  5. **Event Log Explorer:** Real-time searchable log stream with instant filtering by IP, user, status (success/failure), and source type.
  6. **IOC Threat Feeds & Settings:** Manager for blocked IPs, CIDRs, working hours definition, brute force thresholds, and detection sensitivity.
