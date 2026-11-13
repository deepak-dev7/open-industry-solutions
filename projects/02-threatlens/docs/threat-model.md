# ThreatLens Threat Model & Trust Boundaries

## 1. Assets Protected

- Security event logs containing sensitive corporate hostnames, usernames, internal IP topologies, and timestamp patterns.
- SOC analyst triage notes, incident classifications, and containment actions.
- The host machine running ThreatLens.

---

## 2. Threat Boundaries & Security Mitigations

| Threat | Risk | Mitigation in ThreatLens |
| --- | --- | --- |
| **Log Injection / Format Exploitation** | Malicious actors crafting crafted syslog entries or ANSI escapes to trick parsers or inject scripts | Strict regex parsing and typed Pydantic models; all UI rendering uses strict `textContent` and explicit DOM nodes (zero `.innerHTML` injection). |
| **Data Exfiltration** | Sensitive corporate employee names or internal IP subnets leaking to external cloud services | **100% Local-First Execution**: Geolocation lookups use offline calculation and local coordinate reference tables; zero outbound network calls are made during ingestion or correlation. |
| **Denial of Service (Oversized Log Bombs)** | Attacker flooding a multi-gigabyte auth log to crash memory | File uploads are capped at 32 MB with streaming line-by-line generators; database inserts use chunked SQLite transactions. |
| **Path Traversal on Log Ingestion** | Directory escape via uploaded file names or CLI target paths | All file handling normalizes paths and materializes uploads in temporary directories with strict UUID prefixes. |
| **SQL Injection** | Manipulated usernames or IP parameters in search queries | Parameterised SQL queries (`?` bind parameters) used exclusively across all SQLite operations. |
| **False Negative Risk (Evasion)** | Adversaries spreading attempts across long time windows to evade simple counters | Configurable multi-window detection (e.g. 5m, 15m, 60m sliding windows) capturing both rapid brute-force and slow password-spray attacks. |
