# Industry Problem Statements — November 2026 Cohort

This document catalogues the eight IT industry domains targeted by Open Industry Solutions (OIS) and defines the technical problem statements for the **November 2026** cohort (Projects 01–10).

All projects below are currently **`PLANNED`**.

---

## Eight IT Industry Domains

1. **Software Engineering & Developer Productivity**
   - Focus: Eliminating insecure defaults, secret leaks, and inconsistent static review gates before code reaches shared branches.
2. **Cybersecurity & Identity (SecOps / IAM)**
   - Focus: Reducing alert fatigue through structured threat enrichment and detecting overly permissive IAM policies before privilege escalation occurs.
3. **Site Reliability Engineering (SRE) & Observability**
   - Focus: Lightweight, self-hostable availability probing, SLO burn-rate visibility, and deterministic alerting without vendor lock-in.
4. **DevOps, CI/CD & Release Safety**
   - Focus: Pre-flight release checks, manifest/configuration drift detection, and automated rollback readiness validation prior to production cutover.
5. **Data Engineering, Databases & Applied AI**
   - Focus: Explaining slow database query plans with deterministic execution telemetry and enforcing contract-driven data quality checks across pipelines.
6. **Networking & Infrastructure Operations**
   - Focus: Diagnosing DNS resolution anomalies, TLS certificate expiration/chain issues, and multi-hop latency degradation from a single portable CLI/agent.
7. **IT Service Management (ITSM) & Enterprise Automation**
   - Focus: Reducing manual ticket triage bottlenecks through deterministic rule routing, runbook matching, and auditable remediation workflows.
8. **Cloud Infrastructure & FinOps**
   - Focus: Identifying orphaned cloud resources, over-provisioned compute/storage, and sudden cost anomalies across multi-account environments.

---

## November 2026 Problem Statements

### 01 — CodeGuard
- **Domain:** Software Engineering & Developer Productivity
- **Status:** `PLANNED`
- **Problem Statement:** Engineering teams frequently merge code containing hardcoded credentials, high-risk anti-patterns, and missing static policy checks because enterprise SAST suites are heavy, slow, or fragmented across languages. Teams need a fast, local-first, CI-ready pre-commit and PR guardrail that emits standardised SARIF reports.
- **Target Outcomes:**
  - Deterministic scanning for secrets, dangerous patterns, and policy violations.
  - Sub-second incremental checks on staged diffs and SARIF v2.1.0 output for GitHub Code Scanning.

### 02 — ThreatLens
- **Domain:** Cybersecurity & Identity (SecOps / IAM)
- **Status:** `PLANNED`
- **Problem Statement:** Security analysts spend excessive time correlating raw firewall, authentication, and endpoint log events across disparate JSON/syslog formats without unified severity scoring or IOC matching.
- **Target Outcomes:**
  - Normalised ingestion pipeline for common security event schemas.
  - Configurable rule-based correlation, IOC enrichment, and auditable triage summaries.

### 03 — UptimePulse
- **Domain:** Site Reliability Engineering (SRE) & Observability
- **Status:** `PLANNED`
- **Problem Statement:** Small and mid-sized platform teams either overpay for SaaS synthetic monitoring or deploy fragile cron scripts that lack TLS expiry tracking, multi-region confirmation, and SLO error-budget alerting.
- **Target Outcomes:**
  - Declarative YAML-configured HTTP(S), TCP, DNS, and TLS probes.
  - Prometheus-compatible metrics export and multi-window SLO burn-rate alerts.

### 04 — DeploySafe
- **Domain:** DevOps, CI/CD & Release Safety
- **Status:** `PLANNED`
- **Problem Statement:** Production outages frequently stem from unvalidated configuration changes, missing health probes, breaking schema migrations, or unverified rollback paths pushed through CI/CD pipelines.
- **Target Outcomes:**
  - Automated pre-deployment checklist engine evaluating manifests, environment parity, and health endpoints.
  - Gatekeeper exit codes and structured deployment readiness reports for CI pipelines.

### 05 — QuerySense AI
- **Domain:** Data Engineering, Databases & Applied AI
- **Status:** `PLANNED`
- **Problem Statement:** Application engineers often struggle to interpret raw `EXPLAIN (ANALYZE, BUFFERS)` query plans, missing index opportunities, sequential scan bottlenecks, and join cardinality misestimations until queries degrade production databases.
- **Target Outcomes:**
  - Deterministic query plan parser (starting with PostgreSQL) combined with optional pluggable LLM explanation support.
  - Concrete, verifiable index and query-rewrite recommendations grounded strictly in observed plan nodes.

### 06 — DataTrust
- **Domain:** Data Engineering, Databases & Applied AI
- **Status:** `PLANNED`
- **Problem Statement:** Analytics and ML pipelines silently ingest null spikes, schema drift, duplicate primary keys, and freshness violations when upstream producers evolve without enforceable data contracts.
- **Target Outcomes:**
  - Declarative data contract specifications (YAML/JSON Schema) with CLI and pipeline runners.
  - Quantified data quality validation reports, quarantine hooks, and CI/CD contract diffing.

### 07 — NetScope
- **Domain:** Networking & Infrastructure Operations
- **Status:** `PLANNED`
- **Problem Statement:** Troubleshooting hybrid cloud and on-premise connectivity requires stitching together `dig`, `traceroute`, `openssl`, and `curl` outputs manually, slowing incident resolution for DNS, MTU, routing, and TLS failures.
- **Target Outcomes:**
  - Single portable diagnostic binary/CLI executing parallel DNS, TCP handshake, TLS chain, and HTTP timing checks.
  - Machine-readable JSON snapshots for comparing healthy vs. degraded network paths.

### 08 — ITFlow
- **Domain:** IT Service Management (ITSM) & Enterprise Automation
- **Status:** `PLANNED`
- **Problem Statement:** IT operations desks face high volumes of repetitive Tier-1 requests (access resets, provisioning checks, diagnostic lookups) routed manually without standardised SLA escalation or auditable automation runbooks.
- **Target Outcomes:**
  - Lightweight workflow and ticket-routing engine with declarative approval gates.
  - Full audit trail for automated vs. human-approved IT operational actions.

### 09 — CloudCostIQ
- **Domain:** Cloud Infrastructure & FinOps
- **Status:** `PLANNED`
- **Problem Statement:** Cloud bills escalate unnoticed due to unattached block volumes, idle non-production instances, unmonitored NAT gateway egress, and delayed billing console reviews.
- **Target Outcomes:**
  - Read-only cloud billing and resource utilisation analyser exporting actionable waste findings.
  - Budget threshold and daily anomaly notifications with verifiable resource identifiers.

### 10 — AccessCheck
- **Domain:** Cybersecurity & Identity (SecOps / IAM)
- **Status:** `PLANNED`
- **Problem Statement:** Over time, IAM roles, service accounts, and repository permissions accumulate wildcard privileges, stale API tokens, and unreviewed cross-account trusts that violate least-privilege compliance.
- **Target Outcomes:**
  - Policy graph analyser evaluating IAM/RBAC definitions against least-privilege and separation-of-duties rules.
  - Clear remediation diffs and compliance posture reports (aligned with CIS and NIST controls).

