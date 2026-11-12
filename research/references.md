# References & Industry Standards

This file collects the authoritative open standards, frameworks, and specifications that inform Open Industry Solutions (OIS) architecture, security, and engineering practices.

---

## Security & Compliance Frameworks

- **OWASP Top 10 & ASVS (Application Security Verification Standard):** Baseline controls for web services, APIs, and input validation (`01-codeguard`, `02-threatlens`, `04-deploysafe`).
- **OWASP Top 10 for LLM Applications:** Prompt injection, data leakage, and grounding controls (`05-querysense-ai`).
- **CIS Benchmarks & NIST SP 800-53 / CSF:** Least-privilege IAM auditing, configuration hardening, and audit logging (`02-threatlens`, `10-accesscheck`).
- **SLSA (Supply-chain Levels for Software Artifacts):** Build provenance, dependency pinning, and CI security (`04-deploysafe`, programme CI).
- **CWE / CVE & SARIF v2.1.0 (OASIS):** Standardised vulnerability taxonomy and static analysis exchange format (`01-codeguard`).

---

## Observability, SRE & Networking Standards

- **OpenTelemetry Specification:** Vendor-neutral traces, metrics, and structured logs (`03-uptimepulse`, `08-itflow`).
- **Prometheus Exposition Format:** Standard `/metrics` scraping contract (`03-uptimepulse`).
- **Google SRE Workbook (SLIs, SLOs, Error Budgets):** Multi-window burn-rate alerting methodology (`03-uptimepulse`).
- **RFC 1035 / RFC 8484 (DNS / DoH) & RFC 8446 (TLS 1.3):** Authoritative protocol specifications for network and certificate diagnostics (`07-netscope`).

---

## Data, FinOps & Governance Standards

- **Open Data Contract Standard (ODCS) / JSON Schema:** Schema validation, freshness SLAs, and data quality assertions (`06-datatrust`).
- **FinOps Foundation Framework:** Cloud cost allocation, unit economics, and anomaly management (`09-cloudcostiq`).
- **ITIL 4 Practices (Incident, Change Enablement, Service Request):** Workflow states, approvals, and audit trails (`08-itflow`).

---

## Software Engineering & Repository Standards

- **Conventional Commits v1.0.0:** Structured commit history and automated release notes.
- **Semantic Versioning (SemVer 2.0.0):** Predictable compatibility guarantees for released tools.
- **Keep a Changelog v1.1.0:** Human-readable release history in `progress/changelog.md` and per-project changelogs.
- **Contributor Covenant v2.1:** Community participation guidelines in [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md).

