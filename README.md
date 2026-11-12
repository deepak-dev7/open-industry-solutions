# Open Industry Solutions (OIS)

> **Real-world IT industry problems solved through open-source engineering.**

Open Industry Solutions (OIS) is a structured, production-oriented engineering initiative dedicated to researching, designing, developing, testing, and publishing practical software solutions for genuine IT industry challenges.

---

## Programme Mission

Modern IT teams face recurring operational, security, reliability, data, and cost bottlenecks that often lack lightweight, transparent, and self-hostable open-source tooling.

OIS addresses this gap with a disciplined engineering cadence:

- **Monthly Cadence:** 10 concrete industry problems scoped and engineered per month.
- **Annual Target:** 120 production-oriented solutions published annually.
- **Production-Oriented Engineering:** Reproducible builds, automated testing, clear architecture documentation, security baselines, and operational runbooks.
- **Open-Source First:** Built with open-source languages, protocols, and dependencies wherever practical.

---

## Eight IT Industry Domains

OIS organises its research and engineering output across eight core IT industry domains:

| # | Domain | Focus Areas |
| --- | --- | --- |
| 1 | **Software Engineering & Developer Productivity** | Static analysis, code quality guardrails, automated review hygiene |
| 2 | **Cybersecurity & Identity (SecOps / IAM)** | Threat telemetry triage, least-privilege auditing, access compliance |
| 3 | **Site Reliability Engineering (SRE) & Observability** | Uptime monitoring, SLO tracking, incident correlation |
| 4 | **DevOps, CI/CD & Release Safety** | Pre-deployment verification, progressive delivery checks, rollback safety |
| 5 | **Data Engineering, Databases & Applied AI** | Query performance diagnostics, schema & data quality validation |
| 6 | **Networking & Infrastructure Operations** | Network path diagnostics, DNS/TLS inspection, latency profiling |
| 7 | **IT Service Management (ITSM) & Automation** | Ticket routing, runbook automation, operational workflow orchestration |
| 8 | **Cloud Infrastructure & FinOps** | Cloud spend visibility, idle resource detection, cost anomaly alerting |

---

## November 2026 Cohort (10 Challenges)

Project `01-codeguard` is **`RELEASED`** (`v0.2.0`); Projects `02`–`10` remain **`PLANNED`**.

| ID | Project | Domain | Status | Specification |
| --- | --- | --- | --- | --- |
| 01 | **CodeGuard** | Software Engineering & Developer Productivity | `RELEASED` | [projects/01-codeguard](projects/01-codeguard/README.md) |
| 02 | **ThreatLens** | Cybersecurity & Identity | `PLANNED` | [projects/02-threatlens](projects/02-threatlens/README.md) |
| 03 | **UptimePulse** | SRE & Observability | `PLANNED` | [projects/03-uptimepulse](projects/03-uptimepulse/README.md) |
| 04 | **DeploySafe** | DevOps, CI/CD & Release Safety | `PLANNED` | [projects/04-deploysafe](projects/04-deploysafe/README.md) |
| 05 | **QuerySense AI** | Data Engineering, Databases & Applied AI | `PLANNED` | [projects/05-querysense-ai](projects/05-querysense-ai/README.md) |
| 06 | **DataTrust** | Data Engineering, Databases & Applied AI | `PLANNED` | [projects/06-datatrust](projects/06-datatrust/README.md) |
| 07 | **NetScope** | Networking & Infrastructure Operations | `PLANNED` | [projects/07-netscope](projects/07-netscope/README.md) |
| 08 | **ITFlow** | ITSM & Automation | `PLANNED` | [projects/08-itflow](projects/08-itflow/README.md) |
| 09 | **CloudCostIQ** | Cloud Infrastructure & FinOps | `PLANNED` | [projects/09-cloudcostiq](projects/09-cloudcostiq/README.md) |
| 10 | **AccessCheck** | Cybersecurity & Identity | `PLANNED` | [projects/10-accesscheck](projects/10-accesscheck/README.md) |

---

## Repository Structure

```text
open-industry-solutions/
├── README.md                   # Programme overview and cohort index
├── LICENSE                     # MIT License
├── CONTRIBUTING.md             # Contribution workflow and PR requirements
├── CODE_OF_CONDUCT.md          # Community conduct standards
├── .gitignore                  # Git exclusion rules
├── .editorconfig               # Consistent formatting across editors
├── research/                   # Problem discovery, ADRs, and references
│   ├── industry-problems.md
│   ├── technology-decisions.md
│   └── references.md
├── projects/                   # Individual solution workspaces (01–10)
│   ├── 01-codeguard/
│   ├── 02-threatlens/
│   ├── 03-uptimepulse/
│   ├── 04-deploysafe/
│   ├── 05-querysense-ai/
│   ├── 06-datatrust/
│   ├── 07-netscope/
│   ├── 08-itflow/
│   ├── 09-cloudcostiq/
│   └── 10-accesscheck/
├── docs/                       # Cross-project standards and governance
│   ├── architecture/
│   ├── security/
│   └── development/
├── progress/                   # Monthly tracking and programme changelog
│   ├── monthly-tracker.md
│   └── changelog.md
└── .github/                    # Issue/PR templates and CI validation
    ├── ISSUE_TEMPLATE/
    ├── pull_request_template.md
    └── workflows/
        └── validate.yml
```

---

## Key Documentation

- **Research & Architecture Decisions**
  - [Industry Problem Statements](research/industry-problems.md)
  - [Technology Decisions](research/technology-decisions.md)
  - [References & Standards](research/references.md)
- **Engineering Governance**
  - [Programme Architecture](docs/architecture/programme-architecture.md)
  - [Project Lifecycle & Release Criteria](docs/architecture/project-lifecycle.md)
  - [Security Standards](docs/security/security-standards.md)
  - [Engineering Standards](docs/development/engineering-standards.md)
  - [Development Roadmap](docs/development/roadmap.md)
- **Tracking & Governance**
  - [Monthly Progress Tracker](progress/monthly-tracker.md)
  - [Programme Changelog](progress/changelog.md)
  - [Contributing Guide](CONTRIBUTING.md)
  - [Code of Conduct](CODE_OF_CONDUCT.md)

---

## Project Lifecycle

Every OIS solution moves sequentially through defined lifecycle stages:

`PLANNED` → `DESIGNED` → `IN_DEVELOPMENT` → `VERIFIED` → `RELEASED`

A project is only marked `RELEASED` when it meets all functional, security, testing, and documentation gates defined in [Project Lifecycle & Release Criteria](docs/architecture/project-lifecycle.md).

---

## Licence

This repository is licensed under the [MIT License](LICENSE).

