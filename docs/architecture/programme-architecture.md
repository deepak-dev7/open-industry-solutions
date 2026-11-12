# Programme Architecture

Open Industry Solutions (OIS) is structured as a modular monorepo where each monthly cohort problem lives in an isolated, self-contained project workspace under `projects/<NN>-<slug>/`, governed by shared engineering, security, and documentation standards.

---

## Monorepo Layout & Isolation Boundaries

| Directory | Purpose | Ownership / Change Cadence |
| --- | --- | --- |
| `research/` | Industry problem discovery, ADRs, and external standards | Updated at the start of each monthly cohort and during architecture reviews |
| `projects/<NN>-<slug>/` | Independent solution workspaces (code, tests, docs, container/build files) | Isolated per project; zero cross-project runtime coupling |
| `docs/architecture/` | Programme structure, lifecycle states, and release gates | Stable governance updated via reviewed PRs |
| `docs/security/` | Security baseline, secret hygiene, and vulnerability handling | Enforced across all projects and CI pipelines |
| `docs/development/` | Coding standards, testing requirements, and programme roadmap | Enforced on every code contribution |
| `progress/` | Monthly delivery tracker and programme-wide changelog | Updated whenever a project transitions lifecycle stages |
| `.github/` | Issue templates, PR template, and CI validation workflows | Enforces repository hygiene automatically |

---

## Target Project Workspace Structure

When a project progresses from `PLANNED` to `DESIGNED` and `IN_DEVELOPMENT`, its directory under `projects/<NN>-<slug>/` follows a predictable layout:

```text
projects/<NN>-<slug>/
├── README.md           # Problem statement, architecture, usage, and status
├── docs/               # Project-specific ADRs, threat model, and runbook
├── src/                # Production source code (added only in IN_DEVELOPMENT)
├── tests/              # Unit, integration, and security tests
└── .github/ or Makefile / Dockerfile  # Reproducible local & CI build targets
```

---

## Architectural Guardrails

1. **No Cross-Project Hidden Dependencies:** Each project must build, test, and run independently without importing internal source files from sibling projects.
2. **Standardised Interfaces:** Tools communicate using open data formats (JSON, YAML, SARIF, Prometheus `/metrics`, OpenTelemetry) so teams can compose solutions without tight coupling.
3. **Truthful Status Reporting:** Documentation and trackers must accurately reflect actual implementation state (`PLANNED` until design/code exists).

