# Technology Decisions

This document establishes the architectural principles and technology selection framework governing all Open Industry Solutions (OIS) projects. Individual projects may refine stack choices via project-level Architecture Decision Records (ADRs) once they transition from `PLANNED` to `DESIGNED`.

---

## Core Selection Principles

1. **Open-Source First:** Prefer permissive or standard OSI-approved open-source dependencies (`MIT`, `Apache-2.0`, `BSD-3-Clause`). Avoid proprietary SDK lock-in where open protocols exist.
2. **Self-Hostable & Local-First:** Solutions must run cleanly on developer workstations, single containers, or standard Kubernetes/VM environments without mandatory SaaS dependencies.
3. **Interoperability via Open Standards:** Adopt established formats—SARIF for static analysis, OpenTelemetry/Prometheus for observability, JSON Schema / YAML for configuration, and REST/OpenAPI for service APIs.
4. **Minimal Operational Footprint:** Favour single binaries or lightweight runtimes with pinned dependencies and reproducible builds.
5. **Security by Default:** Least-privilege execution, read-only modes for auditors/scanners, zero hardcoded secrets, and explicit input validation.

---

## Recommended Baseline Stacks by Workload

| Workload Archetype | Primary Options | Rationale |
| --- | --- | --- |
| **CLI Tools & High-Throughput Agents** (`01-codeguard`, `03-uptimepulse`, `07-netscope`, `10-accesscheck`) | **Go** or **Rust** (or **Python** for rapid rule/plugin ecosystems) | Fast startup, single-binary distribution, strong concurrency primitives, cross-platform builds. |
| **Data, AI & Analytical Engines** (`05-querysense-ai`, `06-datatrust`, `09-cloudcostiq`) | **Python 3.12+** (with `pydantic`, `duckdb`, `polars`, `sqlglot`) | Mature ecosystem for SQL parsing, tabular validation, and pluggable LLM/AI adapters. |
| **Web APIs & Control Planes** (`02-threatlens`, `04-deploysafe`, `08-itflow`) | **Python (FastAPI)**, **Go**, or **TypeScript (Node.js)** | Clear OpenAPI contracts, strong typing, mature testing frameworks, container-ready deployment. |
| **Storage & State** | **SQLite** (embedded/local), **PostgreSQL** (multi-user production) | Reliable ACID guarantees, zero-config local mode with SQLite and scalable production path with PostgreSQL. |
| **Observability & Telemetry** | **OpenTelemetry**, **Prometheus** (`/metrics`), structured **JSON logging** | Vendor-neutral telemetry compatible with existing enterprise monitoring stacks. |
| **Packaging & CI/CD** | **Docker / OCI containers**, **GitHub Actions**, **SBOM (Syft/CycloneDX)** | Reproducible builds, automated verification, and supply-chain transparency. |

---

## Architecture Decision Record (ADR) Template

When a project moves into `DESIGNED`, record key technical choices using the following structure:

```markdown
# ADR-NNN: <Decision Title>

- **Status:** Proposed | Accepted | Superseded
- **Date:** YYYY-MM-DD
- **Project:** <NN-project-slug>

## Context
What problem or constraint requires a decision?

## Decision
What specific technology, pattern, or boundary was chosen?

## Alternatives Considered
What other options were evaluated and why were they rejected?

## Consequences
What operational, performance, security, or maintenance trade-offs follow?
```

---

## Deferred Decisions (Pending Design Phase)

Per programme governance, language bindings, database schemas, and third-party library versions for Projects 01–10 will be finalised and pinned during each project's `DESIGNED` phase—never guessed prematurely.

