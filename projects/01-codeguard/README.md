# 01 — CodeGuard

- **Status:** `VERIFIED`
- **Cohort:** November 2026
- **Domain:** Software Engineering & Developer Productivity
- **Version:** `0.2.0`
- **Stack:** Python 3.11+, FastAPI, Uvicorn, Pydantic, SQLite (WAL), Vanilla ES6 + CSS Design System, Docker

---

## Problem Statement

Engineering teams frequently merge code containing hardcoded credentials, unsafe language patterns, and CI workflow misconfigurations because enterprise SAST tools can be slow, heavy, or require uploading proprietary repositories to external cloud services.

**CodeGuard** is a **local-first static security & code-quality web workbench and CLI** that inspects source trees, uploaded folders, and Git diffs locally without executing untrusted code, persists scan history and finding triage in SQLite, and exports **JSON**, **OASIS SARIF v2.1.0**, and **HTML** reports.

---

## Architecture & Engineering Documentation

- [ADR-001: Architecture & Technology Selection](docs/ADR-001-architecture.md)
- [Design Specification & UI Wireframes](docs/design-specification.md)
- [Database Schema (SQLite)](docs/database-schema.md)
- [REST API Specification](docs/api-specification.md)
- [Threat Model & Trust Boundaries](docs/threat-model.md)

---

## Key Capabilities

- **Web Workbench (`codeguard ui`):**
  - **Dashboard:** Aggregate KPIs, open findings by severity, top recurring rules, and recent scan runs.
  - **Scanner:** Interactive local folder browser (`/api/browse`), approved folder path scan, and browser folder upload (`webkitdirectory`) with automatic binary/ignore filtering.
  - **Scan History & Reports:** Persisted scan history in SQLite, severity/rule/text filtering, finding triage (`open`, `acknowledged`, `false_positive`), and one-click JSON, SARIF v2.1.0, and HTML export.
  - **Rules Catalog:** Searchable directory of all 14 built-in CWE-mapped rules.
  - **Settings & Audit Log:** Configurable fail-on gate, approved scan roots, disabled rules, allowlist regexes, and a security audit log.
  - **Light & Dark Themes:** Persistent high-contrast UI theme switcher.
- **Zero-Trust Security Controls:**
  - Static-only inspection (`ast.parse` and bounded regexes); never executes scanned code.
  - Automatic secret redaction before persisting or displaying snippets.
  - Path traversal protection on uploads, approved-root enforcement, sliding-window rate limiting, parameterised SQLite queries, and strict CSP/security headers.

---

## Local Installation & Running

From `projects/01-codeguard/`:

```bash
pip install -e ".[dev]"
```

### Launch the Web Application

```bash
codeguard ui --host 127.0.0.1 --port 8765
```

Open `http://127.0.0.1:8765` in your browser. Interactive OpenAPI docs are available at `http://127.0.0.1:8765/docs`.

### Run via Docker

From `projects/01-codeguard/`:

```bash
docker compose up --build
```

The container exposes port `8765`, stores SQLite state in the `codeguard_data` volume (`/data/codeguard.db`), and mounts the local directory read-only at `/workspace`.

---

## CLI Usage

```bash
codeguard scan .
codeguard scan --staged
codeguard scan --diff origin/main --format sarif --output codeguard.sarif
codeguard rules
codeguard init
```

| Exit Code | Meaning |
| --- | --- |
| `0` | Scan completed with no findings at or above `--fail-on` |
| `1` | One or more findings met or exceeded `--fail-on` |
| `2` | Invalid CLI arguments, missing target/config, or Git command error |

---

## Running Automated Tests

From `projects/01-codeguard/`:

```bash
pytest -v
```

---

## Built-In Rules (14 Rules)

| Rule ID | Severity | CWE | Summary |
| --- | --- | --- | --- |
| `CG-SEC-001` | `CRITICAL` | CWE-798 | Hardcoded provider tokens (GitHub, AWS, Slack, Stripe) |
| `CG-SEC-002` | `CRITICAL` | CWE-321 | PEM-encoded private key headers |
| `CG-SEC-003` | `HIGH` | CWE-798 | High-entropy literal assigned to secret/token/password variable |
| `CG-PY-001` | `HIGH` | CWE-95 | Python `eval()` or `exec()` |
| `CG-PY-002` | `HIGH` | CWE-78 | Python `os.system()` or `subprocess.*(..., shell=True)` |
| `CG-PY-003` | `HIGH` | CWE-502 | Python `pickle.load/loads` or `marshal.load/loads` |
| `CG-PY-004` | `HIGH` | CWE-502 | Python `yaml.load()` without `SafeLoader` / `CSafeLoader` |
| `CG-PY-005` | `MEDIUM` | CWE-328 | Weak hash `hashlib.md5()` / `hashlib.sha1()` without `usedforsecurity=False` |
| `CG-PY-006` | `HIGH` | CWE-295 | Disabled TLS verification (`verify=False` or `ssl._create_unverified_context()`) |
| `CG-PY-007` | `MEDIUM` | CWE-377 | Insecure `tempfile.mktemp()` |
| `CG-PY-008` | `HIGH` | CWE-89 | Dynamic SQL expression passed to `.execute()` |
| `CG-CFG-001` | `MEDIUM` | CWE-269 | GitHub Actions workflow missing `permissions:` or using `write-all` |
| `CG-JS-001` | `HIGH` | CWE-79 | JS/TS `eval()`, `new Function()`, `.innerHTML =`, or `dangerouslySetInnerHTML` |
| `CG-SH-001` | `HIGH` | CWE-829 | Shell `curl`/`wget` piped directly into `sh`/`bash` |
