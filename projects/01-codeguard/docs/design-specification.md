# CodeGuard Design Specification

## 1. Industry Problem & Requirements

Software teams routinely merge source code containing hardcoded tokens, command/SQL injection sinks, unsafe deserialization, and overly permissive CI workflows. Traditional SAST platforms require heavy infrastructure or cloud SaaS uploads of proprietary repositories.

**CodeGuard** solves this as a **local-first static security & code-quality workbench** combining:
- Zero-trust local folder scanning and safe folder-upload analysis.
- Deterministic Python AST inspection, provider secret detection (with automatic redaction), and cross-language static rules.
- Persisted scan history, finding triage workflow, SARIF v2.1.0 / JSON / HTML reporting, and an auditable configuration console.

---

## 2. User Personas

| Persona | Goals | Primary Workflows |
| --- | --- | --- |
| **Application Security Engineer** | Audit repositories quickly without leaking proprietary code externally; triage findings and export SARIF/HTML reports. | Scanner (browse/path), Scan History & Finding Triage, Rules Catalog, Audit Log. |
| **Software Developer** | Catch secrets and insecure coding patterns before opening a PR; understand exact file/line/remediation. | Folder Upload or Local Path Scan, CLI `--staged`, Inline Suppression guidance. |
| **DevOps / Platform Lead** | Enforce baseline fail-on severity thresholds, restrict approved scan roots, and monitor recurring rule trends. | Dashboard metrics, Settings (`fail_on`, `allowed_roots`, `disabled_rules`). |

---

## 3. UI Architecture & Wireframes

```text
+------------------------------------------------------------------------+
| [Sidebar Navigation]              | [Top Bar: Breadcrumb + Theme + API]|
|  CodeGuard Studio (v0.2.0)        +------------------------------------+
|  - Dashboard                      |                                    |
|  - Scanner                        |  Active View Workspace             |
|  - Scan History & Reports         |  - KPI Cards / Severity Breakdown  |
|  - Rules Catalog                  |  - Folder Browser / Upload Form    |
|  - Settings & Audit Log           |  - Filterable Findings Table       |
|  - Help & Docs                    |  - Export Controls (JSON/SARIF/HTML|
+-----------------------------------+------------------------------------+
```

### Visual Design System
- **Identity:** Precision AppSec & Developer Workbench.
- **Themes:** High-contrast **Dark** (`#0b1120` canvas, `#111a2e` surface, `#6366f1` / `#38bdf8` accents) and **Light** (`#f8fafc` canvas, `#ffffff` surface, `#4f46e5` primary) persisted in `localStorage`.
- **Typography:** System sans-serif for UI hierarchy (`Inter`/`Segoe UI`), monospace (`JetBrains Mono`/`Consolas`) for file paths, line numbers, rule IDs, and redacted code snippets.
- **Severity Tokens:** `CRITICAL` (`#ef4444`), `HIGH` (`#f97316`), `MEDIUM` (`#eab308`), `LOW` (`#0ea5e9`), `PASS` (`#10b981`).
- **XSS Safety:** All dynamic UI elements use `textContent` and explicit DOM construction (`document.createElement`)—zero `.innerHTML` interpolation of scan data.

