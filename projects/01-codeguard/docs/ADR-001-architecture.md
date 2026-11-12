# ADR-001: CodeGuard Architecture and Technology Selection

- **Status:** Accepted
- **Date:** 2026-11-12
- **Project:** 01-codeguard

---

## Context

CodeGuard addresses the need for a fast, local-first, CI-ready static security and code-quality guardrail that catches hardcoded credentials, dangerous language patterns, and configuration risks before code is merged. To be practical across developer workstations and CI runners without complex setup, it must install cleanly, run deterministically, and emit standardised **SARIF v2.1.0** reports.

## Decision

1. **Implementation Language:** Python 3.11+ using **zero mandatory third-party runtime dependencies** (standard library only: `ast`, `tomllib`, `re`, `json`, `math`, `pathlib`, `argparse`, `subprocess`).
2. **Dual Analysis Engine:**
   - **AST-based analysis** (`ast.NodeVisitor`) for Python source files to avoid regex false positives in comments/strings and accurately inspect call arguments (e.g., `shell=True`, `verify=False`, `yaml.safe_load` vs `yaml.load`).
   - **Bounded pattern + Shannon entropy analysis** for secrets and cross-language patterns (`.js`, `.ts`, `.sh`, `.yml`, `.yaml`, etc.).
3. **Output Formats:** Human-readable terminal text, structured JSON, and OASIS **SARIF v2.1.0** for GitHub Code Scanning.
4. **Secret Redaction:** Matched credential values are redacted before leaving the scanner so findings never expose raw secrets in CI logs or SARIF artifacts.
5. **Git Diff Awareness:** Support `--staged` and `--diff <ref>` modes invoking `git` directly via `subprocess.run(..., shell=False)`.

## Alternatives Considered

- **Go or Rust single binary:** Strong runtime performance, but neither toolchain is guaranteed on every contributor workstation, and Python AST parsing is built into Python's standard library.
- **Wrapping multiple external scanners (Bandit, Gitleaks, Semgrep):** Adds heavy installation prerequisites and inconsistent configuration schemas. CodeGuard provides a unified, self-contained baseline instead.

## Consequences

- **Positive:** Zero dependency supply-chain footprint at runtime; works offline and in minimal Python 3.11+ environments; trivial to test with both `unittest` and `pytest`.
- **Trade-off:** AST deep-inspection rules initially target Python, while JavaScript, TypeScript, Shell, and YAML rely on targeted line/structural rules until additional parsers are added.
