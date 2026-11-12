# 01 — CodeGuard

- **Status:** `VERIFIED`
- **Cohort:** November 2026
- **Domain:** Software Engineering & Developer Productivity
- **Version:** `0.1.0`
- **Requires:** Python 3.11+ (zero mandatory third-party runtime dependencies)

---

## Problem Statement

Engineering teams frequently merge code containing hardcoded credentials, unsafe language patterns, and CI workflow misconfigurations because enterprise SAST tools can be slow, heavy, or difficult to run locally before pushing.

CodeGuard provides a fast, zero-dependency, local-first static security and quality guardrail that runs on directories, individual files, or Git diffs (`--staged`, `--diff <ref>`) and outputs human-readable text, JSON, or **SARIF v2.1.0**.

---

## Architecture & Security Documentation

- [ADR-001: Architecture & Technology Selection](docs/ADR-001-architecture.md)
- [Threat Model & Trust Boundaries](docs/threat-model.md)

---

## Installation

From `projects/01-codeguard/`:

```bash
pip install -e .
```

Or run directly without installation using `PYTHONPATH=src`:

```bash
python -m codeguard.cli --help
```

---

## CLI Usage

### Scan a directory or repository

```bash
codeguard scan .
```

### Scan only staged Git changes (pre-commit workflow)

```bash
codeguard scan --staged
```

### Scan changes against a Git ref

```bash
codeguard scan --diff origin/main
```

### Generate SARIF v2.1.0 or JSON reports

```bash
codeguard scan . --format sarif --output codeguard.sarif
codeguard scan . --format json --fail-on medium
```

### List built-in rules

```bash
codeguard rules
codeguard rules --format json
```

### Create a starter `.codeguard.toml`

```bash
codeguard init
```

### Exit Codes

| Exit Code | Meaning |
| --- | --- |
| `0` | Scan completed with no findings at or above `--fail-on` |
| `1` | One or more findings met or exceeded `--fail-on` |
| `2` | Invalid CLI arguments, missing target/config, or Git command error |

---

## Built-In Rules

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

---

## Configuration & Suppressions

Create `.codeguard.toml` in the repository root (or pass `--config <path>`):

```toml
[codeguard]
fail_on = "high"
max_file_size_kb = 1024
entropy_threshold = 4.2
ignore_paths = [".git/**", ".venv/**", "node_modules/**", "dist/**"]
disabled_rules = []
allowlist_patterns = ["EXAMPLE_KEY"]
```

Inline suppressions are supported on the finding line or immediately preceding line:

```python
legacy_hash = hashlib.md5(data)  # codeguard: ignore[CG-PY-005]
```

---

## Running Tests

From `projects/01-codeguard/`:

```bash
python -m unittest discover -s tests -v
```

---

## Known Limitations

- Deep AST inspection currently covers Python (`ast` module); JavaScript, TypeScript, Shell, and GitHub Actions YAML use targeted pattern checks.
- Secret detection relies on curated provider prefixes, private key headers, and Shannon entropy heuristics; bespoke internal token formats should be paired with custom secret management controls.
