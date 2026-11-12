# CodeGuard Threat Model & Trust Boundaries

## Assets Protected

- Repository source code and configuration files scanned locally or in CI.
- Developer credentials and tokens that may accidentally exist in working trees (must not be leaked by CodeGuard's own output).
- Host workstation / CI runner executing `codeguard`.

---

## Trust Boundaries & Mitigations

| Threat | Mitigation in CodeGuard |
| --- | --- |
| **Secret leakage in logs / SARIF reports** | All secret findings pass through `redact_secret()`, masking interior characters before constructing `Finding` snippets or formatted output. |
| **Code execution on untrusted repositories** | CodeGuard performs purely static inspection (`ast.parse` and text scanning). It **never** imports or executes scanned files. |
| **Command injection via `--diff` or file paths** | Git commands run via `subprocess.run([...], shell=False)` with explicit argument lists; user-supplied `--diff` refs starting with `-` are rejected to prevent git flag injection. |
| **Denial of service (large/binary files or ReDoS)** | Files containing null bytes (binary) or exceeding `max_file_size_kb` (default 1024 KB) are skipped. Regex patterns avoid catastrophic backtracking (`.*` nested quantifiers). |
| **Symlink traversal outside workspace** | Directory walking uses `os.walk(..., followlinks=False)` and skips symlinked directories/files outside the scan root. |
