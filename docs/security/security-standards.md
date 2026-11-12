# Security Standards

Security is a first-class engineering requirement across every Open Industry Solutions (OIS) project and repository workflow.

---

## Mandatory Repository Rules

1. **Zero Secrets in Git History:** Never commit API keys, personal access tokens, passwords, private keys (`.pem`, `.key`), `.env` files, or cloud credential JSON files.
2. **Least-Privilege Permissions:**
   - GitHub Actions workflows must declare minimal `permissions:` blocks (read-only by default).
   - Security and FinOps auditors (`02-threatlens`, `09-cloudcostiq`, `10-accesscheck`) must default to read-only operations.
3. **Input Validation & Safe Parsing:**
   - Validate all external inputs (CLI flags, YAML/JSON configs, HTTP payloads, SQL/log inputs).
   - Use parameterised database queries and safe YAML loaders (`yaml.safe_load`).
   - Avoid shell command injection (`subprocess` with `shell=True` or unescaped string interpolation).
4. **Dependency & Supply-Chain Hygiene:**
   - Pin dependency versions via lockfiles where supported.
   - Run automated vulnerability audits and static analysis before release.
5. **No Bypassing Controls:** Never disable TLS certificate verification, Git security checks, or authentication enforcement in production paths.

---

## Reporting a Security Vulnerability

If you discover a security vulnerability in any OIS specification, workflow, or implementation:

1. **Do not** open a public GitHub issue with exploit details.
2. Use GitHub's **Private Vulnerability Reporting** (Security Advisories) on the repository once enabled, or contact the repository maintainer directly.
3. Include affected project/path, reproduction steps, impact assessment, and any suggested mitigation.

---

## Pre-Release Security Review Checklist

Before any project leaves `IN_DEVELOPMENT`:

- [ ] Threat model / trust boundaries documented.
- [ ] Secret scan passed with zero findings.
- [ ] Static analysis / SAST check passed.
- [ ] Dependency vulnerability scan reviewed with no unaddressed critical/high issues.
- [ ] Default configuration uses secure-by-default settings.

