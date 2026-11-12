# Engineering Standards

All code, configuration, and documentation in Open Industry Solutions (OIS) must meet the standards below.

---

## 1. Code Quality & Maintainability

- **Clarity over Cleverness:** Write small, single-purpose functions with shallow nesting and explicit error handling.
- **Formatting & Editor Consistency:** Follow `.editorconfig` rules (UTF-8, LF line endings, trailing newline).
- **Typing & Linting:**
  - Python: type hints enforced (`mypy` / `pyright`), formatted and linted with `ruff`.
  - Go: `gofmt`, `go vet`, and `golangci-lint`.
  - TypeScript/Node.js: strict TypeScript (`"strict": true`), ESLint, Prettier.
- **No Dead or Placeholder Code:** Do not commit stub implementations, fake test assertions, or fabricated benchmark numbers.

---

## 2. Testing Standards

- **Unit Tests:** Cover core domain logic, boundary conditions, and error paths.
- **Integration Tests:** Verify real component interactions (CLI execution, database queries, HTTP endpoints) using deterministic local fixtures or containers.
- **Honest Verification:** Never relax assertions to make failing tests pass. Report exact test scope and outcomes in pull requests.

---

## 3. Documentation Standards

- Every project directory must contain an up-to-date `README.md` reflecting its true lifecycle status.
- Public APIs, CLI flags, environment variables, and configuration schemas must be documented alongside code changes.
- Non-obvious design trade-offs should be captured in an ADR.

---

## 4. Git & CI Discipline

- Keep `main` always clean, buildable, and verified by `.github/workflows/validate.yml`.
- Use atomic commits following Conventional Commits.
- Never force-push to `main`.

