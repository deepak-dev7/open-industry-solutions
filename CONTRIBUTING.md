# Contributing to Open Industry Solutions (OIS)

Thank you for your interest in contributing to Open Industry Solutions. Every solution in this repository is built to address genuine IT industry problems with production-ready, open-source engineering.

---

## Ways to Contribute

1. **Propose an Industry Problem:** Submit a problem statement using the Industry Problem Proposal issue template.
2. **Refine Architecture & Research:** Improve problem definitions, threat models, or technology decision records in `research/` and `docs/`.
3. **Implement or Review Solutions:** Contribute code, tests, CI workflows, or documentation within a project directory under `projects/`.
4. **Report Bugs or Security Issues:** File bug reports via GitHub Issues, or follow the confidential security reporting instructions in [Security Standards](docs/security/security-standards.md).

---

## Development Workflow

1. **Fork and Branch**
   - Create a branch from `main` using a descriptive prefix:
     - `feat/<project-slug>-<short-description>`
     - `fix/<project-slug>-<short-description>`
     - `docs/<short-description>`
     - `chore/<short-description>`
2. **Follow Engineering & Security Standards**
   - Adhere to [Engineering Standards](docs/development/engineering-standards.md).
   - Adhere to [Security Standards](docs/security/security-standards.md).
   - Never commit secrets, credentials, API keys, `.env` files, or private certificates.
3. **Write Tests & Documentation**
   - Code changes must include automated tests covering happy paths and edge cases.
   - Update the relevant project `README.md` and `progress/monthly-tracker.md` when advancing lifecycle status.
4. **Verify Locally**
   - Run linters, type checks, and test suites before opening a pull request.
   - Do not fabricate test results, benchmarks, or metrics.
5. **Open a Pull Request**
   - Fill out the [Pull Request Template](.github/pull_request_template.md) completely.
   - Ensure all GitHub Actions checks in `.github/workflows/validate.yml` pass.

---

## Commit Message Convention

Use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat(01-codeguard): add SARIF output formatter`
- `fix(03-uptimepulse): handle TLS timeout edge case`
- `docs(research): document November 2026 problem statements`
- `chore(ci): update repository validation workflow`

---

## Code of Conduct

All participants are expected to uphold the [Code of Conduct](CODE_OF_CONDUCT.md).

