# Project Lifecycle & Release Criteria

Every OIS project follows a strict five-stage lifecycle. Transitions are recorded in the project's `README.md` and in [progress/monthly-tracker.md](../../progress/monthly-tracker.md).

---

## Lifecycle States

1. **`PLANNED`**
   - Problem statement, domain classification, and target outcomes are documented.
   - No implementation code exists yet.
2. **`DESIGNED`**
   - Architecture Decision Records (ADRs), data/API contracts, threat model, and test strategy are documented and reviewed.
3. **`IN_DEVELOPMENT`**
   - Core implementation, unit tests, and integration tests are actively built under `projects/<NN>-<slug>/`.
4. **`VERIFIED`**
   - All automated checks pass (lint, type checks, unit/integration tests, dependency & secret scans) and documentation matches actual behaviour.
5. **`RELEASED`**
   - All release criteria below are satisfied, tagged, and recorded in `progress/changelog.md`.

---

## Release Gate Checklist

A project may transition to **`RELEASED`** only when every item below is verified:

- [ ] **Functional Completeness:** Core problem statement requirements are implemented and reproducible.
- [ ] **Automated Test Suite:** Unit and integration tests run cleanly in CI with no skipped critical assertions or fabricated fixtures.
- [ ] **Security & Secret Hygiene:** No hardcoded secrets, passing static/dependency vulnerability checks, and documented threat boundaries.
- [ ] **Documentation Accuracy:** Project `README.md` includes verified setup instructions, configuration reference, CLI/API examples, and known limitations.
- [ ] **Observability & Error Handling:** Clear exit codes, structured error messages, and non-silent failure modes.
- [ ] **Licencing Compliance:** All third-party dependencies use OSI-approved licences compatible with the MIT License.

