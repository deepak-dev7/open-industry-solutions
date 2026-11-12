# 10 — AccessCheck

- **Status:** `PLANNED`
- **Cohort:** November 2026
- **Domain:** Cybersecurity & Identity (SecOps / IAM)

---

## Problem Statement

IAM policies, Kubernetes RBAC roles, and service accounts accumulate wildcard permissions and stale access grants over time, creating privilege escalation paths and audit failures.

## Planned Scope

- Read-only policy parser and permission graph analyser for common IAM/RBAC formats.
- Least-privilege and separation-of-duties rule checks mapped to CIS/NIST guidance.
- Clear remediation diffs highlighting excessive permissions.

## Current State

Specification only (`PLANNED`). No implementation code exists yet.

