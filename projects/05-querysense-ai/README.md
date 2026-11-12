# 05 — QuerySense AI

- **Status:** `PLANNED`
- **Cohort:** November 2026
- **Domain:** Data Engineering, Databases & Applied AI

---

## Problem Statement

Developers routinely encounter degraded database performance due to sequential scans, suboptimal joins, and missing indexes, yet find raw execution plans (`EXPLAIN ANALYZE`) difficult to translate into safe schema or query fixes.

## Planned Scope

- Deterministic query execution plan parser (initially targeting PostgreSQL JSON plans).
- Grounded bottleneck detection (sequential scans, sort spills, row estimate drift).
- Optional pluggable LLM explanation adapter strictly constrained to observed plan telemetry.

## Current State

Specification only (`PLANNED`). No implementation code exists yet.

