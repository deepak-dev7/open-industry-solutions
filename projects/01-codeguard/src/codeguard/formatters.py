"""Output formatters for CodeGuard: human-readable text, JSON, and SARIF v2.1.0."""

from __future__ import annotations

import json

from codeguard import __version__
from codeguard.models import ScanResult, Severity
from codeguard.rules import ALL_RULES


def format_text(result: ScanResult, fail_on: Severity) -> str:
    """Format scan results as a clear terminal summary and findings report."""
    lines: list[str] = [
        f"CodeGuard Scan Report ({result.root})",
        f"Files scanned: {result.files_scanned} | Skipped: {result.files_skipped} | Suppressed: {result.suppressed_count}",
        f"Findings: {len(result.findings)} (fail-on threshold: {fail_on.label})",
    ]

    if not result.findings:
        lines.append("Result: PASS (no policy or security findings detected).")
    else:
        lines.append("")
        for idx, finding in enumerate(result.findings, start=1):
            lines.append(
                f"[{idx}] {finding.severity.name} {finding.rule_id} ({finding.cwe}) "
                f"{finding.file_path}:{finding.line}:{finding.column}"
            )
            lines.append(f"    Message:     {finding.message}")
            if finding.snippet:
                lines.append(f"    Snippet:     {finding.snippet}")
            lines.append(f"    Remediation: {finding.remediation}")

    if result.errors:
        lines.append("")
        lines.append("Notices:")
        for err in result.errors:
            lines.append(f"  - {err}")

    return "\n".join(lines) + "\n"


def format_json(result: ScanResult) -> str:
    """Format scan results as structured JSON."""
    payload = {
        "tool": "codeguard",
        "version": __version__,
        "root": result.root,
        "summary": {
            "files_scanned": result.files_scanned,
            "files_skipped": result.files_skipped,
            "suppressed_count": result.suppressed_count,
            "findings_count": len(result.findings),
        },
        "findings": [finding.to_dict() for finding in result.findings],
        "errors": result.errors,
    }
    return json.dumps(payload, indent=2) + "\n"


def format_sarif(result: ScanResult) -> str:
    """Format scan results as OASIS SARIF v2.1.0 for GitHub Code Scanning."""
    driver_rules = [
        {
            "id": rule.rule_id,
            "name": rule.name,
            "shortDescription": {"text": rule.name},
            "fullDescription": {"text": rule.description},
            "help": {"text": f"{rule.remediation} ({rule.cwe})"},
            "defaultConfiguration": {"level": rule.severity.sarif_level},
            "properties": {
                "category": rule.category,
                "cwe": rule.cwe,
                "severity": rule.severity.label,
            },
        }
        for rule in ALL_RULES
    ]

    sarif_results = [
        {
            "ruleId": finding.rule_id,
            "level": finding.severity.sarif_level,
            "message": {"text": finding.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file_path,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": finding.line,
                            "startColumn": finding.column,
                        },
                    }
                }
            ],
            "properties": {
                "cwe": finding.cwe,
                "category": finding.category,
                "severity": finding.severity.label,
            },
        }
        for finding in result.findings
    ]

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeGuard",
                        "version": __version__,
                        "informationUri": "https://github.com/deepak-dev7/open-industry-solutions/tree/main/projects/01-codeguard",
                        "rules": driver_rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(sarif_doc, indent=2) + "\n"
