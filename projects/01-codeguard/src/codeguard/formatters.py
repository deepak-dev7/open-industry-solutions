"""Output formatters for CodeGuard: human-readable text, JSON, SARIF v2.1.0, and HTML."""

from __future__ import annotations

import html
import json
from typing import Any

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


def format_html_report(scan_record: dict[str, Any]) -> str:
    """Render a standalone, HTML-escaped report for a persisted CodeGuard scan."""
    target = html.escape(str(scan_record["target_label"]))
    created_at = html.escape(str(scan_record["created_at"]))
    status_text = "FAIL" if scan_record["failed"] else "PASS"
    rows: list[str] = []
    for f in scan_record.get("findings", []):
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(f['severity']).upper())}</td>"
            f"<td><code>{html.escape(str(f['rule_id']))}</code></td>"
            f"<td>{html.escape(str(f['cwe']))}</td>"
            f"<td><code>{html.escape(str(f['file_path']))}:{int(f['line'])}:{int(f['column'])}</code></td>"
            f"<td>{html.escape(str(f['message']))}<br><small>{html.escape(str(f['remediation']))}</small></td>"
            f"<td>{html.escape(str(f['status']))}</td>"
            "</tr>"
        )
    table_body = "\n".join(rows) if rows else '<tr><td colspan="6">No findings detected.</td></tr>'
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>CodeGuard Report — {target}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 32px; color: #0f172a; }}
    h1 {{ margin-bottom: 4px; }}
    .meta {{ color: #475569; margin-bottom: 20px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
    th, td {{ border: 1px solid #cbd5e1; padding: 10px; text-align: left; vertical-align: top; }}
    th {{ background: #f1f5f9; }}
    code {{ background: #f1f5f9; padding: 2px 5px; border-radius: 4px; }}
  </style>
</head>
<body>
  <h1>CodeGuard Security &amp; Quality Report</h1>
  <p class="meta">Target: <code>{target}</code> | Scanned: {created_at} | Status: <strong>{status_text}</strong> | Files: {int(scan_record['files_scanned'])} | Findings: {int(scan_record['findings_count'])}</p>
  <table>
    <thead>
      <tr><th>Severity</th><th>Rule</th><th>CWE</th><th>Location</th><th>Details &amp; Remediation</th><th>Status</th></tr>
    </thead>
    <tbody>
      {table_body}
    </tbody>
  </table>
</body>
</html>
"""
