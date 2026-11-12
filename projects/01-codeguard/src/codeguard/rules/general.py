"""Cross-language static rules for GitHub Actions YAML, JS/TS, and Shell scripts."""

from __future__ import annotations

import re
from pathlib import Path

from codeguard.models import Finding, Rule, Severity

GENERAL_RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="CG-CFG-001",
        name="GitHub Actions Overly Permissive or Missing Permissions",
        severity=Severity.MEDIUM,
        category="ci-security",
        cwe="CWE-269",
        description="Flags GitHub Actions workflows granting write-all permissions or omitting explicit permissions.",
        remediation="Declare a minimal top-level 'permissions:' block (for example 'contents: read').",
    ),
    Rule(
        rule_id="CG-JS-001",
        name="Unsafe JavaScript/TypeScript Execution or DOM Sink",
        severity=Severity.HIGH,
        category="js-security",
        cwe="CWE-79",
        description="Flags eval(), new Function(), innerHTML assignment, and dangerouslySetInnerHTML.",
        remediation="Avoid dynamic code evaluation and sanitise or bind text content safely.",
    ),
    Rule(
        rule_id="CG-SH-001",
        name="Unsafe Remote Pipe-to-Shell Execution",
        severity=Severity.HIGH,
        category="shell-security",
        cwe="CWE-829",
        description="Flags piping curl/wget output directly into sh or bash.",
        remediation="Download artifacts, verify checksums or signatures, and execute explicitly.",
    ),
)

_RULE_BY_ID = {r.rule_id: r for r in GENERAL_RULES}

_JS_EXTENSIONS = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"})
_SHELL_EXTENSIONS = frozenset({".sh", ".bash", ".zsh"})
_YAML_EXTENSIONS = frozenset({".yml", ".yaml"})

_JS_UNSAFE_RE = re.compile(
    r"\b(?:eval\s*\(|new\s+Function\s*\()|\.innerHTML\s*=|\bdangerouslySetInnerHTML\b"
)
_SHELL_PIPE_RE = re.compile(r"\b(?:curl|wget)\b[^|\r\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b")
_GHA_PERMISSIONS_RE = re.compile(r"^permissions\s*:", re.MULTILINE)
_GHA_WRITE_ALL_RE = re.compile(r"^\s*permissions\s*:\s*write-all\b", re.MULTILINE)


def _make_finding(
    rule_id: str,
    file_path: str,
    line: int,
    column: int,
    message: str,
    snippet: str,
) -> Finding:
    rule = _RULE_BY_ID[rule_id]
    trimmed = snippet.strip()
    if len(trimmed) > 160:
        trimmed = trimmed[:157] + "..."
    return Finding(
        rule_id=rule.rule_id,
        rule_name=rule.name,
        severity=rule.severity,
        category=rule.category,
        cwe=rule.cwe,
        file_path=file_path,
        line=line,
        column=column,
        message=message,
        remediation=rule.remediation,
        snippet=trimmed,
    )


def _is_github_workflow(file_path: str) -> bool:
    normalized = file_path.replace("\\", "/")
    return "/.github/workflows/" in f"/{normalized}" and Path(file_path).suffix.lower() in _YAML_EXTENSIONS


def scan_general_rules(file_path: str, content: str) -> list[Finding]:
    """Run targeted static checks for GitHub Actions YAML, JS/TS, and Shell files."""
    findings: list[Finding] = []
    suffix = Path(file_path).suffix.lower()
    lines = content.splitlines()

    if _is_github_workflow(file_path):
        write_all = _GHA_WRITE_ALL_RE.search(content)
        if write_all:
            line_no = content[: write_all.start()].count("\n") + 1
            findings.append(
                _make_finding(
                    "CG-CFG-001",
                    file_path,
                    line_no,
                    1,
                    "GitHub Actions workflow grants 'permissions: write-all'.",
                    lines[line_no - 1] if line_no <= len(lines) else "",
                )
            )
        elif not _GHA_PERMISSIONS_RE.search(content):
            findings.append(
                _make_finding(
                    "CG-CFG-001",
                    file_path,
                    1,
                    1,
                    "GitHub Actions workflow omits an explicit least-privilege 'permissions:' block.",
                    lines[0] if lines else "",
                )
            )

    if suffix in _JS_EXTENSIONS:
        for line_no, raw_line in enumerate(lines, start=1):
            stripped = raw_line.lstrip()
            if stripped.startswith(("//", "/*", "*")):
                continue
            match = _JS_UNSAFE_RE.search(raw_line)
            if match:
                findings.append(
                    _make_finding(
                        "CG-JS-001",
                        file_path,
                        line_no,
                        match.start() + 1,
                        f"Unsafe JavaScript/TypeScript pattern '{match.group(0).strip()}'.",
                        raw_line,
                    )
                )

    if suffix in _SHELL_EXTENSIONS or (lines and lines[0].startswith("#!") and "sh" in lines[0]):
        for line_no, raw_line in enumerate(lines, start=1):
            if raw_line.lstrip().startswith("#"):
                continue
            match = _SHELL_PIPE_RE.search(raw_line)
            if match:
                findings.append(
                    _make_finding(
                        "CG-SH-001",
                        file_path,
                        line_no,
                        match.start() + 1,
                        "Remote script piped directly into shell without integrity verification.",
                        raw_line,
                    )
                )

    return findings
