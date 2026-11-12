"""Core data models for CodeGuard findings, rules, and configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Ordered severity levels for findings and fail-on thresholds."""

    LOW = 10
    MEDIUM = 20
    HIGH = 30
    CRITICAL = 40

    @classmethod
    def from_str(cls, value: str) -> Severity:
        """Parse a case-insensitive severity string."""
        normalized = value.strip().upper()
        try:
            return cls[normalized]
        except KeyError as exc:
            valid = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"Invalid severity '{value}'. Expected one of: {valid}") from exc

    @property
    def label(self) -> str:
        """Return lowercase severity name."""
        return self.name.lower()

    @property
    def sarif_level(self) -> str:
        """Map CodeGuard severity to SARIF v2.1.0 level."""
        if self >= Severity.HIGH:
            return "error"
        if self == Severity.MEDIUM:
            return "warning"
        return "note"


@dataclass(frozen=True)
class Rule:
    """Metadata describing a static analysis or secret rule."""

    rule_id: str
    name: str
    severity: Severity
    category: str
    cwe: str
    description: str
    remediation: str


@dataclass(frozen=True)
class Finding:
    """A single policy, security, or secret finding produced by a scan."""

    rule_id: str
    rule_name: str
    severity: Severity
    category: str
    cwe: str
    file_path: str
    line: int
    column: int
    message: str
    remediation: str
    snippet: str = ""

    def to_dict(self) -> dict[str, object]:
        """Serialize finding to a JSON-compatible dictionary."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.label,
            "category": self.category,
            "cwe": self.cwe,
            "file_path": self.file_path,
            "line": self.line,
            "column": self.column,
            "message": self.message,
            "remediation": self.remediation,
            "snippet": self.snippet,
        }


@dataclass
class CodeGuardConfig:
    """Configuration options loaded from .codeguard.toml or CLI defaults."""

    ignore_paths: tuple[str, ...] = (
        ".git",
        ".git/**",
        ".venv",
        ".venv/**",
        "venv/**",
        "node_modules",
        "node_modules/**",
        "__pycache__/**",
        "dist/**",
        "build/**",
        "*.min.js",
        "*.lock",
    )
    disabled_rules: tuple[str, ...] = ()
    allowlist_patterns: tuple[str, ...] = ()
    fail_on: Severity = Severity.HIGH
    max_file_size_kb: int = 1024
    entropy_threshold: float = 4.2


@dataclass
class ScanResult:
    """Aggregated result of a CodeGuard scan run."""

    root: str
    files_scanned: int
    files_skipped: int
    suppressed_count: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def should_fail(self, fail_on: Severity) -> bool:
        """Return True when any finding meets or exceeds the fail_on severity."""
        return any(f.severity >= fail_on for f in self.findings)
