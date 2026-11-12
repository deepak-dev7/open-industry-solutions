"""CodeGuard: fast, local-first static security and quality guardrail."""

from codeguard.models import CodeGuardConfig, Finding, Rule, ScanResult, Severity

__version__ = "0.2.0"

__all__ = [
    "__version__",
    "CodeGuardConfig",
    "Finding",
    "Rule",
    "ScanResult",
    "Severity",
]
