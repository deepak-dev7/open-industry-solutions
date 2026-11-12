"""Secret and high-entropy credential detection rules."""

from __future__ import annotations

import math
import re
from collections import Counter

from codeguard.models import CodeGuardConfig, Finding, Rule, Severity
from codeguard.redaction import redact_line, redact_secret

SECRET_RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="CG-SEC-001",
        name="Hardcoded Provider Token or Key",
        severity=Severity.CRITICAL,
        category="secrets",
        cwe="CWE-798",
        description="Detects hardcoded cloud, VCS, or API provider tokens (GitHub, AWS, Slack, Stripe).",
        remediation="Revoke and rotate the credential immediately, then inject it via environment variables or a secret manager.",
    ),
    Rule(
        rule_id="CG-SEC-002",
        name="Private Key Material",
        severity=Severity.CRITICAL,
        category="secrets",
        cwe="CWE-321",
        description="Detects PEM-encoded private key blocks committed to source files.",
        remediation="Remove the private key from the repository, rotate the keypair, and store keys outside version control.",
    ),
    Rule(
        rule_id="CG-SEC-003",
        name="High-Entropy Credential Assignment",
        severity=Severity.HIGH,
        category="secrets",
        cwe="CWE-798",
        description="Detects hardcoded high-entropy strings assigned to sensitive variable names (secret, token, api_key, password).",
        remediation="Replace hardcoded literal values with runtime secret injection or environment configuration.",
    ),
)

_RULE_BY_ID = {r.rule_id: r for r in SECRET_RULES}

_PROVIDER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("GitHub personal access token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
    ("GitHub fine-grained PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("Stripe live secret key", re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b")),
)

_PRIVATE_KEY_RE = re.compile(r"-{5}BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-{5}")

_ASSIGNMENT_RE = re.compile(
    r"""(?i)\b([A-Za-z0-9_]*(?:password|passwd|secret|api_key|apikey|access_token|auth_token|private_key)[A-Za-z0-9_]*)\b"""
    r"""\s*[:=]\s*["']([^"'\r\n]{12,120})["']"""
)

_PLACEHOLDER_MARKERS = (
    "example",
    "placeholder",
    "changeme",
    "replace_me",
    "your_",
    "dummy",
    "sample",
    "test_only",
    "xxxx",
    "****",
    "<your",
    "${",
)


def shannon_entropy(value: str) -> float:
    """Compute Shannon entropy (bits per character) of a string."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _is_placeholder(value: str) -> bool:
    """Return True if a literal looks like an obvious template placeholder or env reference."""
    lowered = value.strip().lower()
    if any(marker in lowered for marker in _PLACEHOLDER_MARKERS):
        return True
    if lowered.startswith(("env:", "$", "vault:", "arn:aws:secretsmanager:")):
        return True
    return len(set(value)) <= 3


def scan_secrets(file_path: str, content: str, config: CodeGuardConfig) -> list[Finding]:
    """Scan file text for hardcoded provider tokens, private keys, and high-entropy assignments."""
    findings: list[Finding] = []
    lines = content.splitlines()

    for line_no, raw_line in enumerate(lines, start=1):
        matched_provider = False

        for label, pattern in _PROVIDER_PATTERNS:
            for match in pattern.finditer(raw_line):
                secret_val = match.group(0)
                rule = _RULE_BY_ID["CG-SEC-001"]
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        category=rule.category,
                        cwe=rule.cwe,
                        file_path=file_path,
                        line=line_no,
                        column=match.start() + 1,
                        message=f"Detected {label} ({redact_secret(secret_val)}).",
                        remediation=rule.remediation,
                        snippet=redact_line(raw_line, secret_val),
                    )
                )
                matched_provider = True

        key_match = _PRIVATE_KEY_RE.search(raw_line)
        if key_match:
            rule = _RULE_BY_ID["CG-SEC-002"]
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    category=rule.category,
                    cwe=rule.cwe,
                    file_path=file_path,
                    line=line_no,
                    column=key_match.start() + 1,
                    message="Detected PEM-encoded private key header in source file.",
                    remediation=rule.remediation,
                    snippet=redact_line(raw_line, key_match.group(0)),
                )
            )

        if matched_provider:
            continue

        for assign_match in _ASSIGNMENT_RE.finditer(raw_line):
            var_name, literal_val = assign_match.group(1), assign_match.group(2)
            if _is_placeholder(literal_val) or " " in literal_val.strip():
                continue
            entropy = shannon_entropy(literal_val)
            if entropy >= config.entropy_threshold:
                rule = _RULE_BY_ID["CG-SEC-003"]
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        category=rule.category,
                        cwe=rule.cwe,
                        file_path=file_path,
                        line=line_no,
                        column=assign_match.start(2) + 1,
                        message=(
                            f"High-entropy literal assigned to '{var_name}' "
                            f"(entropy={entropy:.2f}, value={redact_secret(literal_val)})."
                        ),
                        remediation=rule.remediation,
                        snippet=redact_line(raw_line, literal_val),
                    )
                )

    return findings
