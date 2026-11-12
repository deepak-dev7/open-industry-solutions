"""Secret redaction utilities so findings never leak raw credentials."""

from __future__ import annotations


def redact_secret(value: str) -> str:
    """Mask interior characters of a sensitive value while preserving short context."""
    cleaned = value.strip()
    if len(cleaned) <= 8:
        return "****"
    prefix_len = 4 if len(cleaned) >= 12 else 2
    suffix_len = 4 if len(cleaned) >= 16 else 2
    return f"{cleaned[:prefix_len]}****{cleaned[-suffix_len:]}"


def redact_line(line: str, secret_value: str) -> str:
    """Replace an identified secret substring inside a source line with its masked form."""
    trimmed = line.strip()
    if secret_value and secret_value in trimmed:
        trimmed = trimmed.replace(secret_value, redact_secret(secret_value))
    if len(trimmed) > 160:
        return trimmed[:157] + "..."
    return trimmed
