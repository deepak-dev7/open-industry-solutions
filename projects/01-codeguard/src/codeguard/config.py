"""Configuration loader and starter config generator for CodeGuard."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from codeguard.models import CodeGuardConfig, Severity

DEFAULT_CONFIG_FILENAME = ".codeguard.toml"

STARTER_CONFIG_TOML = """# CodeGuard configuration
[codeguard]
fail_on = "high"
max_file_size_kb = 1024
entropy_threshold = 4.2

ignore_paths = [
  ".git/**",
  ".venv/**",
  "node_modules/**",
  "dist/**",
  "build/**",
  "*.lock",
]

disabled_rules = []

allowlist_patterns = [
  "EXAMPLE_KEY",
  "changeme",
]
"""


def _validate_str_list(raw: object, field_name: str) -> tuple[str, ...]:
    """Validate that a TOML config entry is a list of non-empty strings."""
    if raw is None:
        return ()
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise ValueError(f"Config '{field_name}' must be a list of strings.")
    return tuple(item for item in raw if item)


def load_config(config_path: Path | None, root: Path) -> CodeGuardConfig:
    """Load .codeguard.toml from explicit path or root directory if present."""
    candidate = config_path if config_path is not None else root / DEFAULT_CONFIG_FILENAME
    if config_path is not None and not candidate.is_file():
        raise FileNotFoundError(f"Configuration file not found: {candidate}")
    if not candidate.is_file():
        return CodeGuardConfig()

    with candidate.open("rb") as fh:
        parsed = tomllib.load(fh)

    section = parsed.get("codeguard", parsed)
    if not isinstance(section, dict):
        raise ValueError("Invalid configuration: expected [codeguard] table.")

    defaults = CodeGuardConfig()
    ignore_paths = (
        _validate_str_list(section["ignore_paths"], "ignore_paths")
        if "ignore_paths" in section
        else defaults.ignore_paths
    )
    disabled_rules = _validate_str_list(section.get("disabled_rules"), "disabled_rules")
    allowlist_patterns = _validate_str_list(section.get("allowlist_patterns"), "allowlist_patterns")
    for pattern in allowlist_patterns:
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"Invalid allowlist regex '{pattern}': {exc}") from exc

    fail_on = (
        Severity.from_str(str(section["fail_on"]))
        if "fail_on" in section
        else defaults.fail_on
    )

    max_size = section.get("max_file_size_kb", defaults.max_file_size_kb)
    if not isinstance(max_size, int) or isinstance(max_size, bool) or max_size <= 0:
        raise ValueError("Config 'max_file_size_kb' must be a positive integer.")

    entropy = section.get("entropy_threshold", defaults.entropy_threshold)
    if not isinstance(entropy, (int, float)) or isinstance(entropy, bool) or entropy <= 0:
        raise ValueError("Config 'entropy_threshold' must be a positive number.")

    return CodeGuardConfig(
        ignore_paths=ignore_paths,
        disabled_rules=disabled_rules,
        allowlist_patterns=allowlist_patterns,
        fail_on=fail_on,
        max_file_size_kb=max_size,
        entropy_threshold=float(entropy),
    )
