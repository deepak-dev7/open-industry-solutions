"""Rule registry aggregating all built-in CodeGuard rules."""

from __future__ import annotations

from codeguard.models import Rule
from codeguard.rules.general import GENERAL_RULES
from codeguard.rules.python_ast import PYTHON_AST_RULES
from codeguard.rules.secrets import SECRET_RULES

ALL_RULES: tuple[Rule, ...] = SECRET_RULES + PYTHON_AST_RULES + GENERAL_RULES
RULE_INDEX: dict[str, Rule] = {rule.rule_id: rule for rule in ALL_RULES}

__all__ = [
    "ALL_RULES",
    "RULE_INDEX",
    "GENERAL_RULES",
    "PYTHON_AST_RULES",
    "SECRET_RULES",
]
