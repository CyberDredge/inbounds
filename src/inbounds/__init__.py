"""inbounds: check a target against a bug bounty program's scope."""

from inbounds.matcher import Scope, Status, Verdict, rule_matches
from inbounds.normalize import Target, UnclearTarget, normalize, normalize_hostname
from inbounds.rules import Rule, RuleError, RuleKind, parse_rule

__version__ = "0.1.0.dev0"

__all__ = [
    "Rule",
    "RuleError",
    "RuleKind",
    "Scope",
    "Status",
    "Target",
    "UnclearTarget",
    "Verdict",
    "normalize",
    "normalize_hostname",
    "parse_rule",
    "rule_matches",
    "__version__",
]
