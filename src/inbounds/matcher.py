"""Decide whether a target is in scope, and say which rule decided it.

Decision order (see SPEC.md, "Verdicts"):

1. A target that cannot be normalized safely is UNCLEAR.
2. If any deny rule matches, OUT_OF_SCOPE (deny beats allow).
3. If an allow rule matches, IN_SCOPE.
4. Otherwise OUT_OF_SCOPE ("no allow rule matched"). The matcher fails closed.

When several rules of the same kind match, the first one in the order given
is the one named in the verdict, so results are deterministic.
"""

from __future__ import annotations

import datetime
import enum
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass

from inbounds.normalize import Target, UnclearTarget, normalize
from inbounds.rules import Rule, RuleKind, parse_rule

WILDCARD_DEPTHS = ("any", "one")
DEFAULT_MAX_AGE_DAYS = 90
DEFAULT_PORTS = {"http": 80, "https": 443}


class Status(enum.StrEnum):
    IN_SCOPE = "IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    UNCLEAR = "UNCLEAR"

    @property
    def exit_code(self) -> int:
        """CLI exit code: 0 in scope, 1 out of scope, 2 unclear."""
        return {Status.IN_SCOPE: 0, Status.OUT_OF_SCOPE: 1, Status.UNCLEAR: 2}[self]


@dataclass(frozen=True)
class Verdict:
    """The answer for one target. ``rule`` is the rule text that decided it, or None."""

    status: Status
    target: str
    rule: str | None
    reason: str
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "target": self.target,
            "rule": self.rule,
            "reason": self.reason,
            "warnings": list(self.warnings),
        }


class Scope:
    """A set of allow and deny rules plus options.

    ``allow`` and ``deny`` are rule strings (or already parsed ``Rule``
    objects). A rule that cannot be parsed raises ``RuleError`` here, at
    construction, so a broken scope never produces verdicts.

    ``captured`` (a ``datetime.date``) is when the scope was copied from the
    program's policy. It drives the stale-scope warning: a scope older than
    ``max_age_days`` still gives verdicts, with a warning attached, and the
    status is never changed because of age. ``name`` and ``source`` are
    informational only (the source is never fetched).
    """

    def __init__(
        self,
        allow: Iterable[str | Rule] = (),
        deny: Iterable[str | Rule] = (),
        wildcard_depth: str = "any",
        *,
        name: str | None = None,
        captured: datetime.date | None = None,
        source: str | None = None,
        max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    ) -> None:
        if wildcard_depth not in WILDCARD_DEPTHS:
            raise ValueError(f"wildcard_depth must be one of {WILDCARD_DEPTHS}, got {wildcard_depth!r}")
        if isinstance(max_age_days, bool) or not isinstance(max_age_days, int) or max_age_days < 1:
            raise ValueError(f"max_age_days must be a whole number of days, 1 or more, got {max_age_days!r}")
        if captured is not None and type(captured) is not datetime.date:
            raise ValueError(f"captured must be a datetime.date, got {captured!r}")
        self.wildcard_depth = wildcard_depth
        self.allow: tuple[Rule, ...] = tuple(_as_rule(r) for r in allow)
        self.deny: tuple[Rule, ...] = tuple(_as_rule(r) for r in deny)
        self.name = name
        self.captured = captured
        self.source = source
        self.max_age_days = max_age_days

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> Scope:
        """Load a scope from a TOML file. Raises ``ScopeFileError`` if it is not usable."""
        from inbounds.scopefile import load_scope

        return load_scope(path)

    def stale_warnings(self, today: datetime.date | None = None) -> tuple[str, ...]:
        """Warnings about the age of the scope; empty when it is fresh.

        Warnings only. Nothing here changes a verdict's status.
        """
        if self.captured is None:
            return ()
        age = ((today or datetime.date.today()) - self.captured).days
        if age < 0:
            return (f"scope captured date {self.captured} is in the future; check it for a typo",)
        if age > self.max_age_days:
            return (
                f"scope was captured {age} days ago on {self.captured}, older than "
                f"max_age_days = {self.max_age_days}; check the program's published policy "
                "for changes",
            )
        return ()

    def check(self, raw: str, *, today: datetime.date | None = None) -> Verdict:
        """Return the verdict for one target string. Never raises on bad input.

        ``today`` is for tests; it defaults to the current date.
        """
        shown = _shown(raw)
        stale = self.stale_warnings(today)
        try:
            target = normalize(raw)
        except UnclearTarget as exc:
            return Verdict(Status.UNCLEAR, shown, None, exc.reason, stale)

        warnings = list(target.warnings)

        for rule in self.deny:
            if rule_matches(rule, target, self.wildcard_depth, deny=True):
                return Verdict(
                    Status.OUT_OF_SCOPE,
                    shown,
                    rule.text,
                    f"denied by rule {rule.text}",
                    (*warnings, *stale),
                )

        for rule in self.deny:
            note = _unapplied_deny_note(rule, target)
            if note:
                warnings.append(note)

        for rule in self.allow:
            if rule_matches(rule, target, self.wildcard_depth, deny=False):
                return Verdict(
                    Status.IN_SCOPE,
                    shown,
                    rule.text,
                    f"allowed by rule {rule.text}",
                    (*warnings, *stale),
                )

        return Verdict(
            Status.OUT_OF_SCOPE, shown, None, "no allow rule matched", (*warnings, *stale)
        )


def rule_matches(rule: Rule, target: Target, wildcard_depth: str = "any", *, deny: bool = False) -> bool:
    """True if ``rule`` covers ``target``.

    Deny wildcards always match at any depth, whatever ``wildcard_depth`` says:
    when in doubt a deny should win, not be skipped.
    """
    kind = rule.kind
    if kind is RuleKind.CIDR:
        assert rule.network is not None
        return (
            target.ip is not None
            and target.ip.version == rule.network.version
            and target.ip in rule.network
        )
    if kind is RuleKind.IP:
        return target.ip is not None and target.ip == rule.ip and _port_ok(rule, target)
    if kind is RuleKind.HOST:
        return target.ip is None and target.host == rule.host and _port_ok(rule, target)
    if kind is RuleKind.WILDCARD:
        depth = "any" if deny else wildcard_depth
        return target.ip is None and _wildcard_ok(rule, target, depth) and _port_ok(rule, target)
    if kind is RuleKind.URL_PREFIX:
        return (
            target.is_url
            and target.scheme == rule.scheme
            and target.host == rule.host
            and _port_ok(rule, target)
            and _path_ok(rule, target)
        )
    raise AssertionError(f"unhandled rule kind {kind!r}")  # pragma: no cover


def _wildcard_ok(rule: Rule, target: Target, depth: str) -> bool:
    assert rule.host is not None
    suffix = "." + rule.host
    if not target.host.endswith(suffix):
        return False
    # Normalized hosts have no empty labels, so a host ending in the suffix always
    # has a non-empty subdomain part in front of it (the apex never matches).
    prefix = target.host[: -len(suffix)]
    return depth == "any" or "." not in prefix


def _effective_port(target: Target) -> int | None:
    if target.port is not None:
        return target.port
    if target.scheme is not None:
        return DEFAULT_PORTS.get(target.scheme)
    return None


def _port_ok(rule: Rule, target: Target) -> bool:
    """A rule without a port matches any port. A rule with a port needs a known, equal port."""
    if rule.port is None:
        return True
    return _effective_port(target) == rule.port


def _path_ok(rule: Rule, target: Target) -> bool:
    """Match on a path-segment boundary, case-sensitively.

    A rule path ending in ``/`` covers everything beneath that directory but not
    the bare path without the slash. A rule path without a trailing ``/`` covers
    that exact path and everything beneath it.
    """
    assert rule.path is not None and target.path is not None
    if rule.path.endswith("/"):
        return target.path.startswith(rule.path)
    return target.path == rule.path or target.path.startswith(rule.path + "/")


def _unapplied_deny_note(rule: Rule, target: Target) -> str | None:
    """Explain a deny rule that names this host but could not be checked.

    A deny limited to a port or a path cannot be applied to a target that does
    not say which port or path it means. The status is unchanged; the warning
    makes sure that is not invisible.
    """
    if rule.kind in (RuleKind.HOST, RuleKind.IP) and rule.port is not None:
        same_host = target.host == rule.host
        if same_host and _effective_port(target) is None:
            return (
                f"deny rule {rule.text} is limited to port {rule.port}; "
                "the target does not name a port, so it was not applied"
            )
    elif rule.kind is RuleKind.WILDCARD and rule.port is not None:
        if (
            target.ip is None
            and _wildcard_ok(rule, target, "any")
            and _effective_port(target) is None
        ):
            return (
                f"deny rule {rule.text} is limited to port {rule.port}; "
                "the target does not name a port, so it was not applied"
            )
    elif rule.kind is RuleKind.URL_PREFIX:
        if not target.is_url and target.host == rule.host:
            return (
                f"deny rule {rule.text} is limited to a URL path; "
                "the target is a bare host, so it was not applied"
            )
    return None


def _as_rule(rule: str | Rule) -> Rule:
    return rule if isinstance(rule, Rule) else parse_rule(rule)


_USERINFO_RE = re.compile(r"^(\s*[A-Za-z][A-Za-z0-9+.\-]*://)[^/?#]*@")


def _shown(raw: object) -> str:
    """The target text as shown in a verdict.

    Userinfo (``user:password@``) is replaced with ``***`` so a password typed
    into a URL never ends up in output or logs. Non-text input is shown by type.
    """
    if not isinstance(raw, str):
        return f"<{type(raw).__name__}>"
    return _USERINFO_RE.sub(r"\1***@", raw)
