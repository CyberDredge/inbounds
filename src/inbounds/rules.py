"""Parse scope rule text into typed rules.

A bad rule is an error, never a guess: a rule that silently means something
other than what its author wrote is how out-of-scope testing starts. Anything
this module cannot read unambiguously raises ``RuleError``.

Supported rule forms (see SPEC.md, "Rule types"):

* exact host        ``app.example.org``
* wildcard host     ``*.example.com`` (subdomains only, never the apex)
* URL prefix        ``https://example.net/api/``
* IP address        ``203.0.113.5`` or ``2001:db8::1``
* CIDR range        ``203.0.113.0/24`` or ``2001:db8::/32``

Host, wildcard and IP rules may carry an optional ``:port`` suffix. A rule
without a port matches any port.
"""

from __future__ import annotations

import enum
import ipaddress
import re
from dataclasses import dataclass

from inbounds.normalize import IPAddress, UnclearTarget, normalize

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

_CIDR_RE = re.compile(r"[0-9A-Fa-f:.]+/[0-9]{1,3}")


class RuleKind(enum.StrEnum):
    HOST = "host"
    WILDCARD = "wildcard"
    URL_PREFIX = "url_prefix"
    IP = "ip"
    CIDR = "cidr"


class RuleError(ValueError):
    """A scope rule cannot be interpreted safely. ``reason`` says why."""

    def __init__(self, rule: object, reason: str) -> None:
        super().__init__(f"invalid rule {rule!r}: {reason}")
        self.rule = rule
        self.reason = reason


@dataclass(frozen=True)
class Rule:
    """One parsed scope rule.

    ``text`` is the rule as written (outer whitespace stripped), used when a
    verdict names the rule that decided it. For host and wildcard rules
    ``host`` is the normalized host (for wildcards, the part after ``*.``).
    For URL rules ``scheme``, ``host``, ``port`` and ``path`` are set.
    """

    text: str
    kind: RuleKind
    host: str | None = None
    ip: IPAddress | None = None
    network: IPNetwork | None = None
    scheme: str | None = None
    port: int | None = None
    path: str | None = None


def parse_rule(text: str) -> Rule:
    """Parse one rule string, or raise ``RuleError``."""
    if not isinstance(text, str):
        raise RuleError(text, "rule must be text")
    rule_text = text.strip()
    if not rule_text:
        raise RuleError(text, "empty rule")

    if "*" in rule_text:
        return _parse_wildcard(rule_text)
    if "://" in rule_text:
        return _parse_url(rule_text)
    if "/" in rule_text:
        return _parse_cidr(rule_text)
    return _parse_host_or_ip(rule_text)


def _parse_wildcard(text: str) -> Rule:
    if not text.startswith("*.") or "*" in text[1:]:
        raise RuleError(text, "a wildcard is only supported as a leading '*.' on a host name")
    rest = text[2:]
    if "/" in rest or "://" in rest:
        raise RuleError(text, "wildcard rules cannot carry a scheme or path")
    target = _normalize_rule_part(text, rest)
    if target.is_ip:
        raise RuleError(text, "a wildcard cannot be applied to an IP address")
    return Rule(text=text, kind=RuleKind.WILDCARD, host=target.host, port=target.port)


def _parse_url(text: str) -> Rule:
    if "?" in text or "#" in text:
        raise RuleError(text, "a query string or fragment in a rule would be silently dropped")
    target = _normalize_rule_part(text, text)
    if not target.is_url:
        raise RuleError(text, "not a URL rule")
    return Rule(
        text=text,
        kind=RuleKind.URL_PREFIX,
        host=target.host,
        scheme=target.scheme,
        port=target.port,
        path=target.path,
    )


def _parse_cidr(text: str) -> Rule:
    if not _CIDR_RE.fullmatch(text):
        raise RuleError(text, "expected a CIDR range like 203.0.113.0/24 or a full URL with a scheme")
    try:
        network = ipaddress.ip_network(text, strict=True)
    except ValueError as exc:
        raise RuleError(text, f"not a valid CIDR range ({exc})") from None
    return Rule(text=text, kind=RuleKind.CIDR, network=network)


def _parse_host_or_ip(text: str) -> Rule:
    target = _normalize_rule_part(text, text)
    if target.is_ip:
        return Rule(text=text, kind=RuleKind.IP, ip=target.ip, host=target.host, port=target.port)
    return Rule(text=text, kind=RuleKind.HOST, host=target.host, port=target.port)


def _normalize_rule_part(rule_text: str, to_normalize: str):
    try:
        target = normalize(to_normalize)
    except UnclearTarget as exc:
        raise RuleError(rule_text, exc.reason) from None
    if target.warnings:
        # Userinfo or IPv4-mapped IPv6 in a rule: make the author write it plainly.
        raise RuleError(rule_text, "; ".join(target.warnings))
    return target
