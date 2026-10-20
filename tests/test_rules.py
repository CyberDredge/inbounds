"""Tests for rule parsing (build step 2)."""

from __future__ import annotations

import dataclasses
import ipaddress

import pytest

from inbounds.rules import Rule, RuleError, RuleKind, parse_rule

# (text, kind, host, port, scheme, path)
VALID = [
    ("app.example.org", RuleKind.HOST, "app.example.org", None, None, None),
    ("  APP.Example.ORG.  ", RuleKind.HOST, "app.example.org", None, None, None),
    ("app.example.org:8443", RuleKind.HOST, "app.example.org", 8443, None, None),
    ("localhost", RuleKind.HOST, "localhost", None, None, None),
    ("bücher.example.com", RuleKind.HOST, "xn--bcher-kva.example.com", None, None, None),
    ("*.example.com", RuleKind.WILDCARD, "example.com", None, None, None),
    ("*.Example.COM", RuleKind.WILDCARD, "example.com", None, None, None),
    ("*.example.com:8443", RuleKind.WILDCARD, "example.com", 8443, None, None),
    ("*.bücher.example", RuleKind.WILDCARD, "xn--bcher-kva.example", None, None, None),
    ("https://example.net/api/", RuleKind.URL_PREFIX, "example.net", None, "https", "/api/"),
    ("HTTPS://Example.NET/api", RuleKind.URL_PREFIX, "example.net", None, "https", "/api"),
    ("https://example.net", RuleKind.URL_PREFIX, "example.net", None, "https", "/"),
    ("http://example.net:8080/x/", RuleKind.URL_PREFIX, "example.net", 8080, "http", "/x/"),
    ("https://203.0.113.5/x/", RuleKind.URL_PREFIX, "203.0.113.5", None, "https", "/x/"),
    ("https://example.net/a/../b/", RuleKind.URL_PREFIX, "example.net", None, "https", "/b/"),
    ("203.0.113.5", RuleKind.IP, "203.0.113.5", None, None, None),
    ("203.0.113.5:8443", RuleKind.IP, "203.0.113.5", 8443, None, None),
    ("2001:db8::1", RuleKind.IP, "2001:db8::1", None, None, None),
    ("[2001:db8::1]:8443", RuleKind.IP, "2001:db8::1", 8443, None, None),
    ("203.0.113.0/24", RuleKind.CIDR, None, None, None, None),
    ("2001:db8::/32", RuleKind.CIDR, None, None, None, None),
    ("0.0.0.0/0", RuleKind.CIDR, None, None, None, None),
]


@pytest.mark.parametrize("text,kind,host,port,scheme,path", VALID)
def test_valid_rules(text, kind, host, port, scheme, path):
    rule = parse_rule(text)
    assert rule.kind is kind
    assert rule.host == host
    assert rule.port == port
    assert rule.scheme == scheme
    assert rule.path == path
    assert rule.text == text.strip()


def test_ip_and_cidr_rules_carry_address_objects():
    assert parse_rule("203.0.113.5").ip == ipaddress.ip_address("203.0.113.5")
    assert parse_rule("203.0.113.0/24").network == ipaddress.ip_network("203.0.113.0/24")
    assert parse_rule("2001:db8::/32").network == ipaddress.ip_network("2001:db8::/32")


INVALID = [
    # Empty
    "",
    "   ",
    # Wildcards only as a leading '*.'
    "*",
    "*.",
    "*example.com",
    "a.*.example.com",
    "*.*.example.com",
    "example.*",
    "https://*.example.com/",
    "*.example.com/path",
    "*.203.0.113.5",
    "https://example.net/api/*",
    # Things that would be silently dropped or reinterpreted
    "https://example.net/api/?x=1",
    "https://example.net/api/#top",
    "https://user:pw@example.net/api/",
    "::ffff:203.0.113.7",
    # Path without a scheme
    "example.com/path",
    "//example.com/path",
    # Bad CIDR forms
    "203.0.113.5/24",
    "203.0.113.0/33",
    "203.0.113.0/",
    "203.0.113.0/255.255.255.0",
    "2001:db8::/129",
    "203.0.113.0/24:80",
    "fe80::/10%eth0",
    # Unsupported schemes and malformed hosts
    "ftp://example.com/",
    "exa mple.com",
    "-bad.example.com",
    "127.1",
    "2130706433",
    "example.com:0",
    "example.com:99999",
]


@pytest.mark.parametrize("text", INVALID, ids=lambda s: repr(s)[:40])
def test_invalid_rules_raise(text):
    with pytest.raises(RuleError) as info:
        parse_rule(text)
    assert info.value.reason
    assert isinstance(info.value, ValueError)


def test_non_text_rule_raises():
    with pytest.raises(RuleError):
        parse_rule(None)  # type: ignore[arg-type]
    with pytest.raises(RuleError):
        parse_rule(42)  # type: ignore[arg-type]


def test_rule_is_immutable():
    rule = parse_rule("example.com")
    with pytest.raises(dataclasses.FrozenInstanceError):
        rule.host = "evil.net"  # type: ignore[misc]
    assert isinstance(rule, Rule)


def test_rule_error_message_names_the_rule():
    with pytest.raises(RuleError) as info:
        parse_rule("*example.com")
    assert "*example.com" in str(info.value)
    assert "leading" in info.value.reason


@pytest.mark.parametrize(
    "text",
    ["faß.example.com", "*.faß.example.com", "https://faß.example.com/x", "faß.example.com:8443", "fa\u03c2.example.com"],
    ids=lambda s: ascii(s)[:40],
)
def test_rules_with_idna_deviation_characters_are_rejected(text):
    with pytest.raises(RuleError) as info:
        parse_rule(text)
    assert "xn--" in info.value.reason


def test_the_explicit_xn_form_is_a_valid_rule():
    assert parse_rule("xn--fa-hia.example.com").host == "xn--fa-hia.example.com"
