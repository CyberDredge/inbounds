"""Table-driven tests for target normalization (build step 1)."""

from __future__ import annotations

import dataclasses
import ipaddress

import pytest

from inbounds.normalize import Target, UnclearTarget, normalize, normalize_hostname


def ip(text: str):
    return ipaddress.ip_address(text)


# (raw, host, ip, scheme, port, path)
VALID = [
    # Plain host names
    ("api.example.com", "api.example.com", None, None, None, None),
    ("API.EXAMPLE.COM.", "api.example.com", None, None, None, None),
    ("  api.example.com\r\n", "api.example.com", None, None, None, None),
    ("localhost", "localhost", None, None, None, None),
    ("app_1.example.com", "app_1.example.com", None, None, None, None),
    ("a-b.example.com", "a-b.example.com", None, None, None, None),
    ("bücher.example.com", "xn--bcher-kva.example.com", None, None, None, None),
    ("example.com:8443", "example.com", None, None, 8443, None),
    # IP addresses
    ("203.0.113.50", "203.0.113.50", ip("203.0.113.50"), None, None, None),
    ("2001:db8::1", "2001:db8::1", ip("2001:db8::1"), None, None, None),
    ("2001:0DB8:0:0:0:0:0:1", "2001:db8::1", ip("2001:db8::1"), None, None, None),
    ("[2001:db8::1]", "2001:db8::1", ip("2001:db8::1"), None, None, None),
    ("[2001:db8::1]:8443", "2001:db8::1", ip("2001:db8::1"), None, 8443, None),
    ("::ffff:203.0.113.7", "203.0.113.7", ip("203.0.113.7"), None, None, None),
    # URLs
    ("https://api.example.com", "api.example.com", None, "https", None, "/"),
    (
        "HTTPS://API.EXAMPLE.COM:8443/Path?x=1#frag",
        "api.example.com",
        None,
        "https",
        8443,
        "/Path",
    ),
    ("https://example.net/api/v1", "example.net", None, "https", None, "/api/v1"),
    ("http://example.net?x=1", "example.net", None, "http", None, "/"),
    ("https://203.0.113.5/x", "203.0.113.5", ip("203.0.113.5"), "https", None, "/x"),
    (
        "https://[2001:db8::1]:8443/a",
        "2001:db8::1",
        ip("2001:db8::1"),
        "https",
        8443,
        "/a",
    ),
    # Userinfo trick: the real host is whatever follows the last '@'
    ("https://api.example.com@evil.net/", "evil.net", None, "https", None, "/"),
    ("http://example.com:80@evil.net:8080/x", "evil.net", None, "http", 8080, "/x"),
    # Dot-segments are resolved so a path prefix rule cannot be walked out of
    ("https://example.net/api/../admin", "example.net", None, "https", None, "/admin"),
    ("https://example.net/api/./v1", "example.net", None, "https", None, "/api/v1"),
    ("https://example.net/a/b/.", "example.net", None, "https", None, "/a/b/"),
    ("https://example.net/a/..", "example.net", None, "https", None, "/"),
    ("https://example.net/../../x", "example.net", None, "https", None, "/x"),
    ("https://example.net/a//b", "example.net", None, "https", None, "/a//b"),
]


@pytest.mark.parametrize("raw,host,ip_value,scheme,port,path", VALID)
def test_valid_targets(raw, host, ip_value, scheme, port, path):
    target = normalize(raw)
    assert target.host == host
    assert target.ip == ip_value
    assert target.scheme == scheme
    assert target.port == port
    assert target.path == path
    assert target.raw == raw


UNCLEAR = [
    # Empty and unparseable
    "",
    "   ",
    "\n",
    "exa mple.com",
    "exa\tmple.com",
    "example.com\x00",
    "ex ample.com",
    "x" * 3000,
    # Invisible and bidirectional characters
    "exa​mple.com",
    "example‮.com",
    # Obfuscated or non-canonical IP forms
    "2130706433",
    "0x7f000001",
    "0177.0.0.1",
    "0x7f.0.0.1",
    "127.1",
    "1.2.3",
    "203.0.113.050",
    # Unsupported schemes
    "ftp://api.example.com",
    "ssh://example.com",
    "file:///etc/passwd",
    "javascript:alert(1)",
    "mailto:a@example.com",
    "://example.com",
    # Ranges are not valid targets in v1
    "203.0.113.0/24",
    "2001:db8::/32",
    # Text after the host without a scheme
    "example.com/path",
    "//example.com",
    "example.com?x=1",
    "example.com#x",
    "user@example.com",
    # Backslashes (read as slashes by browsers)
    "https://example.com\\@evil.net/",
    "https:\\\\example.com",
    # Encoded dots, slashes, backslashes, null bytes in the path
    "https://example.com/%2e%2e/admin",
    "https://example.com/%2E%2E/admin",
    "https://example.com/a%2Fb",
    "https://example.com/a%5cb",
    "https://example.com/%00",
    # Missing or malformed authority
    "https://",
    "https:///example.com",
    "https://:8080/",
    "https://example.com:/",
    "https://example.com:80a/",
    "https://example.com:8443:9/",
    "https://2001:db8::1/",
    "https://[example.com]/",
    # Ports
    "https://example.com:0/",
    "https://example.com:99999/",
    "https://example.com:123456/",
    "https://example.com:٨٠/",
    # Percent-encoded host
    "https://exa%6dple.com/",
    # Wildcards and malformed host names are not valid targets
    "*.example.com",
    "a..b.example.com",
    ".example.com",
    "-bad.example.com",
    "a" * 64 + ".example.com",
    "a." * 130 + "com",
    "2001:db8::zz",
    # IPv6 zone identifiers
    "fe80::1%eth0",
    "https://[fe80::1%25eth0]/",
]


@pytest.mark.parametrize("raw", UNCLEAR, ids=lambda s: repr(s)[:40])
def test_unclear_targets(raw):
    with pytest.raises(UnclearTarget) as info:
        normalize(raw)
    assert isinstance(info.value.reason, str) and info.value.reason


def test_non_text_input_is_unclear():
    with pytest.raises(UnclearTarget):
        normalize(None)  # type: ignore[arg-type]
    with pytest.raises(UnclearTarget):
        normalize(2130706433)  # type: ignore[arg-type]


def test_obfuscated_ip_reason_names_the_problem():
    with pytest.raises(UnclearTarget) as info:
        normalize("2130706433")
    assert "obfuscated" in info.value.reason


def test_backslash_reason_names_the_problem():
    with pytest.raises(UnclearTarget) as info:
        normalize("https://example.com\\@evil.net/")
    assert "backslash" in info.value.reason


def test_userinfo_is_ignored_and_never_echoed():
    target = normalize("https://admin:hunter2@example.com/")
    assert target.host == "example.com"
    assert len(target.warnings) == 1
    warning = target.warnings[0]
    assert "userinfo" in warning
    assert "hunter2" not in warning
    assert "admin" not in warning


def test_ipv4_mapped_ipv6_is_treated_as_ipv4_with_warning():
    target = normalize("::ffff:203.0.113.7")
    assert target.ip == ip("203.0.113.7")
    assert target.warnings and "IPv4-mapped" in target.warnings[0]


def test_plain_targets_have_no_warnings():
    assert normalize("api.example.com").warnings == ()
    assert normalize("https://example.net/api/").warnings == ()


def test_target_flags():
    assert normalize("203.0.113.5").is_ip and not normalize("203.0.113.5").is_url
    assert normalize("https://example.com").is_url and not normalize("https://example.com").is_ip
    assert not normalize("example.com").is_url


def test_target_is_immutable():
    target = normalize("example.com")
    with pytest.raises(dataclasses.FrozenInstanceError):
        target.host = "evil.net"  # type: ignore[misc]


def test_every_valid_host_is_lowercase_ascii():
    for raw, *_ in VALID:
        host = normalize(raw).host
        assert host == host.lower()
        assert host.isascii()


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Example.COM.", "example.com"),
        ("bücher.example", "xn--bcher-kva.example"),
        ("EXAMPLE.com", "example.com"),
    ],
)
def test_normalize_hostname(raw, expected):
    assert normalize_hostname(raw) == expected


@pytest.mark.parametrize("raw", ["", ".", "*.example.com", "a..b", "127.1", "example.com/x"])
def test_normalize_hostname_rejects_bad_input(raw):
    with pytest.raises(UnclearTarget):
        normalize_hostname(raw)


def test_returns_target_instances():
    assert isinstance(normalize("example.com"), Target)
