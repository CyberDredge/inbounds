"""Table-driven matcher tests (build step 2).

The first table is the required test table from SPEC.md, row for row. The
sample scope below is the one in the spec.
"""

from __future__ import annotations

import dataclasses

import pytest

from inbounds.matcher import Scope, Status, Verdict
from inbounds.rules import RuleError

IN, OUT, UNCLEAR = Status.IN_SCOPE, Status.OUT_OF_SCOPE, Status.UNCLEAR

ALLOW = ["*.example.com", "app.example.org", "https://example.net/api/", "203.0.113.0/24"]
DENY = ["admin.example.com", "*.staging.example.com", "203.0.113.7"]


@pytest.fixture(scope="module")
def scope() -> Scope:
    return Scope(allow=ALLOW, deny=DENY, wildcard_depth="any")


@pytest.fixture(scope="module")
def scope_one() -> Scope:
    return Scope(allow=ALLOW, deny=DENY, wildcard_depth="one")


# (target, status, deciding rule or None) -- one row per row of the SPEC.md table
SPEC_TABLE = [
    ("api.example.com", IN, "*.example.com"),
    ("a.b.example.com", IN, "*.example.com"),
    ("example.com", OUT, None),
    ("notexample.com", OUT, None),
    ("example.com.evil.net", OUT, None),
    ("API.EXAMPLE.COM.", IN, "*.example.com"),
    ("admin.example.com", OUT, "admin.example.com"),
    ("x.staging.example.com", OUT, "*.staging.example.com"),
    ("https://api.example.com@evil.net/", OUT, None),
    ("https://example.net/api/v1", IN, "https://example.net/api/"),
    ("https://example.net/apix", OUT, None),
    ("https://example.net/", OUT, None),
    ("203.0.113.50", IN, "203.0.113.0/24"),
    ("203.0.113.7", OUT, "203.0.113.7"),
    ("203.0.114.1", OUT, None),
    ("2001:db8::1", OUT, None),
    ("bücher.example.com", IN, "*.example.com"),
    ("2130706433", UNCLEAR, None),
    ("0x7f000001", UNCLEAR, None),
    ("ftp://api.example.com", UNCLEAR, None),
    ("exa mple.com", UNCLEAR, None),
    ("", UNCLEAR, None),
    ("203.0.113.0/24", UNCLEAR, None),
]


@pytest.mark.parametrize("target,status,rule", SPEC_TABLE, ids=lambda v: repr(v)[:40])
def test_spec_table(scope, target, status, rule):
    verdict = scope.check(target)
    assert verdict.status is status
    assert verdict.rule == rule
    assert verdict.reason


def test_spec_table_has_every_row():
    # 22 rows in SPEC.md; the "exa mple.com / empty string" row is two targets here.
    assert len(SPEC_TABLE) == 23


def test_userinfo_trick_names_the_real_host(scope):
    verdict = scope.check("https://api.example.com@evil.net/")
    assert verdict.status is OUT
    assert any("evil.net" in w for w in verdict.warnings)
    assert not any("api.example.com" in w for w in verdict.warnings)


def test_wildcard_depth_one(scope_one):
    assert scope_one.check("a.example.com").status is IN
    assert scope_one.check("a.b.example.com").status is OUT
    assert scope_one.check("a.b.example.com").reason == "no allow rule matched"
    assert scope_one.check("example.com").status is OUT


def test_invalid_wildcard_depth_is_rejected():
    with pytest.raises(ValueError):
        Scope(allow=["*.example.com"], wildcard_depth="two")


# ---- precedence and fail-closed behaviour -------------------------------------


def test_deny_beats_allow_whatever_the_order():
    a = Scope(allow=["*.example.com"], deny=["admin.example.com"])
    b = Scope(allow=["admin.example.com"], deny=["admin.example.com"])
    assert a.check("admin.example.com").status is OUT
    assert b.check("admin.example.com").status is OUT


def test_empty_scope_is_everything_out_of_scope():
    verdict = Scope().check("api.example.com")
    assert verdict.status is OUT and verdict.rule is None
    assert verdict.reason == "no allow rule matched"


def test_unclear_still_wins_with_an_empty_scope():
    assert Scope().check("exa mple.com").status is UNCLEAR


def test_first_matching_rule_is_named():
    scope = Scope(allow=["*.example.com", "api.example.com"])
    assert scope.check("api.example.com").rule == "*.example.com"
    scope = Scope(allow=["api.example.com", "*.example.com"])
    assert scope.check("api.example.com").rule == "api.example.com"


def test_deny_wildcard_does_not_cover_its_apex(scope):
    # *.staging.example.com denies subdomains only; the apex is allowed by *.example.com.
    verdict = scope.check("staging.example.com")
    assert verdict.status is IN and verdict.rule == "*.example.com"


def test_deny_wildcard_always_matches_any_depth(scope_one):
    # Allow rules honour wildcard_depth = one, but deny wildcards never get narrower.
    scope = Scope(
        allow=["a.b.staging.example.com", "*.example.com"],
        deny=["*.staging.example.com"],
        wildcard_depth="one",
    )
    verdict = scope.check("a.b.staging.example.com")
    assert verdict.status is OUT and verdict.rule == "*.staging.example.com"


def test_unparseable_rule_fails_at_construction():
    with pytest.raises(RuleError):
        Scope(allow=["*.example.com", "https://*.example.net/"])
    with pytest.raises(RuleError):
        Scope(deny=["203.0.113.5/24"])


# ---- host and wildcard rules ---------------------------------------------------


@pytest.mark.parametrize(
    "target,expected",
    [
        ("app.example.org", IN),
        ("APP.EXAMPLE.ORG", IN),
        ("sub.app.example.org", OUT),  # exact host does not imply subdomains
        ("app.example.org.evil.net", OUT),
        ("xapp.example.org", OUT),
        ("https://app.example.org/anything/at/all?q=1#f", IN),  # host rule ignores scheme and path
        ("http://app.example.org:8080/", IN),  # rule without a port matches any port
        ("app.example.org:9999", IN),
    ],
)
def test_exact_host_rule(target, expected):
    scope = Scope(allow=["app.example.org"])
    assert scope.check(target).status is expected


def test_wildcard_matches_subdomains_of_urls():
    scope = Scope(allow=["*.example.com"])
    assert scope.check("https://api.example.com/v1/users").status is IN
    assert scope.check("https://example.com/").status is OUT


def test_host_rules_never_match_ip_targets():
    scope = Scope(allow=["*.example.com", "app.example.org"])
    assert scope.check("203.0.113.5").status is OUT
    assert scope.check("https://203.0.113.5/").status is OUT


def test_lookalike_and_suffix_tricks():
    scope = Scope(allow=["*.example.com"], deny=["*.admin.example.com"])
    for target in [
        "example.com.evil.net",
        "evil-example.com",
        "api.example.com.evil.net",
        "api.example.comevil.net",
        "https://evil.net/api.example.com",
        "https://evil.net/?host=api.example.com",
        "https://evil.net/#api.example.com",
    ]:
        assert scope.check(target).status is OUT, target


def test_idn_rule_and_target_agree():
    scope = Scope(allow=["*.bücher.example"])
    assert scope.check("shop.bücher.example").status is IN
    assert scope.check("shop.xn--bcher-kva.example").status is IN
    assert scope.check("shop.bucher.example").status is OUT


# ---- ports -------------------------------------------------------------------


@pytest.mark.parametrize(
    "target,expected",
    [
        ("api.example.com:8443", IN),
        ("https://api.example.com:8443/x", IN),
        ("api.example.com:9999", OUT),
        ("api.example.com", OUT),  # no port stated, so it cannot be shown to match
        ("http://api.example.com/", OUT),  # default port 80
        ("api.example.com:443", OUT),
    ],
)
def test_port_restricted_allow_rule(target, expected):
    scope = Scope(allow=["api.example.com:8443"])
    assert scope.check(target).status is expected


def test_default_port_counts_for_urls():
    scope = Scope(allow=["api.example.com:443"])
    assert scope.check("https://api.example.com/").status is IN
    assert scope.check("http://api.example.com/").status is OUT


def test_port_restricted_deny_applies_to_that_port():
    scope = Scope(allow=["*.example.com"], deny=["api.example.com:8443"])
    assert scope.check("api.example.com:8443").status is OUT
    assert scope.check("api.example.com:9000").status is IN


def test_port_restricted_deny_warns_when_target_has_no_port():
    scope = Scope(allow=["*.example.com"], deny=["api.example.com:8443"])
    verdict = scope.check("api.example.com")
    assert verdict.status is IN
    assert any("8443" in w and "was not applied" in w for w in verdict.warnings)


def test_port_restricted_wildcard_deny_warns_too():
    scope = Scope(allow=["*.example.com"], deny=["*.example.com:8443"])
    verdict = scope.check("api.example.com")
    assert verdict.status is IN
    assert any("8443" in w for w in verdict.warnings)


def test_url_scheme_gives_a_default_port_so_no_warning():
    scope = Scope(allow=["*.example.com"], deny=["api.example.com:443"])
    verdict = scope.check("https://api.example.com/")
    assert verdict.status is OUT and verdict.rule == "api.example.com:443"


# ---- URL prefix rules ---------------------------------------------------------


@pytest.mark.parametrize(
    "target,expected",
    [
        ("https://example.net/api/", IN),
        ("https://example.net/api/v1", IN),
        ("https://example.net/api/v1/users/7?x=1#frag", IN),
        ("https://EXAMPLE.net/api/v1", IN),
        ("https://example.net/api", OUT),  # rule ends in '/', bare path is not covered
        ("https://example.net/apix", OUT),
        ("https://example.net/api-v2/", OUT),
        ("https://example.net/API/v1", OUT),  # path rules are case-sensitive
        ("https://example.net/", OUT),
        ("https://example.net/admin", OUT),
        ("http://example.net/api/v1", OUT),  # scheme must match
        ("https://example.net:8443/api/v1", IN),  # rule without a port matches any port
        ("https://sub.example.net/api/v1", OUT),
        ("https://example.net.evil.net/api/v1", OUT),
        ("example.net", OUT),  # a bare host says nothing about the path
        ("example.net:443", OUT),
    ],
)
def test_url_prefix_rule_with_trailing_slash(target, expected):
    scope = Scope(allow=["https://example.net/api/"])
    assert scope.check(target).status is expected


@pytest.mark.parametrize(
    "target,expected",
    [
        ("https://example.net/api", IN),
        ("https://example.net/api/", IN),
        ("https://example.net/api/v1", IN),
        ("https://example.net/apix", OUT),
        ("https://example.net/ap", OUT),
    ],
)
def test_url_prefix_rule_without_trailing_slash(target, expected):
    scope = Scope(allow=["https://example.net/api"])
    assert scope.check(target).status is expected


def test_url_rule_without_a_path_covers_the_whole_host():
    scope = Scope(allow=["https://example.net"])
    assert scope.check("https://example.net/anything/here").status is IN
    assert scope.check("http://example.net/").status is OUT


def test_dot_segments_cannot_walk_out_of_a_path_rule():
    scope = Scope(allow=["https://example.net/api/"])
    assert scope.check("https://example.net/api/../admin").status is OUT
    assert scope.check("https://example.net/api/./v1").status is IN
    assert scope.check("https://example.net/x/../api/v1").status is IN


def test_encoded_dot_segments_are_unclear_not_guessed():
    scope = Scope(allow=["https://example.net/api/"])
    assert scope.check("https://example.net/api/%2e%2e/admin").status is UNCLEAR
    assert scope.check("https://example.net/api/%2E%2E/admin").status is UNCLEAR
    assert scope.check("https://example.net/api/..%2fadmin").status is UNCLEAR


def test_url_deny_rule_beats_host_allow():
    scope = Scope(allow=["*.example.com"], deny=["https://api.example.com/internal/"])
    assert scope.check("https://api.example.com/internal/x").status is OUT
    assert scope.check("https://api.example.com/internal/x").rule == "https://api.example.com/internal/"
    assert scope.check("https://api.example.com/public/x").status is IN
    assert scope.check("https://api.example.com/internal/../public/x").status is IN
    assert scope.check("https://api.example.com/public/../internal/x").status is OUT


def test_url_deny_warns_when_target_is_a_bare_host():
    scope = Scope(allow=["*.example.com"], deny=["https://api.example.com/internal/"])
    verdict = scope.check("api.example.com")
    assert verdict.status is IN
    assert any("limited to a URL path" in w for w in verdict.warnings)


def test_url_rule_with_ip_host():
    scope = Scope(allow=["https://203.0.113.5/app/"])
    assert scope.check("https://203.0.113.5/app/x").status is IN
    assert scope.check("https://203.0.113.5/other").status is OUT
    assert scope.check("203.0.113.5").status is OUT


# ---- IP and CIDR rules --------------------------------------------------------


def test_ip_rule_ipv4():
    scope = Scope(allow=["203.0.113.5"])
    assert scope.check("203.0.113.5").status is IN
    assert scope.check("203.0.113.5:8080").status is IN
    assert scope.check("https://203.0.113.5/x").status is IN
    assert scope.check("203.0.113.6").status is OUT


def test_ip_rule_ipv6_any_spelling():
    scope = Scope(allow=["2001:db8::1"])
    for target in ["2001:db8::1", "2001:0DB8:0:0:0:0:0:1", "[2001:db8::1]", "https://[2001:db8::1]:8443/x"]:
        assert scope.check(target).status is IN, target
    assert scope.check("2001:db8::2").status is OUT


def test_ip_rule_with_port():
    scope = Scope(allow=["203.0.113.5:8443"])
    assert scope.check("203.0.113.5:8443").status is IN
    assert scope.check("203.0.113.5").status is OUT
    assert scope.check("https://203.0.113.5:8443/").status is IN


def test_cidr_boundaries():
    scope = Scope(allow=["203.0.113.0/24"])
    assert scope.check("203.0.113.0").status is IN
    assert scope.check("203.0.113.255").status is IN
    assert scope.check("203.0.112.255").status is OUT
    assert scope.check("203.0.114.0").status is OUT


def test_ipv6_cidr():
    scope = Scope(allow=["2001:db8::/32"], deny=["2001:db8:bad::/48"])
    assert scope.check("2001:db8:1::1").status is IN
    assert scope.check("2001:db8:bad::1").status is OUT
    assert scope.check("2001:db9::1").status is OUT


def test_cidr_family_mismatch_never_matches():
    assert Scope(allow=["203.0.113.0/24"]).check("2001:db8::1").status is OUT
    assert Scope(allow=["2001:db8::/32"]).check("203.0.113.1").status is OUT


def test_cidr_matches_url_targets_with_ip_hosts():
    scope = Scope(allow=["203.0.113.0/24"])
    assert scope.check("https://203.0.113.9/path").status is IN


def test_cidr_does_not_match_host_names():
    assert Scope(allow=["203.0.113.0/24"]).check("api.example.com").status is OUT


def test_deny_ip_beats_cidr():
    scope = Scope(allow=["203.0.113.0/24"], deny=["203.0.113.7"])
    assert scope.check("203.0.113.7").rule == "203.0.113.7"
    assert scope.check("https://203.0.113.7/x").status is OUT


def test_ipv4_mapped_ipv6_hits_the_ipv4_deny_rule():
    scope = Scope(allow=["203.0.113.0/24"], deny=["203.0.113.7"])
    verdict = scope.check("::ffff:203.0.113.7")
    assert verdict.status is OUT and verdict.rule == "203.0.113.7"
    assert any("IPv4-mapped" in w for w in verdict.warnings)
    mapped_ok = scope.check("::ffff:203.0.113.8")
    assert mapped_ok.status is IN
    assert any("IPv4-mapped" in w for w in mapped_ok.warnings)


@pytest.mark.parametrize(
    "target",
    [
        "2130706433",
        "0x7f000001",
        "0177.0.0.1",
        "127.1",
        "203.0.113.050",
        "203.0.113.0/24",
        "2001:db8::/32",
        "fe80::1%eth0",
    ],
)
def test_obfuscated_or_range_targets_are_unclear_even_if_a_rule_could_match(target):
    scope = Scope(allow=["203.0.113.0/24", "2001:db8::/32", "*.example.com"])
    verdict = scope.check(target)
    assert verdict.status is UNCLEAR
    assert verdict.rule is None


# ---- verdict shape ---------------------------------------------------------------


def test_verdict_fields_and_json_shape(scope):
    verdict = scope.check("api.example.com")
    assert isinstance(verdict, Verdict)
    assert verdict.to_dict() == {
        "status": "IN_SCOPE",
        "target": "api.example.com",
        "rule": "*.example.com",
        "reason": "allowed by rule *.example.com",
        "warnings": [],
    }


def test_unclear_verdict_has_a_reason_and_no_rule(scope):
    verdict = scope.check("2130706433")
    assert verdict.status is UNCLEAR
    assert verdict.rule is None
    assert "obfuscated" in verdict.reason


def test_out_of_scope_denied_reason_names_the_rule(scope):
    verdict = scope.check("admin.example.com")
    assert verdict.reason == "denied by rule admin.example.com"


def test_verdict_is_immutable(scope):
    verdict = scope.check("api.example.com")
    with pytest.raises(dataclasses.FrozenInstanceError):
        verdict.status = OUT  # type: ignore[misc]


def test_status_exit_codes():
    assert IN.exit_code == 0
    assert OUT.exit_code == 1
    assert UNCLEAR.exit_code == 2


def test_status_values_are_plain_strings():
    assert IN == "IN_SCOPE" and str(OUT) == "OUT_OF_SCOPE" and UNCLEAR.value == "UNCLEAR"


@pytest.mark.parametrize("bad", [None, 2130706433, b"example.com", ["example.com"]])
def test_non_text_target_is_unclear_not_a_crash(scope, bad):
    verdict = scope.check(bad)  # type: ignore[arg-type]
    assert verdict.status is UNCLEAR
    assert isinstance(verdict.target, str)


def test_userinfo_password_never_appears_in_a_verdict(scope):
    verdict = scope.check("https://admin:hunter2@api.example.com/")
    assert verdict.status is IN
    assert "hunter2" not in " ".join(verdict.warnings)
    assert "hunter2" not in verdict.reason
    assert "hunter2" not in str(verdict.rule)
    assert "hunter2" not in verdict.target
    assert "hunter2" not in repr(verdict.to_dict())
    assert verdict.target == "https://***@api.example.com/"


def test_userinfo_password_is_hidden_in_unclear_and_out_of_scope_verdicts(scope):
    unclear = scope.check("https://admin:hunter2@api.example.com/%2e%2e/x")
    out = scope.check("https://admin:hunter2@evil.net/")
    assert unclear.status is UNCLEAR and out.status is OUT
    assert "hunter2" not in repr(unclear.to_dict())
    assert "hunter2" not in repr(out.to_dict())


def test_check_does_not_mutate_the_scope(scope):
    before = (scope.allow, scope.deny, scope.wildcard_depth)
    for target in ["api.example.com", "admin.example.com", "", "2130706433"]:
        scope.check(target)
    assert (scope.allow, scope.deny, scope.wildcard_depth) == before


# ---- step 6 ---------------------------------------------------------------------------------


def test_sharp_s_is_unclear_not_silently_ss():
    scope = Scope(allow=["fass.example.com", "xn--fa-hia.example.com"])
    assert scope.check("faß.example.com").status is UNCLEAR
    assert scope.check("fass.example.com").status is IN
    assert scope.check("xn--fa-hia.example.com").status is IN


@pytest.mark.parametrize("kwargs", [{"allow": "*.example.com"}, {"allow": ["a.example.com"], "deny": "admin.example.com"}, {"allow": b"a.example.com"}])
def test_a_bare_string_for_allow_or_deny_is_a_clear_type_error(kwargs):
    with pytest.raises(TypeError) as info:
        Scope(**kwargs)
    assert "list" in str(info.value)
