"""Tests for the scope file loader and the stale-scope warning (build step 3)."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from inbounds import Scope, ScopeFileError, Status, load_scope, parse_scope

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "example-program.toml"

ALLOW = ["*.example.com", "app.example.org", "https://example.net/api/", "203.0.113.0/24"]
DENY = ["admin.example.com", "*.staging.example.com", "203.0.113.7"]

MINIMAL = """\
[program]
captured = 2026-10-18

[rules]
allow = ["*.example.com"]
"""


def write(tmp_path: Path, text: str | bytes, name: str = "scope.toml") -> Path:
    path = tmp_path / name
    if isinstance(text, bytes):
        path.write_bytes(text)
    else:
        path.write_text(text, encoding="utf-8", newline="")
    return path


# ---- the example file and the happy path -----------------------------------------


def test_example_file_loads_and_matches_the_in_memory_scope():
    loaded = load_scope(EXAMPLE)
    manual = Scope(allow=ALLOW, deny=DENY, wildcard_depth="any")
    assert loaded.name == "example-program"
    assert loaded.source == "https://example.com/security"
    assert loaded.captured == dt.date(2026, 10, 18)
    assert loaded.max_age_days == 90
    assert [r.text for r in loaded.allow] == ALLOW
    assert [r.text for r in loaded.deny] == DENY
    today = dt.date(2026, 10, 19)
    for target in [
        "api.example.com",
        "a.b.example.com",
        "example.com",
        "admin.example.com",
        "x.staging.example.com",
        "https://example.net/api/v1",
        "https://example.net/apix",
        "203.0.113.50",
        "203.0.113.7",
        "2001:db8::1",
        "bücher.example.com",
        "2130706433",
        "",
    ]:
        a, b = loaded.check(target, today=today), manual.check(target)
        assert (a.status, a.rule, a.reason) == (b.status, b.rule, b.reason), target
        assert a.warnings == ()


def test_scope_load_classmethod_accepts_str_and_path():
    assert isinstance(Scope.load(EXAMPLE), Scope)
    assert isinstance(Scope.load(str(EXAMPLE)), Scope)


def test_minimal_file_uses_defaults(tmp_path):
    scope = load_scope(write(tmp_path, MINIMAL))
    assert scope.wildcard_depth == "any"
    assert scope.max_age_days == 90
    assert scope.name is None and scope.source is None
    assert scope.deny == ()
    assert scope.captured == dt.date(2026, 10, 18)


def test_options_are_applied(tmp_path):
    text = MINIMAL.replace(
        "[rules]", '[options]\nwildcard_depth = "one"\nmax_age_days = 30\n\n[rules]'
    ).replace('allow = ["*.example.com"]', 'allow = ["*.example.com"]\ndeny = ["bad.example.com"]')
    scope = load_scope(write(tmp_path, text))
    assert scope.wildcard_depth == "one"
    assert scope.max_age_days == 30
    assert scope.check("a.b.example.com").status is Status.OUT_OF_SCOPE
    assert scope.check("bad.example.com").rule == "bad.example.com"


def test_windows_style_files_load(tmp_path):
    crlf = MINIMAL.replace("\n", "\r\n").encode("utf-8")
    assert load_scope(write(tmp_path, crlf)).allow[0].text == "*.example.com"
    bom = b"\xef\xbb\xbf" + MINIMAL.encode("utf-8")
    assert load_scope(write(tmp_path, bom, "bom.toml")).allow[0].text == "*.example.com"


def test_captured_may_be_a_quoted_iso_date(tmp_path):
    text = MINIMAL.replace("2026-10-18", '"2026-10-18"')
    assert load_scope(write(tmp_path, text)).captured == dt.date(2026, 10, 18)


def test_parse_scope_from_text():
    assert parse_scope(MINIMAL).allow[0].text == "*.example.com"


# ---- problems with the file itself ------------------------------------------------


def test_missing_file(tmp_path):
    with pytest.raises(ScopeFileError) as info:
        load_scope(tmp_path / "nope.toml")
    assert "cannot read" in info.value.problem
    assert "nope.toml" in str(info.value)


def test_directory_instead_of_file(tmp_path):
    with pytest.raises(ScopeFileError):
        load_scope(tmp_path)


def test_oversized_file(tmp_path):
    with pytest.raises(ScopeFileError) as info:
        load_scope(write(tmp_path, b"#" * (1_048_576 + 1)))
    assert "larger than" in info.value.problem


def test_not_utf8(tmp_path):
    with pytest.raises(ScopeFileError) as info:
        load_scope(write(tmp_path, b"\xff\xfe\x00\x00[program]"))
    assert "UTF-8" in info.value.problem


def test_not_toml(tmp_path):
    with pytest.raises(ScopeFileError) as info:
        load_scope(write(tmp_path, "[program\ncaptured = "))
    assert "not valid TOML" in info.value.problem


# ---- structure and typos -----------------------------------------------------------


def bad(text: str) -> ScopeFileError:
    with pytest.raises(ScopeFileError) as info:
        parse_scope(text, where="scope.toml")
    assert str(info.value).startswith("scope.toml: ")
    return info.value


def test_missing_sections():
    assert "[program]" in bad('[rules]\nallow = ["a.example.com"]\n').problem
    assert "[rules]" in bad("[program]\ncaptured = 2026-10-18\n").problem


def test_missing_captured_is_an_error():
    err = bad('[program]\nname = "x"\n\n[rules]\nallow = ["a.example.com"]\n')
    assert "captured" in err.problem and "required" in err.problem


@pytest.mark.parametrize(
    "text,key",
    [
        (MINIMAL + "denies = []\n", "denies"),  # the dangerous typo: a dropped deny list
        (MINIMAL.replace("allow", "alow"), "alow"),
        (MINIMAL.replace("[program]", "[program]\nnmae = 'x'"), "nmae"),
        (MINIMAL + "\n[options]\nwildcard_deph = 'one'\n", "wildcard_deph"),
        (MINIMAL + "\n[extra]\nx = 1\n", "extra"),
        (MINIMAL + "\nextra_top = 1\n", "extra_top"),
    ],
)
def test_unknown_keys_are_errors(text, key):
    err = bad(text)
    assert repr(key) in err.problem and "unknown key" in err.problem


def test_section_must_be_a_table():
    assert "must be a table" in bad('program = "x"\n[rules]\nallow = ["a.example.com"]\n').problem


@pytest.mark.parametrize("value", ['"90"', "0", "-5", "1.5", "true", "[90]"])
def test_bad_max_age_days(value):
    err = bad(MINIMAL.replace("[rules]", f"[options]\nmax_age_days = {value}\n\n[rules]"))
    assert "max_age_days" in err.problem


@pytest.mark.parametrize("value", ['"two"', '"ANY"', "1", "true"])
def test_bad_wildcard_depth(value):
    err = bad(MINIMAL.replace("[rules]", f"[options]\nwildcard_depth = {value}\n\n[rules]"))
    assert "wildcard_depth" in err.problem


@pytest.mark.parametrize(
    "value",
    ["2026-10-18T10:00:00", "2026-10-18T10:00:00Z", '"18/10/2026"', '"2026-13-45"', '"2026-1-5"', "20261018", "true", "10:00:00"],
)
def test_bad_captured(value):
    err = bad(MINIMAL.replace("2026-10-18", value))
    assert "captured" in err.problem


def test_name_and_source_must_be_text():
    assert "program.name" in bad(MINIMAL.replace("[program]", "[program]\nname = 5")).problem
    assert "program.source" in bad(MINIMAL.replace("[program]", "[program]\nsource = 5")).problem


def test_rules_must_be_lists_of_text():
    assert "must be a list" in bad(MINIMAL.replace('["*.example.com"]', '"*.example.com"')).problem
    assert "must be text" in bad(MINIMAL.replace('["*.example.com"]', '["a.example.com", 5]')).problem
    assert "allow[1]" in bad(MINIMAL.replace('["*.example.com"]', '["a.example.com", 5]')).problem
    assert "must be a list" in bad(MINIMAL + 'deny = "x.example.com"\n').problem


def test_empty_allow_is_an_error_but_empty_deny_is_fine():
    assert "no rules" in bad(MINIMAL.replace('["*.example.com"]', "[]")).problem
    assert "no rules" in bad("[program]\ncaptured = 2026-10-18\n[rules]\ndeny = []\n").problem
    assert parse_scope(MINIMAL + "deny = []\n").deny == ()


def test_bad_rule_names_the_list_index_and_the_rule():
    text = MINIMAL.replace('["*.example.com"]', '["a.example.com", "https://*.example.net/", "b.example.com"]')
    err = bad(text)
    assert "rules.allow[1]" in err.problem
    assert "https://*.example.net/" in err.problem
    err = bad(MINIMAL + 'deny = ["203.0.113.5/24"]\n')
    assert "rules.deny[0]" in err.problem


def test_scope_file_error_is_a_value_error():
    assert issubclass(ScopeFileError, ValueError)


# ---- stale-scope warning -----------------------------------------------------------

CAPTURED = dt.date(2026, 10, 18)


def stale_scope(max_age_days: int = 90) -> Scope:
    return Scope(allow=ALLOW, deny=DENY, captured=CAPTURED, max_age_days=max_age_days)


def test_fresh_scope_has_no_warning():
    assert stale_scope().stale_warnings(CAPTURED) == ()
    assert stale_scope().stale_warnings(CAPTURED + dt.timedelta(days=90)) == ()  # exactly the limit


def test_old_scope_warns_the_day_after_the_limit():
    warnings = stale_scope().stale_warnings(CAPTURED + dt.timedelta(days=91))
    assert len(warnings) == 1
    assert "91 days ago" in warnings[0]
    assert "2026-10-18" in warnings[0]
    assert "max_age_days = 90" in warnings[0]


def test_future_captured_date_warns():
    warnings = stale_scope().stale_warnings(CAPTURED - dt.timedelta(days=1))
    assert len(warnings) == 1 and "future" in warnings[0]


def test_scope_without_a_captured_date_never_warns():
    assert Scope(allow=ALLOW).stale_warnings(dt.date(2099, 1, 1)) == ()


@pytest.mark.parametrize(
    "target,status",
    [
        ("api.example.com", Status.IN_SCOPE),
        ("admin.example.com", Status.OUT_OF_SCOPE),
        ("example.com", Status.OUT_OF_SCOPE),
        ("2130706433", Status.UNCLEAR),
        ("", Status.UNCLEAR),
    ],
)
def test_staleness_adds_a_warning_but_never_changes_the_status(target, status):
    scope = stale_scope(max_age_days=30)
    fresh = scope.check(target, today=CAPTURED)
    old = scope.check(target, today=CAPTURED + dt.timedelta(days=400))
    assert fresh.status is old.status is status
    assert fresh.rule == old.rule and fresh.reason == old.reason
    assert fresh.warnings == ()
    assert len(old.warnings) == 1 and "400 days ago" in old.warnings[0]


def test_stale_warning_comes_after_the_target_warnings():
    scope = stale_scope(max_age_days=30)
    verdict = scope.check("::ffff:203.0.113.8", today=CAPTURED + dt.timedelta(days=100))
    assert verdict.status is Status.IN_SCOPE
    assert "IPv4-mapped" in verdict.warnings[0]
    assert "days ago" in verdict.warnings[1]


def test_stale_warning_reaches_json_output():
    verdict = stale_scope(30).check("api.example.com", today=CAPTURED + dt.timedelta(days=100))
    assert len(verdict.to_dict()["warnings"]) == 1


def test_check_without_today_uses_the_real_date():
    assert Scope(allow=ALLOW, captured=dt.date(2000, 1, 1)).check("api.example.com").warnings
    assert Scope(allow=ALLOW, captured=dt.date.today()).check("api.example.com").warnings == ()


def test_loaded_scope_warns_when_old(tmp_path):
    scope = load_scope(write(tmp_path, MINIMAL))
    verdict = scope.check("api.example.com", today=dt.date(2027, 6, 1))
    assert verdict.status is Status.IN_SCOPE and verdict.warnings


# ---- Scope constructor validation ----------------------------------------------------


@pytest.mark.parametrize("bad_value", [0, -1, 1.5, True, "90", None])
def test_scope_rejects_bad_max_age_days(bad_value):
    with pytest.raises(ValueError):
        Scope(allow=ALLOW, max_age_days=bad_value)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad_value", ["2026-10-18", dt.datetime(2026, 10, 18, 9, 0), 20261018])
def test_scope_rejects_non_date_captured(bad_value):
    with pytest.raises(ValueError):
        Scope(allow=ALLOW, captured=bad_value)  # type: ignore[arg-type]


def test_rule_with_an_idna_deviation_character_is_a_file_error():
    err = bad(MINIMAL.replace('["*.example.com"]', '["faß.example.com"]'))
    assert "rules.allow[0]" in err.problem
    assert "xn--" in err.problem
