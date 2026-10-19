"""Tests for the command line interface (build step 4)."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from inbounds import Scope, __version__
from inbounds.cli import MAX_LINE_CHARS, main

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "examples" / "example-program.toml"

OLD_SCOPE = """\
[program]
captured = 2000-01-01

[rules]
allow = ["*.example.com"]
"""


def run(argv: list[str], stdin: str = "") -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, stdin=io.StringIO(stdin), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


@pytest.fixture
def scope_file() -> str:
    return str(EXAMPLE)


# ---- check ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "target,code,status",
    [
        ("api.example.com", 0, "IN_SCOPE"),
        ("a.b.example.com", 0, "IN_SCOPE"),
        ("example.com", 1, "OUT_OF_SCOPE"),
        ("admin.example.com", 1, "OUT_OF_SCOPE"),
        ("https://api.example.com@evil.net/", 1, "OUT_OF_SCOPE"),
        ("https://example.net/api/v1", 0, "IN_SCOPE"),
        ("203.0.113.7", 1, "OUT_OF_SCOPE"),
        ("203.0.113.50", 0, "IN_SCOPE"),
        ("2130706433", 2, "UNCLEAR"),
        ("ftp://api.example.com", 2, "UNCLEAR"),
        ("203.0.113.0/24", 2, "UNCLEAR"),
        ("", 2, "UNCLEAR"),
    ],
)
def test_check_exit_codes(scope_file, target, code, status):
    got, out, _ = run(["check", scope_file, target])
    assert got == code
    assert out.startswith(status + "  ")


def test_check_human_output_names_rule_and_reason(scope_file):
    code, out, err = run(["check", scope_file, "api.example.com"])
    assert code == 0
    assert out.splitlines() == [
        "IN_SCOPE  api.example.com",
        "  rule:    *.example.com",
        "  reason:  allowed by rule *.example.com",
    ]
    assert "warning" not in err.lower() or "captured" in err


def test_check_with_no_deciding_rule_says_none(scope_file):
    _, out, _ = run(["check", scope_file, "example.com"])
    assert "  rule:    (none)" in out
    assert "  reason:  no allow rule matched" in out


def test_check_json(scope_file):
    code, out, _ = run(["check", scope_file, "admin.example.com", "--json"])
    assert code == 1
    data = json.loads(out)
    assert data["status"] == "OUT_OF_SCOPE"
    assert data["rule"] == "admin.example.com"
    assert data["target"] == "admin.example.com"
    assert data["reason"] == "denied by rule admin.example.com"
    assert isinstance(data["warnings"], list)
    assert out.count("\n") == 1  # exactly one JSON object on one line


def test_check_json_is_ascii_safe(scope_file):
    code, out, _ = run(["check", scope_file, "bücher.example.com", "--json"])
    assert code == 0
    assert out.isascii()
    assert json.loads(out)["target"] == "bücher.example.com"


def test_check_warnings_go_to_stderr_not_stdout(scope_file):
    code, out, err = run(["check", scope_file, "::ffff:203.0.113.8"])
    assert code == 0
    assert "IPv4-mapped" in err and err.startswith("inbounds: warning: ")
    assert "IPv4-mapped" not in out


def test_check_json_also_carries_warnings(scope_file):
    _, out, err = run(["check", scope_file, "::ffff:203.0.113.8", "--json"])
    assert "IPv4-mapped" in json.loads(out)["warnings"][0]
    assert "IPv4-mapped" in err


def test_stale_scope_warns_on_stderr_and_never_changes_the_exit_code(tmp_path):
    path = tmp_path / "old.toml"
    path.write_text(OLD_SCOPE, encoding="utf-8")
    code, out, err = run(["check", str(path), "api.example.com"])
    assert code == 0 and out.startswith("IN_SCOPE")
    assert err.count("warning:") == 1 and "days ago" in err and "2000-01-01" in err
    code, _, err = run(["check", str(path), "evil.net"])
    assert code == 1 and "days ago" in err
    code, _, err = run(["check", str(path), "2130706433"])
    assert code == 2 and "days ago" in err


def test_check_never_prints_raw_control_characters(scope_file):
    code, out, _ = run(["check", scope_file, "ex\x1b[31mple.com"])
    assert code == 2
    assert "\x1b" not in out
    assert "\\x1b" in out
    code, out, _ = run(["check", scope_file, "exa‮mple.com"])
    assert "‮" not in out and "\\u202e" in out


def test_check_hides_userinfo_passwords(scope_file):
    code, out, err = run(["check", scope_file, "https://admin:hunter2@api.example.com/", "--json"])
    assert code == 0
    assert "hunter2" not in out and "hunter2" not in err


def test_check_target_starting_with_a_dash_needs_double_dash(scope_file):
    code, out, _ = run(["check", scope_file, "--", "-bad.example.com"])
    assert code == 2 and out.startswith("UNCLEAR")
    code, _, err = run(["check", scope_file, "-bad.example.com"])
    assert code == 2  # argparse usage error


def test_check_bad_scope_file_is_exit_2_with_nothing_on_stdout(tmp_path):
    bad = tmp_path / "bad.toml"
    bad.write_text('[program]\ncaptured = 2026-10-18\n[rules]\nallow = ["https://*.example.com/"]\ndenies = []\n')
    for path in (bad, tmp_path / "missing.toml"):
        code, out, err = run(["check", str(path), "api.example.com"])
        assert code == 2 and out == ""
        assert err.startswith("inbounds: error: ")


# ---- filter ----------------------------------------------------------------------------

LINES = "\n".join(
    [
        "api.example.com",
        "evil.net",
        "https://example.net/api/v1",
        "https://example.net/admin",
        "admin.example.com",
        "203.0.113.50",
        "203.0.113.7",
        "2130706433",
        "exa mple.com",
        "app.example.org",
    ]
)


def test_filter_prints_only_in_scope_lines_in_order(scope_file):
    code, out, err = run(["filter", scope_file], LINES + "\n")
    assert code == 0
    assert out.splitlines() == [
        "api.example.com",
        "https://example.net/api/v1",
        "203.0.113.50",
        "app.example.org",
    ]
    assert "UNCLEAR: 2130706433: " in err
    assert "UNCLEAR: exa mple.com: " in err
    assert "2 line(s) were UNCLEAR" in err


def test_filter_invert_prints_only_out_of_scope_lines(scope_file):
    code, out, err = run(["filter", scope_file, "--invert"], LINES + "\n")
    assert code == 0
    assert out.splitlines() == [
        "evil.net",
        "https://example.net/admin",
        "admin.example.com",
        "203.0.113.7",
    ]
    assert "2130706433" in err  # UNCLEAR is reported in both modes


def test_filter_never_prints_unclear_lines_on_stdout(scope_file):
    for flags in ([], ["--invert"]):
        _, out, _ = run(["filter", scope_file, *flags], "2130706433\nexa mple.com\n\x00\n")
        assert out == ""


def test_filter_skips_blank_lines_and_keeps_going(scope_file):
    code, out, err = run(["filter", scope_file], "\n   \napi.example.com\n\n\t\nevil.net\n")
    assert code == 0 and out == "api.example.com\n"
    assert "UNCLEAR" not in err


def test_filter_handles_crlf_bom_and_a_missing_final_newline(scope_file):
    code, out, _ = run(["filter", scope_file], "﻿api.example.com\r\nevil.net\r\napp.example.org")
    assert out == "api.example.com\napp.example.org\n"


def test_filter_prints_the_line_as_given(scope_file):
    _, out, _ = run(["filter", scope_file], "  API.EXAMPLE.COM.  \n")
    assert out == "  API.EXAMPLE.COM.  \n"


def test_filter_with_empty_input_is_fine(scope_file):
    assert run(["filter", scope_file], "") == (0, "", "")


def test_filter_exit_code_is_zero_even_when_nothing_matches(scope_file):
    code, out, _ = run(["filter", scope_file], "evil.net\n")
    assert code == 0 and out == ""


def test_filter_reports_a_too_long_line_without_buffering_it(scope_file):
    huge = "a" * (MAX_LINE_CHARS * 5)
    code, out, err = run(["filter", scope_file], f"api.example.com\n{huge}\napp.example.org\n")
    assert code == 0
    assert out.splitlines() == ["api.example.com", "app.example.org"]
    assert f"line 2: line is longer than {MAX_LINE_CHARS}" in err
    assert huge not in err


def test_filter_too_long_final_line_without_newline(scope_file):
    code, out, err = run(["filter", scope_file], "api.example.com\n" + "a" * (MAX_LINE_CHARS * 2))
    assert out == "api.example.com\n" and "line 2" in err


def test_filter_line_exactly_at_the_limit_is_read_whole(scope_file):
    line = ("a" * 60 + ".") * 60 + "example.com"  # long but not over the line limit
    assert len(line) < MAX_LINE_CHARS
    code, out, err = run(["filter", scope_file], line + "\n")
    assert "longer than" not in err


def test_filter_stale_warning_is_printed_once(tmp_path):
    path = tmp_path / "old.toml"
    path.write_text(OLD_SCOPE, encoding="utf-8")
    code, out, err = run(["filter", str(path)], "a.example.com\nb.example.com\nevil.net\n")
    assert code == 0 and out == "a.example.com\nb.example.com\n"
    assert err.count("days ago") == 1


def test_filter_line_warnings_name_the_line_and_hide_passwords(scope_file):
    code, out, err = run(
        ["filter", scope_file], "https://admin:hunter2@api.example.com/\n::ffff:203.0.113.8\n"
    )
    assert code == 0
    assert out.splitlines() == ["https://admin:hunter2@api.example.com/", "::ffff:203.0.113.8"]
    assert "hunter2" not in err
    assert "https://***@api.example.com/: warning" not in err  # format is 'warning: target: text'
    assert "warning: https://***@api.example.com/: userinfo" in err
    assert "warning: ::ffff:203.0.113.8: " in err


def test_filter_never_prints_raw_control_characters_to_stderr(scope_file):
    _, _, err = run(["filter", scope_file], "ex\x1b[31mple.com\n")
    assert "\x1b" not in err and "\\x1b" in err


def test_filter_bad_scope_file(tmp_path):
    code, out, err = run(["filter", str(tmp_path / "nope.toml")], "api.example.com\n")
    assert code == 2 and out == "" and "error:" in err


# ---- init --------------------------------------------------------------------------------


def test_init_writes_a_valid_template_with_todays_date(tmp_path):
    path = tmp_path / "scope.toml"
    code, out, err = run(["init", str(path)])
    assert code == 0 and err == ""
    assert "fictional" in out
    scope = Scope.load(path)
    assert scope.captured is not None and scope.stale_warnings() == ()
    example = Scope.load(EXAMPLE)
    assert [r.text for r in scope.allow] == [r.text for r in example.allow]
    assert [r.text for r in scope.deny] == [r.text for r in example.deny]
    assert scope.check("api.example.com").status.exit_code == 0


def test_init_template_only_uses_reserved_example_names():
    text = (ROOT / "src" / "inbounds" / "cli.py").read_text(encoding="utf-8")
    template = text.split('TEMPLATE = """', 1)[1].split('"""', 1)[0]
    for line in template.splitlines():
        if line.lstrip().startswith(('"', "allow", "deny")):
            assert any(
                token in line for token in ("example.", "203.0.113.", "allow = [", "deny = [", "]")
            ), line


def test_init_refuses_to_overwrite(tmp_path):
    path = tmp_path / "scope.toml"
    path.write_text("keep me", encoding="utf-8")
    code, out, err = run(["init", str(path)])
    assert code == 2 and out == ""
    assert "already exists" in err and "--force" in err
    assert path.read_text(encoding="utf-8") == "keep me"


def test_init_force_overwrites(tmp_path):
    path = tmp_path / "scope.toml"
    path.write_text("old", encoding="utf-8")
    code, _, _ = run(["init", str(path), "--force"])
    assert code == 0
    assert Scope.load(path).name == "example-program"


def test_init_into_a_missing_folder_is_a_clean_error(tmp_path):
    code, out, err = run(["init", str(tmp_path / "no" / "such" / "scope.toml")])
    assert code == 2 and out == "" and "cannot write" in err


def test_init_writes_lf_line_endings(tmp_path):
    path = tmp_path / "scope.toml"
    run(["init", str(path)])
    assert b"\r" not in path.read_bytes()


# ---- usage --------------------------------------------------------------------------------


def test_no_arguments_is_a_usage_error():
    code, out, err = run([])
    assert code == 2 and out == "" and "usage" in err.lower()


def test_unknown_command_is_a_usage_error():
    assert run(["scan", "x"])[0] == 2


def test_version_and_help_exit_zero(capsys):
    assert main(["--version"]) == 0
    assert __version__ in capsys.readouterr().out
    assert main(["--help"]) == 0
    assert "safety net" in capsys.readouterr().out


# ---- as a real process ----------------------------------------------------------------------


def process(*args: str, stdin: str = "", env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    full_env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "PYTHONDONTWRITEBYTECODE": "1"}
    full_env.update(env or {})
    return subprocess.run(
        [sys.executable, "-m", "inbounds", *args],
        input=stdin.encode("utf-8"),
        capture_output=True,
        env=full_env,
        timeout=60,
    )


def test_process_exit_codes_and_streams():
    res = process("check", str(EXAMPLE), "api.example.com")
    assert res.returncode == 0 and res.stdout.decode().startswith("IN_SCOPE")
    assert process("check", str(EXAMPLE), "example.com").returncode == 1
    assert process("check", str(EXAMPLE), "2130706433").returncode == 2
    assert process().returncode == 2


def test_process_filter_over_a_pipe():
    res = process("filter", str(EXAMPLE), stdin=LINES + "\n")
    assert res.returncode == 0
    assert res.stdout.decode().splitlines()[0] == "api.example.com"
    assert b"UNCLEAR" in res.stderr


def test_process_does_not_crash_on_a_console_that_cannot_show_the_text():
    res = process(
        "check", str(EXAMPLE), "bücher.example.com", env={"PYTHONIOENCODING": "ascii"}
    )
    assert res.returncode == 0
    assert b"Traceback" not in res.stderr
    assert b"IN_SCOPE" in res.stdout and b"\\xfc" in res.stdout


def test_process_version():
    res = process("--version")
    assert res.returncode == 0 and __version__ in res.stdout.decode()


@pytest.mark.skipif(os.name != "posix", reason="pipe-closing behaviour is checked on POSIX")
def test_process_closing_the_output_pipe_early_is_not_an_error():
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "PYTHONDONTWRITEBYTECODE": "1"}
    proc = subprocess.Popen(
        [sys.executable, "-m", "inbounds", "filter", str(EXAMPLE)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    assert proc.stdin and proc.stdout and proc.stderr

    def feed() -> None:  # a thread, so a full pipe in either direction cannot deadlock the test
        try:
            proc.stdin.write(b"api.example.com\n" * 200000)
            proc.stdin.close()
        except (BrokenPipeError, ValueError, OSError):
            pass

    feeder = threading.Thread(target=feed, daemon=True)
    feeder.start()
    try:
        assert proc.stdout.readline() == b"api.example.com\n"
        proc.stdout.close()
        err = proc.stderr.read()
        assert proc.wait(timeout=30) == 0
        assert b"Traceback" not in err and b"Exception ignored" not in err
    finally:
        if proc.poll() is None:
            proc.kill()
        feeder.join(timeout=10)
