"""Command line interface: ``inbounds init | check | filter``.

Exit codes (see SPEC.md, "CLI"):

* ``check``: 0 IN_SCOPE, 1 OUT_OF_SCOPE, 2 UNCLEAR or any error.
* ``filter``: 0 when it ran (UNCLEAR lines are reported on stderr, never
  silently dropped), 2 when the scope file or the usage is bad.
* ``init``: 0 on success, 2 on error.

Warnings (stale scope, userinfo in a URL, and so on) always go to stderr, so
stdout stays clean for pipes. ``check --json`` also carries them in the
``warnings`` field.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime
import json
import os
import sys
from collections.abc import Iterator
from typing import TextIO

from inbounds import __version__
from inbounds.matcher import Scope, Status, Verdict
from inbounds.scopefile import ScopeFileError

PROG = "inbounds"
MAX_LINE_CHARS = 4096  # filter: longer lines are reported UNCLEAR, never buffered whole

TEMPLATE = """\
# Fictional template. Not a real program.
#
# Replace the rules below with the scope from the program's own published
# policy page, and set `captured` to the day you copied it. The program's
# policy is the only authority on scope; this file is a safety net for typos.
#
# Do not commit real scope data to a public repository.

[program]
name = "example-program"
captured = {captured}                       # the date you copied the scope; drives the stale warning
source = "https://example.com/security"     # where you copied it from (informational only, never fetched)

[options]
wildcard_depth = "any"                      # "any": *.example.com matches a.b.example.com; "one": only a.example.com
max_age_days = 90                           # warn when the scope is older than this

[rules]
allow = [
    "*.example.com",                        # subdomains only; list example.com itself separately if it is in scope
    "app.example.org",
    "https://example.net/api/",             # URL prefix, matched on a path-segment boundary
    "203.0.113.0/24",
]
deny = [
    "admin.example.com",
    "*.staging.example.com",
    "203.0.113.7",
]
"""


def main(
    argv: list[str] | None = None,
    *,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Run the CLI and return the exit code. Streams can be injected for tests."""
    real_streams = stdin is None and stdout is None and stderr is None
    stdin = stdin if stdin is not None else sys.stdin
    stdout = stdout if stdout is not None else sys.stdout
    stderr = stderr if stderr is not None else sys.stderr
    if real_streams:
        _harden_streams(stdin, stdout, stderr)

    parser = _build_parser()
    try:
        # argparse prints help and usage errors to sys.stdout / sys.stderr itself.
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse exits on --help (0) and on usage errors (2)
        return exc.code if isinstance(exc.code, int) else 2

    try:
        if args.command == "init":
            return _cmd_init(args, stdout, stderr)
        if args.command == "check":
            return _cmd_check(args, stdout, stderr)
        return _cmd_filter(args, stdin, stdout, stderr)
    except ScopeFileError as exc:
        _err(stderr, f"error: {_safe(str(exc))}")
        return 2
    except BrokenPipeError:
        # The reader of our output went away (for example `| head`). Not an error.
        if real_streams:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0


def run() -> None:
    """Console script entry point."""
    sys.exit(main())


# ---- commands -----------------------------------------------------------------------


def _cmd_init(args: argparse.Namespace, stdout: TextIO, stderr: TextIO) -> int:
    text = TEMPLATE.format(captured=datetime.date.today().isoformat())
    mode = "w" if args.force else "x"  # "x" refuses to overwrite an existing file
    try:
        with open(args.file, mode, encoding="utf-8", newline="\n") as handle:
            handle.write(text)
    except FileExistsError:
        _err(stderr, f"error: {_safe(args.file)} already exists; use --force to overwrite it")
        return 2
    except OSError as exc:
        _err(stderr, f"error: cannot write {_safe(args.file)} ({exc.strerror or exc})")
        return 2
    print(f"Wrote a fictional template to {_safe(args.file)}.", file=stdout)
    print(
        "Replace the rules with the scope from the program's own policy page and set "
        "`captured` to the day you copied it. Do not commit real scope data to a public repo.",
        file=stdout,
    )
    return 0


def _cmd_check(args: argparse.Namespace, stdout: TextIO, stderr: TextIO) -> int:
    scope = Scope.load(args.file)
    verdict = scope.check(args.target)
    for warning in verdict.warnings:
        _err(stderr, f"warning: {_safe(warning)}")
    if args.json:
        print(json.dumps(verdict.to_dict(), ensure_ascii=True), file=stdout)
    else:
        _print_verdict(verdict, stdout)
    return verdict.status.exit_code


def _cmd_filter(args: argparse.Namespace, stdin: TextIO, stdout: TextIO, stderr: TextIO) -> int:
    scope = Scope.load(args.file)
    stale = scope.stale_warnings()
    for warning in stale:
        _err(stderr, f"warning: {_safe(warning)}")

    wanted = Status.OUT_OF_SCOPE if args.invert else Status.IN_SCOPE
    unclear = 0
    for number, line, too_long in _read_lines(stdin):
        if too_long:
            unclear += 1
            _err(stderr, f"UNCLEAR: line {number}: line is longer than {MAX_LINE_CHARS} characters")
            continue
        if not line.strip():
            continue  # blank lines are noise, not targets
        verdict = scope.check(line)
        for warning in verdict.warnings:
            if warning not in stale:
                _err(stderr, f"warning: {_safe(verdict.target)}: {_safe(warning)}")
        if verdict.status is Status.UNCLEAR:
            unclear += 1
            _err(stderr, f"UNCLEAR: {_safe(verdict.target)}: {_safe(verdict.reason)}")
        elif verdict.status is wanted:
            print(line, file=stdout)
    if unclear:
        _err(stderr, f"{unclear} line(s) were UNCLEAR and were not checked; see above")
    return 0


# ---- helpers --------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Check a target against a bug bounty program's scope. "
        "The program's published policy is the only authority on scope; "
        "this tool is a safety net for typos and recon noise.",
    )
    parser.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="{init,check,filter}")

    init = sub.add_parser("init", help="write a fictional template scope file")
    init.add_argument("file", help="where to write the scope file")
    init.add_argument("--force", action="store_true", help="overwrite the file if it exists")

    check = sub.add_parser(
        "check",
        help="check one target (exit 0 in scope, 1 out of scope, 2 unclear or error)",
        description="Check one target. If the target starts with '-', put '--' before it.",
    )
    check.add_argument("file", help="scope file (TOML)")
    check.add_argument("target", help="host, IP, or http(s) URL to check")
    check.add_argument("--json", action="store_true", help="print the verdict as one JSON object")

    flt = sub.add_parser(
        "filter",
        help="read targets from stdin, print the in-scope ones",
        description="Read one target per line from stdin and print the lines that are IN_SCOPE. "
        "UNCLEAR lines are reported on stderr and never printed. Blank lines are skipped.",
    )
    flt.add_argument("file", help="scope file (TOML)")
    flt.add_argument("--invert", action="store_true", help="print the OUT_OF_SCOPE lines instead")
    return parser


def _print_verdict(verdict: Verdict, stdout: TextIO) -> None:
    print(f"{verdict.status.value}  {_safe(verdict.target)}", file=stdout)
    print(f"  rule:    {_safe(verdict.rule) if verdict.rule else '(none)'}", file=stdout)
    print(f"  reason:  {_safe(verdict.reason)}", file=stdout)


def _read_lines(stream: TextIO) -> Iterator[tuple[int, str, bool]]:
    """Yield (line number, text without its line ending, too_long) without buffering huge lines."""
    number = 0
    while True:
        chunk = stream.readline(MAX_LINE_CHARS + 1)
        if not chunk:
            return
        number += 1
        if number == 1:
            chunk = chunk.removeprefix("\ufeff")  # a byte order mark from a Windows pipe
        if len(chunk) > MAX_LINE_CHARS and not chunk.endswith("\n"):
            while True:  # discard the rest of the oversized line
                rest = stream.readline(MAX_LINE_CHARS)
                if not rest or rest.endswith("\n"):
                    break
            yield number, "", True
            continue
        yield number, chunk.rstrip("\r\n"), False


def _safe(text: str) -> str:
    """Make text safe to print: control and invisible characters become \\uXXXX escapes.

    A target comes from outside, and a raw escape sequence in it could rewrite
    what the terminal shows.
    """
    return "".join(
        ch if ch.isprintable() else ch.encode("unicode_escape").decode("ascii") for ch in text
    )


def _err(stderr: TextIO, message: str) -> None:
    print(f"{PROG}: {message}", file=stderr)


def _harden_streams(stdin: TextIO, stdout: TextIO, stderr: TextIO) -> None:
    """Never crash on an odd character: a Windows console may not be UTF-8."""
    for stream, errors in ((stdout, "backslashreplace"), (stderr, "backslashreplace"), (stdin, "replace")):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(errors=errors)
            except (OSError, ValueError):
                pass
