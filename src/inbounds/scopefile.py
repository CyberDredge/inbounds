"""Load a scope from a TOML file (see SPEC.md, "Scope file (TOML)").

The loader is strict on purpose. A typo that silently drops a deny rule
(``denies = [...]``) or an unreadable allow rule is how someone ends up testing
something they were not allowed to test, so every problem is an error with a
message that says what to fix. Nothing here touches the network; the
``source`` field is informational and is never fetched.
"""

from __future__ import annotations

import datetime
import os
import re
import tomllib
from pathlib import Path
from typing import Any

from inbounds.matcher import DEFAULT_MAX_AGE_DAYS, WILDCARD_DEPTHS, Scope
from inbounds.rules import Rule, RuleError, parse_rule

MAX_FILE_BYTES = 1_048_576  # 1 MiB is far more than any real scope file

_ISO_DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")

_PROGRAM_KEYS = {"name", "captured", "source"}
_OPTION_KEYS = {"wildcard_depth", "max_age_days"}
_RULE_KEYS = {"allow", "deny"}
_TOP_KEYS = {"program", "options", "rules"}


class ScopeFileError(ValueError):
    """The scope file cannot be used. ``where`` names the file, ``problem`` what is wrong."""

    def __init__(self, where: object, problem: str) -> None:
        super().__init__(f"{where}: {problem}")
        self.where = str(where)
        self.problem = problem


def load_scope(path: str | os.PathLike[str]) -> Scope:
    """Read and validate a scope file. Raises ``ScopeFileError`` on any problem."""
    file = Path(path)
    try:
        with file.open("rb") as handle:
            raw = handle.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise ScopeFileError(file, f"cannot read the file ({exc.strerror or exc})") from None
    if len(raw) > MAX_FILE_BYTES:
        raise ScopeFileError(file, f"file is larger than {MAX_FILE_BYTES} bytes")
    try:
        # utf-8-sig: Windows editors often save a UTF-8 byte order mark.
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ScopeFileError(file, "file is not valid UTF-8") from None
    return parse_scope(text, where=str(file))


def parse_scope(text: str, where: str = "<string>") -> Scope:
    """Validate scope file text and build a ``Scope``."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ScopeFileError(where, f"not valid TOML ({exc})") from None

    _no_unknown_keys(where, "the top level", data, _TOP_KEYS)
    program = _table(where, data, "program", _PROGRAM_KEYS, required=True)
    options = _table(where, data, "options", _OPTION_KEYS, required=False)
    rules = _table(where, data, "rules", _RULE_KEYS, required=True)

    name = _optional_text(where, "program.name", program.get("name"))
    source = _optional_text(where, "program.source", program.get("source"))
    if "captured" not in program:
        raise ScopeFileError(
            where,
            "program.captured is required (the date you copied the scope, like 2026-10-18); "
            "it is how the tool knows when the scope is out of date",
        )
    captured = _parse_date(where, program["captured"])

    wildcard_depth = options.get("wildcard_depth", "any")
    if wildcard_depth not in WILDCARD_DEPTHS:
        raise ScopeFileError(
            where, f"options.wildcard_depth must be \"any\" or \"one\", got {wildcard_depth!r}"
        )
    max_age_days = options.get("max_age_days", DEFAULT_MAX_AGE_DAYS)
    if isinstance(max_age_days, bool) or not isinstance(max_age_days, int) or max_age_days < 1:
        raise ScopeFileError(
            where, f"options.max_age_days must be a whole number of days, 1 or more, got {max_age_days!r}"
        )

    allow = _parse_rules(where, rules, "allow")
    deny = _parse_rules(where, rules, "deny")
    if not allow:
        raise ScopeFileError(
            where, "rules.allow has no rules, so every target would be OUT_OF_SCOPE; add the in-scope rules"
        )

    return Scope(
        allow=allow,
        deny=deny,
        wildcard_depth=wildcard_depth,
        name=name,
        captured=captured,
        source=source,
        max_age_days=max_age_days,
    )


def _no_unknown_keys(where: str, label: str, table: dict[str, Any], allowed: set[str]) -> None:
    unknown = sorted(set(table) - allowed)
    if unknown:
        expected = ", ".join(sorted(allowed))
        raise ScopeFileError(
            where, f"unknown key {unknown[0]!r} in {label} (expected: {expected}); a typo here would silently drop rules"
        )


def _table(
    where: str, data: dict[str, Any], key: str, allowed: set[str], *, required: bool
) -> dict[str, Any]:
    if key not in data:
        if required:
            raise ScopeFileError(where, f"missing the [{key}] section")
        return {}
    table = data[key]
    if not isinstance(table, dict):
        raise ScopeFileError(where, f"[{key}] must be a table, like [{key}] on its own line")
    _no_unknown_keys(where, f"[{key}]", table, allowed)
    return table


def _optional_text(where: str, label: str, value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ScopeFileError(where, f"{label} must be text")
    return value


def _parse_date(where: str, value: object) -> datetime.date:
    if type(value) is datetime.date:
        return value
    if isinstance(value, str) and _ISO_DATE_RE.fullmatch(value):
        try:
            return datetime.date.fromisoformat(value)
        except ValueError:
            pass
    raise ScopeFileError(
        where,
        f"program.captured must be a date like 2026-10-18 (no time of day), got {value!r}",
    )


def _parse_rules(where: str, rules: dict[str, Any], key: str) -> list[Rule]:
    values = rules.get(key, [])
    if not isinstance(values, list):
        raise ScopeFileError(where, f"rules.{key} must be a list, like {key} = [\"example.com\"]")
    parsed: list[Rule] = []
    for index, value in enumerate(values):
        if not isinstance(value, str):
            raise ScopeFileError(where, f"rules.{key}[{index}] must be text, got {value!r}")
        try:
            parsed.append(parse_rule(value))
        except RuleError as exc:
            raise ScopeFileError(where, f"rules.{key}[{index}] {value!r}: {exc.reason}") from None
    return parsed
