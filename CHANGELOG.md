# Changelog

All notable changes to this project are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

First pre-release (0.1.0.dev0). Not yet published to PyPI.

### Added
- Target normalization that refuses to guess: obfuscated IP forms, hidden and control characters, backslashes, encoded path tricks and unsupported schemes are `UNCLEAR`.
- Rule types: exact host, wildcard host, URL prefix, IP, and CIDR, with optional ports.
- `Scope` matcher with `IN_SCOPE`, `OUT_OF_SCOPE` and `UNCLEAR` verdicts. Deny beats allow, and the verdict names the rule that decided it.
- Strict TOML scope file loader and a stale-scope warning.
- `inbounds init`, `inbounds check` and `inbounds filter`.
- Test suite built around the required test table in `SPEC.md`, and CI on Python 3.11, 3.12 and 3.13.

### Changed
- Host names containing `ß`, `ς` or a zero-width joiner are now `UNCLEAR` (and invalid as rules). Python's IDNA 2003 codec and current browsers turn them into different hosts, so the tool no longer picks one. Write the `xn--` form instead.
- `Scope(allow="...")` with a bare string now raises a `TypeError` that asks for a list.
- README documents how full-width letters and dot-like characters are mapped.
- `pyproject.toml` gains `[project.urls]`; a Dependabot config keeps the pinned GitHub Actions current.
