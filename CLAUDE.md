# CLAUDE.md: inbounds

Public, zero-dependency Python library and CLI that checks a target against a bug bounty program's scope and returns an explainable verdict. `SPEC.md` is the source of truth. Owner: CyberDredge (GitHub). Repo location: `C:\inbounds` (Windows).

## Rules (non-negotiable)
- **Git: review and flag only.** No commit, push, PR, merge, reset, rebase, tag, or branch deletion without the owner's explicit approval in that session. Say what is ready and let the owner decide.
- **This repo is public.** No real program scope data, tokens, API keys, `.env` content, personal details, or email addresses anywhere (code, tests, docs, commit text). Examples use only `example.com`, `example.net`, `example.org` and the RFC 5737 ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
- **No network access** in code or tests. No DNS lookups.
- **Zero runtime dependencies** (standard library only). Dev dependency: `pytest` only.
- **Fail closed.** Never guess at ambiguous input. Unclear means UNCLEAR.
- **Every matching or normalization rule change needs a test row.**
- Write invisible, control and look-alike characters in tests and code as `\uXXXX` escapes, never as raw characters (a test enforces this).
- Stay inside this folder. Do not touch anything outside `C:\inbounds`.

## Commands (PowerShell, from C:\inbounds)
```
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pytest
```
Requires Python 3.11 or newer.

## Where things are
- `SPEC.md` — design, rules, required test table, build order, and a build decisions log at the bottom.
- `src/inbounds/normalize.py` — target normalization (build step 1).
- `src/inbounds/rules.py` — rule parsing into typed rules (build step 2).
- `src/inbounds/matcher.py` — `Scope`, `Verdict`, `Status`, matching (build step 2).
- `src/inbounds/scopefile.py` — TOML scope file loader, strict validation (build step 3).
- `src/inbounds/cli.py` — `inbounds init | check | filter` (build step 4); `__main__.py` makes `python -m inbounds` work.
- `README.md`, `SECURITY.md`, `CHANGELOG.md`, `.github/workflows/ci.yml`, `.github/dependabot.yml` — docs, CI and update PRs for the pinned actions (build steps 5 and 6). `tests/test_repo_hygiene.py` keeps the README honest and checks CI pins, zero dependencies, and no leaks.
- `examples/example-program.toml` — fictional example scope file (a test loads it).
- `tests/` — table-driven tests. `test_matcher_table.py` holds the SPEC.md table row for row.

## Build status (update at the end of each session)
- Step 1 (normalize + tests): committed and pushed (a66801a).
- Step 2 (rules + matcher + SPEC table as tests): committed and pushed (769488b).
- Step 3 (scope file loader + stale warning): committed and pushed (a45fb9d).
- Step 4 (CLI: init, check, filter): committed and pushed (1c2323b).
- Step 5 (README, SECURITY.md, CHANGELOG.md, CI): committed and pushed (04eed44). CI is green on Python 3.11, 3.12 and 3.13, Linux and Windows.
- Step 6 (self-review fixes): written, 456 tests passing on Python 3.11, 3.12 and 3.13 in the build workspace (one POSIX-only test is skipped on Windows), awaiting the owner's review. Not committed. Changes: `ß`, `ς` and the joiners are UNCLEAR (IDNA 2003 vs browsers); Unicode look-alike mapping documented; clear error for a bare string as `allow`/`deny`; `[project.urls]`; Dependabot config; guards against invisible characters in source.
- Next: the owner reviews and commits step 6, then decides on a first release (PyPI name `inbounds` was unregistered when last checked).
