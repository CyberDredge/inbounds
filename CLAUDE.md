# CLAUDE.md: inbounds

Public, zero-dependency Python library and CLI that checks a target against a bug bounty program's scope and returns an explainable verdict. `SPEC.md` is the source of truth. Owner: CyberDredge (GitHub). Repo location: `C:\inbounds` (Windows).

## Rules (non-negotiable)
- **Git: review and flag only.** No commit, push, PR, merge, reset, rebase, tag, or branch deletion without the owner's explicit approval in that session. Say what is ready and let the owner decide.
- **This repo is public.** No real program scope data, tokens, API keys, `.env` content, personal details, or email addresses anywhere (code, tests, docs, commit text). Examples use only `example.com`, `example.net`, `example.org` and the RFC 5737 ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
- **No network access** in code or tests. No DNS lookups.
- **Zero runtime dependencies** (standard library only). Dev dependency: `pytest` only.
- **Fail closed.** Never guess at ambiguous input. Unclear means UNCLEAR.
- **Every matching or normalization rule change needs a test row.**
- Stay inside this folder. Do not touch ROOT, BEM, ServiceOS, or anything outside `C:\inbounds`.

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
- `tests/` — table-driven tests.

## Build status (update at the end of each session)
- Step 1 (normalize + tests): written, tests passing in the build workspace, awaiting the owner's review. Nothing committed.
- Next: step 2 (rules + matcher + the SPEC.md test table as tests).
