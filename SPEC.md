# inbounds: spec (DRAFT v0.1, working name)

Status: v0.1 spec, approved by the owner on 2026-10-18. Build in progress; see the build decisions log at the bottom.

## One line
A small, zero-dependency Python library and CLI that answers "am I allowed to test this target?" against a bug bounty program's scope, with an explainable verdict.

## Positioning (prior art checked 2026-10-18)
- Filters already exist: tomnomnom/inscope (regex .scope file), hacker-scoper (Go, mature: wildcards, regex, CIDR, nmap ranges, "unsure" bucket), scopeX.
- Several Python projects embed their own private matcher: ReconForge (scopecheck), Kambo, h1-mcp, a bounty-platform MCP server.
- Gap: a standalone, importable, rigorously tested matcher with explainable verdicts.
- Differentiator is correctness and reusability, not feature count. Do not chase hacker-scoper on features.
- README must have an honest "Alternatives" section linking the above.

## Goals
- Library first (`Scope.load(path).check(target)`), CLI second.
- Verdict always names the rule that decided it.
- Fail closed: no matching allow rule means OUT_OF_SCOPE. Input we cannot safely interpret means UNCLEAR.
- Python 3.11+, standard library only at runtime (tomllib, ipaddress, urllib.parse).
- Test suite is the credibility: table-driven, adversarial edge cases.

## Non-goals (v1)
- No network calls, no DNS resolution, no scanning, no scraping HackerOne/Bugcrowd/etc.
- No importers (Burp, platform exports) in v1.
- No real program scope files in the repo. Fictional example only (example.com, 203.0.113.0/24).
- CIDR/range targets (e.g. checking `203.0.113.0/24` itself) return UNCLEAR in v1.
- No Windows-only or GUI work.

## Scope file (TOML)
```toml
[program]
name = "example-program"                    # fictional
captured = 2026-10-18                       # date you copied the scope; drives stale warning
source = "https://example.com/security"     # where you copied it from (informational only, never fetched)

[options]
wildcard_depth = "any"                      # "any": *.example.com matches a.b.example.com; "one": only a.example.com
max_age_days = 90

[rules]
allow = ["*.example.com", "app.example.org", "https://example.net/api/", "203.0.113.0/24"]
deny  = ["admin.example.com", "*.staging.example.com", "203.0.113.7"]
```

## Rule types
- Exact host: `app.example.org` (does not imply subdomains)
- Wildcard host: `*.example.com` (subdomains only; does NOT match the apex `example.com`, list it separately)
- URL prefix: `https://example.net/api/` (scheme + host + path, matched on a path-segment boundary)
- IP: `203.0.113.5` (IPv4 or IPv6)
- CIDR: `203.0.113.0/24` (IPv4 or IPv6)
- Optional `:port` suffix on host rules (see open decisions)

## Verdicts
- Status: `IN_SCOPE`, `OUT_OF_SCOPE`, `UNCLEAR`
- Precedence: deny beats allow. No allow match means OUT_OF_SCOPE ("no allow rule matched").
- Fields: `status`, `rule` (rule text or None), `reason`, `warnings`
- Exit codes (check): 0 IN_SCOPE, 1 OUT_OF_SCOPE, 2 UNCLEAR or error
- Stale scope: if `captured` is older than `max_age_days`, warn on stderr and add a warning to the verdict. Never change the status because of staleness.

## Normalization (before matching)
Lowercase; strip one trailing dot; strip userinfo (host is what follows the last `@` in the authority); bracketed IPv6; IDN to punycode; only http/https URL schemes; anything with whitespace/control characters, an empty string, or an unsupported scheme is UNCLEAR. Numeric-looking hosts (decimal like `2130706433`, hex like `0x7f000001`, octal-ish) are UNCLEAR. Never guess.

## CLI
```
inbounds init <file>                       # write a fictional template scope file
inbounds check <file> <target> [--json]    # one verdict, exit code per above
inbounds filter <file> [--invert]          # stdin -> stdout; prints IN_SCOPE only (--invert: OUT_OF_SCOPE only); UNCLEAR lines go to stderr
```

## Required test table (sample scope above, wildcard_depth = any)
| Target | Expected | Why |
|---|---|---|
| api.example.com | IN_SCOPE | wildcard |
| a.b.example.com | IN_SCOPE (OUT with depth = one) | depth option |
| example.com | OUT_OF_SCOPE | wildcard does not cover apex |
| notexample.com | OUT_OF_SCOPE | lookalike |
| example.com.evil.net | OUT_OF_SCOPE | suffix trick |
| API.EXAMPLE.COM. | IN_SCOPE | case and trailing dot |
| admin.example.com | OUT_OF_SCOPE | deny beats allow |
| x.staging.example.com | OUT_OF_SCOPE | deny wildcard |
| https://api.example.com@evil.net/ | OUT_OF_SCOPE | userinfo trick, real host is evil.net |
| https://example.net/api/v1 | IN_SCOPE | URL prefix |
| https://example.net/apix | OUT_OF_SCOPE | segment boundary |
| https://example.net/ | OUT_OF_SCOPE | host has path-restricted rule only |
| 203.0.113.50 | IN_SCOPE | CIDR |
| 203.0.113.7 | OUT_OF_SCOPE | deny IP beats CIDR |
| 203.0.114.1 | OUT_OF_SCOPE | outside CIDR |
| 2001:db8::1 | OUT_OF_SCOPE | no IPv6 rule |
| bücher.example.com | IN_SCOPE | IDN normalized to punycode |
| 2130706433 | UNCLEAR | obfuscated IP form |
| 0x7f000001 | UNCLEAR | obfuscated IP form |
| ftp://api.example.com | UNCLEAR | unsupported scheme |
| `exa mple.com` / empty string | UNCLEAR | unparseable |
| 203.0.113.0/24 | UNCLEAR | range targets unsupported in v1 |

## Repo layout
```
inbounds/
  CLAUDE.md  README.md  LICENSE (MIT)  SECURITY.md  CHANGELOG.md  pyproject.toml
  src/inbounds/{__init__,normalize,rules,matcher,scopefile,cli}.py
  tests/{test_normalize,test_matcher_table,test_scopefile,test_cli}.py
  examples/example-program.toml          # fictional only
  .github/workflows/ci.yml               # pytest on 3.11, 3.12, 3.13
```

## Build order
1. normalize + tests
2. rules + matcher + the table above as tests
3. scope file loader + stale warning + tests
4. CLI (init, check, filter) + tests
5. README (usage, design decisions, disclaimer, Alternatives) and CI
6. Self-review pass for gaps; then the owner decides on the first commit

## README disclaimer (required, plain language)
The program's published policy is the only authority on scope. This tool is a safety net for typos and recon noise. It can be wrong if the scope file is wrong or stale. Verify before you test.

## CLAUDE.md rules for the repo
- Review and flag only on git: no commit, push, PR, merge, reset, or rebase without the owner's explicit approval.
- No network access in code or tests. No real program data. No secrets, tokens, or .env content anywhere.
- Runtime dependencies stay at zero. Dev dependency: pytest only (ruff optional).
- Every matching rule change needs a row in the test table.

## Definition of done (v1)
All table rows pass. 100% of rule types covered by tests. `pip install .` works clean on a fresh venv. README example copy-pastes and runs. No dependencies at runtime.

## Decisions (resolved 2026-10-18)
1. Name: `inbounds` (not registered on PyPI when checked).
2. Port semantics: a rule without a port matches any port.
3. Default `wildcard_depth`: `any`.
4. `*.example.com` does not match the apex `example.com`.
5. License and author line: MIT, handle only (`CyberDredge`), no email address.

## Build decisions log
Decisions made while building, so the reasoning survives between sessions.

### Step 1: normalization (2026-10-18)
- Outer whitespace (including CRLF from piped input) is stripped. Any whitespace, control, or invisible character inside the target (zero-width, bidi override, non-breaking space) is UNCLEAR.
- A scheme is required for anything with a path. `example.com/path`, `//example.com`, and anything with `?`, `#`, or `@` but no scheme is UNCLEAR.
- Backslashes are UNCLEAR (browsers read them as slashes, other tools do not).
- Query strings and fragments are dropped. Dot-segments in URL paths are resolved before matching (`/api/../admin` becomes `/admin`). Percent-encoded dots, slashes, backslashes, and null bytes in a path are UNCLEAR.
- Path case is preserved. Path rules match case-sensitively (decided in step 2).
- Userinfo in a URL is ignored (the host is what follows the last `@`) and a warning is attached. The warning never repeats the userinfo, since it can hold a password.
- Numeric last label (decimal, hex, octal-style, short forms like `127.1`) is UNCLEAR unless the whole thing is a strict dotted-quad IPv4. Leading zeros such as `203.0.113.050` are UNCLEAR.
- IPv6 zone identifiers (`%eth0`) are UNCLEAR. IPv4-mapped IPv6 (`::ffff:203.0.113.7`) is converted to the IPv4 address with a warning, so a deny rule on the IPv4 address also catches it.
- Ports must be plain ASCII digits, 1 to 65535. Empty or zero ports are UNCLEAR. Only an explicitly written port is recorded.
- Host name labels allow letters, digits, hyphen, and underscore. Wildcards, empty labels, labels over 63 characters, and names over 253 characters are UNCLEAR.
- Internationalized names are converted to punycode with Python's built-in IDNA codec (IDNA 2003 rules).
- Target text longer than 2048 characters is UNCLEAR.

### Step 2: rules and matcher (2026-10-19)
- A rule that cannot be read unambiguously is an error (`RuleError`) when the `Scope` is built, never a guess. Rejected: wildcards anywhere except a leading `*.` (so `https://*.example.com/` and `https://example.net/api/*` are errors for now), a query string or fragment in a rule, userinfo, IPv4-mapped IPv6, a path without a scheme, CIDR with host bits set (`203.0.113.5/24`), and netmask-style CIDR.
- Path rules are case-sensitive and match on a path-segment boundary. A rule path ending in `/` covers everything beneath that directory but not the bare path without the slash (`https://example.net/api/` does not cover `https://example.net/api`); this fails closed. A rule path without a trailing `/` covers that exact path and everything beneath it. A URL rule with no path covers the whole host for that scheme.
- A URL rule needs a URL target with the same scheme and host. A bare host target says nothing about a path, so it never matches a URL rule.
- Ports: a rule without a port matches any port. A rule with a port needs a target whose port is known and equal; a URL target without an explicit port uses the scheme default (http 80, https 443). A bare host with no port has no known port.
- Deny rules that cannot be checked (a deny limited to a port or a URL path, against a target that does not say which port or path) are not applied, and a warning says so. The status is not changed by that warning.
- Deny wildcards always match at any depth, even when `wildcard_depth = "one"`. Allow wildcards follow the option. When in doubt a deny should win.
- Host, wildcard and URL rules never match IP targets by name; IP and CIDR rules never match host names. No DNS lookups, ever.
- The first matching rule in file order is the one named in the verdict. Deny rules are checked before any allow rule.
- A verdict shows the target as typed, except that URL userinfo (`user:password@`) is replaced with `***@`, so a password never reaches output or logs.
- `Scope.load(path)` and the stale-scope warning arrive in step 3; `Scope(allow=..., deny=..., wildcard_depth=...)` is the in-memory form.

### Step 3: scope file loader and stale warning (2026-10-19)
- `Scope.load(path)` (and `inbounds.load_scope`, `inbounds.parse_scope(text)`) read the TOML scope file. Every problem raises `ScopeFileError` with the file name and what to fix. The loader is strict because a quiet mistake in a scope file means testing something you were not allowed to test.
- Unknown keys are errors at the top level and in `[program]`, `[options]` and `[rules]`, so a typo like `denies = [...]` cannot silently drop a deny list.
- `program.captured` is required. It is the only way the tool can tell the scope is out of date. It must be a TOML date (`2026-10-18`) or the same text in quotes; a date with a time of day is rejected.
- `rules.allow` must have at least one rule when loading a file (an empty allow list would make everything OUT_OF_SCOPE and is almost certainly a mistake). `rules.deny` may be empty or missing. An in-memory `Scope()` with no rules is still allowed.
- Each rule is parsed with `parse_rule`; a bad one is reported as `rules.allow[2]` or `rules.deny[0]` with the rule text and the reason.
- `options.wildcard_depth` must be `"any"` or `"one"`. `options.max_age_days` must be a whole number, 1 or more; default 90.
- Files larger than 1 MiB and files that are not UTF-8 are rejected. A UTF-8 byte order mark (common from Windows editors) and CRLF line endings are accepted.
- Stale scope: if `captured` is more than `max_age_days` days before today, every verdict (including UNCLEAR) carries a warning. It is one day over the limit, not at it: exactly `max_age_days` days old is fine. A `captured` date in the future also warns (likely a typo). The warning never changes a status. `Scope.check(target, today=...)` takes a date so tests are deterministic.
- The warning is part of `Verdict.warnings`. The CLI (step 4) is responsible for printing it to stderr once per run, not once per line.
- `examples/example-program.toml` is a fictional scope file. A test loads it and checks it behaves like the in-memory sample scope, so the example cannot drift out of date.

### Step 4: command line interface (2026-10-19)
- Commands: `inbounds init <file> [--force]`, `inbounds check <file> <target> [--json]`, `inbounds filter <file> [--invert]`, plus `--version`. Also runs as `python -m inbounds`. The `inbounds` command is registered as a console script in `pyproject.toml`.
- Exit codes: `check` returns 0 IN_SCOPE, 1 OUT_OF_SCOPE, 2 UNCLEAR or any error. `filter` returns 0 whenever it ran (it is a filter, so "nothing matched" is not a failure) and 2 for a bad scope file or bad usage; UNCLEAR lines are never silent, they are reported on stderr and counted in a closing summary line. `init` returns 0 or 2.
- All warnings (stale scope, userinfo in a URL, IPv4-mapped IPv6, an unapplied port or path deny) go to stderr, in `check` and in `filter`, so stdout stays clean for pipes. `check --json` also carries them in the `warnings` field. In `filter` the stale-scope warning is printed once at the start, not once per line.
- `check` prints three lines (status and target, rule, reason). `--json` prints exactly one ASCII-only JSON object on one line.
- Terminal safety: anything printed from a target, rule, reason or warning has control and invisible characters turned into `\xNN` / `\uNNNN` escapes, so a hostile target cannot rewrite what the terminal shows. Output streams use backslash escapes instead of crashing when the console cannot show a character (a common Windows problem).
- `filter` reads one target per line. Blank lines are skipped. CRLF line endings and a leading byte order mark (from a Windows pipe) are accepted. Lines are read in chunks of at most 4096 characters; a longer line is reported UNCLEAR without being held in memory. In-scope lines are printed exactly as given, so the output can feed the next tool; because of that, a password typed into a URL is passed through unchanged in `filter` output (verdicts and warnings still replace it with `***`).
- If the reader of `filter`'s output closes the pipe early (`| head`), the program exits 0 quietly.
- `init` writes a fictional template with `captured` set to today and refuses to overwrite an existing file unless `--force` is given. It reminds you to use the program's own policy page and not to commit real scope data to a public repo. A test checks the template loads and has the same rules as `examples/example-program.toml`.
- A target that starts with `-` must follow `--` (`inbounds check scope.toml -- -odd.example.com`).

### Step 5: README and CI (2026-10-19)
- The README follows the required shape: one-line purpose, the plain-language disclaimer near the top, install, quick start, library use, the scope file and rule types, what the tool refuses to guess, design decisions, honest limits, and an Alternatives section. It says plainly that the project is pre-release and not on PyPI. Install is `pip install git+https://github.com/CyberDredge/inbounds.git`.
- The README cannot drift from the code: `tests/test_repo_hygiene.py` runs every `$ inbounds ...` example in the README and compares the real output, runs the README's Python example, and checks that relative links exist.
- Alternatives lists only projects whose pages were checked on 2026-10-19: Hacker-Scoper (Go, AGPL-3.0; scope from the firebounty database or custom `.inscope` / `.noscope` files; wildcards, regex, CIDR, nmap ranges; an "unsure" bucket), rescope (Go, MIT; fetches scope from platforms and exports it), and inscope (Go; a `.scope` file filter, described from the earlier prior-art check because its page could not be re-fetched). The Python recon projects found earlier are summarised generically as "home-made checks", not named, because their pages were not re-verified.
- CI (`.github/workflows/ci.yml`): pytest on Python 3.11, 3.12 and 3.13 on Linux and Windows, plus a clean-install job that installs without dev dependencies, runs the `inbounds` command, and checks there are no runtime dependencies. Triggers are `push` to `main` and `pull_request`. Permissions are `contents: read` only, credentials are not persisted, there is no `pull_request_target`, and no secrets are used.
- Actions are pinned to full commit SHAs (a movable tag is a supply-chain risk for a security tool): `actions/checkout` v7.0.1 and `actions/setup-python` v7.0.0, looked up and cross-checked on 2026-10-19. A test fails if any action is not pinned to a 40-character SHA. Keeping the pins current is a manual job for now.
- Repo guards in `tests/test_repo_hygiene.py`: zero runtime dependencies in `pyproject.toml`; the package imports only the standard library and none of the network or subprocess modules; no email addresses other than reserved example domains and the GitHub noreply form; no token or private-key patterns; no personal machine paths; the example scope file uses only reserved names.
- `SECURITY.md` points to GitHub private vulnerability reporting, and says what is and is not a vulnerability (a wrong verdict from a wrong scope file is not). `CHANGELOG.md` starts with an Unreleased entry.
