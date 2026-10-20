# inbounds

[![CI](https://github.com/CyberDredge/inbounds/actions/workflows/ci.yml/badge.svg)](https://github.com/CyberDredge/inbounds/actions/workflows/ci.yml)

Check a target against a bug bounty program's scope. Zero dependencies.

> **Disclaimer:** The program's published policy is the only authority on scope. This tool is a safety net for typos and recon noise. It can be wrong if the scope file is wrong or stale. Verify before you test.

`inbounds` answers one question: *am I allowed to test this target?* It gives one of three answers, and always says which rule decided it.

| Verdict | Meaning |
|---|---|
| `IN_SCOPE` | An allow rule matched and no deny rule did. |
| `OUT_OF_SCOPE` | A deny rule matched, or no allow rule matched. |
| `UNCLEAR` | The input cannot be read safely, so the tool refuses to guess. |

It is a Python library first and a command line tool second. It needs Python 3.11 or newer, uses only the standard library, and never touches the network.

> **Status: pre-release (0.1.0.dev0).** Everything described here works and is tested, but the API and scope file format may still change before 0.1.0. It is not on PyPI yet.

## Install

```
pip install git+https://github.com/CyberDredge/inbounds.git
```

To work on it instead, see [Development](#development).

## Quick start

Write a template scope file, then check a target against it:

```
inbounds init scope.toml
inbounds check scope.toml api.example.com
```

```
IN_SCOPE  api.example.com
  rule:    *.example.com
  reason:  allowed by rule *.example.com
```

The template is fictional. Replace its rules with the scope from the program's own policy page, and set `captured` to the day you copied it.

A few more targets against the template. The exit code is 0 for `IN_SCOPE`, 1 for `OUT_OF_SCOPE` and 2 for `UNCLEAR`:

```
$ inbounds check scope.toml example.com
OUT_OF_SCOPE  example.com
  rule:    (none)
  reason:  no allow rule matched

$ inbounds check scope.toml admin.example.com
OUT_OF_SCOPE  admin.example.com
  rule:    admin.example.com
  reason:  denied by rule admin.example.com

$ inbounds check scope.toml 2130706433
UNCLEAR  2130706433
  rule:    (none)
  reason:  numeric host is not a canonical IP address (possible obfuscated IP form)
```

Add `--json` for one machine-readable line:

```
$ inbounds check scope.toml admin.example.com --json
{"status": "OUT_OF_SCOPE", "target": "admin.example.com", "rule": "admin.example.com", "reason": "denied by rule admin.example.com", "warnings": []}
```

### Filtering a list

`filter` reads one target per line from standard input and prints only the in-scope lines:

```
cat hosts.txt | inbounds filter scope.toml          # macOS / Linux
Get-Content hosts.txt | inbounds filter scope.toml  # PowerShell
```

- `--invert` prints the out-of-scope lines instead.
- Lines it cannot read (`UNCLEAR`) are never printed to standard output. They are reported on standard error with the reason, plus a count at the end, so nothing disappears silently.
- Blank lines are skipped.

### Exit codes

| Command | 0 | 1 | 2 |
|---|---|---|---|
| `check` | IN_SCOPE | OUT_OF_SCOPE | UNCLEAR, or any error |
| `filter` | it ran | | bad scope file or bad usage |
| `init` | written | | error (for example, the file exists; use `--force`) |

Warnings (an out-of-date scope, a password inside a URL, and so on) always go to standard error, so standard output stays clean for pipes.

## Use it as a library

```python
from inbounds import Scope

scope = Scope.load("scope.toml")
verdict = scope.check("https://api.example.com/v1")
print(verdict.status, verdict.rule, verdict.reason, verdict.warnings)
# IN_SCOPE *.example.com allowed by rule *.example.com ()

scope = Scope(allow=["*.example.com"], deny=["admin.example.com"])
print(scope.check("admin.example.com").status)   # OUT_OF_SCOPE
print(scope.check("example.com").status)         # OUT_OF_SCOPE: a wildcard does not cover its apex
```

`check` never raises on bad input; an unreadable target comes back as `UNCLEAR`. A scope file or rule that cannot be read raises `ScopeFileError` or `RuleError` when you build the `Scope`, so a broken scope never produces verdicts.

## The scope file

```toml
[program]
name = "example-program"
captured = 2026-10-18        # the date you copied the scope; required
source = "https://example.com/security"   # informational only, never fetched

[options]
wildcard_depth = "any"       # "any": *.example.com matches a.b.example.com; "one": only a.example.com
max_age_days = 90            # warn when the scope is older than this

[rules]
allow = ["*.example.com", "app.example.org", "https://example.net/api/", "203.0.113.0/24"]
deny  = ["admin.example.com", "*.staging.example.com", "203.0.113.7"]
```

The loader is strict on purpose. A misspelled key such as `denies` is an error, not a silently dropped deny list. `captured` is required, and `allow` must not be empty.

### Rule types

| Rule | Example | Matches |
|---|---|---|
| Exact host | `app.example.org` | That host only, not its subdomains. |
| Wildcard host | `*.example.com` | Subdomains only. **Not** `example.com` itself; list the apex separately. |
| URL prefix | `https://example.net/api/` | That scheme and host, and paths beneath `/api/` on a path-segment boundary. `/apix` does not match. |
| IP | `203.0.113.5`, `2001:db8::1` | That address, in any spelling. |
| CIDR | `203.0.113.0/24`, `2001:db8::/32` | Any address in the range. |

Host, wildcard and IP rules may end in `:port`. A rule without a port matches any port.

## What it refuses to guess

Scope mistakes hide in the gaps between how different tools read the same text, so `inbounds` returns `UNCLEAR` rather than "fixing" these:

- Obfuscated IPs: `2130706433`, `0x7f000001`, `0177.0.0.1`, `127.1`, `203.0.113.050`.
- Whitespace, control characters, zero-width and bidirectional-override characters inside a target.
- Backslashes (browsers read them as slashes), and percent-encoded dots, slashes or null bytes in a URL path.
- Any scheme other than `http` and `https`; a path with no scheme; IPv6 zone identifiers; address ranges as targets.
- Wildcards, empty labels and over-long names in a target.
- Internationalized names containing `ß` or `ς`. Older and current standards turn them into different hosts, so the tool will not pick one. Write the `xn--` form if you mean that host. This applies to scope-file rules as well as targets.

It does normalize the things that are safe to normalize: case, one trailing dot, internationalized names (converted to punycode), IPv6 spelling, `..` and `.` path segments, and the userinfo trick. In `https://api.example.com@evil.net/` the real host is `evil.net`, and the tool says so.

Unicode look-alikes are mapped the way browsers map them, without a warning: full-width letters (`ａ` becomes `a`) and the dot-like characters `。`, `．` and `｡` become a plain `.`. The verdict is for the host that results. If you would rather refuse these, filter non-ASCII input out before it reaches `inbounds`.

## Design decisions

- **Fail closed.** No allow rule means `OUT_OF_SCOPE`. Anything uninterpretable means `UNCLEAR`.
- **Deny beats allow**, whatever order the rules are in. Deny wildcards always match at any depth, even when `wildcard_depth = "one"`.
- **The verdict names its rule.** When several rules match, the first one in file order is named.
- **Paths are case-sensitive**, and a rule ending in `/` does not cover the bare path (`https://example.net/api/` does not cover `https://example.net/api`). Drop the trailing slash on the rule if you want both.
- **A stale scope warns but never changes a verdict.** If `captured` is more than `max_age_days` old, every verdict carries a warning.
- **No network, ever.** No DNS lookups, no scraping, no fetching the `source` URL. The scope file is something you copy in by hand.
- **Safe output.** A password typed into a URL is shown as `***` in verdicts and warnings, and control characters in a target are printed as escapes so a hostile target cannot rewrite your terminal.

The full reasoning is in [SPEC.md](SPEC.md), including a log of each build decision.

## Limits

- It checks text, not reality. A host that is in scope on paper can resolve to a third party's server, redirect elsewhere, or sit behind a CDN. With no DNS, the tool cannot see that.
- It only knows the scope you give it. If the scope file is wrong, old, or missing a rule, the verdicts are wrong.
- Scope is only part of a program's rules. Rate limits, forbidden test types, and safe-harbor terms are not modelled.
- Internationalized names use Python's built-in IDNA 2003 codec. The four characters where it differs from browsers (`ß`, `ς` and the two joiners) are refused rather than guessed.
- Range targets (checking `203.0.113.0/24` itself) are `UNCLEAR` in v1.

## Alternatives

`inbounds` is not the first scope filter, and for some jobs the others are the better pick.

- **[Hacker-Scoper](https://github.com/ItsIgnacioPortal/Hacker-Scoper)** (Go, AGPL-3.0). A mature filter for URLs, domains and IPs. It can pull scope automatically from the firebounty database, or read your own `.inscope` and `.noscope` files, and it matches wildcards, regex, CIDR and nmap-style ranges. It also has an "unsure" bucket. Use it if you want scope fetched for you or need regex and range rules.
- **[inscope](https://github.com/tomnomnom/inscope)** (Go, by Tom Hudson). A small, fast filter that checks lines from standard input against a `.scope` file of patterns. Use it for quick shell pipelines.
- **[rescope](https://github.com/root4loot/rescope)** (Go, MIT). Fetches scope definitions from bug bounty platforms and exports them as text, JSON, or Burp Suite and OWASP ZAP scope files. It does a different job (getting scope into your tools), and it pairs with a matcher like this one rather than replacing it.
- **Home-made checks.** Many recon scripts and frameworks carry their own small scope check. That code is usually hard to reuse and rarely tested against hostile input.

Where `inbounds` aims to be different is correctness and reuse: an importable library with explainable verdicts, a test suite built around adversarial inputs, and zero dependencies. It does not fetch scope, import platform exports, or chase the others on features.

## Development

```
git clone https://github.com/CyberDredge/inbounds.git
cd inbounds
python -m venv .venv
.venv\Scripts\Activate.ps1        # PowerShell; on macOS / Linux: source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

The tests are table-driven. `tests/test_matcher_table.py` holds the required test table from [SPEC.md](SPEC.md) row for row. Every matching or normalization rule change needs a test row. CI runs the suite on Python 3.11, 3.12 and 3.13, on Linux and Windows.

```
src/inbounds/
  normalize.py   target text -> canonical form, or UNCLEAR
  rules.py       rule text -> typed rules
  matcher.py     Scope, Verdict, Status
  scopefile.py   TOML scope file loader
  cli.py         inbounds init | check | filter
```

This repository is public. Never commit real program scope data, tokens, or personal details. Examples use only `example.com`, `example.net`, `example.org` and the documentation address ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). Real scope files belong outside the repository; `/scopes/` and `*.private.toml` are already git-ignored.

## Security

See [SECURITY.md](SECURITY.md) for how to report a problem privately.

## License

[MIT](LICENSE)
