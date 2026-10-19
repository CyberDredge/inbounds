"""Guards for a public repository: honest docs, pinned CI, zero dependencies, no leaks."""

from __future__ import annotations

import ast
import io
import re
import shlex
import sys
import tomllib
from pathlib import Path

import pytest

from inbounds.cli import main

ROOT = Path(__file__).resolve().parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")


def cli(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, stdin=io.StringIO(""), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


# ---- the README tells the truth -----------------------------------------------------------


def readme_examples() -> list[tuple[str, str]]:
    """(command line, expected output) for every `$ inbounds ...` example in the README."""
    examples = []
    lines = README.splitlines()
    for i, line in enumerate(lines):
        if line.startswith("$ inbounds "):
            expected = []
            for following in lines[i + 1 :]:
                if not following.strip() or following.startswith("```") or following.startswith("$ "):
                    break
                expected.append(following)
            examples.append((line[2:], "\n".join(expected)))
    return examples


def test_readme_has_examples_to_check():
    assert len(readme_examples()) >= 4


@pytest.mark.parametrize("command,expected", readme_examples(), ids=lambda v: v[:40])
def test_readme_cli_examples_match_real_output(tmp_path, command, expected):
    scope = tmp_path / "scope.toml"
    assert cli(["init", str(scope)])[0] == 0
    argv = shlex.split(command)[1:]
    argv = [str(scope) if part == "scope.toml" else part for part in argv]
    _, out, _ = cli(argv)
    assert out.rstrip("\n") == expected


def test_readme_first_quick_start_output_matches(tmp_path):
    scope = tmp_path / "scope.toml"
    cli(["init", str(scope)])
    _, out, _ = cli(["check", str(scope), "api.example.com"])
    assert out.rstrip("\n") in README


def test_readme_python_example_runs(tmp_path, monkeypatch):
    block = re.search(r"```python\n(.*?)```", README, re.DOTALL)
    assert block, "README has no python example"
    monkeypatch.chdir(tmp_path)
    assert cli(["init", "scope.toml"])[0] == 0
    captured = io.StringIO()
    monkeypatch.setattr(sys, "stdout", captured)
    exec(compile(block.group(1), "README.md", "exec"), {"__name__": "__readme__"})
    printed = captured.getvalue().splitlines()
    assert printed == [
        "IN_SCOPE *.example.com allowed by rule *.example.com ()",
        "OUT_OF_SCOPE",
        "OUT_OF_SCOPE",
    ]


def test_readme_keeps_the_required_disclaimer_and_alternatives():
    assert "The program's published policy is the only authority on scope." in README
    assert "Verify before you test." in README
    assert "## Alternatives" in README
    for link in (
        "https://github.com/ItsIgnacioPortal/Hacker-Scoper",
        "https://github.com/tomnomnom/inscope",
        "https://github.com/root4loot/rescope",
    ):
        assert link in README


def test_every_relative_link_in_the_readme_exists():
    for target in re.findall(r"\]\(([^)#]+)(?:#[^)]*)?\)", README):
        if "://" in target:
            continue
        assert (ROOT / target).exists(), target


# ---- CI is pinned and least-privilege ---------------------------------------------------------


WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))


def test_there_is_a_ci_workflow():
    assert any(p.name == "ci.yml" for p in WORKFLOWS)


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_workflow_actions_are_pinned_to_a_commit_sha(workflow):
    text = workflow.read_text(encoding="utf-8")
    uses = re.findall(r"^\s*-?\s*uses:\s*(\S+)", text, re.MULTILINE)
    assert uses
    for ref in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", ref), f"not pinned to a full SHA: {ref}"


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_workflow_is_least_privilege(workflow):
    text = workflow.read_text(encoding="utf-8")
    assert re.search(r"^permissions:\s*\n\s+contents:\s*read\s*$", text, re.MULTILINE)
    assert "pull_request_target" not in text
    assert "secrets." not in text
    assert "persist-credentials: false" in text


def test_ci_covers_the_supported_python_versions():
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    for version in ("3.11", "3.12", "3.13"):
        assert f'"{version}"' in text


# ---- zero runtime dependencies -------------------------------------------------------------------


def test_pyproject_declares_no_runtime_dependencies():
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["dependencies"] == []
    assert data["project"]["optional-dependencies"]["dev"] == ["pytest>=8"]
    assert data["project"]["requires-python"] == ">=3.11"


def test_package_imports_only_the_standard_library():
    allowed = set(sys.stdlib_module_names) | {"inbounds"}
    for path in (ROOT / "src" / "inbounds").glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module.split(".")[0]]
            for name in names:
                assert name in allowed, f"{path.name} imports non-standard-library module {name!r}"


def test_package_does_no_network_or_process_work():
    banned = {"socket", "urllib.request", "http.client", "requests", "subprocess", "ssl", "ftplib", "smtplib"}
    for path in (ROOT / "src" / "inbounds").glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found = {alias.name for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                found = {node.module}
            else:
                continue
            assert not (found & banned), f"{path.name} imports {found & banned}"


# ---- nothing private in a public repo ---------------------------------------------------------------


SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "build", "dist", "node_modules"}
TEXT_SUFFIXES = {".py", ".md", ".toml", ".yml", ".yaml", ".txt", ".cfg", ".ini"}
TEXT_NAMES = {"LICENSE", ".gitignore", ".gitattributes"}


def repo_text_files() -> list[Path]:
    files = []
    for path in ROOT.rglob("*"):
        parts = set(path.relative_to(ROOT).parts)
        if parts & SKIP_DIRS or any(p.endswith(".egg-info") for p in parts):
            continue
        if path.is_file() and (path.suffix in TEXT_SUFFIXES or path.name in TEXT_NAMES):
            files.append(path)
    return files


ALLOWED_EMAIL_DOMAINS = re.compile(
    r"(?:[\w-]+\.)*(?:example\.(?:com|net|org)|evil\.net|users\.noreply\.github\.com)$", re.IGNORECASE
)
EMAIL_RE = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")
SECRET_PATTERNS = [
    re.compile(r"gh[pousr]_[A-Za-z0-9]{36}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"),
]
# Built in pieces so this file does not match its own rule.
PERSONAL_PATH_MARKERS = ("C:\\Users" + "\\", "One" + "Drive")


def test_the_scan_actually_sees_files():
    names = {p.name for p in repo_text_files()}
    assert {"README.md", "SPEC.md", "cli.py", "ci.yml", "example-program.toml"} <= names


def test_no_real_email_addresses_in_the_repo():
    for path in repo_text_files():
        for match in EMAIL_RE.finditer(path.read_text(encoding="utf-8", errors="replace")):
            assert ALLOWED_EMAIL_DOMAINS.fullmatch(match.group(1)), f"{path.name}: {match.group(0)}"


def test_no_secrets_in_the_repo():
    for path in repo_text_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for pattern in SECRET_PATTERNS:
            assert not pattern.search(text), f"{path.name} matches {pattern.pattern}"


def test_no_personal_paths_in_the_repo():
    for path in repo_text_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for marker in PERSONAL_PATH_MARKERS:
            assert marker not in text, f"{path.name} contains {marker!r}"


def test_example_scope_file_uses_only_reserved_names():
    text = (ROOT / "examples" / "example-program.toml").read_text(encoding="utf-8")
    hosts = re.findall(r"[\w*-]+(?:\.[\w-]+)+", text.split("[rules]", 1)[1])
    for host in hosts:
        assert re.search(r"example\.(?:com|net|org)$|^203\.0\.113\.", host), host
