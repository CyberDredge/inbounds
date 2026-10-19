# Security policy

`inbounds` helps people avoid testing targets they are not allowed to test, so a wrong verdict is a security-relevant bug. Examples:

- a target that should be `OUT_OF_SCOPE` or `UNCLEAR` comes back `IN_SCOPE`;
- a way to make two tools read the same text differently that the normalizer does not catch;
- a crash, hang, or very slow run caused by a crafted target or scope file;
- a secret (such as a URL password) appearing in output.

## Reporting

Please report these **privately**: use GitHub's private vulnerability reporting on this repository (the **Security** tab, then **Report a vulnerability**). Please do not open a public issue for a bypass.

Include the scope file (or just the rules), the target text, the verdict you got, and the verdict you expected. This is a small project run by one person, so there is no fixed response time, but reports are read.

## What is not a vulnerability

- The tool's verdicts depend entirely on the scope file you give it. A wrong, old, or incomplete scope file gives wrong verdicts by design; see the disclaimer in the README.
- A host that is in scope on paper but resolves to a third party. The tool does no DNS lookups.

Supported versions: only the latest commit on `main` while the project is pre-release.
