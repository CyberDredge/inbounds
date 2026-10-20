"""Turn raw target text into a canonical, comparable form.

Design rules (see SPEC.md, "Normalization"):

* Never guess. Anything that cannot be interpreted unambiguously raises
  ``UnclearTarget``; the matcher turns that into an UNCLEAR verdict.
* No network access and no DNS. Pure string and IP handling.
* Scope mistakes hide in parser differences, so inputs that different tools
  read differently (backslashes, percent-encoded dots or slashes, numeric IP
  shorthand, IPv6 zone ids, invisible characters) are refused, not "fixed".
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

MAX_TARGET_LENGTH = 2048
MAX_HOSTNAME_LENGTH = 253
ALLOWED_SCHEMES = frozenset({"http", "https"})

_SCHEME_PREFIX_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://")
_AUTHORITY_RE = re.compile(r"(?P<host>\[[0-9A-Fa-f:.]+\]|[^:\[\]@]+)(?::(?P<port>[0-9]{1,5}))?")
_LABEL_RE = re.compile(r"[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?")
_NUMERIC_LABEL_RE = re.compile(r"0x[0-9a-f]*|[0-9]+")
_RISKY_PATH_ENCODING_RE = re.compile(r"%(2e|2f|5c|00)", re.IGNORECASE)

# The four IDNA "deviation" characters (UTS #46): sharp s, final sigma, and the two
# joiners. Python's codec follows IDNA 2003, which turns "ß" into "ss" and "ς" into
# "σ" and drops the joiners. Current browsers keep them, so the two read the same
# text as different hosts. That is the kind of parser difference this tool refuses.
_IDNA_DEVIATION_CHARS = frozenset("\u00df\u03c2\u200c\u200d")


class UnclearTarget(ValueError):
    """The input cannot be interpreted safely. ``reason`` says why."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Target:
    """A normalized target.

    ``host`` is the lowercase ASCII (punycode) host name, or the canonical text
    of the IP address. ``path`` is set for URL targets only, with dot-segments
    resolved. Query strings and fragments are dropped.
    """

    raw: str
    host: str
    ip: IPAddress | None = None
    scheme: str | None = None
    port: int | None = None
    path: str | None = None
    warnings: tuple[str, ...] = ()

    @property
    def is_ip(self) -> bool:
        return self.ip is not None

    @property
    def is_url(self) -> bool:
        return self.scheme is not None


def normalize_hostname(host: str) -> str:
    """Return the canonical lowercase ASCII (punycode) form of a DNS host name.

    Raises ``UnclearTarget`` for anything that is not a plain, valid host name,
    including numeric hosts that look like obfuscated IP addresses.
    """
    for ch in host:  # the raw text: lower() can turn a capital sigma into a final sigma
        if ch in _IDNA_DEVIATION_CHARS:
            raise UnclearTarget(
                f"host name contains U+{ord(ch):04X}, which older and current standards "
                "turn into different hosts (write the xn-- form if you mean it)"
            )
    name = host.lower()
    if name.endswith("."):
        name = name[:-1]
    if not name:
        raise UnclearTarget("empty host name")
    try:
        name = name.encode("idna").decode("ascii")
    except UnicodeError:
        raise UnclearTarget(
            "host name is not valid (empty or oversized label, or bad internationalized name)"
        ) from None
    if len(name) > MAX_HOSTNAME_LENGTH:
        raise UnclearTarget("host name is too long")
    labels = name.split(".")
    for label in labels:
        if not _LABEL_RE.fullmatch(label):
            raise UnclearTarget(f"host name has an invalid character or shape in label {label!r}")
    if _NUMERIC_LABEL_RE.fullmatch(labels[-1]):
        raise UnclearTarget(
            "numeric host is not a canonical IP address (possible obfuscated IP form)"
        )
    return name


def normalize(raw: str) -> Target:
    """Normalize one target string, or raise ``UnclearTarget`` with the reason."""
    if not isinstance(raw, str):
        raise UnclearTarget("target must be text")
    text = raw.strip()
    if not text:
        raise UnclearTarget("empty target")
    if len(text) > MAX_TARGET_LENGTH:
        raise UnclearTarget("target is too long")
    _reject_unsafe_characters(text)

    prefix = _SCHEME_PREFIX_RE.match(text)
    if prefix is not None:
        return _normalize_url(raw, text, prefix.end())
    if "://" in text:
        raise UnclearTarget("malformed scheme before '://'")
    return _normalize_schemeless(raw, text)


def _reject_unsafe_characters(text: str) -> None:
    for ch in text:
        if unicodedata.category(ch)[0] in ("C", "Z"):
            raise UnclearTarget(
                f"contains whitespace or an invisible or control character (U+{ord(ch):04X})"
            )
    if "\\" in text:
        raise UnclearTarget("contains a backslash, which different tools read as a slash")


def _try_ip(text: str) -> tuple[IPAddress, tuple[str, ...]] | None:
    """Parse strict IP text. Returns None when the text is not an IP at all."""
    if "%" in text:
        if ":" in text:
            raise UnclearTarget("IPv6 zone identifiers are not supported")
        return None
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped, ("IPv4-mapped IPv6 address was treated as its IPv4 address",)
    return ip, ()


def _split_authority(hostport: str) -> tuple[str, bool, int | None]:
    """Split ``host[:port]`` into (host text, was bracketed, port)."""
    match = _AUTHORITY_RE.fullmatch(hostport)
    if match is None:
        raise UnclearTarget("malformed host or port")
    host = match.group("host")
    bracketed = host.startswith("[")
    if bracketed:
        host = host[1:-1]
    port_text = match.group("port")
    port = int(port_text) if port_text is not None else None
    if port is not None and not 1 <= port <= 65535:
        raise UnclearTarget("port is out of range")
    return host, bracketed, port


def _classify_host(host_text: str, bracketed: bool) -> tuple[str, IPAddress | None, tuple[str, ...]]:
    found = _try_ip(host_text)
    if bracketed and (found is None or ":" not in host_text):
        raise UnclearTarget("a bracketed host must be an IPv6 address")
    if found is not None:
        ip, warnings = found
        return str(ip), ip, warnings
    return normalize_hostname(host_text), None, ()


def _normalize_schemeless(raw: str, text: str) -> Target:
    if "/" in text:
        try:
            ipaddress.ip_network(text, strict=False)
        except ValueError:
            raise UnclearTarget(
                "text after the host needs a scheme (https://...) to be interpreted"
            ) from None
        raise UnclearTarget("address ranges (CIDR) are not supported as targets in v1")
    for ch in "?#@":
        if ch in text:
            raise UnclearTarget(f"{ch!r} in a target without a scheme is ambiguous")

    bare = _try_ip(text)
    if bare is not None:
        ip, warnings = bare
        return Target(raw=raw, host=str(ip), ip=ip, warnings=warnings)

    host_text, bracketed, port = _split_authority(text)
    host, ip, warnings = _classify_host(host_text, bracketed)
    return Target(raw=raw, host=host, ip=ip, port=port, warnings=warnings)


def _normalize_url(raw: str, text: str, prefix_end: int) -> Target:
    scheme = text[: prefix_end - 3].lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UnclearTarget(f"unsupported scheme {scheme!r} (only http and https)")

    rest = text[prefix_end:]
    cut = len(rest)
    for ch in "/?#":
        idx = rest.find(ch)
        if idx != -1:
            cut = min(cut, idx)
    authority, tail = rest[:cut], rest[cut:]
    if not authority:
        raise UnclearTarget("URL has no host")

    userinfo, at, hostport = authority.rpartition("@")
    host_text, bracketed, port = _split_authority(hostport)
    host, ip, warnings = _classify_host(host_text, bracketed)
    if at:
        # Never echo the userinfo itself: it may hold a password.
        warnings = (*warnings, f"userinfo in the URL was ignored; the real host is {host}")

    path_part = tail.split("?", 1)[0].split("#", 1)[0]
    if _RISKY_PATH_ENCODING_RE.search(path_part):
        raise UnclearTarget(
            "path contains an encoded dot, slash, backslash or null byte, "
            "which servers decode differently"
        )
    path = _remove_dot_segments(path_part or "/")
    return Target(
        raw=raw, host=host, ip=ip, scheme=scheme, port=port, path=path, warnings=warnings
    )


def _remove_dot_segments(path: str) -> str:
    """Resolve ``.`` and ``..`` segments (RFC 3986 section 5.2.4 behaviour)."""
    segments = path.split("/")[1:]
    out: list[str] = []
    for i, seg in enumerate(segments):
        last = i == len(segments) - 1
        if seg == ".":
            if last:
                out.append("")
        elif seg == "..":
            if out:
                out.pop()
            if last:
                out.append("")
        else:
            out.append(seg)
    return "/" + "/".join(out)
