"""``robots.txt`` parsing and matching per RFC 9309.

The scanner only fetches pages a site lists, but it still asks each origin's ``robots.txt``
first unless the site opts out (checkout pages are often disallowed for crawlers, and the
site owner may want them scanned anyway).

Python's :mod:`urllib.robotparser` predates RFC 9309: it has no ``*`` or ``$`` wildcards
and applies the first matching rule rather than the longest. This module implements the
RFC's rules directly:

* groups start with one or more ``user-agent`` lines; every group whose product token
  matches ours (case-insensitively) is combined, and only if none match are the ``*``
  groups used;
* the most specific (longest) matching rule wins, and ``allow`` wins a tie;
* ``*`` matches any sequence of characters and a trailing ``$`` anchors the end;
* ``/robots.txt`` itself is always allowed;
* only the first 500 KiB are parsed.

The HTTP status semantics (4xx means "no rules", 5xx or unreachable means "disallow
everything") live in :mod:`script_sentinel.fetch`, which builds the policy.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from urllib.parse import quote, urlsplit

# RFC 9309 section 2.5: crawlers must parse at least 500 kibibytes.
MAX_ROBOTS_BYTES = 500 * 1024

_LINE = re.compile(r"^\s*([A-Za-z-]+)\s*:\s*(.*?)\s*$")
_PERCENT = re.compile(r"%([0-9A-Fa-f]{2})")
# Characters RFC 3986 calls unreserved: percent-encoding them changes nothing.
_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")


@dataclass(frozen=True, slots=True)
class Rule:
    allow: bool
    pattern: str

    def matches(self, path: str) -> bool:
        return _compile(self.pattern).match(path) is not None


@dataclass(slots=True)
class _Group:
    agents: list[str] = field(default_factory=list)
    rules: list[Rule] = field(default_factory=list)


def _normalize(value: str) -> str:
    """Canonical percent-encoding, so ``/a%7eb`` and ``/a~b`` compare equal.

    Escapes of unreserved characters are decoded, other escapes get uppercase hex, and
    characters outside printable ASCII are percent-encoded as UTF-8.
    """

    def fix(match: re.Match[str]) -> str:
        char = chr(int(match.group(1), 16))
        return char if char in _UNRESERVED else "%" + match.group(1).upper()

    value = _PERCENT.sub(fix, value)
    return quote(value, safe="/?&=;:@!$'()*+,%#[]~-._")


@lru_cache(maxsize=4096)
def _compile(pattern: str) -> re.Pattern[str]:
    anchored = pattern.endswith("$")
    body = pattern[:-1] if anchored else pattern
    regex = ".*".join(re.escape(part) for part in body.split("*"))
    return re.compile(regex + ("$" if anchored else ""), re.DOTALL)


def _specificity(rule: Rule) -> int:
    # RFC 9309 section 2.2.2: "the most specific match found MUST be used. The most
    # specific match is the match that has the most octets."
    return len(rule.pattern.encode("utf-8"))


def _parse(text: str) -> list[_Group]:
    groups: list[_Group] = []
    current: _Group | None = None
    in_agents = False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0]
        match = _LINE.match(line)
        if match is None:
            continue
        key, value = match.group(1).lower(), match.group(2)
        if key == "user-agent":
            if current is None or not in_agents:
                current = _Group()
                groups.append(current)
            current.agents.append(value.lower())
            in_agents = True
        elif key in ("allow", "disallow"):
            in_agents = False
            if current is None or not value:
                # Rules before any user-agent line belong to no group, and an empty
                # pattern matches nothing.
                continue
            current.rules.append(Rule(allow=key == "allow", pattern=_normalize(value)))
        # Other keys (sitemap, crawl-delay, ...) are not rules and don't end a group.
    return groups


@dataclass(frozen=True, slots=True)
class RobotsPolicy:
    """The rules that apply to one user agent on one origin."""

    rules: tuple[Rule, ...] = ()
    disallow_all: bool = False
    # Why the policy looks like this, for scan snapshots ("parsed", "unavailable", ...).
    source: str = "parsed"

    @classmethod
    def allow_everything(cls, source: str) -> RobotsPolicy:
        return cls(source=source)

    @classmethod
    def disallow_everything(cls, source: str) -> RobotsPolicy:
        return cls(disallow_all=True, source=source)

    @classmethod
    def parse(cls, content: str | bytes, product_token: str) -> RobotsPolicy:
        """The policy ``content`` sets for ``product_token`` (e.g. ``script-sentinel``)."""
        if isinstance(content, bytes):
            content = content[:MAX_ROBOTS_BYTES].decode("utf-8", errors="replace")
        else:
            content = content.encode("utf-8")[:MAX_ROBOTS_BYTES].decode("utf-8", errors="ignore")
        token = product_token.lower()
        groups = _parse(content)
        mine = [g for g in groups if token in g.agents]
        if not mine:
            mine = [g for g in groups if "*" in g.agents]
        return cls(rules=tuple(rule for g in mine for rule in g.rules))

    def can_fetch(self, url: str) -> bool:
        """Whether ``url`` (absolute, or a path) may be fetched."""
        parts = urlsplit(url)
        path = parts.path or "/"
        if path == "/robots.txt":
            return True
        if self.disallow_all:
            return False
        target = _normalize(path)
        if parts.query:
            target += "?" + _normalize(parts.query)
        best: Rule | None = None
        for rule in self.rules:
            if not rule.matches(target):
                continue
            if (
                best is None
                or _specificity(rule) > _specificity(best)
                or (_specificity(rule) == _specificity(best) and rule.allow)
            ):
                best = rule
        return best is None or best.allow
