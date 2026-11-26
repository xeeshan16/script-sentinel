"""What changed between two versions of a script, and how much it matters.

:func:`analyze_change` compares two bodies and returns a :class:`ChangeAnalysis`: the token
diff (:mod:`script_sentinel.diff`), the size and entropy before and after, the URLs and
hosts each body references in its string literals (plus the hosts it hides, see
:mod:`script_sentinel.heuristics`), and the skimmer heuristics' signals and verdicts for
what the new body does that the old one didn't. :func:`change_severity` and
:func:`added_severity` turn that, plus where the script runs, into a severity. Both are
pure functions so the rules can be tested and read on their own.

The severity rules (each step can only raise it):

* a change that only touched comments or whitespace (same normalized hash) is ``info``;
* going back to a body this script served before is ``low``;
* any other code change starts at ``low``;
* growing by more than half (and at least 1 KiB), or the character entropy of a body of
  at least 1 KiB rising by more than 0.3 bits, makes it ``medium``: packing and
  obfuscation do both;
* referencing a host the previous body didn't reference makes it ``high``: that is how
  skimmers send data out;
* each skimmer verdict on the new behaviour raises it to the verdict's severity (reading
  card fields and sending data to another host is ``high``, for example);
* running on a payment page raises the result one level (``high`` becomes ``critical``).

A script that appears on a page an earlier scan inventoried is ``low`` when inline and
``medium`` when external, ``high`` when it comes from a host no other script of the site
uses, raised to the severity of any skimmer verdict on its code, and again one level higher
on a payment page.

A severity says how closely a person should look; the heuristics say where.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from script_sentinel.db.models import Severity
from script_sentinel.diff import TokenDiff, diff_sources, similarity
from script_sentinel.heuristics import Context, Signal, Verdict, assess, inspect
from script_sentinel.jstokens import Token, TokenKind, tokenize, unescape_url_escapes, urls_in

MAX_REFERENCES = 200  # URLs kept per body; hosts are always kept in full
MAX_STORED_HUNKS = 50
MAX_STORED_SIGNALS = 50

GROWTH_RATIO = 0.5
GROWTH_MIN_BYTES = 1024
ENTROPY_RISE_BITS = 0.3

_ORDER = list(Severity)


def raise_severity(severity: Severity, steps: int = 1) -> Severity:
    return _ORDER[min(len(_ORDER) - 1, _ORDER.index(severity) + steps)]


def max_severity(*severities: Severity) -> Severity:
    return max(severities, key=_ORDER.index)


def severity_at_least(severity: Severity, threshold: Severity) -> bool:
    return _ORDER.index(severity) >= _ORDER.index(threshold)


def entropy(text: str) -> float:
    """Shannon entropy in bits per character (0 for an empty string)."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return round(-sum(c / total * math.log2(c / total) for c in counts.values()), 4)


@dataclass(frozen=True, slots=True)
class References:
    """The URLs and hosts a body's string and template literals mention."""

    urls: frozenset[str] = frozenset()
    hosts: frozenset[str] = frozenset()


def references(source: str, tokens: Sequence[Token] | None = None) -> References:
    """URLs in string and template literals, with escapes like ``\\/`` and ``\\x2f`` undone.

    URLs assembled at runtime (``"https://" + host``) are not seen; the skimmer heuristics
    look for that pattern separately.
    """
    urls: set[str] = set()
    hosts: set[str] = set()
    for token in tokenize(source).tokens if tokens is None else tokens:
        if token.kind not in (TokenKind.STRING, TokenKind.TEMPLATE):
            continue
        text = unescape_url_escapes(token.text) if "\\" in token.text else token.text
        if token.kind is TokenKind.TEMPLATE:
            text = text.replace("${", " ")  # a substitution ends the literal text
        for url, host in urls_in(text):
            hosts.add(host)
            if len(urls) < MAX_REFERENCES:
                urls.add(url)
    return References(frozenset(urls), frozenset(hosts))


@dataclass(slots=True)
class ChangeAnalysis:
    """The measurable difference between two bodies of one script."""

    diff: TokenDiff
    old_size: int
    new_size: int
    old_entropy: float
    new_entropy: float
    hosts_added: list[str] = field(default_factory=list)
    hosts_removed: list[str] = field(default_factory=list)
    urls_added: list[str] = field(default_factory=list)
    urls_removed: list[str] = field(default_factory=list)
    # What the new body does that the old one didn't (see script_sentinel.heuristics).
    signals_added: list[Signal] = field(default_factory=list)
    verdicts: list[Verdict] = field(default_factory=list)

    @property
    def size_delta(self) -> int:
        return self.new_size - self.old_size

    @property
    def entropy_delta(self) -> float:
        return round(self.new_entropy - self.old_entropy, 4)

    @property
    def grew_sharply(self) -> bool:
        return (
            self.size_delta >= GROWTH_MIN_BYTES and self.size_delta > self.old_size * GROWTH_RATIO
        )

    @property
    def entropy_rose(self) -> bool:
        # Entropy of a few hundred characters swings with any edit; only count it for
        # bodies large enough for the figure to mean something.
        return self.new_size >= GROWTH_MIN_BYTES and self.entropy_delta > ENTROPY_RISE_BITS

    def to_dict(self, *, max_hunks: int = MAX_STORED_HUNKS) -> dict[str, Any]:
        return {
            "size": {"old": self.old_size, "new": self.new_size, "delta": self.size_delta},
            "entropy": {
                "old": self.old_entropy,
                "new": self.new_entropy,
                "delta": self.entropy_delta,
            },
            "tokens": {
                "old": self.diff.old_tokens,
                "new": self.diff.new_tokens,
                "removed": self.diff.removed,
                "added": self.diff.added,
                "similarity": self.diff.similarity,
            },
            "hosts_added": self.hosts_added,
            "hosts_removed": self.hosts_removed,
            "urls_added": self.urls_added,
            "urls_removed": self.urls_removed,
            "signals_added": [s.to_dict() for s in self.signals_added[:MAX_STORED_SIGNALS]],
            "verdicts": [v.to_dict() for v in self.verdicts],
            "coarse": self.diff.coarse,
            "hunk_count": len(self.diff.hunks),
            "hunks": [h.to_dict() for h in self.diff.hunks[:max_hunks]],
        }


def analyze_change(
    old_source: str,
    new_source: str,
    *,
    old_size: int | None = None,
    new_size: int | None = None,
    context: Context | None = None,
) -> ChangeAnalysis:
    """Compare two bodies. Sizes default to the UTF-8 length of the decoded text.

    ``context`` says which hosts count as the script's own for the skimmer verdicts.
    """
    old_tokens = tokenize(old_source).tokens
    new_tokens = tokenize(new_source).tokens
    old_report = inspect(old_source, old_tokens)
    new_report = inspect(new_source, new_tokens)
    old_refs = references(old_source, old_tokens)
    new_refs = references(new_source, new_tokens)
    old_hosts = old_refs.hosts | old_report.hidden_hosts
    new_hosts = new_refs.hosts | new_report.hidden_hosts
    return ChangeAnalysis(
        diff=diff_sources(old_source, new_source, old_tokens=old_tokens, new_tokens=new_tokens),
        old_size=len(old_source.encode("utf-8")) if old_size is None else old_size,
        new_size=len(new_source.encode("utf-8")) if new_size is None else new_size,
        old_entropy=entropy(old_source),
        new_entropy=entropy(new_source),
        hosts_added=sorted(new_hosts - old_hosts),
        hosts_removed=sorted(old_hosts - new_hosts),
        urls_added=sorted(new_refs.urls - old_refs.urls),
        urls_removed=sorted(old_refs.urls - new_refs.urls),
        signals_added=new_report.new_since(old_report),
        verdicts=assess(new_report, context, previous=old_report),
    )


@dataclass(frozen=True, slots=True)
class Assessment:
    severity: Severity
    reasons: tuple[str, ...]


def change_severity(
    analysis: ChangeAnalysis | None,
    *,
    cosmetic: bool,
    reverted: bool,
    payment_page: bool,
) -> Assessment:
    """The severity of a script serving a new body (see the module docs for the rules)."""
    reasons: list[str] = []
    if cosmetic:
        severity = Severity.INFO
        reasons.append("only comments or whitespace changed")
    else:
        severity = Severity.LOW
        reasons.append("went back to an earlier body" if reverted else "the code changed")
        if analysis is not None and not reverted:
            if analysis.grew_sharply:
                severity = max_severity(severity, Severity.MEDIUM)
                reasons.append(f"grew by {analysis.size_delta} bytes")
            if analysis.entropy_rose:
                severity = max_severity(severity, Severity.MEDIUM)
                reasons.append(f"entropy rose by {analysis.entropy_delta} bits per character")
            if analysis.hosts_added:
                severity = max_severity(severity, Severity.HIGH)
                reasons.append("references new hosts: " + ", ".join(analysis.hosts_added[:5]))
        if analysis is not None:
            # Going back to an earlier body counts too: it may be the skimmer coming back.
            severity = _apply_verdicts(severity, reasons, analysis.verdicts)
    if payment_page and severity is not Severity.INFO:
        severity = raise_severity(severity)
        reasons.append("runs on a payment page")
    return Assessment(severity, tuple(reasons))


def _apply_verdicts(
    severity: Severity, reasons: list[str], verdicts: Sequence[Verdict]
) -> Severity:
    for verdict in verdicts:
        severity = max_severity(severity, verdict.severity)
        reasons.append(verdict.reason)
    return severity


def suspicious_severity(verdicts: Sequence[Verdict], *, payment_page: bool) -> Assessment | None:
    """The severity of a script found on a page's first scan, if the heuristics say it
    looks like a skimmer (a ``high`` verdict or worse); ``None`` otherwise.

    A page's first scan is its baseline and raises nothing by itself, but a skimmer that
    was already there when monitoring started shouldn't become part of the baseline quietly.
    """
    if not any(severity_at_least(v.severity, Severity.HIGH) for v in verdicts):
        return None
    reasons = ["found on the page's first scan"]
    severity = _apply_verdicts(Severity.INFO, reasons, verdicts)
    if payment_page:
        severity = raise_severity(severity)
        reasons.append("runs on a payment page")
    return Assessment(severity, tuple(reasons))


def added_severity(
    *, inline: bool, new_host: bool, payment_page: bool, verdicts: Sequence[Verdict] = ()
) -> Assessment:
    """The severity of a script that appeared on a page inventoried before."""
    if inline:
        severity, reasons = Severity.LOW, ["a new inline script"]
    elif new_host:
        severity, reasons = Severity.HIGH, ["a new external script from a host no other uses"]
    else:
        severity, reasons = Severity.MEDIUM, ["a new external script"]
    severity = _apply_verdicts(severity, reasons, verdicts)
    if payment_page:
        severity = raise_severity(severity)
        reasons.append("runs on a payment page")
    return Assessment(severity, tuple(reasons))


# --- Matching inline blocks across scans -------------------------------------------------


@dataclass(frozen=True, slots=True)
class KnownBlock:
    """An inline script already in the inventory for a page, with its current body."""

    index: int  # the n of its "#inline-<n>" locator
    sha384: str | None
    normalized_sha384: str | None
    text: str | None


@dataclass(frozen=True, slots=True)
class SeenBlock:
    """An inline script found on the page this scan."""

    position: int  # its inline_index on the page this scan (1-based)
    sha384: str
    normalized_sha384: str
    text: str


MATCH_THRESHOLD = 0.6
_MAX_SIMILARITY_PAIRS = 2_500  # 50 x 50 blocks; beyond that only hashes and positions


def match_inline_blocks(known: Sequence[KnownBlock], seen: Sequence[SeenBlock]) -> list[int]:
    """The locator index for each block in ``seen``, in order.

    Blocks keep their identity when the page inserts, removes or reorders inline scripts:

    1. a block with the exact body of a known block takes its index;
    2. then one with the same normalized body (only comments or whitespace changed);
    3. then the most similar known block, if the token similarity is at least
       ``MATCH_THRESHOLD`` (an edited block is a new version of the same script);
    4. then the block's own position, if no other block claimed that index (so a block
       rewritten beyond recognition in place is still a new version of the same script);
    5. anything left gets a new index after every index ever used on the page.
    """
    result: list[int | None] = [None] * len(seen)
    free = {block.index: block for block in known}

    def claim(key: str) -> None:
        for i, block in enumerate(seen):
            if result[i] is not None:
                continue
            wanted = block.sha384 if key == "sha384" else block.normalized_sha384
            for index in sorted(free):
                candidate = free[index]
                value = candidate.sha384 if key == "sha384" else candidate.normalized_sha384
                if value is not None and value == wanted:
                    result[i] = index
                    del free[index]
                    break

    claim("sha384")
    claim("normalized")

    pending = [i for i, r in enumerate(result) if r is None]
    candidates = [b for b in free.values() if b.text is not None]
    if pending and candidates and len(pending) * len(candidates) <= _MAX_SIMILARITY_PAIRS:
        scored = sorted(
            (
                (-similarity(c.text, seen[i].text), seen[i].position, c.index, i)
                for i in pending
                for c in candidates
                if c.text is not None
            ),
        )
        for score, _position, index, i in scored:
            if -score < MATCH_THRESHOLD:
                break
            if result[i] is None and index in free:
                result[i] = index
                del free[index]

    claimed = {r for r in result if r is not None}
    for i, block in enumerate(seen):
        if result[i] is None and block.position not in claimed:
            result[i] = block.position
            claimed.add(block.position)
    next_index = max({block.index for block in known} | claimed, default=0) + 1
    final: list[int] = []
    for r in result:
        if r is None:
            r = next_index
            next_index += 1
        final.append(r)
    return final
