"""A token-level diff between two versions of a script.

Third-party scripts are usually minified onto one or a few lines, so a line diff of a new
vendor build says "line 1 changed" and nothing else. This diff works on the tokens from
:mod:`script_sentinel.jstokens` instead: comments and whitespace never show up as changes,
and an edit in the middle of a 300 KB one-line bundle comes out as the handful of tokens
that differ, with a few tokens of context and the line they are on.

How it stays fast on large bundles:

1. The common prefix and suffix are trimmed first. Vendor rebuilds tend to differ in a few
   places, so this usually leaves a small middle.
2. If the middle is small enough (the product of its two lengths is under
   ``token_budget``), :class:`difflib.SequenceMatcher` compares it token by token.
3. Otherwise the middle is aligned with a patience diff: tokens that occur exactly once
   on each side (identifiers, strings, numbers) anchor the alignment, and the ranges
   between anchors are aligned the same way. Ranges with no unique tokens left go to
   ``SequenceMatcher`` while a total work budget lasts, and are reported whole after that.
   Such a result is marked ``coarse`` so nobody mistakes it for a minimal diff.

``SequenceMatcher``'s "autojunk" heuristic is off: in JavaScript the most frequent tokens
(``.``, ``(``, ``,``) are exactly the ones it would ignore.
"""

from __future__ import annotations

import bisect
import difflib
import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from script_sentinel.jstokens import Token, tokenize

# Work allowed for SequenceMatcher, in products of the two lengths it compares.
DEFAULT_TOKEN_BUDGET = 4_000_000
CONTEXT_TOKENS = 6
MAX_HUNK_TEXT = 2_000  # characters of removed or added text kept per hunk

_LINE_BREAK = re.compile(r"\r\n|[\n\r\u2028\u2029]")


@dataclass(frozen=True, slots=True)
class Hunk:
    """One run of changed tokens. Lines are 1-based lines of the original sources."""

    old_line: int
    new_line: int
    removed: str  # the removed tokens, joined as jstokens.normalize would join them
    added: str
    removed_tokens: int
    added_tokens: int
    before: str  # up to CONTEXT_TOKENS unchanged tokens before the change
    after: str  # ...and after it
    truncated: bool = False  # removed or added text was cut at MAX_HUNK_TEXT

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Hunk:
        return cls(**{name: data[name] for name in cls.__dataclass_fields__ if name in data})

    def to_dict(self) -> dict[str, object]:
        return {
            "old_line": self.old_line,
            "new_line": self.new_line,
            "removed": self.removed,
            "added": self.added,
            "removed_tokens": self.removed_tokens,
            "added_tokens": self.added_tokens,
            "before": self.before,
            "after": self.after,
            "truncated": self.truncated,
        }


@dataclass(slots=True)
class TokenDiff:
    old_tokens: int
    new_tokens: int
    removed: int = 0
    added: int = 0
    hunks: list[Hunk] = field(default_factory=list)
    coarse: bool = False  # parts were compared statement by statement, not token by token

    @property
    def identical(self) -> bool:
        return not self.hunks

    @property
    def similarity(self) -> float:
        """The share of tokens that are unchanged, from 0.0 to 1.0."""
        total = self.old_tokens + self.new_tokens
        if total == 0:
            return 1.0
        return round(1 - (self.removed + self.added) / total, 4)


def _join(tokens: Sequence[Token]) -> str:
    parts: list[str] = []
    for token in tokens:
        if parts:
            parts.append("\n" if token.newline_before else " ")
        parts.append(token.text)
    return "".join(parts)


def _clip(text: str) -> tuple[str, bool]:
    if len(text) <= MAX_HUNK_TEXT:
        return text, False
    return text[:MAX_HUNK_TEXT] + " …", True


class _Lines:
    """Maps character offsets to 1-based line numbers."""

    def __init__(self, source: str) -> None:
        self._starts = [0] + [m.end() for m in _LINE_BREAK.finditer(source)]

    def line(self, offset: int) -> int:
        return bisect.bisect_right(self._starts, offset)


Opcode = tuple[str, int, int, int, int]


def _lis(pairs: Sequence[tuple[int, int]]) -> list[tuple[int, int]]:
    """The longest run of ``pairs`` (sorted by the first item) increasing in the second."""
    tails: list[int] = []  # tails[k]: smallest second item ending a run of length k + 1
    tail_index: list[int] = []
    back: list[int] = [-1] * len(pairs)
    for index, (_, j) in enumerate(pairs):
        k = bisect.bisect_left(tails, j)
        if k == len(tails):
            tails.append(j)
            tail_index.append(index)
        else:
            tails[k] = j
            tail_index[k] = index
        back[index] = tail_index[k - 1] if k else -1
    run: list[tuple[int, int]] = []
    index = tail_index[-1] if tail_index else -1
    while index >= 0:
        run.append(pairs[index])
        index = back[index]
    run.reverse()
    return run


class _Matcher:
    """Patience diff with a work budget.

    Tokens that occur exactly once on both sides anchor the alignment (the longest
    increasing run of them is kept), and the ranges between anchors are aligned the same
    way, recursively. A range with no unique anchors is trimmed of its common prefix and
    suffix and handed to ``SequenceMatcher`` while the budget lasts; after that it is
    reported as one replacement and the diff is marked coarse. Patience diff never looks
    at popular tokens like ``(`` or ``}`` to align, which is what keeps it fast.
    """

    def __init__(self, a: Sequence[str], b: Sequence[str], budget: int) -> None:
        self.a, self.b = a, b
        self.budget = budget
        self.coarse = False
        self.matches: list[tuple[int, int]] = []

    def run(self, alo: int, ahi: int, blo: int, bhi: int) -> list[tuple[int, int]]:
        a, b = self.a, self.b
        stack = [(alo, ahi, blo, bhi)]
        while stack:
            alo, ahi, blo, bhi = stack.pop()
            while alo < ahi and blo < bhi and a[alo] == b[blo]:
                self.matches.append((alo, blo))
                alo, blo = alo + 1, blo + 1
            while alo < ahi and blo < bhi and a[ahi - 1] == b[bhi - 1]:
                ahi, bhi = ahi - 1, bhi - 1
                self.matches.append((ahi, bhi))
            if alo == ahi or blo == bhi:
                continue
            anchors = self._anchors(alo, ahi, blo, bhi)
            if anchors:
                prev_a, prev_b = alo, blo
                for i, j in anchors:
                    stack.append((prev_a, i, prev_b, j))
                    self.matches.append((i, j))
                    prev_a, prev_b = i + 1, j + 1
                stack.append((prev_a, ahi, prev_b, bhi))
                continue
            work = (ahi - alo) * (bhi - blo)
            if work <= self.budget:
                self.budget -= work
                matcher = difflib.SequenceMatcher(None, a[alo:ahi], b[blo:bhi], autojunk=False)
                for i, j, size in matcher.get_matching_blocks():
                    self.matches.extend((alo + i + k, blo + j + k) for k in range(size))
            elif not set(a[alo:ahi]).isdisjoint(b[blo:bhi]):
                # Tokens in common that were never aligned: the diff may not be minimal.
                self.coarse = True
        self.matches.sort()
        return self.matches

    def _anchors(self, alo: int, ahi: int, blo: int, bhi: int) -> list[tuple[int, int]]:
        counts_a = Counter(self.a[alo:ahi])
        counts_b = Counter(self.b[blo:bhi])
        position_b = {self.b[j]: j for j in range(blo, bhi) if counts_b[self.b[j]] == 1}
        pairs = [
            (i, position_b[self.a[i]])
            for i in range(alo, ahi)
            if counts_a[self.a[i]] == 1 and self.a[i] in position_b
        ]
        return _lis(pairs)


def _opcodes(old: Sequence[Token], new: Sequence[Token], budget: int) -> tuple[list[Opcode], bool]:
    """Non-equal opcodes over the full token lists, and whether any part was coarse."""
    a = [t.text for t in old]
    b = [t.text for t in new]
    lo = 0
    limit = min(len(a), len(b))
    while lo < limit and a[lo] == b[lo]:
        lo += 1
    hi_a, hi_b = len(a), len(b)
    while hi_a > lo and hi_b > lo and a[hi_a - 1] == b[hi_b - 1]:
        hi_a -= 1
        hi_b -= 1
    if lo == hi_a and lo == hi_b:
        return [], False
    if lo in (hi_a, hi_b):  # a pure insertion or deletion
        edge = "insert" if lo == hi_a else "delete"
        return [(edge, lo, hi_a, lo, hi_b)], False
    if (hi_a - lo) * (hi_b - lo) <= budget:
        matcher = difflib.SequenceMatcher(None, a[lo:hi_a], b[lo:hi_b], autojunk=False)
        opcodes: list[Opcode] = [
            (tag, lo + i1, lo + i2, lo + j1, lo + j2)
            for tag, i1, i2, j1, j2 in matcher.get_opcodes()
            if tag != "equal"
        ]
        return opcodes, False
    patience = _Matcher(a, b, budget)
    matches = patience.run(lo, hi_a, lo, hi_b)
    result: list[Opcode] = []
    i, j = lo, lo
    # Every gap between consecutive matched pairs is a change; (hi_a, hi_b) closes the last.
    for mi, mj in [*matches, (hi_a, hi_b)]:
        if mi > i or mj > j:
            tag = "replace" if mi > i and mj > j else ("delete" if mi > i else "insert")
            result.append((tag, i, mi, j, mj))
        i, j = mi + 1, mj + 1
    return result, patience.coarse


def diff_sources(
    old_source: str,
    new_source: str,
    *,
    token_budget: int = DEFAULT_TOKEN_BUDGET,
    old_tokens: Sequence[Token] | None = None,
    new_tokens: Sequence[Token] | None = None,
) -> TokenDiff:
    """The token diff from ``old_source`` to ``new_source``. CPU-bound; never raises.

    Pass the sources' tokens if they are already at hand, to avoid tokenizing twice.
    """
    old = tokenize(old_source).tokens if old_tokens is None else old_tokens
    new = tokenize(new_source).tokens if new_tokens is None else new_tokens
    result = TokenDiff(old_tokens=len(old), new_tokens=len(new))
    opcodes, result.coarse = _opcodes(old, new, max(1, token_budget))
    if not opcodes:
        return result
    old_lines = _Lines(old_source)
    new_lines = _Lines(new_source)
    for _tag, i1, i2, j1, j2 in opcodes:
        removed, removed_cut = _clip(_join(old[i1:i2]))
        added, added_cut = _clip(_join(new[j1:j2]))
        old_offset = old[i1].start if i1 < len(old) else len(old_source)
        new_offset = new[j1].start if j1 < len(new) else len(new_source)
        result.hunks.append(
            Hunk(
                old_line=old_lines.line(old_offset),
                new_line=new_lines.line(new_offset),
                removed=removed,
                added=added,
                removed_tokens=i2 - i1,
                added_tokens=j2 - j1,
                before=_join(new[max(0, j1 - CONTEXT_TOKENS) : j1]),
                after=_join(new[j2 : j2 + CONTEXT_TOKENS]),
                truncated=removed_cut or added_cut,
            )
        )
        result.removed += i2 - i1
        result.added += j2 - j1
    return result


def render(diff: TokenDiff, *, max_hunks: int | None = None) -> str:
    """A plain-text rendering for terminals: one block per hunk, ``-``/``+`` lines."""
    return render_hunks(diff.hunks, max_hunks=max_hunks)


def render_hunks(
    hunks: Sequence[Hunk], *, max_hunks: int | None = None, total: int | None = None
) -> str:
    """Render hunks; ``total`` is how many there were if ``hunks`` is already cut short."""
    lines: list[str] = []
    shown = hunks if max_hunks is None else hunks[:max_hunks]
    for hunk in shown:
        lines.append(f"@@ line {hunk.old_line} -> line {hunk.new_line} @@")
        if hunk.before:
            lines.append(f"  … {_one_line(hunk.before)}")
        if hunk.removed:
            lines.extend(f"- {line}" for line in hunk.removed.split("\n"))
        if hunk.added:
            lines.extend(f"+ {line}" for line in hunk.added.split("\n"))
        if hunk.after:
            lines.append(f"  {_one_line(hunk.after)} …")
    hidden = (len(hunks) if total is None else total) - len(shown)
    if hidden > 0:
        lines.append(f"… {hidden} more hunk(s)")
    return "\n".join(lines)


def _one_line(text: str) -> str:
    return text.replace("\n", " ")


def similarity(old_source: str, new_source: str, *, max_tokens: int = 20_000) -> float:
    """How alike two scripts are (0.0 to 1.0), for matching inline blocks.

    Bodies over ``max_tokens`` tokens are compared only by exact token equality, which
    keeps matching cheap on pages that inline a whole bundle. Anything clearly under 0.5
    is reported as 0.0 without computing the exact ratio.
    """
    a = [t.text for t in tokenize(old_source).tokens]
    b = [t.text for t in tokenize(new_source).tokens]
    if a == b:
        return 1.0
    if not a or not b or len(a) > max_tokens or len(b) > max_tokens:
        return 0.0
    matcher = difflib.SequenceMatcher(None, a, b, autojunk=False)
    if matcher.real_quick_ratio() < 0.5 or matcher.quick_ratio() < 0.5:
        return 0.0
    return round(matcher.ratio(), 4)
