"""Skimmer heuristics: what a script does that card skimmers and wallet drainers do.

Change detection (:mod:`script_sentinel.changes`) says *that* a script changed and how much.
This module looks at *what the code does*, in two steps:

1. :func:`inspect` walks a body's tokens and returns a :class:`Report` of **signals**, each
   a rule and a key (``exfil.beacon`` / ``collect.skim.test``, ``collect.card_field`` /
   ``cc-number``), counted, with the first place it occurs as evidence. The rules cover:

   * exfiltration sinks: ``navigator.sendBeacon``, ``fetch``, ``XMLHttpRequest``, image
     pixels, ``WebSocket`` and jQuery's ``$.ajax``/``$.post``, each with the destination
     it sends to when the code says (a URL written out, one it hides, a relative path, or
     one computed at runtime);
   * collection: payment card fields named in strings and selectors, listeners on form
     input (``submit``, ``change``, ``keydown`` and so on), form serialization, cookies
     and web storage;
   * wallets: hard-coded crypto addresses, regular expressions that match them, and
     clipboard access;
   * obfuscation: ``eval`` and ``new Function`` (worst on decoded strings), string timers,
     the ``p,a,c,k,e,r`` packer, obfuscator-style ``_0x`` identifiers, and sensitive
     strings or property names hidden by encoding;
   * injection: scripts created with ``createElement("script")``, written as markup, or
     loaded with ``import()``, and where they load from.

   Before the rules run, the token stream is partly evaluated, the way a reviewer reads
   obfuscated code: ``atob("…")``, ``String.fromCharCode(…)`` and
   ``"…".split("").reverse().join("")`` on literals are decoded, adjacent string
   literals joined with ``+`` are folded, and ``obj["name"]`` becomes ``obj.name``. A URL
   that only appears after that is a **hidden** URL, and its host is reported, which
   covers the hosts :func:`script_sentinel.changes.references` can't see.

2. :func:`assess` combines the signals into :class:`Verdict` objects with a severity. The
   combinations carry the weight, because each signal on its own is everyday code:

   * card fields read, and data sent to a host other than the script's own and the
     site's, or to a hidden one: ``high`` (``medium`` when the destination is computed
     at runtime);
   * form input watched or serialized, and data sent to such a host: ``high``;
   * data sent to a host the code hides: ``high``;
   * cookies or storage read and sent to another host: ``medium``;
   * wallet addresses together with the clipboard, or a hard-coded address together with
     an address-matching pattern (the shape of address-swapping malware): ``high``; an
     address or a matcher alone: ``medium``;
   * ``eval``/``Function`` on decoded strings: ``high``; other code built from strings,
     packing and hidden strings: ``medium``;
   * scripts injected from a hidden host: ``high``; from another host or a runtime
     address: ``medium``;
   * a hidden URL not used by any of the above: ``medium``;
   * data sent to another host, when none of the above already says so: ``low``.

   Given the previous body's report, a verdict only counts when at least one of its
   signals is new or occurs more often: a payment library that always read card fields
   and posted them to its own API doesn't raise anything when it ships a bug fix.

Like everything here this is static and heuristic. It can be evaded by an attacker who
knows the rules, and it flags some legitimate code; a verdict says where a person should
look first, next to the diff, and never approves anything.
"""

from __future__ import annotations

import base64
import binascii
import enum
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from script_sentinel.db.models import Severity
from script_sentinel.jstokens import Token, TokenKind, string_value, tokenize, unescape, urls_in

MAX_SIGNAL_KEYS = 200  # distinct (rule, key) pairs kept per body
EVIDENCE_CHARS = 120
MAX_FOLDED = 65_536  # longest string built by folding "a" + "b"
_ARGUMENT_ATOMS = 400  # how far an argument or expression is followed
_LOOKAHEAD = 80  # atoms searched after `new Image` or createElement for `.src =`
_RANK = list(Severity)


class Category(enum.StrEnum):
    EXFILTRATION = "exfiltration"
    COLLECTION = "collection"
    WALLET = "wallet"
    OBFUSCATION = "obfuscation"
    INJECTION = "injection"
    HIDDEN_URL = "hidden_url"


class Destination(enum.StrEnum):
    """Where a network call or injected script points, as far as the code says."""

    LITERAL = "literal"  # a URL written out in the code
    HIDDEN = "hidden"  # a URL that only appears once literals are decoded or joined
    RELATIVE = "relative"  # a path on the page's own origin
    UNKNOWN = "unknown"  # computed at runtime


# rule -> (category, what it means)
RULES: dict[str, tuple[Category, str]] = {
    "exfil.beacon": (Category.EXFILTRATION, "navigator.sendBeacon"),
    "exfil.fetch": (Category.EXFILTRATION, "fetch()"),
    "exfil.xhr": (Category.EXFILTRATION, "XMLHttpRequest"),
    "exfil.image": (Category.EXFILTRATION, "an image pixel (new Image / <img> src)"),
    "exfil.websocket": (Category.EXFILTRATION, "a WebSocket"),
    "exfil.ajax": (Category.EXFILTRATION, "jQuery $.ajax / $.post / $.get"),
    "collect.card_field": (Category.COLLECTION, "names a payment card field"),
    "collect.form_listener": (Category.COLLECTION, "listens to form input"),
    "collect.form_serialization": (Category.COLLECTION, "serializes forms or their inputs"),
    "collect.stored_data": (Category.COLLECTION, "reads cookies or web storage"),
    "wallet.address": (Category.WALLET, "a hard-coded crypto wallet address"),
    "wallet.matcher": (Category.WALLET, "a pattern that matches wallet addresses"),
    "wallet.clipboard": (Category.WALLET, "reads or writes the clipboard"),
    "obfuscation.eval": (Category.OBFUSCATION, "eval / new Function / string timers"),
    "obfuscation.eval_decoded": (Category.OBFUSCATION, "eval or Function on decoded text"),
    "obfuscation.packer": (Category.OBFUSCATION, "the p,a,c,k,e,r packer"),
    "obfuscation.identifiers": (Category.OBFUSCATION, "obfuscator-style _0x identifiers"),
    "obfuscation.encoded": (Category.OBFUSCATION, "sensitive text hidden by encoding"),
    "obfuscation.hidden_property": (
        Category.OBFUSCATION,
        "a sensitive API reached by a hidden name",
    ),
    "inject.script": (Category.INJECTION, "creates a <script> element"),
    "inject.markup": (Category.INJECTION, "writes <script> markup into the page"),
    "inject.import": (Category.INJECTION, "loads a module with import()"),
    "url.hidden": (Category.HIDDEN_URL, "a URL hidden by encoding or string joining"),
}


@dataclass(slots=True)
class Signal:
    """One thing the code does, counted, with where it first occurs."""

    rule: str
    key: str
    evidence: str
    offset: int
    count: int = 1
    host: str | None = None
    destination: Destination | None = None

    @property
    def category(self) -> Category:
        return RULES[self.rule][0]

    @property
    def fingerprint(self) -> tuple[str, str]:
        return (self.rule, self.key)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "rule": self.rule,
            "category": self.category.value,
            "key": self.key,
            "count": self.count,
            "evidence": self.evidence,
            "offset": self.offset,
        }
        if self.host is not None:
            out["host"] = self.host
        if self.destination is not None:
            out["destination"] = self.destination.value
        return out


@dataclass(slots=True)
class Report:
    """The signals found in one body."""

    signals: list[Signal] = field(default_factory=list)
    hidden_hosts: frozenset[str] = frozenset()
    truncated: bool = False  # more than MAX_SIGNAL_KEYS distinct signals

    def counts(self) -> dict[tuple[str, str], int]:
        return {s.fingerprint: s.count for s in self.signals}

    def new_since(self, previous: Report | None) -> list[Signal]:
        """Signals that are new, or occur more often, than in ``previous``."""
        if previous is None:
            return list(self.signals)
        before = previous.counts()
        return [s for s in self.signals if s.count > before.get(s.fingerprint, 0)]

    def to_dict(self) -> dict[str, Any]:
        return {
            "signals": [s.to_dict() for s in self.signals],
            "hidden_hosts": sorted(self.hidden_hosts),
            "truncated": self.truncated,
        }


# --- Partial evaluation -------------------------------------------------------------------


_NAME, _STR, _NUM, _REGEX, _PUNCT, _TPL = "name", "str", "num", "regex", "punct", "tpl"
_KINDS = {
    TokenKind.IDENTIFIER: _NAME,
    TokenKind.STRING: _STR,
    TokenKind.NUMBER: _NUM,
    TokenKind.REGEX: _REGEX,
    TokenKind.PUNCTUATOR: _PUNCT,
}
_GLOBALS = frozenset({"window", "self", "globalThis", "top", "parent", "frames"})
_IDENTIFIER_NAME = re.compile(r"[A-Za-z_$][\w$]*\Z")
_BASE64 = re.compile(r"[A-Za-z0-9+/]+={0,2}\Z|[A-Za-z0-9_-]+={0,2}\Z")
_ESCAPED_CHAR = re.compile(r"\\(?:x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|u\{[0-9A-Fa-f]+\})")


@dataclass(slots=True)
class _Atom:
    """A token after partial evaluation; strings carry their value, not their source."""

    kind: str
    text: str
    start: int
    end: int
    hidden: str | None = None  # how a string was hidden: base64, charcode, reversed, ...
    parts: tuple[str, ...] = ()  # the literals a folded string was joined from


def _atoms(tokens: Sequence[Token]) -> list[_Atom]:
    out: list[_Atom] = []
    for token in tokens:
        end = token.start + len(token.text)
        if token.kind is TokenKind.TEMPLATE:
            whole = token.text.startswith("`") and token.text.endswith("`") and len(token.text) > 1
            out.append(_Atom(_STR if whole else _TPL, string_value(token), token.start, end))
            continue
        if token.kind is TokenKind.STRING:
            value = string_value(token)
            atom = _Atom(_STR, value, token.start, end)
            # Letters and URL punctuation written as \x.. or \u.... are there to hide text.
            escaped = [m.group() for m in _ESCAPED_CHAR.finditer(token.text)]
            if len(escaped) >= 4:
                decoded = unescape("".join(escaped))
                if all(c.isascii() and (c.isalnum() or c in "/.:-_") for c in decoded):
                    atom.hidden = "escaped"
            out.append(atom)
            continue
        if token.kind is TokenKind.IDENTIFIER and "\\" in token.text:
            # e\u0076al is eval, spelled so that a search for "eval" misses it.
            out.append(_Atom(_NAME, unescape(token.text), token.start, end, hidden="escaped"))
            continue
        out.append(_Atom(_KINDS[token.kind], token.text, token.start, end))
    return out


def _is(atoms: Sequence[_Atom], i: int, text: str) -> bool:
    return 0 <= i < len(atoms) and atoms[i].kind in (_PUNCT, _NAME) and atoms[i].text == text


def _decode_base64(value: str, *, minimum: int = 4) -> str | None:
    """The text a base64 literal encodes, if it is printable text."""
    value = value.strip()
    if len(value) < minimum or not _BASE64.match(value):
        return None
    padded = value + "=" * (-len(value) % 4)
    try:
        raw = (
            base64.urlsafe_b64decode(padded)
            if "-" in value or "_" in value
            else base64.b64decode(padded, validate=True)
        )
        text = raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    if not text or not all(c.isprintable() or c in "\n\r\t" for c in text):
        return None
    return text


def _char_codes(atoms: Sequence[_Atom], i: int) -> tuple[str, int] | None:
    """``String.fromCharCode(n, ...)`` with literal numbers at ``atoms[i]`` (the name)."""
    if not _is(atoms, i + 1, "("):
        return None
    chars: list[str] = []
    j = i + 2
    while j < len(atoms) and atoms[j].kind == _NUM:
        try:
            code = int(atoms[j].text.replace("_", ""), 0)
        except ValueError:
            return None
        if not 0 <= code < 0x110000:
            return None
        chars.append(chr(code))
        j += 1
        if _is(atoms, j, ","):
            j += 1
    if not chars or not _is(atoms, j, ")"):
        return None
    return "".join(chars), j


_REVERSE = (".", "split", "(", "", ")", ".", "reverse", "(", ")", ".", "join", "(", "", ")")


def _reversed(atoms: Sequence[_Atom], i: int) -> int | None:
    """``"…".split("").reverse().join("")`` after the string at ``atoms[i]``: its end."""
    for offset, want in enumerate(_REVERSE, start=1):
        j = i + offset
        if j >= len(atoms):
            return None
        atom = atoms[j]
        if want == "":
            if atom.kind != _STR or atom.text != "":
                return None
        elif atom.text != want or atom.kind == _STR:
            return None
    return i + len(_REVERSE)


def _decode(atoms: list[_Atom]) -> list[_Atom]:
    """Replace decoding calls on literals with the strings they produce."""
    out: list[_Atom] = []
    i = 0
    while i < len(atoms):
        atom = atoms[i]
        decoded: tuple[str, str, int] | None = None  # (value, how, index of the last atom)
        if (
            atom.kind == _NAME
            and atom.text == "atob"
            and _is(atoms, i + 1, "(")
            and i + 3 < len(atoms)
            and atoms[i + 2].kind == _STR
            and _is(atoms, i + 3, ")")
        ):
            text = _decode_base64(atoms[i + 2].text)
            if text is not None:
                decoded = (text, "base64", i + 3)
        elif atom.kind == _NAME and atom.text == "fromCharCode":
            codes = _char_codes(atoms, i)
            if codes is not None:
                decoded = (codes[0], "charcode", codes[1])
                if len(out) >= 2 and out[-1].text == "." and out[-2].text == "String":
                    del out[-2:]
        elif atom.kind == _STR:
            last = _reversed(atoms, i)
            if last is not None:
                decoded = (atom.text[::-1], "reversed", last)
        if decoded is None:
            out.append(atom)
            i += 1
            continue
        value, how, last = decoded
        if len(out) >= 2 and out[-1].text == "." and out[-2].text in _GLOBALS:
            del out[-2:]  # window.atob(...)
        out.append(_Atom(_STR, value, atom.start, atoms[last].end, hidden=how))
        i = last + 1
    return out


def _fold(atoms: list[_Atom]) -> list[_Atom]:
    """Join ``"a" + "b"`` into one string, remembering the pieces."""
    out: list[_Atom] = []
    for atom in atoms:
        if (
            atom.kind == _STR
            and len(out) >= 2
            and out[-1].kind == _PUNCT
            and out[-1].text == "+"
            and out[-2].kind == _STR
            and len(out[-2].text) + len(atom.text) <= MAX_FOLDED
        ):
            left = out[-2]
            del out[-1]
            out[-1] = _Atom(
                _STR,
                left.text + atom.text,
                left.start,
                atom.end,
                hidden=left.hidden or atom.hidden,
                parts=(left.parts or (left.text,)) + (atom.parts or (atom.text,)),
            )
            continue
        out.append(atom)
    for atom in out:
        if atom.parts and atom.hidden is None:
            # A host that no single piece contains was assembled to keep it out of sight.
            visible = {host for part in atom.parts for _, host in urls_in(part)}
            new_hosts = {host for _, host in urls_in(atom.text)} - visible
            new_words = _SENSITIVE_TEXT.search(atom.text) and not any(
                _SENSITIVE_TEXT.search(part) for part in atom.parts
            )
            if new_hosts or new_words:
                atom.hidden = "assembled"
    return out


# Names worth hiding: if code reaches one of these through a decoded or assembled string,
# it is going out of its way not to be read.
_SENSITIVE_PROPERTIES = frozenset(
    {
        "eval",
        "Function",
        "sendBeacon",
        "fetch",
        "XMLHttpRequest",
        "WebSocket",
        "cookie",
        "localStorage",
        "sessionStorage",
        "createElement",
        "appendChild",
        "write",
        "atob",
        "addEventListener",
        "clipboard",
        "querySelector",
        "querySelectorAll",
        "getElementById",
        "value",
        "src",
    }
)


# Words worth hiding inside decoded or assembled text.
_SENSITIVE_TEXT = re.compile(
    r"sendBeacon|XMLHttpRequest|WebSocket|document\.cookie|localStorage|"
    r"createElement|\beval\b|<script|addEventListener|clipboard|"
    r"cc[-_ ]?(?:number|num|exp|csc|cvv)|card[-_ ]?number|\bcvv\b|\bcvc\b",
    re.I,
)


def _members(atoms: list[_Atom]) -> list[_Atom]:
    """Rewrite ``obj["name"]`` as ``obj.name``."""
    out: list[_Atom] = []
    i = 0
    while i < len(atoms):
        atom = atoms[i]
        if (
            atom.kind == _PUNCT
            and atom.text == "["
            and out
            and (out[-1].kind == _NAME or out[-1].text in (")", "]"))
            and i + 2 < len(atoms)
            and atoms[i + 1].kind == _STR
            and _IDENTIFIER_NAME.match(atoms[i + 1].text)
            and _is(atoms, i + 2, "]")
        ):
            name = atoms[i + 1]
            out.append(_Atom(_PUNCT, ".", atom.start, atom.end))
            out.append(_Atom(_NAME, name.text, name.start, name.end, hidden=name.hidden))
            i += 3
            continue
        out.append(atom)
        i += 1
    return out


# --- Rules --------------------------------------------------------------------------------

_CARD_FIELD = re.compile(
    r"(?<![A-Za-z])(?:"
    r"cc[-_ ]?(?:number|num|no|exp(?:iry|iration)?(?:[-_ ]?(?:month|year|date))?|csc|cvv|cvc|name)"
    r"|card[-_ ]?(?:number|num|no|holder|code|cvv|cvc)|cardnumber"
    r"|cvv2?|cvc2?|security[-_ ]?code"
    r"|exp(?:iry|iration)[-_ ]?(?:date|month|year)"
    r")(?![A-Za-z])",
    re.I,
)
_FORM_EVENTS = frozenset(
    {"input", "change", "keydown", "keyup", "keypress", "blur", "focusout", "submit", "paste"}
)
_CLIPBOARD_EVENTS = frozenset({"copy", "cut", "paste"})
_HANDLER_PROPERTIES = {f"on{event}": event for event in _FORM_EVENTS | _CLIPBOARD_EVENTS}
_FORM_SELECTOR = re.compile(r"(?<![\w-])(?:input|select|textarea|form)(?![\w-])", re.I)
_ETH_ADDRESS = re.compile(r"(?<![0-9A-Za-z])0x[0-9a-fA-F]{40}(?![0-9A-Za-z])")
_BECH32_ADDRESS = re.compile(r"(?<![0-9a-z])(?:bc1|tb1)[ac-hj-np-z02-9]{25,87}(?![0-9a-z])")
_BASE58_ADDRESS = re.compile(r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}\Z|T[a-km-zA-HJ-NP-Z1-9]{33}\Z")
_WALLET_PATTERN = re.compile(
    r"0x[^/]{0,24}\{40\}|bc1|\[13\][^/]{0,40}\{2[4-7],3[3-5]\}|\bT\[[^/]{0,40}\{33\}"
)
_DECODERS = frozenset({"atob", "unescape", "decodeURIComponent"})
_OBFUSCATOR_NAME = re.compile(r"_0x[0-9a-f]{4,6}\Z")
_OBFUSCATOR_MIN_NAMES = 10
_SCRIPT_SRC = re.compile(r"""<script\b[^>]*\bsrc\s*=\s*["']?([^"'\s>]+)""", re.I)
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")


@dataclass(frozen=True, slots=True)
class _Target:
    destination: Destination
    host: str | None = None

    @property
    def key(self) -> str:
        return self.host or self.destination.value


_UNKNOWN = _Target(Destination.UNKNOWN)


class _Inspector:
    def __init__(self, source: str, atoms: list[_Atom]) -> None:
        self.source = source
        self.atoms = atoms
        self.found: dict[tuple[str, str], Signal] = {}
        self.truncated = False
        self.hidden_hosts: set[str] = set()
        self.bindings: dict[str, list[tuple[int, _Target]]] = {}

    # Recording -------------------------------------------------------------------------

    def evidence(self, start: int, end: int | None = None) -> str:
        stop = start + EVIDENCE_CHARS if end is None else min(end, start + EVIDENCE_CHARS)
        text = " ".join(self.source[start:stop].split())
        return text if stop >= len(self.source) or end is not None else text + " …"

    def add(
        self,
        rule: str,
        key: str,
        atom: _Atom,
        *,
        target: _Target | None = None,
        end: int | None = None,
    ) -> None:
        fingerprint = (rule, key[:200])
        existing = self.found.get(fingerprint)
        if existing is not None:
            existing.count += 1
            return
        if len(self.found) >= MAX_SIGNAL_KEYS:
            self.truncated = True
            return
        self.found[fingerprint] = Signal(
            rule,
            fingerprint[1],
            self.evidence(atom.start, end),
            atom.start,
            host=target.host if target else None,
            destination=target.destination if target else None,
        )

    # Navigation ------------------------------------------------------------------------

    def at(self, i: int, text: str) -> bool:
        return _is(self.atoms, i, text)

    def name(self, i: int) -> str | None:
        if 0 <= i < len(self.atoms) and self.atoms[i].kind == _NAME:
            return self.atoms[i].text
        return None

    def is_call(self, i: int) -> bool:
        """``atoms[i]`` is a name being called as a global function (not a method)."""
        if not self.at(i + 1, "("):
            return False
        if self.at(i - 1, "function"):
            return False
        if self.at(i - 1, ".") or self.at(i - 1, "?."):
            return self.name(i - 2) in _GLOBALS and not self.at(i - 3, ".")
        return True

    def member_call(self, i: int) -> bool:
        return (self.at(i - 1, ".") or self.at(i - 1, "?.")) and self.at(i + 1, "(")

    def expression(self, start: int) -> int:
        """The index just past the expression or argument starting at ``start``."""
        depth = 0
        j = start
        limit = min(len(self.atoms), start + _ARGUMENT_ATOMS)
        while j < limit:
            atom = self.atoms[j]
            if atom.kind == _PUNCT:
                if atom.text in ("(", "[", "{"):
                    depth += 1
                elif atom.text in (")", "]", "}"):
                    if depth == 0:
                        return j
                    depth -= 1
                elif atom.text in (",", ";") and depth == 0:
                    return j
            elif atom.kind == _TPL:
                # A template piece closes a substitution ("}…") and/or opens one ("…${").
                if self.source.startswith("}", atom.start):
                    if depth == 0:
                        return j
                    depth -= 1
                if self.source.startswith("${", atom.end - 2):
                    depth += 1
            j += 1
        return j

    def arguments(self, paren: int) -> list[tuple[int, int]]:
        """The ``(start, end)`` spans of the arguments of the call whose ``(`` is at ``paren``."""
        spans: list[tuple[int, int]] = []
        j = paren + 1
        while j < len(self.atoms) and not self.at(j, ")") and len(spans) < 8:
            end = self.expression(j)
            spans.append((j, end))
            if not self.at(end, ","):
                break
            j = end + 1
        return spans

    def first_argument(self, paren: int) -> tuple[int, int] | None:
        spans = self.arguments(paren)
        return spans[0] if spans else None

    # Destinations ----------------------------------------------------------------------

    def target(self, start: int, end: int) -> _Target:
        """Where the expression ``atoms[start:end]`` points."""
        span = self.atoms[start:end]
        if not span:
            return _UNKNOWN
        for atom in span:
            if atom.kind in (_STR, _TPL):
                for _, host in urls_in(atom.text):
                    return _Target(Destination.HIDDEN if atom.hidden else Destination.LITERAL, host)
        first = span[0]
        if first.kind == _STR and first.text and not first.text.startswith("//"):
            if not _SCHEME.match(first.text):
                return _Target(Destination.RELATIVE)
            return _UNKNOWN  # data:, blob: or a bare scheme with the rest computed
        if first.kind == _NAME and first.text in self.bindings:
            bound = self.bindings[first.text]
            earlier = [entry for entry in bound if entry[0] < first.start]
            return (earlier or bound)[-1][1]
        if first.kind == _PUNCT and first.text == "{":  # $.ajax({url: ...})
            for k in range(start + 1, end - 2):
                if self.name(k) == "url" and self.at(k + 1, ":"):
                    return self.target(k + 2, self.expression(k + 2))
        return _UNKNOWN

    def bind(self) -> None:
        """Remember what ``name = <URL expression>`` assigns, for ``fetch(name)`` later."""
        for i, atom in enumerate(self.atoms):
            if atom.kind == _NAME and self.at(i + 1, "=") and not self.at(i - 1, "."):
                end = self.expression(i + 2)
                target = self.target(i + 2, end)
                if target.destination is not Destination.UNKNOWN:
                    self.bindings.setdefault(atom.text, []).append((atom.start, target))

    def assigned_src(self, start: int) -> _Target | None:
        """The target of the first ``.src = …`` or ``setAttribute("src", …)`` after ``start``."""
        for j in range(start, min(len(self.atoms), start + _LOOKAHEAD)):
            if self.name(j) == "src" and self.at(j - 1, ".") and self.at(j + 1, "="):
                return self.target(j + 2, self.expression(j + 2))
            if self.name(j) == "setAttribute" and self.at(j + 1, "("):
                spans = self.arguments(j + 1)
                if len(spans) >= 2 and self.atoms[spans[0][0]].text.lower() == "src":
                    return self.target(*spans[1])
        return None

    # The rules -------------------------------------------------------------------------

    def run(self) -> None:
        self.bind()
        atoms = self.atoms
        obfuscator_names: dict[str, _Atom] = {}
        for i, atom in enumerate(atoms):
            if atom.kind == _NAME:
                self.names(i, atom)
                if self.at(i - 1, ".") or self.at(i - 1, "?."):  # form.cc_number, el["cvv"]
                    self.card_fields(atom)
                if atom.hidden is not None and atom.text in _SENSITIVE_PROPERTIES:
                    self.add("obfuscation.hidden_property", atom.text, atom, end=atom.end)
                if _OBFUSCATOR_NAME.match(atom.text):
                    obfuscator_names.setdefault(atom.text, atom)
            elif atom.kind == _STR:
                self.strings(i, atom)
            elif atom.kind == _TPL:
                self.card_fields(atom)
            elif atom.kind == _REGEX and _WALLET_PATTERN.search(atom.text):
                self.add("wallet.matcher", atom.text[:80], atom)
        if len(obfuscator_names) >= _OBFUSCATOR_MIN_NAMES:
            first = min(obfuscator_names.values(), key=lambda a: a.start)
            self.add("obfuscation.identifiers", "_0x", first)
            self.found[("obfuscation.identifiers", "_0x")].count = len(obfuscator_names)

    def sink(self, rule: str, atom: _Atom, target: _Target) -> None:
        self.add(rule, target.key, atom, target=target)

    def names(self, i: int, atom: _Atom) -> None:
        name = atom.text
        if name == "sendBeacon" and self.at(i + 1, "("):
            span = self.first_argument(i + 1)
            self.sink("exfil.beacon", atom, self.target(*span) if span else _UNKNOWN)
        elif name == "fetch" and self.is_call(i):
            span = self.first_argument(i + 1)
            self.sink("exfil.fetch", atom, self.target(*span) if span else _UNKNOWN)
        elif name == "XMLHttpRequest" and self.at(i - 1, "new"):
            target = _UNKNOWN
            for j in range(i, min(len(self.atoms), i + _LOOKAHEAD)):
                if self.name(j) == "open" and self.member_call(j):
                    spans = self.arguments(j + 1)
                    if len(spans) >= 2:
                        target = self.target(*spans[1])
                    break
            self.sink("exfil.xhr", atom, target)
        elif name == "Image" and self.at(i - 1, "new"):
            self.sink("exfil.image", atom, self.assigned_src(i) or _UNKNOWN)
        elif name == "WebSocket" and self.at(i - 1, "new"):
            span = self.first_argument(i + 1) if self.at(i + 1, "(") else None
            self.sink("exfil.websocket", atom, self.target(*span) if span else _UNKNOWN)
        elif (
            name in ("ajax", "post", "get", "getJSON")
            and self.member_call(i)
            and self.name(i - 2) in ("$", "jQuery")
        ):
            span = self.first_argument(i + 1)
            self.sink("exfil.ajax", atom, self.target(*span) if span else _UNKNOWN)
        elif name == "createElement" and self.at(i + 1, "("):
            span = self.first_argument(i + 1)
            tag = self.atoms[span[0]] if span else None
            if tag is not None and tag.kind == _STR and tag.text.lower() == "img":
                self.sink("exfil.image", atom, self.assigned_src(i) or _UNKNOWN)
            elif tag is not None and tag.kind == _STR and tag.text.lower() == "script":
                self.sink("inject.script", atom, self.assigned_src(i) or _UNKNOWN)
        elif (name == "addEventListener" and self.at(i + 1, "(")) or (
            name == "on" and self.member_call(i)
        ):
            self.events(i, atom)
        elif name in _HANDLER_PROPERTIES and self.at(i - 1, ".") and self.at(i + 1, "="):
            event = _HANDLER_PROPERTIES[name]
            rule = "wallet.clipboard" if event in ("copy", "cut") else "collect.form_listener"
            self.add(rule, event, atom)
        elif name == "FormData" and self.at(i - 1, "new"):
            self.add("collect.form_serialization", "FormData", atom)
        elif name in ("serialize", "serializeArray") and self.member_call(i):
            self.add("collect.form_serialization", name, atom)
        elif name == "forms" and self.at(i - 1, ".") and self.name(i - 2) == "document":
            self.add("collect.form_serialization", "document.forms", atom)
        elif name == "querySelectorAll" and self.at(i + 1, "("):
            span = self.first_argument(i + 1)
            selector = self.atoms[span[0]] if span else None
            if selector is not None and selector.kind == _STR:
                match = _FORM_SELECTOR.search(selector.text)
                if match:
                    self.add("collect.form_serialization", match.group().lower(), atom)
        elif name == "cookie" and self.at(i - 1, "."):
            self.add("collect.stored_data", "cookie", atom)
        elif name in ("localStorage", "sessionStorage"):
            self.add("collect.stored_data", name, atom)
        elif name in ("writeText", "write", "readText") and self.at(i - 1, "."):
            if self.name(i - 2) == "clipboard":
                self.add("wallet.clipboard", f"clipboard.{name}", atom)
            elif name == "write" and self.name(i - 2) == "document" and self.at(i + 1, "("):
                self.markup(i, atom, "document.write")
        elif name in ("setData", "getData") and self.name(i - 2) == "clipboardData":
            self.add("wallet.clipboard", f"clipboardData.{name}", atom)
        elif name == "execCommand" and self.at(i + 1, "("):
            span = self.first_argument(i + 1)
            command = self.atoms[span[0]] if span else None
            if command is not None and command.kind == _STR and command.text in ("copy", "paste"):
                self.add("wallet.clipboard", f"execCommand.{command.text}", atom)
        elif (name in ("writeln", "insertAdjacentHTML") and self.at(i + 1, "(")) or (
            name in ("innerHTML", "outerHTML") and self.at(i - 1, ".") and self.at(i + 1, "=")
        ):
            self.markup(i, atom, name)
        elif name == "import" and self.at(i + 1, "(") and not self.at(i - 1, "."):
            span = self.first_argument(i + 1)
            target = self.target(*span) if span else _UNKNOWN
            if target.host is not None:
                self.sink("inject.import", atom, target)
        elif name in ("eval", "Function") and (self.is_call(i) or self.at(i - 1, "new")):
            self.dynamic_code(i, atom)
        elif name in ("setTimeout", "setInterval") and self.is_call(i):
            span = self.first_argument(i + 1)
            if span and self.atoms[span[0]].kind == _STR and span[1] - span[0] == 1:
                self.add("obfuscation.eval", name, atom)

    def events(self, i: int, atom: _Atom) -> None:
        span = self.first_argument(i + 1)
        if not span or self.atoms[span[0]].kind != _STR:
            return
        for event in self.atoms[span[0]].text.split():
            event = event.split(".")[0].lower()  # jQuery namespaces: "submit.plugin"
            if event in ("copy", "cut"):
                self.add("wallet.clipboard", event, atom)
            elif event in _FORM_EVENTS:
                self.add("collect.form_listener", event, atom)

    def markup(self, i: int, atom: _Atom, api: str) -> None:
        """``document.write("<script …>")``, ``el.innerHTML = "<script …>"`` and the like."""
        if self.at(i + 1, "("):
            spans = self.arguments(i + 1)
            if not spans:
                return
            start, end = spans[0][0], spans[-1][1]
        else:  # an assignment
            start, end = i + 2, self.expression(i + 2)
        for atom_ in self.atoms[start:end]:
            if atom_.kind in (_STR, _TPL) and "<script" in atom_.text.lower():
                match = _SCRIPT_SRC.search(atom_.text)
                target = _UNKNOWN
                if match:
                    hosts = [host for _, host in urls_in(match.group(1))]
                    if hosts:
                        how = Destination.HIDDEN if atom_.hidden else Destination.LITERAL
                        target = _Target(how, hosts[0])
                    elif not _SCHEME.match(match.group(1)) and not match.group(1).startswith("//"):
                        target = _Target(Destination.RELATIVE)
                self.add("inject.markup", api, atom, target=target)
                return

    def dynamic_code(self, i: int, atom: _Atom) -> None:
        name = atom.text
        if (
            name == "eval"
            and self.at(i + 2, "function")
            and [self.name(k) for k in range(i + 4, i + 13, 2)] == ["p", "a", "c", "k", "e"]
        ):
            self.add("obfuscation.packer", "p,a,c,k,e,r", atom)
        if not self.at(i + 1, "("):
            self.add("obfuscation.eval", name, atom)
            return
        spans = self.arguments(i + 1)
        decoded = False
        for start, _end in spans[-1:] if name == "Function" else spans[:1]:
            first = self.atoms[start]
            decoded = decoded or (
                (first.kind == _STR and first.hidden in ("base64", "charcode", "reversed"))
                or (first.kind == _NAME and first.text in _DECODERS)
                or (first.text == "String" and self.name(start + 2) == "fromCharCode")
            )
        self.add("obfuscation.eval_decoded" if decoded else "obfuscation.eval", name, atom)

    def strings(self, i: int, atom: _Atom) -> None:
        value = atom.text
        self.card_fields(atom)
        for match in _ETH_ADDRESS.finditer(value):
            self.add("wallet.address", match.group(), atom)
        for match in _BECH32_ADDRESS.finditer(value):
            self.add("wallet.address", match.group(), atom)
        if _BASE58_ADDRESS.match(value):
            self.add("wallet.address", value, atom)
        if self.name(i - 2) == "RegExp" and self.at(i - 1, "(") and _WALLET_PATTERN.search(value):
            self.add("wallet.matcher", value[:80], atom)
        how = atom.hidden
        text = value
        if how is None and 20 <= len(value) <= 100_000:
            decoded = _decode_base64(value, minimum=20)
            if decoded is not None and (_SENSITIVE_TEXT.search(decoded) or any(urls_in(decoded))):
                how, text = "base64", decoded
        if how is None:
            return
        hosts = [host for _, host in urls_in(text)]
        for host in hosts:
            self.hidden_hosts.add(host)
            self.add(
                "url.hidden", host, atom, target=_Target(Destination.HIDDEN, host), end=atom.end
            )
        if _SENSITIVE_TEXT.search(text) or (hosts and how != "assembled"):
            self.add("obfuscation.encoded", how, atom, end=atom.end)

    def card_fields(self, atom: _Atom) -> None:
        if len(atom.text) > 2_000:  # a long text blob, not a selector or field name
            return
        for match in _CARD_FIELD.finditer(atom.text):
            key = re.sub(r"[-_ ]", "-", match.group().lower())
            self.add("collect.card_field", key, atom)


def inspect(source: str, tokens: Sequence[Token] | None = None) -> Report:
    """The signals in ``source`` (see the module docs). Pure; never raises."""
    atoms = _atoms(tokenize(source).tokens if tokens is None else tokens)
    for _ in range(3):  # atob(atob("...")) decodes from the inside out
        decoded = _decode(atoms)
        if len(decoded) == len(atoms):
            break
        atoms = decoded
    inspector = _Inspector(source, _members(_fold(atoms)))
    inspector.run()
    signals = sorted(inspector.found.values(), key=lambda s: (s.offset, s.rule, s.key))
    return Report(signals, frozenset(inspector.hidden_hosts), inspector.truncated)


# --- Verdicts -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Context:
    """Where a script runs: what counts as "its own" destination."""

    script_host: str | None = None  # the host an external script is served from
    site_hosts: frozenset[str] = frozenset()  # the hosts of the site's own origins

    @property
    def trusted(self) -> frozenset[str]:
        return self.site_hosts | ({self.script_host} if self.script_host else set())


@dataclass(frozen=True, slots=True)
class Verdict:
    rule: str
    severity: Severity
    reason: str
    signals: tuple[tuple[str, str], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "severity": self.severity.value,
            "reason": self.reason,
            "signals": [{"rule": r, "key": k} for r, k in self.signals],
        }


def _where(signal: Signal, trusted: frozenset[str]) -> str:
    if signal.destination is Destination.HIDDEN:
        return "hidden"
    if signal.host is not None:
        return "own" if signal.host in trusted else "foreign"
    if signal.destination is Destination.RELATIVE:
        return "own"
    return "runtime"


def _hosts(signals: Iterable[Signal]) -> str:
    hosts = sorted({s.host for s in signals if s.host})
    shown = ", ".join(hosts[:3]) + (f" and {len(hosts) - 3} more" if len(hosts) > 3 else "")
    return shown or "an address computed at runtime"


def _keys(signals: Iterable[Signal], limit: int = 4) -> str:
    keys = sorted({s.key for s in signals})
    return ", ".join(keys[:limit]) + (", …" if len(keys) > limit else "")


def assess(
    report: Report, context: Context | None = None, previous: Report | None = None
) -> list[Verdict]:
    """Combine a report's signals into verdicts (see the module docs), most severe first.

    With ``previous`` (the report of the body this one replaces), a verdict needs at least
    one signal that is new or occurs more often than before.
    """
    context = context or Context()
    trusted = context.trusted
    fresh = {s.fingerprint for s in report.new_since(previous)}
    verdicts: list[Verdict] = []

    def rule(*names: str) -> list[Signal]:
        return [s for s in report.signals if s.rule in names]

    def add(name: str, severity: Severity, reason: str, *groups: list[Signal]) -> None:
        involved = [s for group in groups for s in group]
        if any(s.fingerprint in fresh for s in involved):
            fingerprints = tuple(dict.fromkeys(s.fingerprint for s in involved))
            verdicts.append(Verdict(name, severity, reason, fingerprints))

    sinks = [s for s in report.signals if s.category is Category.EXFILTRATION]
    outbound = [s for s in sinks if _where(s, trusted) in ("foreign", "hidden")]
    runtime = [s for s in sinks if _where(s, trusted) == "runtime"]
    hidden_sinks = [s for s in sinks if _where(s, trusted) == "hidden"]
    cards = rule("collect.card_field")
    forms = rule("collect.form_listener", "collect.form_serialization")
    stored = rule("collect.stored_data")

    if cards and outbound:
        add(
            "skimmer.card_data",
            Severity.HIGH,
            f"reads payment card fields ({_keys(cards)}) and sends data to {_hosts(outbound)}",
            cards,
            outbound,
        )
    elif cards and runtime:
        add(
            "skimmer.card_data",
            Severity.MEDIUM,
            f"reads payment card fields ({_keys(cards)}) and sends data to an address "
            "computed at runtime",
            cards,
            runtime,
        )
    if forms and outbound:
        add(
            "skimmer.form_data",
            Severity.HIGH,
            f"watches form input ({_keys(forms)}) and sends data to {_hosts(outbound)}",
            forms,
            outbound,
        )
    if hidden_sinks:
        add(
            "exfil.hidden_destination",
            Severity.HIGH,
            f"sends data to a host it hides: {_hosts(hidden_sinks)}",
            hidden_sinks,
        )
    if stored and outbound:
        add(
            "exfil.stored_data",
            Severity.MEDIUM,
            f"reads {_keys(stored)} and sends data to {_hosts(outbound)}",
            stored,
            outbound,
        )
    if outbound and not verdicts:  # only when no verdict above already says where it goes
        add("exfil.outbound", Severity.LOW, f"sends data to {_hosts(outbound)}", outbound)

    addresses = rule("wallet.address")
    matchers = rule("wallet.matcher")
    clipboard = rule("wallet.clipboard")
    if (addresses or matchers) and clipboard:
        add(
            "wallet.swap",
            Severity.HIGH,
            "handles crypto wallet addresses and the clipboard, the pattern of "
            "address-swapping malware",
            addresses,
            matchers,
            clipboard,
        )
    elif addresses and matchers:
        add(
            "wallet.swap",
            Severity.HIGH,
            f"matches wallet addresses and carries its own ({_keys(addresses, 2)})",
            addresses,
            matchers,
        )
    elif addresses:
        add(
            "wallet.address",
            Severity.MEDIUM,
            f"hard-codes a crypto wallet address ({_keys(addresses, 2)})",
            addresses,
        )
    elif matchers:
        add("wallet.matcher", Severity.MEDIUM, "looks for crypto wallet addresses", matchers)

    decoded_code = rule("obfuscation.eval_decoded")
    if decoded_code:
        add("obfuscation.decoded_code", Severity.HIGH, "runs code it decodes first", decoded_code)
    dynamic = rule("obfuscation.eval")
    if dynamic:
        add(
            "obfuscation.dynamic_code",
            Severity.MEDIUM,
            f"runs code built from strings ({_keys(dynamic)})",
            dynamic,
        )
    packed = rule(
        "obfuscation.packer",
        "obfuscation.identifiers",
        "obfuscation.encoded",
        "obfuscation.hidden_property",
    )
    if packed:
        what = sorted({RULES[s.rule][1] for s in packed})
        add("obfuscation.packed", Severity.MEDIUM, "is obfuscated: " + "; ".join(what), packed)

    injected = rule("inject.script", "inject.markup", "inject.import")
    hidden_injected = [s for s in injected if _where(s, trusted) == "hidden"]
    other_injected = [s for s in injected if _where(s, trusted) in ("foreign", "runtime")]
    if hidden_injected:
        add(
            "inject.hidden_source",
            Severity.HIGH,
            f"loads more code from a host it hides: {_hosts(hidden_injected)}",
            hidden_injected,
        )
    if other_injected:
        add(
            "inject.script",
            Severity.MEDIUM,
            f"loads more code from {_hosts(other_injected)}",
            other_injected,
        )

    used = {s.host for s in [*sinks, *injected] if s.host}
    unused_hidden = [s for s in rule("url.hidden") if s.host not in used]
    if unused_hidden:
        add(
            "url.hidden",
            Severity.MEDIUM,
            f"hides a URL: {_hosts(unused_hidden)}",
            unused_hidden,
        )

    verdicts.sort(key=lambda v: (-_RANK.index(v.severity), v.rule))
    return verdicts


def worst(verdicts: Iterable[Verdict]) -> Severity | None:
    severities = [v.severity for v in verdicts]
    return max(severities, key=_RANK.index) if severities else None
