"""A small, forgiving JavaScript tokenizer and the normalized form used for hashing.

Two bodies that differ only in comments, indentation or spacing inside a line are the same
program. Vendors rebuild their scripts all the time with a new banner comment, a new
``sourceMappingURL`` or different whitespace, and an alert for each of those would bury the
changes that matter. So every script version gets two hashes:

* ``sha384`` over the exact bytes served (what Subresource Integrity checks), and
* ``normalized_sha384`` over :func:`normalize`'s output, which keeps every token exactly
  as written (strings, template literals and regular expressions included) and replaces
  each run of whitespace and comments with a single separator: a newline if the run
  contained a line break, a space otherwise.

Line breaks are kept because automatic semicolon insertion makes them meaningful
(``return\\nx`` is not ``return x``). Re-wrapping lines therefore changes the normalized
hash, which errs on the side of reporting a change.

The tokenizer follows the ECMAScript lexical grammar closely enough for that purpose, and is
also the basis for the token-level diff (day 5). It never raises: unterminated strings,
comments, template literals or regular expressions end at the end of the input and mark the
result as incomplete. The ``/`` ambiguity (division or the start of a regular expression)
is resolved from the previous significant token, the standard approach for tokenizers that
don't parse.
"""

from __future__ import annotations

import enum
import hashlib
import re
from dataclasses import dataclass, field


class TokenKind(enum.StrEnum):
    IDENTIFIER = "identifier"  # includes keywords and #private names
    NUMBER = "number"
    STRING = "string"
    TEMPLATE = "template"  # a whole template literal, or a piece of one around ${ }
    REGEX = "regex"
    PUNCTUATOR = "punctuator"


@dataclass(frozen=True, slots=True)
class Token:
    kind: TokenKind
    text: str
    start: int
    # Whether a line terminator (on its own or inside a comment) came before this token.
    newline_before: bool


@dataclass(slots=True)
class Tokens:
    tokens: list[Token] = field(default_factory=list)
    comments: int = 0
    # False when the input ended inside a string, comment, template literal or regex.
    complete: bool = True


# Whitespace and line terminators (ECMAScript 12.2 and 12.3). Python's \s covers the
# Unicode space separators and U+2028/U+2029; U+FEFF (the BOM) has to be added.
_WHITESPACE = re.compile(r"[\s\ufeff]+")
_LINE_TERMINATOR = re.compile(r"[\n\r\u2028\u2029]")
_LINE_COMMENT = re.compile(r"//[^\n\r\u2028\u2029]*")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_HASHBANG = re.compile(r"#![^\n\r\u2028\u2029]*")

_UNICODE_ESCAPE = r"\\u(?:[0-9A-Fa-f]{4}|\{[0-9A-Fa-f]+\})"
_ID_START = rf"(?:[A-Za-z_$]|[^\x00-\x7f\s\ufeff]|{_UNICODE_ESCAPE})"
_ID_PART = rf"(?:[\w$]|[^\x00-\x7f\s\ufeff]|{_UNICODE_ESCAPE})"
_IDENTIFIER = re.compile(rf"#?{_ID_START}{_ID_PART}*")

_NUMBER = re.compile(
    r"""
    0[xX][0-9A-Fa-f_]+n?
  | 0[oO][0-7_]+n?
  | 0[bB][01_]+n?
  | (?:\d[\d_]*(?:\.[\d_]*)?|\.\d[\d_]*)(?:[eE][+-]?\d[\d_]*)?n?
    """,
    re.X,
)

# A string ends at its closing quote; an unescaped line break ends it early (an error in
# JavaScript, recorded here as an incomplete token).
_STRING = {
    '"': re.compile(r'"(?:[^"\\\n\r]|\\(?:\r\n|[\s\S]))*("?)'),
    "'": re.compile(r"'(?:[^'\\\n\r]|\\(?:\r\n|[\s\S]))*('?)"),
}
# The body of a template literal up to (and including) its end: a backtick or "${".
_TEMPLATE_BODY = re.compile(r"(?:[^`\\$]|\\[\s\S]|\$(?!\{))*(`|\$\{)?")
_NOT_EOL = r"[^\n\r\u2028\u2029]"
_REGEX = re.compile(
    r"/(?:[^/\\\[\n\r\u2028\u2029]"  # an ordinary character
    rf"|\\{_NOT_EOL}"  # an escape
    rf"|\[(?:[^\]\\\n\r\u2028\u2029]|\\{_NOT_EOL})*\])+/"  # a class, where "/" is literal
    rf"{_ID_PART}*"  # flags
)

_PUNCTUATORS = sorted(
    [
        ">>>=",
        "...",
        "===",
        "!==",
        "**=",
        "<<=",
        ">>=",
        ">>>",
        "&&=",
        "||=",
        "??=",
        "=>",
        "==",
        "!=",
        "<=",
        ">=",
        "&&",
        "||",
        "??",
        "?.",
        "++",
        "--",
        "+=",
        "-=",
        "*=",
        "/=",
        "%=",
        "&=",
        "|=",
        "^=",
        "**",
        "<<",
        ">>",
        "{",
        "}",
        "(",
        ")",
        "[",
        "]",
        ";",
        ",",
        "<",
        ">",
        "+",
        "-",
        "*",
        "/",
        "%",
        "&",
        "|",
        "^",
        "!",
        "~",
        "?",
        ":",
        "=",
        ".",
        "@",
        "#",
    ],
    key=len,
    reverse=True,
)
_PUNCTUATOR = re.compile("|".join(re.escape(p) for p in _PUNCTUATORS))

# After these keywords an expression starts, so "/" begins a regular expression.
_KEYWORDS_BEFORE_EXPRESSION = frozenset(
    {
        "await",
        "case",
        "delete",
        "do",
        "else",
        "in",
        "instanceof",
        "new",
        "of",
        "return",
        "throw",
        "typeof",
        "void",
        "yield",
    }
)


def _regex_allowed(previous: Token | None) -> bool:
    """Whether a ``/`` after ``previous`` starts a regular expression."""
    if previous is None:
        return True
    if previous.kind is TokenKind.PUNCTUATOR:
        # ")" and "]" end an operand, so "/" divides. "}" usually ends a block (a regex
        # can follow) and rarely an object literal, so it is treated as a block end.
        return previous.text not in (")", "]")
    if previous.kind is TokenKind.IDENTIFIER:
        return previous.text in _KEYWORDS_BEFORE_EXPRESSION
    return False


def tokenize(source: str) -> Tokens:
    """Split ``source`` into significant tokens. Never raises."""
    out = Tokens()
    tokens = out.tokens
    pos = 0
    end = len(source)
    newline = False
    # One entry per open "{" or "${": True for a template substitution.
    braces: list[bool] = []

    def emit(kind: TokenKind, text: str, start: int) -> None:
        nonlocal newline
        tokens.append(Token(kind, text, start, newline))
        newline = False

    if source.startswith("#!"):
        match = _HASHBANG.match(source)
        assert match is not None
        pos = match.end()
        out.comments += 1

    while pos < end:
        char = source[pos]

        match = _WHITESPACE.match(source, pos)
        if match:
            if _LINE_TERMINATOR.search(match.group()):
                newline = True
            pos = match.end()
            continue

        if char == "/" and pos + 1 < end and source[pos + 1] in "/*":
            out.comments += 1
            if source[pos + 1] == "/":
                match = _LINE_COMMENT.match(source, pos)
                assert match is not None
                pos = match.end()
                continue
            match = _BLOCK_COMMENT.match(source, pos)
            if match is None:  # unterminated: the rest of the input is a comment
                out.complete = False
                pos = end
                continue
            if _LINE_TERMINATOR.search(match.group()):
                newline = True
            pos = match.end()
            continue

        if char in "\"'":
            match = _STRING[char].match(source, pos)
            assert match is not None
            if not match.group(1):
                out.complete = False
            emit(TokenKind.STRING, match.group(), pos)
            pos = match.end()
            continue

        if char == "`" or (char == "}" and braces and braces[-1]):
            if char == "}":
                braces.pop()
            match = _TEMPLATE_BODY.match(source, pos + 1)
            assert match is not None
            closer = match.group(1)
            if closer == "${":
                braces.append(True)
            elif not closer:
                out.complete = False
            emit(TokenKind.TEMPLATE, source[pos : match.end()], pos)
            pos = match.end()
            continue

        if char == "/" and _regex_allowed(tokens[-1] if tokens else None):
            match = _REGEX.match(source, pos)
            if match:
                emit(TokenKind.REGEX, match.group(), pos)
                pos = match.end()
                continue
            # Not a well-formed literal on this line: fall through and treat "/" as an
            # operator rather than swallowing the rest of the line.

        if char.isdigit() or (char == "." and pos + 1 < end and source[pos + 1].isdigit()):
            match = _NUMBER.match(source, pos)
            if match:
                emit(TokenKind.NUMBER, match.group(), pos)
                pos = match.end()
                continue

        match = _IDENTIFIER.match(source, pos)
        if match:
            emit(TokenKind.IDENTIFIER, match.group(), pos)
            pos = match.end()
            continue

        match = _PUNCTUATOR.match(source, pos)
        if match:
            text = match.group()
            if text == "?." and pos + 2 < end and source[pos + 2].isdigit():
                text = "?"  # "a?.5:b" is a conditional, not optional chaining
            if text == "{":
                braces.append(False)
            elif text == "}" and braces:
                braces.pop()
            emit(TokenKind.PUNCTUATOR, text, pos)
            pos += len(text)
            continue

        # Anything else (a stray backslash, a control character) is kept as itself, so
        # it still counts towards the hash.
        emit(TokenKind.PUNCTUATOR, char, pos)
        pos += 1

    if any(braces):  # the input ended inside a template substitution
        out.complete = False
    return out


def normalize(source: str) -> str:
    """``source`` with comments dropped and whitespace collapsed (see the module docs)."""
    parts: list[str] = []
    for token in tokenize(source).tokens:
        if parts:
            parts.append("\n" if token.newline_before else " ")
        parts.append(token.text)
    return "".join(parts)


def normalized_sha384(source: str) -> str:
    return hashlib.sha384(normalize(source).encode("utf-8")).hexdigest()
