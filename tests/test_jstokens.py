from __future__ import annotations

import pytest

from script_sentinel.jstokens import (
    TokenKind,
    normalize,
    normalized_sha384,
    string_value,
    tokenize,
)


def texts(source: str) -> list[str]:
    return [t.text for t in tokenize(source).tokens]


def kinds(source: str) -> list[TokenKind]:
    return [t.kind for t in tokenize(source).tokens]


def test_identifiers_numbers_and_punctuators() -> None:
    assert texts("let $a_1 = obj?.x ?? 0x1F_00n >>>= 2;") == [
        "let",
        "$a_1",
        "=",
        "obj",
        "?.",
        "x",
        "??",
        "0x1F_00n",
        ">>>=",
        "2",
        ";",
    ]
    assert texts("a ... b => c **= .5e-3 0o17 0b101") == [
        "a",
        "...",
        "b",
        "=>",
        "c",
        "**=",
        ".5e-3",
        "0o17",
        "0b101",
    ]
    # Unicode identifiers, escapes and private names.
    assert texts("const café = \\u0061bc; this.#secret") == [
        "const",
        "café",
        "=",
        "\\u0061bc",
        ";",
        "this",
        ".",
        "#secret",
    ]


def test_optional_chaining_is_not_confused_with_a_conditional() -> None:
    assert texts("a?.5:b") == ["a", "?", ".5", ":", "b"]
    assert texts("a?.b") == ["a", "?.", "b"]


def test_comments_and_whitespace_are_dropped_but_line_breaks_are_noted() -> None:
    result = tokenize("/* banner */\nfoo( // call\n  1 )\u2028bar\ufeff")
    assert [t.text for t in result.tokens] == ["foo", "(", "1", ")", "bar"]
    assert [t.newline_before for t in result.tokens] == [True, False, True, False, True]
    assert result.comments == 2
    assert result.complete
    # A block comment that spans lines counts as a line break.
    assert [t.newline_before for t in tokenize("a /*\n*/ b").tokens] == [False, True]


def test_hashbang() -> None:
    result = tokenize("#!/usr/bin/env node\nrun()")
    assert texts("#!/usr/bin/env node\nrun()") == ["run", "(", ")"]
    assert result.comments == 1


def test_strings_keep_their_exact_text() -> None:
    source = """x = "a // not a comment" + 'it\\'s' + "line\\
continued";"""
    assert texts(source) == [
        "x",
        "=",
        '"a // not a comment"',
        "+",
        "'it\\'s'",
        "+",
        '"line\\\ncontinued"',
        ";",
    ]


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("x = /ab+c/gi.test(y)", TokenKind.REGEX),
        ("return /[/]x/", TokenKind.REGEX),
        ("f(/a\\/b/)", TokenKind.REGEX),
        ("[1, /re/]", TokenKind.REGEX),
        ("}/re/", TokenKind.REGEX),
        ("typeof /x/", TokenKind.REGEX),
        ("a / b / c", TokenKind.PUNCTUATOR),
        ("(a) / 2", TokenKind.PUNCTUATOR),
        ("x[0] / 2", TokenKind.PUNCTUATOR),
        ("1 / 2", TokenKind.PUNCTUATOR),
        ("'s' / 2", TokenKind.PUNCTUATOR),
    ],
)
def test_division_or_regular_expression(source: str, expected: TokenKind) -> None:
    slash = next(t for t in tokenize(source).tokens if t.text.startswith("/"))
    assert slash.kind is expected


def test_a_slash_that_isnt_a_complete_regex_is_an_operator() -> None:
    # "/" where a regex could start, but no closing "/" on the line.
    assert kinds("= /\n2") == [TokenKind.PUNCTUATOR, TokenKind.PUNCTUATOR, TokenKind.NUMBER]


def test_template_literals_with_nested_substitutions() -> None:
    source = "t = `a ${ {k: 1}.k + `in${2}` } b // kept`; // dropped"
    tokens = tokenize(source).tokens
    assert [(t.kind, t.text) for t in tokens if t.kind is TokenKind.TEMPLATE] == [
        (TokenKind.TEMPLATE, "`a ${"),
        (TokenKind.TEMPLATE, "`in${"),
        (TokenKind.TEMPLATE, "}`"),
        (TokenKind.TEMPLATE, "} b // kept`"),
    ]
    assert texts(source)[-1] == ";"
    assert tokenize(source).complete
    # Whitespace inside a template literal is part of the value.
    assert normalize("`a  b`") != normalize("`a b`")


@pytest.mark.parametrize(
    "source",
    ['x = "open\ny', "x = 'open", "x = `open ${a", "a /* open", "x = `open"],
)
def test_unterminated_input_is_tolerated(source: str) -> None:
    result = tokenize(source)
    assert not result.complete
    assert result.tokens[0].text in ("x", "a")


def test_regex_at_the_start_and_odd_digits() -> None:
    assert kinds("/re/.test(x)")[0] is TokenKind.REGEX
    # "²" is a digit to Python but not a JavaScript number; it's kept as a token.
    assert texts("x = ²") == ["x", "=", "²"]


def test_stray_characters_still_count() -> None:
    assert texts("a \\ b \x01") == ["a", "\\", "b", "\x01"]
    assert texts("}") == ["}"]  # an unmatched closing brace


def test_normalize_ignores_comments_and_spacing() -> None:
    v1 = "/*! vendor v1.2.3 built 2026-11-01 */\nfunction f(a,b){\n    return a+b; // sum\n}\n"
    v2 = (
        "/*! vendor v1.2.3 built 2026-11-20 */\nfunction f( a, b ) {\n\treturn a + b;\n}\n"
        "//# sourceMappingURL=f.js.map\n"
    )
    assert normalize(v1) == "function f ( a , b ) {\nreturn a + b ;\n}"
    assert normalize(v1) == normalize(v2)
    assert normalized_sha384(v1) == normalized_sha384(v2)


def test_normalize_keeps_what_changes_behaviour() -> None:
    assert normalize("a = b + c") != normalize("a = b - c")
    assert normalize("a + +b") != normalize("a ++b")
    # A line break after "return" changes the program (automatic semicolon insertion).
    assert normalize("return\nx") != normalize("return x")
    assert normalize("s = 'a // b'") != normalize("s = 'a'")
    assert normalized_sha384("x") != normalized_sha384("y")
    assert len(normalized_sha384("")) == 96


def test_string_values() -> None:
    def value(source: str) -> list[str]:
        return [
            string_value(t)
            for t in tokenize(source).tokens
            if t.kind in (TokenKind.STRING, TokenKind.TEMPLATE)
        ]

    bs = chr(92)  # a backslash, spelled out
    assert value(f"\"a{bs}nb{bs}x41{bs}u0042{bs}u{{43}}{bs}q\" 'it{bs}'s'") == ["a\nbABCq", "it's"]
    assert value(f'"line{bs}\ncontinued" "{bs}u{{110000}}"') == [
        "linecontinued",
        f"{bs}u{{110000}}",
    ]
    assert value('"unterminated') == ["unterminated"]
    assert value("`a${b}c${d}e` `whole` `open") == ["a", "c", "e", "whole", "open"]
