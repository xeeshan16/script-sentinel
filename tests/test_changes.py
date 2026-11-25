"""Change analysis, severity rules and inline block matching (pure functions)."""

from __future__ import annotations

import hashlib

import pytest

from script_sentinel import changes
from script_sentinel.changes import (
    KnownBlock,
    SeenBlock,
    added_severity,
    analyze_change,
    change_severity,
    entropy,
    match_inline_blocks,
    max_severity,
    raise_severity,
    references,
    severity_at_least,
)
from script_sentinel.db.models import Severity
from script_sentinel.jstokens import normalized_sha384


def test_severity_helpers() -> None:
    assert raise_severity(Severity.LOW) is Severity.MEDIUM
    assert raise_severity(Severity.HIGH, 5) is Severity.CRITICAL
    assert max_severity(Severity.INFO, Severity.HIGH, Severity.LOW) is Severity.HIGH
    assert severity_at_least(Severity.HIGH, Severity.MEDIUM)
    assert not severity_at_least(Severity.LOW, Severity.MEDIUM)


def test_entropy() -> None:
    assert entropy("") == 0.0
    assert entropy("aaaa") == 0.0
    assert entropy("abab") == 1.0
    assert entropy("abcd") == 2.0


def test_references_in_strings_and_templates() -> None:
    source = r"""
        // https://in-a-comment.test/ is not code
        var a = "https://Cdn.Vendor.com/x.js?v=1";
        var b = 'https:\/\/escaped.test\/c';
        var c = "\x68ttps://hex-escaped.test/p", u = "\u{2f}\u002fbraced.test/";
        var d = `wss://socket.test:8443/feed?id=${id}`;
        var e = "//protocol-relative.test/pixel.gif";
        var f = "a//b", g = "http://localhost:3000/dev", h = "http://[::1]:8080/";
        var i = "https://bad-port.test:99999/", j = /https:\/\/regex.test/;
        var k = "not a url", l = "ftp://other-scheme.test/";
    """
    refs = references(source)
    assert refs.hosts == {
        "cdn.vendor.com",
        "escaped.test",
        "hex-escaped.test",
        "braced.test",
        "socket.test",
        "protocol-relative.test",
        "localhost",
        "[::1]",
        "other-scheme.test",  # as a //host reference inside the string
    }
    assert "https://Cdn.Vendor.com/x.js?v=1" in refs.urls
    assert "https://escaped.test/c" in refs.urls
    assert "wss://socket.test:8443/feed?id=" in refs.urls
    assert "//protocol-relative.test/pixel.gif" in refs.urls
    assert references("var x = 1;") == changes.References()


def test_references_keep_every_host_but_cap_urls() -> None:
    source = "".join(f'u("https://h{i}.test/");' for i in range(changes.MAX_REFERENCES + 20))
    refs = references(source)
    assert len(refs.hosts) == changes.MAX_REFERENCES + 20
    assert len(refs.urls) == changes.MAX_REFERENCES


def test_analyze_change() -> None:
    old = 'fetch("/api/cart");'
    new = 'fetch("/api/cart"); navigator.sendBeacon("https://collect.test/c", d);'
    analysis = analyze_change(old, new)
    assert analysis.hosts_added == ["collect.test"]
    assert analysis.urls_added == ["https://collect.test/c"]
    assert analysis.hosts_removed == analysis.urls_removed == []
    assert analysis.size_delta == len(new) - len(old)
    assert analysis.diff.added == 9
    data = analysis.to_dict(max_hunks=0)
    assert data["hunks"] == []
    assert data["hunk_count"] == 1
    assert data["tokens"] == {
        "old": analysis.diff.old_tokens,
        "new": analysis.diff.new_tokens,
        "removed": 0,
        "added": 9,
        "similarity": analysis.diff.similarity,
    }
    back = analyze_change(new, old, old_size=500, new_size=100)
    assert back.hosts_removed == ["collect.test"]
    assert back.size_delta == -400


def _analysis(
    *,
    old: str = "a();",
    new: str = "b();",
    old_size: int | None = None,
    new_size: int | None = None,
) -> changes.ChangeAnalysis:
    return analyze_change(old, new, old_size=old_size, new_size=new_size)


def test_change_severity_rules() -> None:
    plain = _analysis()
    assert change_severity(plain, cosmetic=False, reverted=False, payment_page=False) == (
        changes.Assessment(Severity.LOW, ("the code changed",))
    )
    cosmetic = change_severity(plain, cosmetic=True, reverted=False, payment_page=True)
    assert cosmetic.severity is Severity.INFO  # never raised, not even on a payment page
    reverted = change_severity(
        _analysis(new='x("https://new.test/")'), cosmetic=False, reverted=True, payment_page=True
    )
    # Going back to an earlier body: its references were seen before, so no new-host rule.
    assert reverted.severity is Severity.MEDIUM
    assert reverted.reasons == ("went back to an earlier body", "runs on a payment page")
    grew = change_severity(
        _analysis(old_size=1000, new_size=3000), cosmetic=False, reverted=False, payment_page=False
    )
    assert grew.severity is Severity.MEDIUM
    assert "grew by 2000 bytes" in grew.reasons
    host = change_severity(
        _analysis(new='x("https://new.test/")'), cosmetic=False, reverted=False, payment_page=True
    )
    assert host.severity is Severity.CRITICAL
    assert host.reasons[1] == "references new hosts: new.test"
    assert change_severity(None, cosmetic=False, reverted=False, payment_page=False).severity is (
        Severity.LOW
    )


def test_entropy_only_counts_for_bodies_of_a_kilobyte() -> None:
    readable = "var total = price * quantity;\n" * 40  # ~1.2 KB of low-entropy code
    packed = 'eval(atob("' + "".join(chr(65 + (i * 7919) % 58) for i in range(1200)) + '"));'
    big = analyze_change(readable, packed)
    assert big.entropy_rose
    assert not big.grew_sharply
    assessment = change_severity(big, cosmetic=False, reverted=False, payment_page=False)
    assert assessment.severity is Severity.MEDIUM
    assert any(r.startswith("entropy rose by") for r in assessment.reasons)
    small = analyze_change("aaaa();", "q(1,2,3,'xyz');")
    assert small.entropy_delta > changes.ENTROPY_RISE_BITS
    assert not small.entropy_rose


@pytest.mark.parametrize(
    ("inline", "new_host", "payment_page", "expected"),
    [
        (True, False, False, Severity.LOW),
        (True, True, True, Severity.MEDIUM),
        (False, False, False, Severity.MEDIUM),
        (False, True, False, Severity.HIGH),
        (False, True, True, Severity.CRITICAL),
    ],
)
def test_added_severity(
    inline: bool, new_host: bool, payment_page: bool, expected: Severity
) -> None:
    assert (
        added_severity(inline=inline, new_host=new_host, payment_page=payment_page).severity
        is expected
    )


def _known(index: int, text: str | None) -> KnownBlock:
    if text is None:
        return KnownBlock(index, None, None, None)
    return KnownBlock(index, _sha(text), normalized_sha384(text), text)


def _seen(position: int, text: str) -> SeenBlock:
    return SeenBlock(position, _sha(text), normalized_sha384(text), text)


def _sha(text: str) -> str:
    return hashlib.sha384(text.encode()).hexdigest()


CONFIG = 'window.checkoutConfig = {currency: "EUR", locale: "en-IE", theme: "dark"};'
LAYER = "window.dataLayer = window.dataLayer || []; dataLayer.push({page: 'checkout'});"


def test_inserting_a_block_keeps_the_others() -> None:
    known = [_known(1, CONFIG), _known(2, LAYER)]
    seen = [_seen(1, "window.abTest = 'B';"), _seen(2, CONFIG), _seen(3, LAYER)]
    assert match_inline_blocks(known, seen) == [3, 1, 2]


def test_matching_by_normalized_body_and_similarity() -> None:
    known = [_known(1, CONFIG), _known(2, LAYER)]
    reformatted = CONFIG.replace(" ", "  ") + " // build 7"
    edited = LAYER.replace("'checkout'", "'checkout-v2'")
    # Reordered as well: identity follows the content, not the position.
    assert match_inline_blocks(known, [_seen(1, edited), _seen(2, reformatted)]) == [2, 1]


def test_rewritten_blocks_fall_back_to_their_position() -> None:
    known = [_known(1, CONFIG), _known(2, LAYER)]
    seen = [_seen(1, "skim(document.forms[0]);"), _seen(2, LAYER)]
    assert match_inline_blocks(known, seen) == [1, 2]
    # Position 1 is taken by a matched block, so the rewritten one gets a new index.
    seen = [_seen(1, CONFIG), _seen(2, "skim();"), _seen(3, "other();")]
    assert match_inline_blocks([_known(1, CONFIG), _known(5, None)], seen) == [1, 2, 3]
    seen = [_seen(1, "x();"), _seen(2, CONFIG)]
    assert match_inline_blocks([_known(1, CONFIG), _known(4, None)], seen) == [5, 1]


def test_duplicate_blocks_and_empty_inputs() -> None:
    known = [_known(1, CONFIG), _known(2, CONFIG)]
    assert match_inline_blocks(known, [_seen(1, CONFIG), _seen(2, CONFIG), _seen(3, CONFIG)]) == [
        1,
        2,
        3,
    ]
    assert match_inline_blocks([], [_seen(1, CONFIG)]) == [1]
    # Two edits of the same block: the closer one keeps its identity.
    near = LAYER.replace("'checkout'", "'checkout2'")
    far = LAYER.replace("'checkout'", "'other'").replace("page", "view")
    assert match_inline_blocks([_known(1, LAYER)], [_seen(1, far), _seen(2, near)]) == [2, 1]
    assert match_inline_blocks(known, []) == []


def test_similarity_is_skipped_for_huge_pages(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(changes, "_MAX_SIMILARITY_PAIRS", 1)
    known = [_known(1, CONFIG), _known(2, LAYER)]
    edited = LAYER.replace("'checkout'", "'checkout-v2'")
    # Without the similarity step, the edited block keeps its own position.
    assert match_inline_blocks(known, [_seen(1, edited)]) == [1]
