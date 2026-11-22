from __future__ import annotations

import pytest

from script_sentinel.robots import MAX_ROBOTS_BYTES, RobotsPolicy, Rule

TOKEN = "script-sentinel"


def policy(text: str) -> RobotsPolicy:
    return RobotsPolicy.parse(text, TOKEN)


def test_no_rules_allows_everything() -> None:
    assert policy("").can_fetch("https://shop.test/checkout")
    assert policy("# just a comment\nSitemap: https://shop.test/sitemap.xml").can_fetch("/a")


def test_star_group_applies_when_no_group_names_us() -> None:
    p = policy("User-agent: *\nDisallow: /checkout\n")
    assert not p.can_fetch("https://shop.test/checkout")
    assert not p.can_fetch("https://shop.test/checkout/step-2")
    assert p.can_fetch("https://shop.test/")


def test_our_group_replaces_the_star_group() -> None:
    text = """
    User-agent: *
    Disallow: /

    User-agent: Script-Sentinel
    Disallow: /admin/
    """
    p = policy(text)
    assert p.can_fetch("https://shop.test/checkout")
    assert not p.can_fetch("https://shop.test/admin/users")


def test_groups_for_the_same_agent_are_combined() -> None:
    text = """
    user-agent: script-sentinel
    disallow: /a

    user-agent: other
    disallow: /b

    user-agent: script-sentinel
    disallow: /c
    """
    p = policy(text)
    assert not p.can_fetch("/a")
    assert p.can_fetch("/b")
    assert not p.can_fetch("/c")


def test_consecutive_user_agent_lines_share_a_group() -> None:
    p = policy("User-agent: googlebot\nUser-agent: script-sentinel\nDisallow: /private\n")
    assert not p.can_fetch("/private")


def test_rules_before_any_user_agent_are_ignored() -> None:
    assert policy("Disallow: /\nUser-agent: other\nDisallow: /x").can_fetch("/x")


def test_empty_disallow_matches_nothing() -> None:
    assert policy("User-agent: *\nDisallow:\n").can_fetch("/anything")


def test_longest_match_wins_and_allow_wins_ties() -> None:
    text = """
    User-agent: *
    Disallow: /shop
    Allow: /shop/checkout
    Disallow: /shop/checkout/admin
    Allow: /tie
    Disallow: /tie
    """
    p = policy(text)
    assert not p.can_fetch("/shop/cart")
    assert p.can_fetch("/shop/checkout")
    assert not p.can_fetch("/shop/checkout/admin")
    assert p.can_fetch("/tie")


def test_wildcards_and_end_anchor() -> None:
    text = """
    User-agent: *
    Disallow: /*.php$
    Disallow: /private*/data
    Disallow: /*?session=
    """
    p = policy(text)
    assert not p.can_fetch("/index.php")
    assert p.can_fetch("/index.php?x=1")  # $ anchors the end of path + query
    assert not p.can_fetch("/private-area/data")
    assert not p.can_fetch("/cart?session=abc")
    assert p.can_fetch("/cart?lang=en")


def test_robots_txt_itself_is_always_allowed() -> None:
    assert policy("User-agent: *\nDisallow: /").can_fetch("https://shop.test/robots.txt")
    assert RobotsPolicy.disallow_everything("unreachable").can_fetch("/robots.txt")


def test_percent_encoding_is_compared_canonically() -> None:
    p = policy("User-agent: *\nDisallow: /caf%c3%a9\nDisallow: /a%7Eb\n")
    assert not p.can_fetch("/café")
    assert not p.can_fetch("/caf%C3%A9")
    assert not p.can_fetch("/a~b")


def test_comments_and_odd_whitespace() -> None:
    p = policy("  USER-AGENT :  *   # everyone\n\tDISALLOW:/secret # no\nnot a rule line\n")
    assert not p.can_fetch("/secret/x")


def test_only_the_first_500_kib_are_parsed() -> None:
    filler = "# " + "x" * (MAX_ROBOTS_BYTES + 10) + "\n"
    text = "User-agent: *\n" + filler + "Disallow: /late\n"
    assert policy(text).can_fetch("/late")
    assert RobotsPolicy.parse(text.encode(), TOKEN).can_fetch("/late")


def test_disallow_and_allow_everything() -> None:
    assert not RobotsPolicy.disallow_everything("unreachable (503)").can_fetch("/")
    allow = RobotsPolicy.allow_everything("unavailable (404)")
    assert allow.can_fetch("/")
    assert allow.source == "unavailable (404)"


def test_empty_path_is_root() -> None:
    assert not policy("User-agent: *\nDisallow: /$").can_fetch("https://shop.test")


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        ("/", "/x", True),
        ("/x$", "/x", True),
        ("/x$", "/xy", False),
        ("*", "/anything", True),
        ("/a*b*c", "/a-b-c-d", True),
        ("/a.b", "/aXb", False),  # dots are literal
    ],
)
def test_rule_matching(pattern: str, path: str, expected: bool) -> None:
    assert Rule(allow=False, pattern=pattern).matches(path) is expected
