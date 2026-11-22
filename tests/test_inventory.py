from __future__ import annotations

import base64
import hashlib

import pytest

from script_sentinel.db.models import ScriptType
from script_sentinel.inventory import (
    classify_type,
    decode_data_url,
    inline_locator,
    parse_scripts,
)

PAGE = "https://shop.test/checkout/index.html"


def test_external_and_inline_scripts_in_document_order() -> None:
    html = """<!doctype html><html><head>
    <script>window.cfg = {a: 1};</script>
    <script src="/js/app.js" defer></script>
    <script src="https://cdn.vendor.test/w.js" async integrity=" sha384-abc "
            crossorigin referrerpolicy="no-referrer"></script>
    </head><body>
    <script nonce="r4nd0m">console.log("</div>")</script>
    </body></html>"""
    inv = parse_scripts(html, PAGE)
    assert [s.position for s in inv.scripts] == [1, 2, 3, 4]
    cfg, app, vendor, tail = inv.scripts
    assert cfg.is_inline
    assert cfg.body == "window.cfg = {a: 1};"
    assert cfg.inline_index == 1
    assert cfg.body_sha384 == hashlib.sha384(b"window.cfg = {a: 1};").hexdigest()
    assert cfg.body_size == 20
    assert app.src == "https://shop.test/js/app.js"
    assert app.is_defer
    assert not app.is_async
    assert app.inline_index is None
    assert app.body_sha384 is None
    assert app.body_size is None
    assert vendor.integrity == "sha384-abc"
    assert vendor.crossorigin == "anonymous"  # a bare attribute means anonymous
    assert vendor.referrerpolicy == "no-referrer"
    assert vendor.is_async
    assert tail.body == 'console.log("</div>")'
    assert tail.inline_index == 2
    assert tail.nonce == "r4nd0m"
    assert tail.nonce_digest == hashlib.sha256(b"r4nd0m").hexdigest()[:16]
    assert cfg.nonce_digest is None
    assert inv.warnings == []


def test_relative_sources_resolve_against_the_page_and_drop_fragments() -> None:
    html = '<script src="lib.js#v2"></script><script src="//cdn.test/x.js"></script>'
    inv = parse_scripts(html, PAGE)
    assert [s.src for s in inv.scripts] == [
        "https://shop.test/checkout/lib.js",
        "https://cdn.test/x.js",
    ]


def test_first_base_href_wins() -> None:
    html = """<head><base target="_blank"><base href="https://static.shop.test/v3/">
    <base href="https://ignored.test/"></head><script src="app.js"></script>"""
    inv = parse_scripts(html, PAGE)
    assert inv.base_url == "https://static.shop.test/v3/"
    assert inv.scripts[0].src == "https://static.shop.test/v3/app.js"


def test_base_href_with_a_non_http_scheme_is_ignored() -> None:
    inv = parse_scripts('<base href="javascript:alert(1)"><script src="a.js"></script>', PAGE)
    assert inv.scripts[0].src == "https://shop.test/checkout/a.js"
    assert inv.warnings == ["ignored <base href> with scheme: javascript:alert(1)"]


@pytest.mark.parametrize(
    ("type_attribute", "language", "expected"),
    [
        (None, None, ScriptType.CLASSIC),
        ("", None, ScriptType.CLASSIC),
        ("  ", None, ScriptType.CLASSIC),
        ("text/javascript", None, ScriptType.CLASSIC),
        ("Application/JavaScript; charset=utf-8", None, ScriptType.CLASSIC),
        ("module", None, ScriptType.MODULE),
        (" MODULE ", None, ScriptType.MODULE),
        ("importmap", None, ScriptType.IMPORTMAP),
        ("application/ld+json", None, None),
        ("text/template", None, None),
        ("speculationrules", None, None),
        (None, "javascript", ScriptType.CLASSIC),
        (None, "vbscript", None),
        ("module", "vbscript", ScriptType.MODULE),  # language only matters without type
    ],
)
def test_classify_type(
    type_attribute: str | None, language: str | None, expected: ScriptType | None
) -> None:
    assert classify_type(type_attribute, language) is expected


def test_data_blocks_are_counted_not_inventoried() -> None:
    html = """<script type="application/ld+json">{"@type": "Product"}</script>
    <script type="importmap">{"imports": {"x": "/x.js"}}</script>
    <script type="module" src="/m.js"></script>"""
    inv = parse_scripts(html, PAGE)
    assert inv.data_blocks == 1
    assert [s.script_type for s in inv.scripts] == [ScriptType.IMPORTMAP, ScriptType.MODULE]
    assert inv.scripts[0].type_attribute == "importmap"


def test_external_import_maps_are_skipped_with_a_warning() -> None:
    inv = parse_scripts('<script type="importmap" src="/map.json"></script>', PAGE)
    assert inv.scripts == []
    assert inv.warnings == ["skipped <script type=importmap src=/map.json>"]


def test_scripts_in_template_and_noscript_never_run() -> None:
    html = """<template><script src="/t.js"></script><template><script>x</script></template>
    </template><noscript><script src="/n.js"></script></noscript><script src="/real.js"></script>
    """
    inv = parse_scripts(html, PAGE)
    assert [s.src for s in inv.scripts] == ["https://shop.test/real.js"]
    assert inv.scripts[0].position == 1


def test_svg_scripts_use_href() -> None:
    html = """<svg><script href="/svg-a.js"/><script xlink:href="/svg-b.js"></script>
    <script>inline()</script></svg><script href="/not-svg.js">x()</script>"""
    inv = parse_scripts(html, PAGE)
    assert [(s.src, s.in_svg) for s in inv.scripts] == [
        ("https://shop.test/svg-a.js", True),
        ("https://shop.test/svg-b.js", True),
        (None, True),
        (None, False),  # outside SVG, href is not a source; the body runs inline
    ]


def test_data_urls_become_inline_scripts() -> None:
    payload = base64.b64encode(b"alert('hi')").decode()
    html = f"""<script src="data:text/javascript;base64,{payload}"></script>
    <script src="data:,console.log(%22x%22)"></script>"""
    inv = parse_scripts(html, PAGE)
    assert [(s.src, s.body, s.inline_index) for s in inv.scripts] == [
        (None, "alert('hi')", 1),
        (None, 'console.log("x")', 2),
    ]


def test_unfetchable_sources_are_warnings() -> None:
    html = """<script src=""></script><script src="javascript:void(0)"></script>
    <script src="blob:https://shop.test/uuid"></script><script src="data:base64"></script>
    <script src="data:;base64,!!!"></script><script src="/ok.js"></script>"""
    inv = parse_scripts(html, PAGE)
    assert [s.src for s in inv.scripts] == ["https://shop.test/ok.js"]
    assert inv.scripts[0].position == 1
    assert inv.warnings == [
        "skipped <script> with an empty src (never runs)",
        "skipped <script> with a javascript: src that can't be fetched: javascript:void(0)",
        "skipped <script> with a blob: src that can't be fetched: blob:https://shop.test/uuid",
        "skipped <script> with an invalid data: URL",
        "skipped <script> with an invalid data: URL",
    ]


def test_overlong_sources_are_skipped() -> None:
    inv = parse_scripts(f'<script src="/{"a" * 2100}.js"></script>', PAGE)
    assert inv.scripts == []
    assert inv.warnings == ["skipped <script> whose src is longer than 2048 characters"]


def test_scripts_in_comments_are_ignored_and_markup_in_scripts_is_text() -> None:
    html = """<!-- <script src="/old.js"></script> -->
    <script>document.write('<script src="/nested.js"><\\/script>')</script>"""
    inv = parse_scripts(html, PAGE)
    assert len(inv.scripts) == 1
    assert inv.scripts[0].body is not None
    assert "/nested.js" in inv.scripts[0].body


def test_unterminated_script_at_end_of_document_is_kept() -> None:
    inv = parse_scripts("<p>hi</p><script>var unterminated = 1;", PAGE)
    assert [s.body for s in inv.scripts] == ["var unterminated = 1;"]


def test_unterminated_script_inside_template_is_dropped() -> None:
    assert parse_scripts("<template><script>x", PAGE).scripts == []


def test_stray_end_tags_do_not_break_nesting() -> None:
    html = "</template></noscript></svg><script src='/a.js'></script>"
    assert [s.src for s in parse_scripts(html, PAGE).scripts] == ["https://shop.test/a.js"]


def test_flags_and_empty_attributes() -> None:
    html = '<script src="/a.js" nomodule nonce="" integrity="" crossorigin="USE-CREDENTIALS">'
    html += "</script>"
    (script,) = parse_scripts(html, PAGE).scripts
    assert script.nomodule
    assert script.nonce is None
    assert script.integrity is None
    assert script.crossorigin == "use-credentials"


def test_decode_data_url() -> None:
    assert decode_data_url("data:,a%20b") == "a b"
    assert decode_data_url("data:text/javascript;charset=latin-1,caf%E9") == "café"
    assert decode_data_url("data:;charset=no-such-codec,ok") == "ok"
    assert decode_data_url("data:;base64,YW Jj") == "abc"  # whitespace in base64 is allowed
    assert decode_data_url("data:nocomma") is None


def test_inline_locator() -> None:
    assert inline_locator("https://shop.test/", 3) == "https://shop.test/#inline-3"
