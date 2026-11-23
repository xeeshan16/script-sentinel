from __future__ import annotations

import codecs
import hashlib

from script_sentinel.jstokens import normalized_sha384
from script_sentinel.sri import integrity_value
from script_sentinel.versions import decode_script, digest_body


def test_decode_script_follows_browser_priorities() -> None:
    assert decode_script(codecs.BOM_UTF8 + "é".encode(), "text/javascript; charset=latin-1") == "é"
    assert decode_script(codecs.BOM_UTF16_LE + "é".encode("utf-16-le")) == "é"
    assert decode_script(codecs.BOM_UTF16_BE + "é".encode("utf-16-be")) == "é"
    assert decode_script("é".encode("latin-1"), 'text/javascript; charset="ISO-8859-1"') == "é"
    assert decode_script("é".encode(), "text/javascript; charset=bogus") == "é"
    assert decode_script("é".encode(), "text/javascript; foo=bar; charset=") == "é"
    assert decode_script(b"\xff") == "\ufffd"


def test_nul_characters_are_replaced_in_the_stored_text_only() -> None:
    body = b"a\x00b"
    digest = digest_body(body)
    assert digest.text == "a\ufffdb"
    assert digest.sha384 == hashlib.sha384(body).hexdigest()


def test_digest_body() -> None:
    body = b"/* v1 */ run();"
    digest = digest_body(body)
    assert digest.size_bytes == len(body)
    assert digest.sri == integrity_value(body)
    assert set(digest.digests) == {"sha256", "sha384", "sha512"}
    assert digest.normalized_sha384 == normalized_sha384("run();")
