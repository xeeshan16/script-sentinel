"""Finding the scripts an HTML page loads.

:func:`parse_scripts` walks a page with the standard library's tokenizer and returns every
``<script>`` element a browser would treat as code, in document order, with the attributes
that matter for integrity monitoring.

It follows the HTML standard where it changes the answer:

* the ``type`` attribute decides whether a block is code. Missing, empty or a JavaScript
  MIME type is a classic script, ``module`` is a module script, ``importmap`` is recorded
  because it controls where modules load from, and anything else is a data block
  (``application/ld+json``, templates), which never runs;
* the first ``<base href>`` changes how relative ``src`` values resolve;
* scripts inside ``<template>`` or ``<noscript>`` never run with scripting enabled, so
  they are skipped;
* inside ``<svg>`` a script names its source with ``href`` or ``xlink:href``;
* a ``data:`` URL in ``src`` is code embedded in the page, so it is treated as an inline
  script with the decoded body.

It also records any Content Security Policy set with ``<meta http-equiv>``, and warns about
an ``integrity`` attribute on a cross-origin script without ``crossorigin``: the request is
then made in no-cors mode, the response is opaque, and browsers refuse to run the script.

Anything that can't be inventoried (``javascript:`` or ``blob:`` sources, an empty ``src``,
an undecodable ``data:`` URL) is reported as a warning rather than silently dropped.

Static parsing only sees scripts present in the HTML. Scripts injected at runtime by other
scripts are the dynamic renderer's job (day 11 of the plan).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import unquote_to_bytes, urldefrag, urljoin, urlsplit

from script_sentinel.db.models import ScriptType
from script_sentinel.origins import MAX_URL_LENGTH, InvalidUrlError, origin_of

# https://mimesniff.spec.whatwg.org/#javascript-mime-type
JAVASCRIPT_MIME_TYPES = frozenset(
    {
        "application/ecmascript",
        "application/javascript",
        "application/x-ecmascript",
        "application/x-javascript",
        "text/ecmascript",
        "text/javascript",
        "text/javascript1.0",
        "text/javascript1.1",
        "text/javascript1.2",
        "text/javascript1.3",
        "text/javascript1.4",
        "text/javascript1.5",
        "text/jscript",
        "text/livescript",
        "text/x-ecmascript",
        "text/x-javascript",
    }
)

# Elements whose contents never execute when scripting is enabled.
_INERT_CONTAINERS = frozenset({"template", "noscript"})


@dataclass(frozen=True, slots=True)
class ParsedScript:
    """One ``<script>`` element that a browser would act on."""

    position: int  # 1-based, among inventoried scripts on the page, in document order
    script_type: ScriptType
    type_attribute: str | None
    # External scripts: the absolute URL (fragment dropped). Inline scripts: None.
    src: str | None
    # Inline scripts (and decoded data: URLs): the body as served.
    body: str | None
    inline_index: int | None  # 1-based among inline scripts, used to build its locator
    integrity: str | None = None
    crossorigin: str | None = None
    referrerpolicy: str | None = None
    nonce: str | None = None
    is_async: bool = False
    is_defer: bool = False
    nomodule: bool = False
    in_svg: bool = False

    @property
    def is_inline(self) -> bool:
        return self.src is None

    @property
    def body_sha384(self) -> str | None:
        if self.body is None:
            return None
        return hashlib.sha384(self.body.encode("utf-8")).hexdigest()

    @property
    def body_size(self) -> int | None:
        return None if self.body is None else len(self.body.encode("utf-8"))

    @property
    def nonce_digest(self) -> str | None:
        """A short digest of the nonce.

        Nonces are per-response secrets, so the value itself is not kept, but a digest is
        enough to notice a nonce that never changes (which defeats the point of a nonce).
        """
        if self.nonce is None:
            return None
        return hashlib.sha256(self.nonce.encode("utf-8")).hexdigest()[:16]


@dataclass(slots=True)
class PageInventory:
    scripts: list[ParsedScript] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    base_url: str = ""
    data_blocks: int = 0  # <script> elements with a non-code type, which never run
    # Policies from <meta http-equiv="Content-Security-Policy" content="...">.
    meta_csp: list[str] = field(default_factory=list)


def classify_type(type_attribute: str | None, language: str | None = None) -> ScriptType | None:
    """The script type for a ``type`` attribute, or None for a data block.

    Follows "prepare the script element" in the HTML standard, including the legacy
    ``language`` attribute that applies when ``type`` is absent.
    """
    if type_attribute is None:
        if language:
            type_attribute = "text/" + language
        else:
            return ScriptType.CLASSIC
    value = type_attribute.strip().lower()
    if not value:
        return ScriptType.CLASSIC
    essence = value.split(";", 1)[0].strip()
    if essence in JAVASCRIPT_MIME_TYPES:
        return ScriptType.CLASSIC
    if value == "module":
        return ScriptType.MODULE
    if value == "importmap":
        return ScriptType.IMPORTMAP
    return None


def decode_data_url(url: str) -> str | None:
    """The text a ``data:`` URL carries, or None if it isn't a valid one."""
    header, sep, payload = url[5:].partition(",")
    if not sep:
        return None
    params = [p.strip().lower() for p in header.split(";")]
    raw = unquote_to_bytes(payload)
    if "base64" in params[1:]:
        try:
            raw = base64.b64decode(b"".join(raw.split()), validate=True)
        except (binascii.Error, ValueError):
            return None
    charset = next((p[8:] for p in params if p.startswith("charset=")), "utf-8")
    try:
        return raw.decode(charset, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


class _ScriptParser(HTMLParser):
    def __init__(self, page_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.inventory = PageInventory(base_url=page_url)
        self._page_origin = _origin_or_none(page_url)
        self._base_seen = False
        self._inert_depth = 0
        self._svg_depth = 0
        self._open: dict[str, str | None] | None = None
        self._open_in_svg = False
        self._body: list[str] = []
        self._position = 0
        self._inline = 0

    # The tokenizer calls these.

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _INERT_CONTAINERS:
            self._inert_depth += 1
        elif tag == "svg":
            self._svg_depth += 1
        elif tag == "base" and not self._base_seen:
            self._set_base(dict(attrs))
        elif tag == "meta" and self._inert_depth == 0:
            self._meta(dict(attrs))
        elif tag == "script":
            self._open = dict(attrs)
            self._open_in_svg = self._svg_depth > 0
            self._body = []

    def handle_endtag(self, tag: str) -> None:
        if tag in _INERT_CONTAINERS:
            self._inert_depth = max(0, self._inert_depth - 1)
        elif tag == "svg":
            self._svg_depth = max(0, self._svg_depth - 1)
        elif tag == "script" and self._open is not None:
            attrs, self._open = self._open, None
            if self._inert_depth == 0:
                self._finish_script(attrs, "".join(self._body))

    def handle_data(self, data: str) -> None:
        if self._open is not None:
            self._body.append(data)

    def close(self) -> None:
        super().close()
        if self._open is not None:
            # An unterminated <script> at the end of the document still runs.
            attrs, self._open = self._open, None
            if self._inert_depth == 0:
                self._finish_script(attrs, "".join(self._body))

    # Helpers.

    def _set_base(self, attrs: dict[str, str | None]) -> None:
        href = (attrs.get("href") or "").strip()
        if not href:
            return
        self._base_seen = True
        resolved = urljoin(self.inventory.base_url, href)
        if urlsplit(resolved).scheme in ("http", "https"):
            self.inventory.base_url = resolved
        else:
            self.inventory.warnings.append(f"ignored <base href> with scheme: {href[:80]}")

    def _meta(self, attrs: dict[str, str | None]) -> None:
        equiv = (attrs.get("http-equiv") or "").strip().lower()
        content = (attrs.get("content") or "").strip()
        if equiv == "content-security-policy" and content:
            self.inventory.meta_csp.append(content[:8192])

    def _finish_script(self, attrs: dict[str, str | None], body: str) -> None:
        script_type = classify_type(attrs.get("type"), attrs.get("language"))
        if script_type is None:
            self.inventory.data_blocks += 1
            return
        if self._open_in_svg:
            src_value = attrs.get("href", attrs.get("xlink:href", attrs.get("src")))
        else:
            src_value = attrs.get("src")
        if src_value is None:
            self._add(attrs, script_type, body=body)
            return
        src = src_value.strip()
        if not src:
            self.inventory.warnings.append("skipped <script> with an empty src (never runs)")
            return
        if script_type is ScriptType.IMPORTMAP:
            # Browsers don't support external import maps; the element is ignored.
            self.inventory.warnings.append(f"skipped <script type=importmap src={src[:80]}>")
            return
        resolved = urljoin(self.inventory.base_url, src)
        scheme = urlsplit(resolved).scheme.lower()
        if scheme == "data":
            decoded = decode_data_url(resolved)
            if decoded is None:
                self.inventory.warnings.append("skipped <script> with an invalid data: URL")
                return
            self._add(attrs, script_type, body=decoded)
        elif scheme in ("http", "https"):
            absolute = urldefrag(resolved).url
            if len(absolute) > MAX_URL_LENGTH:
                self.inventory.warnings.append(
                    f"skipped <script> whose src is longer than {MAX_URL_LENGTH} characters"
                )
                return
            self._add(attrs, script_type, src=absolute)
        else:
            self.inventory.warnings.append(
                f"skipped <script> with a {scheme}: src that can't be fetched: {src[:80]}"
            )

    def _add(
        self,
        attrs: dict[str, str | None],
        script_type: ScriptType,
        *,
        src: str | None = None,
        body: str | None = None,
    ) -> None:
        self._position += 1
        inline_index = None
        if src is None:
            self._inline += 1
            inline_index = self._inline
        integrity = _clean(attrs.get("integrity"))
        crossorigin = _flag_value(attrs, "crossorigin")
        if (
            src is not None
            and integrity is not None
            and crossorigin is None
            and _origin_or_none(src) != self._page_origin
        ):
            self.inventory.warnings.append(
                f"integrity on cross-origin script {src[:200]} without a crossorigin "
                "attribute: browsers will refuse to run it"
            )
        self.inventory.scripts.append(
            ParsedScript(
                position=self._position,
                script_type=script_type,
                type_attribute=attrs.get("type"),
                src=src,
                body=body,
                inline_index=inline_index,
                integrity=integrity,
                crossorigin=crossorigin,
                referrerpolicy=_clean(attrs.get("referrerpolicy")),
                nonce=attrs.get("nonce") or None,
                is_async="async" in attrs,
                is_defer="defer" in attrs,
                nomodule="nomodule" in attrs,
                in_svg=self._open_in_svg,
            )
        )


def _origin_or_none(url: str) -> str | None:
    try:
        return str(origin_of(url))
    except InvalidUrlError:
        return None


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    return value or None


def _flag_value(attrs: dict[str, str | None], name: str) -> str | None:
    """An enumerated attribute's value; a bare ``crossorigin`` means ``anonymous``."""
    if name not in attrs:
        return None
    value = (attrs[name] or "").strip().lower()
    return value or "anonymous"


def parse_scripts(html: str, page_url: str) -> PageInventory:
    """Every script on the page that a browser would act on, in document order."""
    parser = _ScriptParser(page_url)
    parser.feed(html)
    parser.close()
    return parser.inventory


def inline_locator(page_url: str, inline_index: int) -> str:
    """The inventory locator of the ``inline_index``-th inline script on a page."""
    return f"{page_url}#inline-{inline_index}"
