#!/usr/bin/env python3
"""Validate the static Neural Cinema site without external dependencies."""

from __future__ import annotations

import base64
import binascii
import inspect
import re
import sys
from html import entities as html_entities
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_FILES = ["index.html", "app.js", "styles.css", "README.md", "LICENSE", "CHANGELOG.md"]
SRI_DIGEST_BYTES = {
    "sha384": 48,
    "sha512": 64,
}
SRI_ALGORITHM_STRENGTH = {
    "sha384": 384,
    "sha512": 512,
}
SRI_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
# SRI option-expression = 1*VCHAR (RFC 5234 VCHAR = %x21-7E); non-ASCII is invalid.
SRI_OPTION_EXPRESSION_RE = re.compile(r"^[\x21-\x7E]+$")
# SRI/HTML "split on ASCII whitespace": TAB, LF, FF, CR, SPACE (not Unicode NBSP).
SRI_ASCII_WHITESPACE_RE = re.compile(r"[ \t\n\r\f]+")
SECURITY_SCRIPT_ATTRS = frozenset({"src", "href", "xlink:href", "integrity", "crossorigin"})
# SVG elements that switch child content into the HTML namespace (HTML integration points).
SVG_HTML_INTEGRATION_POINTS = frozenset({"foreignobject", "desc", "title"})
# MathML text integration points (HTML namespace children; not MathML <script>).
MATHML_HTML_INTEGRATION_POINTS = frozenset({"mi", "mo", "mn", "ms", "mtext"})
# Inside MathML HTML integration points, these children stay in the MathML namespace.
MATHML_HTML_INTEGRATION_EXCEPTIONS = frozenset({"mglyph", "malignmark"})
MATHML_ANNOTATION_XML_HTML_ENCODINGS = frozenset({"text/html", "application/xhtml+xml"})
# HTML/SRI ASCII whitespace used for stripping (not Unicode NBSP).
ASCII_WHITESPACE = " \t\n\r\f"
# Classic JavaScript MIME types plus the empty/missing type default and module.
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
# HTML start tags that exit SVG/MathML foreign content (WHATWG "in foreign content").
FOREIGN_HTML_BREAKOUT_TAGS = frozenset(
    {
        "b",
        "big",
        "blockquote",
        "body",
        "br",
        "center",
        "code",
        "dd",
        "div",
        "dl",
        "dt",
        "em",
        "embed",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "head",
        "hr",
        "i",
        "img",
        "li",
        "listing",
        "menu",
        "meta",
        "nobr",
        "ol",
        "p",
        "pre",
        "ruby",
        "s",
        "small",
        "span",
        "strong",
        "strike",
        "sub",
        "sup",
        "table",
        "tt",
        "u",
        "ul",
        "var",
    }
)
FOREIGN_HTML_BREAKOUT_FONT_ATTRS = frozenset({"color", "face", "size"})
# HTMLParser treats script/style/xmp/iframe/noembed/noframes as rawtext/CDATA
# and textarea/title as RCDATA; plaintext is a separate hardcoded RAWTEXT mode.
# In SVG/MathML foreign content those elements are ordinary markup, so nested
# tags (e.g. <svg><style><script href> or <svg><textarea><script href>) must be
# retokenized rather than swallowed. Keep title as RCDATA only in SVG so SVG
# <title> buffering still sees the full RCDATA run; MathML <title> is ordinary
# foreign markup (HTML breakout tags inside it must still be tokenized).
# getattr keeps import working on Python builds that lack the 3.12+ attribute.
_HTML_CDATA_CONTENT_ELEMENTS = HTMLParser.CDATA_CONTENT_ELEMENTS
_FOREIGN_CDATA_CONTENT_ELEMENTS: tuple[str, ...] = ()
_HTML_RCDATA_CONTENT_ELEMENTS = getattr(
    HTMLParser, "RCDATA_CONTENT_ELEMENTS", ("textarea", "title")
)
_FOREIGN_RCDATA_SVG_CONTENT_ELEMENTS = tuple(
    name for name in _HTML_RCDATA_CONTENT_ELEMENTS if name != "textarea"
)
_FOREIGN_RCDATA_MATH_CONTENT_ELEMENTS: tuple[str, ...] = ()
# Python 3.14+ passes escapable= to distinguish RCDATA; older HTMLParser rejects it.
_SET_CDATA_MODE_ACCEPTS_ESCAPABLE = (
    "escapable" in inspect.signature(HTMLParser.set_cdata_mode).parameters
)
# Document URL used as the initial base for top-level HTML (matches browsers).
DOCUMENT_URL = "index.html"
DECLARATIVE_SHADOW_ROOT_MODES = frozenset({"open", "closed"})
# Pin CDN URL → expected SRI token so mistyped/stale digests fail without fetching.
TRUSTED_EXTERNAL_SCRIPT_INTEGRITY = {
    "https://unpkg.com/three@0.149.0/build/three.min.js": (
        "sha384-RRHfJ6w1mTlKUBMYT/hvnRiOzEB/vyRV3DrQOseb6oYfvaZSfdd0byS4bHps0k2R"
    ),
    "https://unpkg.com/lucide@0.468.0/dist/umd/lucide.min.js": (
        "sha384-uTYyvsSSUZeaPhb5RbKlQa0zY/WpX/QHfvg2mczXyBQOpkWPEDy9lczyp+w7SKXu"
    ),
}


def ascii_lower(value: str) -> str:
    """ASCII-only lowercasing (HTML ASCII case-insensitive matching).

    Unicode casefold() would map characters such as U+017F (long s) onto ASCII
    letters and incorrectly recognize sandbox tokens browsers reject.
    """
    return "".join(chr(ord(char) + 32) if "A" <= char <= "Z" else char for char in value)


def html5_named_character(
    name: str, *, had_semicolon: bool | None = None
) -> str | None:
    """Resolve an HTML5 named character reference (entity name without ``&``/``;``).

    ``html.parser`` reports the same entity name for ``&num`` and ``&num;``. When
    ``had_semicolon`` is False, only semicolonless legacy forms (bare HTML5 keys /
    ``name2codepoint``) are decoded — inventing a trailing semicolon would turn
    ``&num`` into ``#`` and falsely match trusted URLs after fragment stripping.
    When ``had_semicolon`` is True or unknown, prefer the semicolon-terminated
    HTML5 table entry (covers entities like ``period`` absent from the legacy map).
    """
    if had_semicolon is False:
        value = html_entities.html5.get(name)
        if value is not None:
            return value
        codepoint = html_entities.name2codepoint.get(name)
        if codepoint is not None:
            return chr(codepoint)
        return None
    for key in (f"{name};", name):
        value = html_entities.html5.get(key)
        if value is not None:
            return value
    codepoint = html_entities.name2codepoint.get(name)
    if codepoint is not None:
        return chr(codepoint)
    return None


def decode_numeric_charref(name: str) -> str:
    """Decode a numeric character reference; invalid code points become U+FFFD."""
    try:
        if name[:1].lower() == "x":
            codepoint = int(name[1:], 16)
        else:
            codepoint = int(name)
    except ValueError:
        return "\uFFFD"
    # HTML5: surrogates and values outside Unicode range are U+FFFD.
    if codepoint > 0x10FFFF or 0xD800 <= codepoint <= 0xDFFF:
        return "\uFFFD"
    try:
        return chr(codepoint)
    except ValueError:
        return "\uFFFD"


class SiteParser(HTMLParser):
    def __init__(
        self,
        fallback_base: str | None = None,
        *,
        scripts_enabled: bool = True,
    ) -> None:
        # Keep character references as entity/charref events so SVG <title>
        # escaped markup (&lt;script...&gt;) is not re-tokenized as real tags.
        super().__init__(convert_charrefs=False)
        self.title = ""
        self._in_title = False
        self._template_depth = 0
        self._noscript_depth = 0
        # Declarative shadow roots are active, but <base> inside them is not the
        # document base URL. Track depth so shadow <base> cannot leak outward.
        self._shadow_root_depth = 0
        # Stack of template kinds ("inert" | "shadow") so nested close tags
        # decrement the matching open kind rather than aggregate depths.
        self._template_kinds: list[str] = []
        # True when the matching mglyph/malignmark start tag entered MathML.
        self._mathml_exception_entered: list[bool] = []
        # Track HTML vs SVG namespace so foreignObject/desc/title HTML scripts use src.
        self._namespaces: list[str] = ["html"]
        # Open start tags (non-inert) so MathML→SVG applies only under annotation-xml.
        self._open_tags: list[str] = []
        # Parallel stack: True when the matching start tag pushed an HTML integration namespace.
        self._integration_point_pushed: list[bool] = []
        # Parallel to _integration_point_pushed: True only for MathML text IPs (mi/mo/mn/ms/mtext).
        # annotation-xml HTML IPs are HTML but must not enable the mglyph/malignmark exception.
        self._mathml_text_integration_pushed: list[bool] = []
        # Parallel tag names so ancestor end tags can unwind nested integration markers.
        self._integration_point_tags: list[str] = []
        # HTMLParser treats <title> as RCDATA; re-parse literal SVG <title> text as HTML.
        self._svg_title_integration = False
        # Buffer SVG <title> RCDATA (including non-delimiter charrefs) and reparse once.
        self._svg_title_buffer: list[str] = []
        self.meta_description = ""
        self.canvas_ids: set[str] = set()
        # Explicit HTML <base href>; fallback_base is used for about:srcdoc inheritance.
        self.base_href: str | None = None
        self._fallback_base = fallback_base
        # Sandboxed iframes without allow-scripts still fetch non-script resources.
        self._scripts_enabled = scripts_enabled
        # (raw, resolved_at_encounter) so later <base> cannot rewrite earlier refs.
        self.link_refs: list[tuple[str, str]] = []
        self.script_refs: list[tuple[str, str]] = []
        self.external_scripts: list[dict[str, object]] = []

    def _enter_cdata_mode(self, elem: str, *, escapable: bool = False) -> None:
        """Call HTMLParser.set_cdata_mode with runtime-compatible arguments."""
        if _SET_CDATA_MODE_ACCEPTS_ESCAPABLE:
            super().set_cdata_mode(elem, escapable=escapable)
        else:
            super().set_cdata_mode(elem)

    def _active_base(self) -> str | None:
        return self.base_href if self.base_href is not None else self._fallback_base

    def _current_namespace(self) -> str:
        return self._namespaces[-1]

    def _in_svg_namespace(self) -> bool:
        return self._current_namespace() == "svg"

    def _in_math_namespace(self) -> bool:
        return self._current_namespace() == "math"

    def _in_html_namespace(self) -> bool:
        return self._current_namespace() == "html"

    def _in_foreign_namespace(self) -> bool:
        return self._current_namespace() in {"svg", "math"}

    def _in_inert_content(self) -> bool:
        # <template> contents are fully inert. <noscript> skips scripts but keeps links.
        return self._template_depth > 0 or self._noscript_depth > 0

    def _flush_svg_title_buffer(self) -> None:
        """Reparse buffered SVG <title> markup as one HTML fragment."""
        markup = "".join(self._svg_title_buffer)
        self._svg_title_buffer.clear()
        if not markup.strip():
            return
        nested = SiteParser(
            fallback_base=self._active_base(),
            scripts_enabled=self._scripts_enabled,
        )
        # Same-document SVG-title fragments inherit a selected base lock: if the
        # outer document already chose <base>, nested <base> must not replace it.
        # Iframe srcdoc parsers keep independent base selection (no copy here).
        if self.base_href is not None:
            nested.base_href = self.base_href
        nested.feed(markup)
        nested.close()
        self._merge_nested_document(nested, propagate_base=True)

    def _append_svg_title_reference(self, escaped: str, decoded: str) -> None:
        """Keep attribute charrefs; do not retokenize escaped tag delimiters."""
        # Escaped &lt;/&gt;/&quot;/&#34;/&apos; (and numeric equivalents) must stay
        # escaped so nested reparsing cannot invent new attributes from a quote
        # that browsers keep inside the attribute value. ASCII whitespace
        # references (e.g. &#9;) must also stay escaped: browsers keep the
        # decoded tab inside an unquoted attribute value, while a nested parse
        # that inserts a raw tab would fabricate new attributes. Ampersand
        # references (&amp;/&#38;) must stay escaped too: inserting a raw `&`
        # lets the nested parser decode a following named/numeric reference a
        # second time (e.g. &#38;num; → &num; → #). Other references (e.g.
        # &#x2e;) belong in attribute values of literal executable markup and
        # must be preserved as decoded characters.
        if any(char in "<>\"'&" or char in ASCII_WHITESPACE for char in decoded):
            self._svg_title_buffer.append(escaped)
            return
        self._svg_title_buffer.append(decoded)

    def _push_open_tag(self, tag: str) -> None:
        self._open_tags.append(tag)

    def _pop_open_tag(self, tag: str) -> None:
        if self._open_tags and self._open_tags[-1] == tag:
            self._open_tags.pop()
            return
        # End tags may close an ancestor; pop until the matching start tag.
        for index in range(len(self._open_tags) - 1, -1, -1):
            if self._open_tags[index] == tag:
                del self._open_tags[index:]
                return

    def _current_open_tag(self) -> str | None:
        return self._open_tags[-1] if self._open_tags else None

    def _merge_nested_document(
        self, nested: SiteParser, *, propagate_base: bool = False
    ) -> None:
        self.link_refs.extend(nested.link_refs)
        self.script_refs.extend(nested.script_refs)
        self.external_scripts.extend(nested.external_scripts)
        # SVG-title fragment parsing can establish the document's first <base>.
        # Do not propagate bases from separate iframe srcdoc documents.
        if (
            propagate_base
            and self._shadow_root_depth == 0
            and self.base_href is None
            and nested.base_href is not None
        ):
            self.base_href = nested.base_href

    def _enter_namespace(self, namespace: str) -> None:
        self._namespaces.append(namespace)

    def _leave_namespace(self, namespace: str) -> None:
        if len(self._namespaces) > 1 and self._namespaces[-1] == namespace:
            self._namespaces.pop()

    def _leave_html_integration_namespace(self) -> None:
        """Pop nested foreign scopes inside an HTML integration point, then HTML.

        Closing ``</desc>`` / ``</foreignobject>`` must also pop SVG/MathML
        namespaces entered under that integration point (e.g. ``<desc><math>``),
        matching the HTML tree builder's ancestor-end-tag unwind.
        """
        while len(self._namespaces) > 1 and self._namespaces[-1] in {"svg", "math"}:
            self._namespaces.pop()
        self._leave_namespace("html")

    def _leave_foreign_element(self, namespace: str) -> None:
        """Pop through HTML integration scopes until the matching foreign element.

        Ancestor end tags such as ``</svg>`` inside ``foreignObject`` pop both the
        integration-point HTML scope and the SVG element (HTML foreign-content rules).
        Nested foreign namespaces under those scopes (e.g. MathML inside ``desc``)
        are unwound as well.
        """
        while len(self._namespaces) > 1:
            current = self._namespaces[-1]
            if current == namespace:
                self._namespaces.pop()
                return
            if current in {"svg", "math"}:
                self._namespaces.pop()
                continue
            if current != "html":
                return
            # Drain non-pushing integration markers nested under this HTML scope.
            while self._integration_point_pushed and not self._integration_point_pushed[-1]:
                self._pop_integration_point()
            if not (self._integration_point_pushed and self._integration_point_pushed[-1]):
                return
            self._pop_integration_point()
            self._namespaces.pop()
            if self._svg_title_integration:
                self._flush_svg_title_buffer()
                self._svg_title_integration = False
                self._in_title = False

    def _leave_all_foreign_namespaces(self) -> None:
        """Pop every nested SVG/MathML scope, matching HTML foreign-content breakout."""
        while self._in_foreign_namespace() and len(self._namespaces) > 1:
            self._namespaces.pop()

    def close(self) -> None:
        # HTMLParser holds unclosed RCDATA (SVG <title>) until end=True; flush
        # that into handle_data first, then reparse any pending title markup.
        super().close()
        if self._svg_title_integration:
            self._flush_svg_title_buffer()
            self._svg_title_integration = False

    def _is_foreign_html_breakout(self, tag: str, values: dict[str, str | None]) -> bool:
        """True when a start tag exits SVG/MathML foreign content into HTML."""
        if tag in FOREIGN_HTML_BREAKOUT_TAGS:
            return True
        # <font> breaks out only when color/face/size is present (HTML foreign content).
        return tag == "font" and bool(FOREIGN_HTML_BREAKOUT_FONT_ATTRS & values.keys())

    def _push_html_integration_point(self, tag: str, *, mathml_text: bool = False) -> None:
        self._enter_namespace("html")
        self._integration_point_pushed.append(True)
        self._mathml_text_integration_pushed.append(mathml_text)
        self._integration_point_tags.append(tag)

    def _record_integration_point_skipped(self, tag: str) -> None:
        """Matching end tag must not pop an outer integration-point namespace."""
        self._integration_point_pushed.append(False)
        self._mathml_text_integration_pushed.append(False)
        self._integration_point_tags.append(tag)

    def _pop_integration_point(self) -> bool:
        """Pop integration-point stacks together; True if HTML namespace was pushed."""
        if not self._integration_point_pushed:
            return False
        pushed = self._integration_point_pushed.pop()
        if self._mathml_text_integration_pushed:
            self._mathml_text_integration_pushed.pop()
        if self._integration_point_tags:
            self._integration_point_tags.pop()
        return pushed

    def _close_integration_points_through(self, tag: str) -> None:
        """Pop nested integration markers closed by an ancestor end tag.

        Example: ``<svg><desc><foreignobject></desc>`` — ``</desc>`` pops both the
        HTML-namespace ``foreignobject`` marker and the ``desc`` HTML scope so a
        following SVG ``<script href>`` is not misread as HTML ``src``.
        Unmatched end tags (e.g. ``</title>`` with only a ``desc`` marker) are
        ignored, matching the browser, so they do not drain unrelated scopes.
        """
        if tag not in self._integration_point_tags:
            return
        while self._integration_point_tags:
            marker_tag = self._integration_point_tags[-1]
            if marker_tag == "title" and self._svg_title_integration:
                self._flush_svg_title_buffer()
                self._svg_title_integration = False
                self._in_title = False
            if self._pop_integration_point():
                self._leave_html_integration_namespace()
            if marker_tag == tag:
                break

    def _named_ref_had_semicolon(self, name: str) -> bool:
        """True when the source named reference included a terminating semicolon."""
        lineno, offset = self.getpos()
        lines = self.rawdata.splitlines(keepends=True)
        if lineno < 1 or lineno > len(lines):
            return False
        abs_index = sum(len(lines[index]) for index in range(lineno - 1)) + offset
        expect = f"&{name}"
        if self.rawdata[abs_index : abs_index + len(expect)] != expect:
            return False
        return self.rawdata[abs_index + len(expect) : abs_index + len(expect) + 1] == ";"

    def _in_mathml_text_integration_point(self) -> bool:
        """True when current HTML namespace came from a MathML text IP (not annotation-xml)."""
        return bool(
            self._mathml_text_integration_pushed and self._mathml_text_integration_pushed[-1]
        )

    def _maybe_enter_mathml_html_integration(
        self, tag: str, values: dict[str, str | None]
    ) -> bool:
        """Enter HTML namespace for MathML text/annotation-xml integration points."""
        if not self._in_math_namespace():
            return False
        if tag in MATHML_HTML_INTEGRATION_POINTS:
            self._push_html_integration_point(tag, mathml_text=True)
            return True
        if tag == "annotation-xml":
            # Encoding match is ASCII case-insensitive and exact; do not strip.
            encoding = ascii_lower(values.get("encoding") or "")
            if encoding in MATHML_ANNOTATION_XML_HTML_ENCODINGS:
                # HTML-enabled annotation-xml is an HTML IP, not a MathML text IP.
                self._push_html_integration_point(tag, mathml_text=False)
                return True
            # Still record a stack slot so the matching end tag does not pop outer state.
            self._record_integration_point_skipped(tag)
            return False
        return False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # Browsers keep the first duplicate attribute; dict(attrs) would last-win.
        values, duplicates = first_wins_attrs(attrs)
        # Nested <math>/<svg> foreign content exits every foreign scope before HTML tags.
        if self._in_foreign_namespace() and self._is_foreign_html_breakout(tag, values):
            self._leave_all_foreign_namespaces()
        # Foreign-namespace rawtext/CDATA/RCDATA elements are ordinary markup;
        # retokenize nested tags. HTML keeps CDATA/RCDATA so script/style/iframe
        # and textarea bodies stay text. SVG <title> remains RCDATA for buffering;
        # MathML <title> does not (ordinary foreign element).
        if self._in_foreign_namespace():
            self.CDATA_CONTENT_ELEMENTS = _FOREIGN_CDATA_CONTENT_ELEMENTS
            if self._in_svg_namespace():
                self.RCDATA_CONTENT_ELEMENTS = _FOREIGN_RCDATA_SVG_CONTENT_ELEMENTS
            else:
                self.RCDATA_CONTENT_ELEMENTS = _FOREIGN_RCDATA_MATH_CONTENT_ELEMENTS
        else:
            self.CDATA_CONTENT_ELEMENTS = _HTML_CDATA_CONTENT_ELEMENTS
            self.RCDATA_CONTENT_ELEMENTS = _HTML_RCDATA_CONTENT_ELEMENTS
        if tag == "template":
            # Only HTML-namespace <template> is inert. Declarative shadow roots
            # (shadowrootmode=open|closed) attach and run parser-inserted scripts.
            # SVG <template> is ordinary SVG content whose descendants can execute.
            # Nested templates inside an inert <template> stay inert even when they
            # carry shadowrootmode (browser does not attach until the host is live).
            if self._in_html_namespace():
                if is_declarative_shadow_root(values) and self._template_depth == 0:
                    self._template_kinds.append("shadow")
                    self._shadow_root_depth += 1
                else:
                    self._template_kinds.append("inert")
                    self._template_depth += 1
                    return
        if tag == "noscript":
            # Noscript fallback scripts never execute. Only the HTML element
            # participates; SVG-namespaced noscript is not a noscript context.
            if self._in_html_namespace():
                self._noscript_depth += 1
                return
        if self._template_depth > 0:
            # Ignore tags inside <template>; browsers do not fetch/execute them.
            return
        if self._noscript_depth > 0:
            # When scripting is disabled, noscript fallbacks still apply <base>
            # and fetch non-script resources such as stylesheets. Skip scripts.
            if (
                tag == "base"
                and self._in_html_namespace()
                and self._shadow_root_depth == 0
                and self.base_href is None
                and "href" in values
            ):
                href = values["href"] or ""
                self.base_href = resolve_reference(href, self._fallback_base)
            if tag == "link" and values.get("href"):
                href = values["href"]
                resolved = resolve_reference(href, self._active_base())
                self.link_refs.append((href, resolved))
            return
        entered_html_integration = False
        if tag == "svg":
            # SVG from HTML or nested SVG enters the SVG namespace. From MathML,
            # only an immediate annotation-xml child switches (WHATWG foreign
            # content); ordinary MathML keeps a MathML-namespaced "svg" token.
            if self._in_html_namespace() or self._in_svg_namespace():
                self._enter_namespace("svg")
            elif (
                self._in_math_namespace()
                and self._current_open_tag() == "annotation-xml"
            ):
                self._enter_namespace("svg")
        elif tag == "math":
            # Math from HTML/MathML enters MathML. A math-named token in SVG stays
            # in the SVG namespace so descendant scripts still fetch href.
            if self._in_html_namespace() or self._in_math_namespace():
                self._enter_namespace("math")
        elif tag in MATHML_HTML_INTEGRATION_EXCEPTIONS:
            # mglyph/malignmark stay MathML only when the immediate adjusted
            # current element is a MathML text integration point. An intervening
            # HTML child (e.g. span under mi) processes them in the HTML namespace.
            if (
                self._in_html_namespace()
                and self._current_open_tag() in MATHML_HTML_INTEGRATION_POINTS
                and self._in_mathml_text_integration_point()
            ):
                self._enter_namespace("math")
                self._mathml_exception_entered.append(True)
            else:
                # End tag must not pop the surrounding MathML scope unless this
                # start tag actually entered MathML (e.g. mglyph in annotation-xml).
                self._mathml_exception_entered.append(False)
        elif tag in SVG_HTML_INTEGRATION_POINTS:
            # foreignObject, desc, and title are SVG HTML integration points.
            # Only push when currently in SVG; nested HTML-namespace copies must
            # not push, but still record False so their end tags do not pop the
            # outer integration-point namespace.
            if self._in_svg_namespace():
                self._push_html_integration_point(tag, mathml_text=False)
                entered_html_integration = True
                if tag == "title":
                    # html.parser keeps title contents as text; flag for re-parse.
                    self._svg_title_buffer.clear()
                    self._svg_title_integration = True
            else:
                self._record_integration_point_skipped(tag)
        elif tag in MATHML_HTML_INTEGRATION_POINTS or tag == "annotation-xml":
            if self._maybe_enter_mathml_html_integration(tag, values):
                entered_html_integration = True
            elif not self._in_math_namespace():
                # Matching end tags must not pop an outer integration-point state.
                self._record_integration_point_skipped(tag)
        if tag == "title" and self._in_html_namespace() and not entered_html_integration:
            # Document <title> only; SVG <title> is an integration point, not the page title.
            self._in_title = True
        if (
            tag == "base"
            and self._in_html_namespace()
            and self._shadow_root_depth == 0
            and self.base_href is None
            and "href" in values
        ):
            # Only HTML-namespace <base> sets the document base; SVG <base> is ignored.
            # A present empty href resolves to the document URL and locks out later
            # bases; only a missing href attribute is ignored.
            # Resolve against the inherited fallback so relative nested bases cannot
            # hide external scripts as local repository paths.
            href = values["href"] or ""
            self.base_href = resolve_reference(href, self._fallback_base)
        if tag == "meta" and values.get("name") == "description":
            self.meta_description = values.get("content") or ""
        if tag == "canvas" and values.get("id"):
            self.canvas_ids.add(values["id"])
        if tag == "link" and values.get("href"):
            href = values["href"]
            resolved = resolve_reference(href, self._active_base())
            self.link_refs.append((href, resolved))
        if tag == "iframe" and self._in_html_namespace():
            # SVG-namespaced <iframe> does not create a nested browsing context;
            # its srcdoc is inert and must not be parsed as an executable document.
            srcdoc = values.get("srcdoc")
            if srcdoc:
                # Sandbox without allow-scripts still parses and fetches non-script
                # resources (stylesheets, etc.); only executable scripts are suppressed.
                allows_scripts = iframe_allows_scripts(
                    "sandbox" in values, values.get("sandbox")
                )
                nested = SiteParser(
                    fallback_base=self._active_base(),
                    scripts_enabled=allows_scripts,
                )
                nested.feed(srcdoc)
                nested.close()
                self._merge_nested_document(nested)
        if tag == "script":
            # MathML-namespace <script> has no HTML script-fetching behavior.
            if self._in_math_namespace():
                self._push_open_tag(tag)
                return
            # Sandboxed docs without allow-scripts (and noscript) still parse markup
            # but must not treat scripts as fetchable/executable resources.
            if not self._scripts_enabled:
                self._push_open_tag(tag)
                return
            # Non-JS MIME types are data blocks: browsers do not fetch/execute src.
            # When type is absent, a nonempty obsolete language attribute still
            # selects the classic type as text/<language>.
            if not is_executable_script_type(effective_script_type(values)):
                self._push_open_tag(tag)
                return
            src = script_resource_url(values, self._in_svg_namespace())
            if src:
                resolved_src = resolve_reference(src, self._active_base())
                self.script_refs.append((src, resolved_src))
                if is_external(resolved_src):
                    self.external_scripts.append(
                        {
                            "src": resolved_src,
                            "raw_src": src,
                            "integrity": values.get("integrity"),
                            "has_crossorigin": "crossorigin" in values,
                            "crossorigin": values.get("crossorigin"),
                            "duplicate_security_attrs": sorted(
                                duplicates & SECURITY_SCRIPT_ATTRS
                            ),
                            # Browsers do not apply HTML SRI to SVGScriptElement fetches.
                            "svg_script": self._in_svg_namespace(),
                        }
                    )
        self._push_open_tag(tag)

    def set_cdata_mode(self, elem: str, *, escapable: bool = False) -> None:
        # HTMLParser hard-codes plaintext RAWTEXT independently of CDATA/RCDATA
        # tuples. Foreign-namespace <plaintext> is ordinary markup.
        if self._in_foreign_namespace() and elem.lower() == "plaintext":
            return
        self._enter_cdata_mode(elem, escapable=escapable)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # HTMLParser treats /> as start+end and never enters CDATA. Browsers ignore
        # the solidus on HTML rawtext/RCDATA elements, so keep the element open and
        # consume following tokens as text until the real end tag. Compare against
        # the HTML element sets: CDATA_CONTENT_ELEMENTS may still hold the foreign
        # empty tuple from a prior SVG/MathML start tag.
        if not self._in_foreign_namespace() and (
            tag in _HTML_CDATA_CONTENT_ELEMENTS
            or tag in _HTML_RCDATA_CONTENT_ELEMENTS
            or tag == "plaintext"
        ):
            self.handle_starttag(tag, attrs)
            if tag == "plaintext" or tag in _HTML_CDATA_CONTENT_ELEMENTS:
                self._enter_cdata_mode(tag, escapable=False)
            else:
                self._enter_cdata_mode(tag, escapable=True)
            return
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag == "template":
            # Only HTML-namespace <template> pushes _template_kinds. SVG/MathML
            # </template> must not pop shadow/inert state opened by an ancestor.
            if not self._in_html_namespace():
                if self._template_depth == 0 and self._noscript_depth == 0:
                    self._pop_open_tag(tag)
                return
            if not self._template_kinds:
                return
            kind = self._template_kinds.pop()
            if kind == "inert":
                if self._template_depth > 0:
                    self._template_depth -= 1
                return
            if kind == "shadow":
                if self._shadow_root_depth > 0:
                    self._shadow_root_depth -= 1
                self._pop_open_tag(tag)
            return
        if tag == "noscript":
            if self._noscript_depth > 0:
                self._noscript_depth -= 1
            return
        if self._in_inert_content():
            return
        self._pop_open_tag(tag)
        if tag in MATHML_HTML_INTEGRATION_EXCEPTIONS:
            entered = (
                self._mathml_exception_entered.pop()
                if self._mathml_exception_entered
                else False
            )
            if entered:
                self._leave_namespace("math")
            return
        if tag in SVG_HTML_INTEGRATION_POINTS:
            # Ancestor end tags (e.g. </desc> with a nested HTML foreignobject) must
            # unwind every nested integration marker the tree builder would pop.
            if tag == "title":
                if self._svg_title_integration:
                    self._flush_svg_title_buffer()
                self._svg_title_integration = False
                self._in_title = False
            self._close_integration_points_through(tag)
            return
        if tag in MATHML_HTML_INTEGRATION_POINTS or tag == "annotation-xml":
            self._close_integration_points_through(tag)
            return
        if tag == "svg":
            # Only leave namespaces actually entered by an SVG start tag. An
            # svg-named token in MathML (outside annotation-xml) never entered SVG.
            if any(namespace == "svg" for namespace in self._namespaces):
                self._leave_foreign_element("svg")
            return
        if tag == "math":
            # math-named elements in SVG stay in the SVG namespace; do not search
            # for a MathML scope by popping the surrounding SVG element.
            if any(namespace == "math" for namespace in self._namespaces):
                self._leave_foreign_element("math")
            return

    def handle_data(self, data: str) -> None:
        if self._svg_title_integration:
            # Buffer fragments; charrefs may split RCDATA mid-attribute.
            self._svg_title_buffer.append(data)
            return
        if self._in_title:
            self.title += data.strip()

    def handle_entityref(self, name: str) -> None:
        if self._svg_title_integration:
            had_semicolon = self._named_ref_had_semicolon(name)
            char = html5_named_character(name, had_semicolon=had_semicolon)
            if char is not None:
                escaped = f"&{name};" if had_semicolon else f"&{name}"
                self._append_svg_title_reference(escaped, char)
            else:
                # Preserve unrecognized / semicolonless non-legacy refs literally.
                escaped = f"&{name};" if had_semicolon else f"&{name}"
                self._svg_title_buffer.append(escaped)
            return
        if self._in_title:
            char = html5_named_character(name)
            if char is not None:
                self.title += char

    def handle_charref(self, name: str) -> None:
        if self._svg_title_integration:
            decoded = decode_numeric_charref(name)
            self._append_svg_title_reference(f"&#{name};", decoded)
            return
        if self._in_title:
            self.title += decode_numeric_charref(name)


def first_wins_attrs(
    attrs: list[tuple[str, str | None]],
) -> tuple[dict[str, str | None], set[str]]:
    """Map attributes with browser first-wins semantics; report duplicated names."""
    values: dict[str, str | None] = {}
    duplicates: set[str] = set()
    for key, value in attrs:
        if key in values:
            duplicates.add(key)
            continue
        values[key] = value
    return values, duplicates


def is_external(reference: str) -> bool:
    try:
        parsed = urlparse(reference)
    except ValueError:
        # Malformed references (e.g. https://[) must not abort the checker; treat
        # scheme-like values as external so policy validation reports them.
        return ":" in reference or reference.startswith("//")
    if parsed.scheme in {"http", "https", "data"}:
        return True
    # Network-path URLs (//host/...) have a nonempty authority and are fetched
    # from that host even without an explicit scheme. Treat them as external so
    # path-normalization cannot reclassify them as local repository files.
    if parsed.netloc:
        return True
    # Triple-slash (or more) forms keep an empty urllib netloc, but browsers
    # still parse an authority (e.g. ///workspace/... → host "workspace").
    return reference.startswith("///")


def can_be_a_base_url(url: str) -> bool:
    """True when ``url`` can serve as a hierarchical base for relative references.

    Opaque-path URLs such as ``mailto:`` / ``data:`` / ``javascript:`` are valid
    ``<base href>`` values but cannot resolve relative refs; ``urljoin`` would
    otherwise return the relative string unchanged and falsely accept a local file.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    scheme = ascii_lower(parsed.scheme) if parsed.scheme else ""
    if not scheme:
        # Document-relative bases (e.g. index.html) remain hierarchical.
        return True
    if scheme in {"http", "https", "ws", "wss", "ftp", "file"}:
        return True
    # Non-special schemes require an authority component to be a base URL.
    return bool(parsed.netloc)


def resolve_reference(reference: str, base_href: str | None) -> str:
    """Resolve a document-relative URL against the active <base href>, if any.

    Browsers treat backslashes as slashes when resolving special-scheme URLs, so
    ``\\\\host\\dir/`` becomes a network-path base. ``urllib.parse.urljoin`` does
    not, which would otherwise keep relative scripts local while the browser
    fetches an external URL.
    """
    ref = reference.replace("\\", "/") if "\\" in reference else reference
    # Triple-slash forms (///host/path) are network-path URLs whose host is the
    # first path segment. urllib treats them as absolute paths (empty netloc) and
    # urljoin against a scheme-less document URL collapses them to /host/path,
    # which can then look like a local repository file. Normalize to //host/path
    # before joining so classification and https bases match browser behavior.
    if ref.startswith("///"):
        ref = ref[1:]
    if not base_href:
        return ref
    base = base_href.replace("\\", "/")
    if not can_be_a_base_url(base):
        # Absolute/network-path refs still stand alone; relative refs cannot
        # resolve and must not be mistaken for repository-local paths.
        try:
            ref_parsed = urlparse(ref)
        except ValueError:
            return f"__unresolved_opaque_base__/{ref}"
        if ref_parsed.scheme or ref.startswith("//"):
            return ref
        return f"__unresolved_opaque_base__/{ref}"
    try:
        return urljoin(base, ref)
    except ValueError:
        # Malformed base/reference (e.g. https://[): browsers ignore the bad base
        # and keep resolving against the document URL instead of aborting.
        return ref


def iframe_allows_scripts(has_sandbox: bool, sandbox: str | None) -> bool:
    """True when an iframe may execute scripts (no sandbox, or allow-scripts)."""
    if not has_sandbox:
        return True
    # HTML sandbox keywords are ASCII case-insensitive and split only on ASCII
    # whitespace. NBSP (and other Unicode spaces) do not separate tokens, so
    # `allow-scripts\u00a0foo` is one unrecognized token and scripts stay disabled.
    # Use ASCII lowercasing, not Unicode casefold(), so U+017F does not forge
    # allow-scripts.
    tokens = [
        token
        for token in SRI_ASCII_WHITESPACE_RE.split(ascii_lower(sandbox or ""))
        if token
    ]
    return "allow-scripts" in tokens


def script_resource_url(values: dict[str, str | None], in_svg: bool) -> str | None:
    """Return the executable script URL for HTML src or SVG href/xlink:href.

    SVG scripts fetch href/xlink:href; HTML scripts use src. Preferring HTML src
    inside SVG would miss an external href attack that the browser still loads.
    A present empty ``href`` still wins over ``xlink:href`` (browser precedence).
    """
    if in_svg:
        if "href" in values:
            return values.get("href")
        if "xlink:href" in values:
            return values.get("xlink:href")
        return None
    return values.get("src")


def is_declarative_shadow_root(values: dict[str, str | None]) -> bool:
    """True when template declares an attachable shadow root (open or closed)."""
    mode = values.get("shadowrootmode")
    if mode is None:
        return False
    # HTML attribute matching for shadowrootmode is ASCII case-insensitive and
    # exact; surrounding whitespace is not stripped, so " open " stays inert.
    return ascii_lower(mode) in DECLARATIVE_SHADOW_ROOT_MODES


def effective_script_type(values: dict[str, str | None]) -> str | None:
    """Return the browser-effective script type, including obsolete language."""
    if "type" in values:
        return values.get("type")
    language = values.get("language")
    if language is not None and language.strip(ASCII_WHITESPACE):
        return f"text/{language}"
    return None


def is_executable_script_type(script_type: str | None) -> bool:
    """True when a script element is classic/module JS rather than a data block."""
    if script_type is None:
        return True
    # HTML strips only ASCII whitespace from the type; NBSP must remain so the
    # value stays an unrecognized (inert) data-block type.
    lowered = ascii_lower(script_type.strip(ASCII_WHITESPACE))
    if not lowered:
        return True
    # Module state is an exact ASCII case-insensitive match for "module".
    # Parameterized values like "module;x" are not modules and not JS MIME types.
    if lowered == "module":
        return True
    mime = lowered.split(";", 1)[0].strip(ASCII_WHITESPACE)
    return mime in JAVASCRIPT_MIME_TYPES


def strip_url_fragment(url: str) -> str:
    """Remove a URL fragment for trusted-map lookup; preserve query parameters."""
    fragment_index = url.find("#")
    if fragment_index == -1:
        return url
    return url[:fragment_index]


def normalize_local_reference(reference: str) -> Path:
    """Resolve a local asset path and ensure it stays under the repository root."""
    path = (ROOT / reference.removeprefix("./")).resolve()
    if not path.is_relative_to(ROOT):
        raise ValueError(f"local reference escapes repository root: {reference}")
    return path


def is_anonymous_crossorigin(crossorigin: str | None) -> bool:
    """True for the CORS anonymous state, including the empty-value shorthand.

    HTML CORS settings treat a missing/empty value and any keyword other than
    ``use-credentials`` (including invalid values) as the anonymous state.
    Matching is ASCII case-insensitive; Unicode casefold must not forge the
    credentials keyword (e.g. U+017F long s).
    """
    if crossorigin is None or crossorigin == "":
        return True
    return ascii_lower(crossorigin) != "use-credentials"


def pad_base64(digest: str) -> str:
    """Add optional Base64 padding so unpadded SRI digests still decode."""
    remainder = len(digest) % 4
    if remainder == 0:
        return digest
    return digest + ("=" * (4 - remainder))


def split_sri_tokens(integrity: str) -> list[str]:
    """Split integrity metadata on ASCII whitespace only (SRI/HTML rules)."""
    return [token for token in SRI_ASCII_WHITESPACE_RE.split(integrity) if token]


def sri_algorithm_and_digest(token: str) -> tuple[str, str] | None:
    """Parse algorithm and Base64 digest, stripping optional SRI ?options.

    SRI hash expressions are ``algo-base64[?option-expression]``. Options must be
    removed before digest validation so stronger tokens with ``?foo`` still win
    algorithm selection the way browsers do. A trailing ``?`` with an empty option
    expression, or a non-VCHAR option expression, is malformed and must not be
    treated as a valid hash expression.
    """
    if "-" not in token:
        return None
    algorithm, rest = token.split("-", 1)
    # SRI hash-algo tokens are ASCII case-insensitive (SHA384 == sha384).
    algorithm = ascii_lower(algorithm)
    if "?" in rest:
        digest, option_expression = rest.split("?", 1)
        # SRI requires a non-empty option expression of VCHAR (%x21-7E) after '?'.
        # Non-ASCII suffixes (e.g. ?é or ?\u00a0) are malformed and discarded by browsers.
        if not SRI_OPTION_EXPRESSION_RE.fullmatch(option_expression):
            return None
    else:
        digest = rest
    if algorithm not in SRI_DIGEST_BYTES or not digest:
        return None
    return algorithm, digest


def recognized_sri_algorithm(token: str) -> str | None:
    """Return known algorithm when digest is ABNF Base64-shaped, ignoring length.

    Browsers select the strongest recognized algorithm before validating digest
    length, so short tokens like sha512-A or sha512-AA== still win over sha384.
    Option suffixes such as ?foo are parsed off before the Base64 alphabet check.
    Do not require b64decode(validate=True): lengths congruent to 1 mod 4 are
    still syntactically valid ``base64-value`` tokens for algorithm selection.
    """
    parsed = sri_algorithm_and_digest(token)
    if parsed is None:
        return None
    algorithm, digest = parsed
    if not SRI_BASE64_RE.fullmatch(digest):
        return None
    return algorithm


def normalize_sri_token(token: str) -> str | None:
    """Return algorithm-padded_digest for a well-formed SRI token, else None."""
    parsed = sri_algorithm_and_digest(token)
    if parsed is None:
        return None
    algorithm, digest = parsed
    if not SRI_BASE64_RE.fullmatch(digest):
        return None
    expected_bytes = SRI_DIGEST_BYTES[algorithm]
    padded = pad_base64(digest)
    try:
        decoded = base64.b64decode(padded, validate=True)
    except binascii.Error:
        return None
    if len(decoded) != expected_bytes:
        return None
    return f"{algorithm}-{padded}"


def is_valid_sri_integrity(integrity: str) -> bool:
    """Return True when integrity contains at least one well-formed SRI digest."""
    tokens = split_sri_tokens(integrity)
    if not tokens:
        return False
    return any(normalize_sri_token(token) is not None for token in tokens)


def integrity_matches_trusted(integrity: str, expected: str) -> bool:
    """True when browser-selected digests include the trusted token.

    Browsers verify only the strongest supported algorithm present. A trusted
    sha384 plus a well-formed but wrong sha512 must therefore fail, because the
    browser will enforce the stronger token. Wrong-length stronger tokens still
    participate in algorithm selection.
    """
    expected_normalized = normalize_sri_token(expected)
    if expected_normalized is None:
        return False
    expected_algorithm = expected_normalized.split("-", 1)[0]
    expected_strength = SRI_ALGORITHM_STRENGTH[expected_algorithm]

    recognized_algorithms: set[str] = set()
    tokens_by_algorithm: dict[str, list[str]] = {}
    for token in split_sri_tokens(integrity):
        algorithm = recognized_sri_algorithm(token)
        if algorithm is None:
            continue
        recognized_algorithms.add(algorithm)
        normalized = normalize_sri_token(token)
        if normalized is None:
            continue
        tokens_by_algorithm.setdefault(algorithm, []).append(normalized)

    if not recognized_algorithms:
        return False

    strongest = max(
        recognized_algorithms,
        key=lambda algorithm: SRI_ALGORITHM_STRENGTH[algorithm],
    )
    if SRI_ALGORITHM_STRENGTH[strongest] != expected_strength:
        # Stronger unexpected tokens win in the browser; weaker-only sets cannot
        # satisfy a stronger trusted pin either.
        return False
    return expected_normalized in tokens_by_algorithm.get(strongest, [])


def validate_required_files(errors: list[str]) -> None:
    for relative_path in REQUIRED_FILES:
        if not (ROOT / relative_path).is_file():
            errors.append(f"missing required file: {relative_path}")


def validate_html(errors: list[str]) -> None:
    html_path = ROOT / "index.html"
    if not html_path.is_file():
        return

    text = html_path.read_text(encoding="utf-8")
    # Seed the document URL so relative/query-only <base href> values resolve
    # the same way browsers do against the deployed page URL.
    parser = SiteParser(fallback_base=DOCUMENT_URL)
    parser.feed(text)
    parser.close()

    if parser.title != "Neural Cinema":
        errors.append("index.html title must be Neural Cinema")
    if len(parser.meta_description) < 80:
        errors.append("index.html meta description is too short")
    if "neural-canvas" not in parser.canvas_ids:
        errors.append("index.html must contain canvas#neural-canvas")

    # Use encounter-time resolution; do not re-resolve against a later <base>.
    references = parser.link_refs + parser.script_refs
    for raw_reference, resolved in references:
        if is_external(resolved):
            if resolved.startswith("http://"):
                errors.append(f"external reference must use https: {resolved}")
            # External refs (including those made external by an earlier <base>)
            # are validated via external_scripts / CDN policy below for scripts.
            continue
        try:
            path = normalize_local_reference(resolved)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if not path.is_file():
            errors.append(f"local reference does not exist: {raw_reference}")

    for script in parser.external_scripts:
        src = str(script["src"] or "")
        integrity = str(script.get("integrity") or "")
        duplicate_attrs = script.get("duplicate_security_attrs") or []
        if script.get("svg_script"):
            # SVGScriptElement fetches ignore HTML integrity metadata in browsers.
            errors.append(
                "external SVG script is forbidden "
                f"(browsers do not enforce SRI on SVGScriptElement): {src}"
            )
            continue
        if duplicate_attrs:
            joined = ", ".join(str(name) for name in duplicate_attrs)
            errors.append(
                f"external script has duplicate security attributes ({joined}): {src}"
            )
        if not is_valid_sri_integrity(integrity):
            errors.append(f"external script missing or malformed SRI integrity: {src}")
        # Browsers omit fragments from the request; match trusted pins without them.
        trusted = TRUSTED_EXTERNAL_SCRIPT_INTEGRITY.get(strip_url_fragment(src))
        if trusted is None:
            errors.append(f"untrusted external script (no pinned SRI mapping): {src}")
        elif not integrity_matches_trusted(integrity, trusted):
            errors.append(f"external script integrity does not match trusted digest: {src}")
        # Missing crossorigin rejects; empty value / None means anonymous (HTML CORS).
        if not script.get("has_crossorigin"):
            errors.append(f"external script must set crossorigin=anonymous: {src}")
        else:
            crossorigin = script.get("crossorigin")
            crossorigin_value = crossorigin if isinstance(crossorigin, str) or crossorigin is None else str(crossorigin)
            if not is_anonymous_crossorigin(crossorigin_value):
                errors.append(f"external script must set crossorigin=anonymous: {src}")

    forbidden_references = ["local" + "host", "127.0.0.1", "/" + "Users/"]
    for forbidden in forbidden_references:
        if forbidden in text:
            errors.append(f"index.html contains forbidden local reference: {forbidden}")


def validate_app(errors: list[str]) -> None:
    app_path = ROOT / "app.js"
    if not app_path.is_file():
        return

    text = app_path.read_text(encoding="utf-8")
    expected_selectors = [
        "#neural-canvas",
        "#arch-title",
        "#layer-cards",
        "#pause-button",
        "#reseed-button",
        "#density-slider",
    ]
    for selector in expected_selectors:
        if selector not in text:
            errors.append(f"app.js is missing expected selector: {selector}")

    architecture_count = len(re.findall(r'title: "[^"]+"', text))
    if architecture_count < 3:
        errors.append("app.js should define at least three architecture presets")


def main() -> int:
    errors: list[str] = []
    validate_required_files(errors)
    validate_html(errors)
    validate_app(errors)

    if errors:
        print("Static site check failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print("Static site check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
