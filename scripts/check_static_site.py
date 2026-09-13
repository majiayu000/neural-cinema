#!/usr/bin/env python3
"""Validate the static Neural Cinema site without external dependencies."""

from __future__ import annotations

import base64
import binascii
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
# HTML start tags that exit SVG/MathML foreign content (WHATWG "in foreign content").
SVG_HTML_BREAKOUT_TAGS = frozenset(
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
SVG_HTML_BREAKOUT_FONT_ATTRS = frozenset({"color", "face", "size"})
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


class SiteParser(HTMLParser):
    def __init__(self, fallback_base: str | None = None) -> None:
        # Keep character references as entity/charref events so SVG <title>
        # escaped markup (&lt;script...&gt;) is not re-tokenized as real tags.
        super().__init__(convert_charrefs=False)
        self.title = ""
        self._in_title = False
        self._template_depth = 0
        self._noscript_depth = 0
        # Track HTML vs SVG namespace so foreignObject/desc/title HTML scripts use src.
        self._namespaces: list[str] = ["html"]
        # Parallel stack: True when the matching start tag pushed an HTML integration namespace.
        self._integration_point_pushed: list[bool] = []
        # HTMLParser treats <title> as RCDATA; re-parse literal SVG <title> text as HTML.
        self._svg_title_integration = False
        # Buffer SVG <title> RCDATA (including non-delimiter charrefs) and reparse once.
        self._svg_title_buffer: list[str] = []
        self.meta_description = ""
        self.canvas_ids: set[str] = set()
        # Explicit HTML <base href>; fallback_base is used for about:srcdoc inheritance.
        self.base_href: str | None = None
        self._fallback_base = fallback_base
        # (raw, resolved_at_encounter) so later <base> cannot rewrite earlier refs.
        self.link_refs: list[tuple[str, str]] = []
        self.script_refs: list[tuple[str, str]] = []
        self.external_scripts: list[dict[str, object]] = []

    def _active_base(self) -> str | None:
        return self.base_href if self.base_href is not None else self._fallback_base

    def _current_namespace(self) -> str:
        return self._namespaces[-1]

    def _in_svg_namespace(self) -> bool:
        return self._current_namespace() == "svg"

    def _in_html_namespace(self) -> bool:
        return self._current_namespace() == "html"

    def _in_inert_content(self) -> bool:
        # <template> contents are fully inert. <noscript> skips scripts but keeps links.
        return self._template_depth > 0 or self._noscript_depth > 0

    def _flush_svg_title_buffer(self) -> None:
        """Reparse buffered SVG <title> markup as one HTML fragment."""
        markup = "".join(self._svg_title_buffer)
        self._svg_title_buffer.clear()
        if not markup.strip():
            return
        nested = SiteParser(fallback_base=self._active_base())
        nested.feed(markup)
        self._merge_nested_document(nested)

    def _append_svg_title_reference(self, escaped: str, decoded: str) -> None:
        """Keep attribute charrefs; do not retokenize escaped tag delimiters."""
        # Escaped &lt;/&gt; (and numeric equivalents) must stay escaped so they
        # remain inert title text. Other references (e.g. &#x2e;) belong in
        # attribute values of literal executable markup and must be preserved.
        if decoded in "<>":
            self._svg_title_buffer.append(escaped)
            return
        self._svg_title_buffer.append(decoded)

    def _merge_nested_document(self, nested: SiteParser) -> None:
        self.link_refs.extend(nested.link_refs)
        self.script_refs.extend(nested.script_refs)
        self.external_scripts.extend(nested.external_scripts)

    def _enter_namespace(self, namespace: str) -> None:
        self._namespaces.append(namespace)

    def _leave_namespace(self, namespace: str) -> None:
        if len(self._namespaces) > 1 and self._namespaces[-1] == namespace:
            self._namespaces.pop()

    def _leave_all_svg_namespaces(self) -> None:
        """Pop every nested SVG scope, matching HTML foreign-content breakout."""
        while self._in_svg_namespace() and len(self._namespaces) > 1:
            self._namespaces.pop()

    def _is_svg_html_breakout(self, tag: str, values: dict[str, str | None]) -> bool:
        """True when a start tag exits SVG foreign content into the HTML namespace."""
        if tag in SVG_HTML_BREAKOUT_TAGS:
            return True
        # <font> breaks out only when color/face/size is present (HTML foreign content).
        return tag == "font" and bool(SVG_HTML_BREAKOUT_FONT_ATTRS & values.keys())

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # Browsers keep the first duplicate attribute; dict(attrs) would last-win.
        values, duplicates = first_wins_attrs(attrs)
        # Nested <svg><svg><p> exits every SVG scope before processing p.
        if self._in_svg_namespace() and self._is_svg_html_breakout(tag, values):
            self._leave_all_svg_namespaces()
        if tag == "template":
            # Only HTML-namespace <template> is inert. SVG <template> is ordinary
            # SVG content whose descendant scripts can still execute.
            if self._in_html_namespace():
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
            # When scripting is disabled, noscript fallbacks still fetch non-script
            # resources such as stylesheets. Skip executable scripts only.
            if tag == "link" and values.get("href"):
                href = values["href"]
                resolved = resolve_reference(href, self._active_base())
                self.link_refs.append((href, resolved))
            return
        entered_html_integration = False
        if tag == "svg":
            self._enter_namespace("svg")
        elif tag in SVG_HTML_INTEGRATION_POINTS:
            # foreignObject, desc, and title are SVG HTML integration points.
            # Only push when currently in SVG; nested HTML-namespace copies must
            # not push, but still record False so their end tags do not pop the
            # outer integration-point namespace.
            if self._in_svg_namespace():
                self._enter_namespace("html")
                self._integration_point_pushed.append(True)
                entered_html_integration = True
                if tag == "title":
                    # html.parser keeps title contents as text; flag for re-parse.
                    self._svg_title_buffer.clear()
                    self._svg_title_integration = True
            else:
                self._integration_point_pushed.append(False)
        if tag == "title" and self._in_html_namespace() and not entered_html_integration:
            # Document <title> only; SVG <title> is an integration point, not the page title.
            self._in_title = True
        if (
            tag == "base"
            and self._in_html_namespace()
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
            if srcdoc and iframe_allows_scripts("sandbox" in values, values.get("sandbox")):
                # about:srcdoc inherits the embedding document's base URL.
                nested = SiteParser(fallback_base=self._active_base())
                nested.feed(srcdoc)
                self._merge_nested_document(nested)
        if tag == "script":
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
                        }
                    )

    def handle_endtag(self, tag: str) -> None:
        if tag == "template":
            if self._template_depth > 0:
                self._template_depth -= 1
            return
        if tag == "noscript":
            if self._noscript_depth > 0:
                self._noscript_depth -= 1
            return
        if self._in_inert_content():
            return
        if tag in SVG_HTML_INTEGRATION_POINTS:
            # Pop HTML namespace only when this end tag matches a start that pushed.
            if tag == "title":
                if self._svg_title_integration:
                    self._flush_svg_title_buffer()
                self._svg_title_integration = False
                self._in_title = False
            if self._integration_point_pushed and self._integration_point_pushed.pop():
                self._leave_namespace("html")
            return
        if tag == "svg":
            self._leave_namespace("svg")
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
            char = html_entities.name2codepoint.get(name)
            if char is not None:
                self._append_svg_title_reference(f"&{name};", chr(char))
            return
        if self._in_title:
            char = html_entities.name2codepoint.get(name)
            if char is not None:
                self.title += chr(char)

    def handle_charref(self, name: str) -> None:
        if self._svg_title_integration:
            try:
                decoded = chr(int(name[1:], 16) if name[:1].lower() == "x" else int(name))
            except ValueError:
                return
            self._append_svg_title_reference(f"&#{name};", decoded)
            return
        if self._in_title:
            try:
                self.title += chr(int(name[1:], 16) if name[:1].lower() == "x" else int(name))
            except ValueError:
                return


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
    parsed = urlparse(reference)
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


def resolve_reference(reference: str, base_href: str | None) -> str:
    """Resolve a document-relative URL against the active <base href>, if any.

    Browsers treat backslashes as slashes when resolving special-scheme URLs, so
    ``\\\\host\\dir/`` becomes a network-path base. ``urllib.parse.urljoin`` does
    not, which would otherwise keep relative scripts local while the browser
    fetches an external URL.
    """
    if not base_href:
        return reference.replace("\\", "/") if "\\" in reference else reference
    base = base_href.replace("\\", "/")
    ref = reference.replace("\\", "/")
    return urljoin(base, ref)


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
    """
    if in_svg:
        return values.get("href") or values.get("xlink:href")
    return values.get("src")


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
    """
    if crossorigin is None or crossorigin == "":
        return True
    return crossorigin.casefold() != "use-credentials"


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
    parser = SiteParser()
    parser.feed(text)

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
