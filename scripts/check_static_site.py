#!/usr/bin/env python3
"""Validate the static Neural Cinema site without external dependencies."""

from __future__ import annotations

import base64
import binascii
import re
import sys
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
# Pin CDN URL → expected SRI token so mistyped/stale digests fail without fetching.
TRUSTED_EXTERNAL_SCRIPT_INTEGRITY = {
    "https://unpkg.com/three@0.149.0/build/three.min.js": (
        "sha384-RRHfJ6w1mTlKUBMYT/hvnRiOzEB/vyRV3DrQOseb6oYfvaZSfdd0byS4bHps0k2R"
    ),
    "https://unpkg.com/lucide@0.468.0/dist/umd/lucide.min.js": (
        "sha384-uTYyvsSSUZeaPhb5RbKlQa0zY/WpX/QHfvg2mczXyBQOpkWPEDy9lczyp+w7SKXu"
    ),
}


class SiteParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.title = ""
        self._in_title = False
        self._template_depth = 0
        self._noscript_depth = 0
        self._svg_depth = 0
        self.meta_description = ""
        self.canvas_ids: set[str] = set()
        self.base_href: str | None = None
        # (raw, resolved_at_encounter) so later <base> cannot rewrite earlier refs.
        self.link_refs: list[tuple[str, str]] = []
        self.script_refs: list[tuple[str, str]] = []
        self.external_scripts: list[dict[str, object]] = []

    def _in_inert_content(self) -> bool:
        # <template> and <noscript> contents are not executable dependencies.
        return self._template_depth > 0 or self._noscript_depth > 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # Browsers keep the first duplicate attribute; dict(attrs) would last-win.
        values, duplicates = first_wins_attrs(attrs)
        if tag == "template":
            # Template contents are inert; nested templates still nest the depth.
            self._template_depth += 1
            return
        if tag == "noscript":
            # Noscript fallback is inert when scripting is enabled, and scripts
            # cannot execute when scripting is disabled either.
            self._noscript_depth += 1
            return
        if self._in_inert_content():
            # Ignore tags inside inert containers; browsers do not fetch/execute them.
            return
        if tag == "svg":
            self._svg_depth += 1
        if tag == "title":
            self._in_title = True
        if tag == "base" and self.base_href is None and values.get("href"):
            # HTML uses the first <base href>; later bases are ignored.
            # Encounter-time resolution still matters for classic scripts before it.
            self.base_href = values["href"]
        if tag == "meta" and values.get("name") == "description":
            self.meta_description = values.get("content") or ""
        if tag == "canvas" and values.get("id"):
            self.canvas_ids.add(values["id"])
        if tag == "link" and values.get("href"):
            href = values["href"]
            resolved = resolve_reference(href, self.base_href)
            self.link_refs.append((href, resolved))
        if tag == "script":
            src = script_resource_url(values, self._svg_depth > 0)
            if src:
                resolved_src = resolve_reference(src, self.base_href)
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
        if tag == "svg":
            if self._svg_depth > 0:
                self._svg_depth -= 1
            return
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data.strip()


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
    return parsed.scheme in {"http", "https", "data"}


def resolve_reference(reference: str, base_href: str | None) -> str:
    """Resolve a document-relative URL against the active <base href>, if any."""
    if not base_href:
        return reference
    return urljoin(base_href, reference)


def script_resource_url(values: dict[str, str | None], in_svg: bool) -> str | None:
    """Return the executable script URL for HTML src or SVG href/xlink:href."""
    src = values.get("src")
    if src:
        return src
    if in_svg:
        return values.get("href") or values.get("xlink:href")
    return None


def normalize_local_reference(reference: str) -> Path:
    """Resolve a local asset path and ensure it stays under the repository root."""
    path = (ROOT / reference.removeprefix("./")).resolve()
    if not path.is_relative_to(ROOT):
        raise ValueError(f"local reference escapes repository root: {reference}")
    return path


def is_anonymous_crossorigin(crossorigin: str | None) -> bool:
    """True for the CORS anonymous state, including the empty-value shorthand."""
    if crossorigin is None or crossorigin == "":
        return True
    return crossorigin.casefold() == "anonymous"


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
    """Return known algorithm when digest is Base64-shaped, ignoring length.

    Browsers select the strongest recognized algorithm before validating digest
    length, so short tokens like sha512-AA== still win over sha384. Option
    suffixes such as ?foo are parsed off before the Base64 check.
    """
    parsed = sri_algorithm_and_digest(token)
    if parsed is None:
        return None
    algorithm, digest = parsed
    if not SRI_BASE64_RE.fullmatch(digest):
        return None
    padded = pad_base64(digest)
    try:
        base64.b64decode(padded, validate=True)
    except binascii.Error:
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
        trusted = TRUSTED_EXTERNAL_SCRIPT_INTEGRITY.get(src)
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
