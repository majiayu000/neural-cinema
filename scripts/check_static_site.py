#!/usr/bin/env python3
"""Validate the static Neural Cinema site without external dependencies."""

from __future__ import annotations

import base64
import binascii
import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_FILES = ["index.html", "app.js", "styles.css", "README.md", "LICENSE", "CHANGELOG.md"]
SRI_DIGEST_BYTES = {
    "sha384": 48,
    "sha512": 64,
}
SRI_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
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
        self.meta_description = ""
        self.canvas_ids: set[str] = set()
        self.link_hrefs: list[str] = []
        self.script_srcs: list[str] = []
        self.external_scripts: list[dict[str, str | None]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "title":
            self._in_title = True
        if tag == "meta" and values.get("name") == "description":
            self.meta_description = values.get("content") or ""
        if tag == "canvas" and values.get("id"):
            self.canvas_ids.add(values["id"])
        if tag == "link" and values.get("href"):
            self.link_hrefs.append(values["href"])
        if tag == "script" and values.get("src"):
            src = values["src"]
            self.script_srcs.append(src)
            if is_external(src):
                self.external_scripts.append(
                    {
                        "src": src,
                        "integrity": values.get("integrity"),
                        "crossorigin": values.get("crossorigin"),
                    }
                )

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data.strip()


def is_external(reference: str) -> bool:
    parsed = urlparse(reference)
    return parsed.scheme in {"http", "https", "data"}


def normalize_local_reference(reference: str) -> Path:
    """Resolve a local asset path and ensure it stays under the repository root."""
    path = (ROOT / reference.removeprefix("./")).resolve()
    if not path.is_relative_to(ROOT):
        raise ValueError(f"local reference escapes repository root: {reference}")
    return path


def pad_base64(digest: str) -> str:
    """Add optional Base64 padding so unpadded SRI digests still decode."""
    remainder = len(digest) % 4
    if remainder == 0:
        return digest
    return digest + ("=" * (4 - remainder))


def normalize_sri_token(token: str) -> str | None:
    """Return algorithm-padded_digest for a well-formed SRI token, else None."""
    if "-" not in token:
        return None
    algorithm, digest = token.split("-", 1)
    expected_bytes = SRI_DIGEST_BYTES.get(algorithm)
    if expected_bytes is None or not digest:
        return None
    if not SRI_BASE64_RE.fullmatch(digest):
        return None
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
    tokens = [token for token in integrity.split() if token]
    if not tokens:
        return False
    return any(normalize_sri_token(token) is not None for token in tokens)


def integrity_matches_trusted(integrity: str, expected: str) -> bool:
    """True when integrity includes a token equivalent to the trusted digest."""
    expected_normalized = normalize_sri_token(expected)
    if expected_normalized is None:
        return False
    for token in integrity.split():
        if not token:
            continue
        normalized = normalize_sri_token(token)
        if normalized == expected_normalized:
            return True
    return False


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

    references = parser.link_hrefs + parser.script_srcs
    for reference in references:
        if is_external(reference):
            if reference.startswith("http://"):
                errors.append(f"external reference must use https: {reference}")
            continue
        try:
            path = normalize_local_reference(reference)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if not path.is_file():
            errors.append(f"local reference does not exist: {reference}")

    for script in parser.external_scripts:
        src = script["src"] or ""
        integrity = script.get("integrity") or ""
        crossorigin = script.get("crossorigin") or ""
        if not is_valid_sri_integrity(integrity):
            errors.append(f"external script missing or malformed SRI integrity: {src}")
        trusted = TRUSTED_EXTERNAL_SCRIPT_INTEGRITY.get(src)
        if trusted is None:
            errors.append(f"untrusted external script (no pinned SRI mapping): {src}")
        elif not integrity_matches_trusted(integrity, trusted):
            errors.append(f"external script integrity does not match trusted digest: {src}")
        if crossorigin != "anonymous":
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
