#!/usr/bin/env python3
"""Validate the static Neural Cinema site without external dependencies."""

from __future__ import annotations

import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_FILES = ["index.html", "app.js", "styles.css", "README.md", "LICENSE", "CHANGELOG.md"]


class SiteParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.title = ""
        self._in_title = False
        self.meta_description = ""
        self.canvas_ids: set[str] = set()
        self.link_hrefs: list[str] = []
        self.script_srcs: list[str] = []

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
            self.script_srcs.append(values["src"])

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
    return ROOT / reference.removeprefix("./")


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
        path = normalize_local_reference(reference)
        if not path.is_file():
            errors.append(f"local reference does not exist: {reference}")

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
