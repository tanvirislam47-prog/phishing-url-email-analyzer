"""Bounded, local text helpers shared by the email analyzer."""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urlsplit


_HTTP_URL_RE = re.compile(r"(?i)https?://[^\s<>\"']+")
_WHITESPACE_RE = re.compile(r"\s+")


def safe_excerpt(text: str, limit: int = 240) -> str:
    """Collapse whitespace and return a bounded, display-safe text excerpt."""

    normalized = _WHITESPACE_RE.sub(" ", text or "").strip()
    if len(normalized) <= limit:
        return normalized
    return normalized[: max(limit - 1, 1)].rstrip() + "…"


def normalize_text(text: str) -> str:
    """Normalize only whitespace for deterministic local phrase matching."""

    return _WHITESPACE_RE.sub(" ", text or "").strip()


def find_phrase(text: str, phrases: tuple[str, ...] | list[str]) -> str | None:
    """Return the first bounded phrase match, preferring longer phrases."""

    lowered = (text or "").casefold()
    for phrase in sorted(phrases, key=lambda value: (-len(value), value)):
        pattern = rf"(?<![\w]){re.escape(phrase.casefold())}(?![\w])"
        if re.search(pattern, lowered):
            return phrase
    return None


def contains_phrase(text: str, phrases: tuple[str, ...] | list[str]) -> bool:
    return find_phrase(text, phrases) is not None


def extract_http_urls(text: str, *, limit: int = 20) -> list[str]:
    """Extract bounded, syntactically plausible HTTP(S) URLs from plain text."""

    if not text or limit <= 0:
        return []
    results: list[str] = []
    seen: set[str] = set()
    for match in _HTTP_URL_RE.finditer(text):
        candidate = _trim_url_punctuation(match.group(0))
        if not candidate or candidate in seen:
            continue
        try:
            parsed = urlsplit(candidate)
            if parsed.scheme.casefold() not in {"http", "https"} or not parsed.netloc:
                continue
            _ = parsed.hostname
        except ValueError:
            continue
        seen.add(candidate)
        results.append(candidate)
        if len(results) >= limit:
            break
    return results


def _trim_url_punctuation(candidate: str) -> str:
    trimmed = candidate.rstrip(".,;:!?\"'")
    while trimmed.endswith(")") and trimmed.count(")") > trimmed.count("("):
        trimmed = trimmed[:-1]
    while trimmed.endswith("]") and trimmed.count("]") > trimmed.count("["):
        trimmed = trimmed[:-1]
    return trimmed


class SafeHTMLTextParser(HTMLParser):
    """Collect visible text from an HTML fragment without executing markup."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._ignored_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.casefold() in {"script", "style"}:
            self._ignored_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() in {"script", "style"}:
            self._ignored_depth = max(self._ignored_depth - 1, 0)

    def handle_data(self, data: str) -> None:
        if self._ignored_depth == 0:
            self.parts.append(data)


def extract_html_text(html: str, *, limit: int = 30000) -> str:
    """Return bounded visible text from HTML, ignoring scripts and styles."""

    parser = SafeHTMLTextParser()
    try:
        parser.feed((html or "")[:limit])
        parser.close()
    except (ValueError, TypeError):
        pass
    return normalize_text(" ".join(parser.parts))[:limit]


class SafeHTMLLinkParser(HTMLParser):
    """Collect anchor text and href values without rendering or executing HTML."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[dict[str, str]] = []
        self._active_href: str | None = None
        self._active_text: list[str] = []
        self._ignored_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        lowered = tag.casefold()
        if lowered in {"script", "style"}:
            self._ignored_depth += 1
            return
        if self._ignored_depth or lowered != "a":
            return
        attributes = {key.casefold(): value or "" for key, value in attrs}
        self._active_href = attributes.get("href", "")
        self._active_text = []

    def handle_data(self, data: str) -> None:
        if self._ignored_depth == 0 and self._active_href is not None:
            self._active_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.casefold()
        if lowered in {"script", "style"}:
            self._ignored_depth = max(self._ignored_depth - 1, 0)
            return
        if self._ignored_depth or lowered != "a" or self._active_href is None:
            return
        self.links.append(
            {
                "href": self._active_href,
                "visible_text": _WHITESPACE_RE.sub(" ", " ".join(self._active_text)).strip(),
            }
        )
        self._active_href = None
        self._active_text = []


def extract_html_links(html: str, *, limit: int = 20) -> list[dict[str, str]]:
    """Parse a bounded HTML fragment as inert text and return anchor metadata."""

    parser = SafeHTMLLinkParser()
    try:
        parser.feed((html or "")[:30000])
        parser.close()
    except (ValueError, TypeError):
        return parser.links[:limit]
    return parser.links[:limit]
