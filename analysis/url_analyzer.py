"""Deterministic, offline URL analysis.

This module treats every submitted URL as untrusted text. It imports only
standard-library parsing and inspection utilities and never performs DNS,
HTTP, HTTPS, crawling, redirect following, or external lookups.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from .constants import (
    BRAND_LIKE_KEYWORDS,
    COMMON_WEB_PORTS,
    EXCESSIVE_HYPHEN_THRESHOLD,
    EXCESSIVE_PATH_DEPTH_THRESHOLD,
    EXCESSIVE_PUNCTUATION_THRESHOLD,
    EXCESSIVE_REPEATED_SEPARATOR_THRESHOLD,
    EXCESSIVE_SUBDOMAIN_THRESHOLD,
    INDICATOR_POINTS,
    LONG_ENCODED_SEQUENCE_THRESHOLD,
    LONG_HOSTNAME_THRESHOLD,
    LONG_PATH_THRESHOLD,
    LONG_URL_THRESHOLD,
    MAX_FRAGMENT_LENGTH,
    MAX_HOSTNAME_LENGTH,
    MAX_PATH_LENGTH,
    MAX_QUERY_LENGTH,
    MAX_URL_LENGTH,
    REPEATED_ENCODING_THRESHOLD,
    SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_TLDS,
    URL_SHORTENER_DOMAINS,
)
from .types import IndicatorResult, URLAnalysisResult, URLFeatures

_CONTROL_CHARACTER_RE = re.compile(r"[\x00-\x1f\x7f]")
_PERCENT_ENCODING_RE = re.compile(r"%[0-9a-fA-F]{2}")
_LONG_ENCODING_RE = re.compile(
    rf"(?:%[0-9a-fA-F]{{2}}){{{LONG_ENCODED_SEQUENCE_THRESHOLD},}}"
)
_SUSPICIOUS_PUNCTUATION = frozenset("<>[]{}^`|\\")


class URLAnalyzer:
    """Analyze a URL string locally and return features plus indicators."""

    rule_version = "url-v1"

    def analyze(self, submitted_url: str) -> URLAnalysisResult:
        original_url = submitted_url if isinstance(submitted_url, str) else ""
        if not isinstance(submitted_url, str):
            return self._failure(original_url, "The submitted URL must be text.")

        value = submitted_url.strip()
        if not value:
            return self._failure(original_url, "The URL is empty.")
        if len(value) > MAX_URL_LENGTH:
            return self._failure(
                value[:MAX_URL_LENGTH],
                f"The URL exceeds the maximum supported length of {MAX_URL_LENGTH} characters.",
            )
        if _CONTROL_CHARACTER_RE.search(value):
            return self._failure(value, "The URL contains control characters.")

        try:
            parsed = urlsplit(value)
            scheme = parsed.scheme.casefold()
            if not scheme:
                return self._failure(value, "The URL is missing a scheme such as http or https.")
            if not parsed.netloc:
                return self._failure(value, "The URL does not contain a parseable hostname.")

            # Accessing parsed.port and parsed.hostname can raise ValueError for
            # malformed bracketed IPv6 or invalid port syntax.
            hostname = (parsed.hostname or "").casefold().rstrip(".")
            port = parsed.port
            username = parsed.username
            password = parsed.password
            netloc = parsed.netloc
        except ValueError as exc:
            return self._failure(value, f"The URL is malformed: {exc}.")

        if not hostname:
            return self._failure(value, "The URL does not contain a parseable hostname.")
        if re.search(r"[\s<>\"{}|^`]", hostname):
            return self._failure(value, "The URL contains invalid hostname characters.")
        if len(hostname) > MAX_HOSTNAME_LENGTH:
            return self._failure(
                value,
                f"The hostname exceeds the maximum supported length of {MAX_HOSTNAME_LENGTH} characters.",
            )
        if len(parsed.path) > MAX_PATH_LENGTH:
            return self._failure(
                value,
                f"The path exceeds the maximum supported length of {MAX_PATH_LENGTH} characters.",
            )
        if len(parsed.query) > MAX_QUERY_LENGTH:
            return self._failure(
                value,
                f"The query exceeds the maximum supported length of {MAX_QUERY_LENGTH} characters.",
            )
        if len(parsed.fragment) > MAX_FRAGMENT_LENGTH:
            return self._failure(
                value,
                f"The fragment exceeds the maximum supported length of {MAX_FRAGMENT_LENGTH} characters.",
            )

        normalized_url = self._normalize_url(
            scheme=scheme,
            hostname=hostname,
            port=port,
            netloc=parsed.netloc,
            path=parsed.path,
            query=parsed.query,
            fragment=parsed.fragment,
        )
        features = self._extract_features(
            value=value,
            scheme=scheme,
            hostname=hostname,
            port=port,
            username=username,
            password=password,
            netloc=netloc,
            path=parsed.path,
            query=parsed.query,
            fragment=parsed.fragment,
        )
        indicators = self._evaluate_rules(features)

        return URLAnalysisResult(
            success=True,
            original_url=original_url,
            normalized_url=normalized_url,
            features=features,
            indicators=tuple(indicators),
            analysis_metadata={
                "analyzer": "url",
                "rule_version": self.rule_version,
                "network_access": False,
            },
        )

    @staticmethod
    def _normalize_url(
        *,
        scheme: str,
        hostname: str,
        port: int | None,
        netloc: str,
        path: str,
        query: str,
        fragment: str,
    ) -> str:
        """Normalize scheme and hostname without decoding or executing content."""

        userinfo = ""
        if "@" in netloc:
            userinfo = netloc.rsplit("@", 1)[0] + "@"
        display_host = f"[{hostname}]" if ":" in hostname and not hostname.startswith("[") else hostname
        normalized_netloc = f"{userinfo}{display_host}"
        if port is not None:
            normalized_netloc += f":{port}"
        return urlunsplit((scheme, normalized_netloc, path, query, fragment))

    def _extract_features(
        self,
        *,
        value: str,
        scheme: str,
        hostname: str,
        port: int | None,
        username: str | None,
        password: str | None,
        netloc: str,
        path: str,
        query: str,
        fragment: str,
    ) -> URLFeatures:
        labels = [label for label in hostname.split(".") if label]
        ip_version = self._ip_version(hostname)
        uses_ip = ip_version is not None
        domain, subdomain = self._domain_parts(hostname, uses_ip)
        path_segments = [segment for segment in path.split("/") if segment]
        encoded_scope = "".join((hostname, path, query, fragment))
        percent_matches = _PERCENT_ENCODING_RE.findall(encoded_scope)
        keyword_matches = self._keyword_matches(hostname, path, query)
        brand_like_matches = self._brand_like_matches(
            hostname=hostname,
            path=path,
            subdomain_count=max(len(labels) - 2, 0) if not uses_ip else 0,
            hyphen_count=hostname.count("-"),
        )
        tld = labels[-1] if labels else ""
        punctuation_scope = hostname + path + query + fragment
        repeated_separator_count = path.count("//") + query.count("&&")
        suspicious_punctuation_count = sum(
            character in _SUSPICIOUS_PUNCTUATION for character in punctuation_scope
        )
        hyphen_count = hostname.count("-")

        return URLFeatures(
            scheme=scheme,
            hostname=hostname,
            domain=domain,
            subdomain=subdomain,
            port=port,
            path=path,
            query=query,
            fragment=fragment,
            url_length=len(value),
            hostname_length=len(hostname),
            path_length=len(path),
            hostname_label_count=len(labels),
            subdomain_count=max(len(labels) - 2, 0) if not uses_ip else 0,
            query_parameter_count=self._query_parameter_count(query),
            path_depth=len(path_segments),
            uses_ip=uses_ip,
            ip_version=ip_version,
            uses_https=scheme == "https",
            uses_http=scheme == "http",
            has_at_symbol="@" in netloc,
            has_authentication_syntax=username is not None or password is not None,
            has_punycode=any(label.startswith("xn--") for label in labels),
            has_percent_encoding=bool(percent_matches),
            percent_encoding_count=len(percent_matches),
            has_repeated_percent_encoding=len(percent_matches) >= REPEATED_ENCODING_THRESHOLD,
            has_long_encoded_sequence=bool(_LONG_ENCODING_RE.search(encoded_scope)),
            has_backslash="\\" in value,
            repeated_separator_count=repeated_separator_count,
            suspicious_punctuation_count=suspicious_punctuation_count,
            has_suspicious_tld=tld in SUSPICIOUS_TLDS,
            uses_shortener=hostname.removeprefix("www.") in URL_SHORTENER_DOMAINS,
            has_explicit_port=port is not None,
            has_unusual_port=port is not None and port not in COMMON_WEB_PORTS,
            suspicious_keyword_matches=tuple(keyword_matches),
            brand_like_matches=tuple(brand_like_matches),
        )

    @staticmethod
    def _ip_version(hostname: str) -> int | None:
        try:
            return ipaddress.ip_address(hostname).version
        except ValueError:
            return None

    @staticmethod
    def _domain_parts(hostname: str, uses_ip: bool) -> tuple[str, str]:
        if uses_ip:
            return hostname, ""
        labels = [label for label in hostname.split(".") if label]
        if len(labels) <= 2:
            return hostname, ""
        return ".".join(labels[-2:]), ".".join(labels[:-2])

    @staticmethod
    def _query_parameter_count(query: str) -> int:
        return len([part for part in query.split("&") if part])

    @staticmethod
    def _keyword_matches(hostname: str, path: str, query: str) -> list[dict[str, str]]:
        matches: list[dict[str, str]] = []
        for location, component in (("hostname", hostname), ("path", path), ("query", query)):
            lowered = component.casefold()
            for keyword in sorted(SUSPICIOUS_KEYWORDS, key=lambda item: (-len(item), item)):
                pattern = rf"(?<![a-z0-9]){re.escape(keyword)}(?![a-z0-9])"
                if re.search(pattern, lowered):
                    matches.append(
                        {
                            "keyword": keyword,
                            "location": location,
                            "category": SUSPICIOUS_KEYWORDS[keyword],
                        }
                    )
        return matches

    @staticmethod
    def _brand_like_matches(
        *, hostname: str, path: str, subdomain_count: int, hyphen_count: int
    ) -> list[dict[str, str]]:
        """Find brand-like words only when reinforced by unusual structure."""

        if subdomain_count < 1 and hyphen_count < 2:
            return []
        scope = (("hostname", hostname), ("path", path))
        matches: list[dict[str, str]] = []
        for location, component in scope:
            lowered = component.casefold()
            for keyword in sorted(BRAND_LIKE_KEYWORDS):
                if re.search(rf"(?<![a-z0-9]){re.escape(keyword)}(?![a-z0-9])", lowered):
                    matches.append({"keyword": keyword, "location": location})
        return matches

    def _evaluate_rules(self, features: URLFeatures) -> list[IndicatorResult]:
        indicators: list[IndicatorResult] = []
        order = 1

        def add(
            code: str,
            category: str,
            title: str,
            severity: str,
            evidence: str,
            explanation: str,
            recommendation: str,
        ) -> None:
            nonlocal order
            indicators.append(
                IndicatorResult(
                    code=code,
                    category=category,
                    title=title,
                    severity=severity,
                    points=INDICATOR_POINTS[code],
                    evidence=evidence[:1000],
                    explanation=explanation,
                    recommendation=recommendation,
                    sort_order=order,
                )
            )
            order += 1

        if features.uses_ip:
            add(
                "URL_IP_ADDRESS",
                "hostname",
                "IP address used as hostname",
                "HIGH",
                f"Hostname: {features.hostname}",
                "A raw IPv4 or IPv6 address is used instead of a conventional domain name. This can make the destination harder to associate with an organization, although IP-based services are not automatically malicious.",
                "Verify the destination through a trusted, independent channel before interacting with it.",
            )
        if features.uses_http:
            add(
                "URL_HTTP",
                "transport",
                "Unencrypted HTTP scheme",
                "MEDIUM",
                "Scheme: http",
                "HTTP does not encrypt traffic in transit, which can expose requests and credentials. HTTPS also does not guarantee that a site is legitimate.",
                "Avoid submitting sensitive information unless the organization and destination have been independently verified.",
            )
        if features.scheme not in {"http", "https"}:
            add(
                "URL_UNKNOWN_SCHEME",
                "transport",
                "Unknown or non-web scheme",
                "MEDIUM",
                f"Scheme: {features.scheme}",
                "The scheme is not the expected HTTP or HTTPS web scheme, so the link may not behave like an ordinary web address.",
                "Do not open the link unless the scheme and intended application are explicitly trusted.",
            )
        if features.url_length > LONG_URL_THRESHOLD:
            add(
                "URL_LONG",
                "length",
                "Unusually long URL",
                "LOW",
                f"Length: {features.url_length} characters",
                f"The URL exceeds the documented review threshold of {LONG_URL_THRESHOLD} characters and may be harder to inspect manually.",
                "Review the complete destination carefully and avoid relying only on the visible beginning of the link.",
            )
        if features.hostname_length > LONG_HOSTNAME_THRESHOLD:
            add(
                "URL_LONG_HOSTNAME",
                "hostname",
                "Long hostname",
                "LOW",
                f"Hostname length: {features.hostname_length} characters",
                f"The hostname exceeds the documented review threshold of {LONG_HOSTNAME_THRESHOLD} characters, which can make identity cues difficult to read.",
                "Compare the registrable-looking domain with the organization you expect, without assuming that length proves maliciousness.",
            )
        if features.path_length > LONG_PATH_THRESHOLD:
            add(
                "URL_LONG_PATH",
                "path",
                "Unusually long path",
                "LOW",
                f"Path length: {features.path_length} characters",
                f"The path exceeds the documented review threshold of {LONG_PATH_THRESHOLD} characters and may conceal the meaningful part of a destination.",
                "Inspect the complete path as text and verify the destination independently before continuing.",
            )
        if features.subdomain_count > EXCESSIVE_SUBDOMAIN_THRESHOLD:
            add(
                "URL_EXCESSIVE_SUBDOMAINS",
                "hostname",
                "Many hostname subdomains",
                "MEDIUM",
                f"Subdomain count: {features.subdomain_count}",
                f"The hostname contains more than {EXCESSIVE_SUBDOMAIN_THRESHOLD} subdomain levels. Multiple levels can be legitimate, but they can also make the apparent organization difficult to identify.",
                "Focus on the domain near the end of the hostname rather than the first familiar-looking label.",
            )
        if features.hostname.count("-") >= EXCESSIVE_HYPHEN_THRESHOLD:
            add(
                "URL_EXCESSIVE_HYPHENS",
                "hostname",
                "Excessive hostname hyphens",
                "LOW",
                f"Hyphen count: {features.hostname.count('-')}",
                f"The hostname contains at least {EXCESSIVE_HYPHEN_THRESHOLD} hyphens, which can make an address resemble a constructed or lookalike domain.",
                "Check the actual domain structure and verify the organization independently.",
            )
        if features.has_at_symbol:
            add(
                "URL_AT_SYMBOL",
                "authority",
                "At-symbol in URL authority",
                "HIGH",
                "An @ symbol appears before the host portion.",
                "An at-symbol in the authority can make text before it look like the destination while the actual host appears after it.",
                "Treat the host after the @ symbol as the destination and avoid the link until it is independently verified.",
            )
        if features.has_authentication_syntax:
            add(
                "URL_AUTHENTICATION_SYNTAX",
                "authority",
                "Authentication-like URL syntax",
                "MEDIUM",
                "User-information syntax is present in the URL authority.",
                "Embedded user information can make the visible authority confusing and is uncommon for ordinary user-facing links.",
                "Do not enter credentials into a link containing embedded user-information syntax.",
            )
        if features.has_suspicious_tld:
            tld = features.hostname.rsplit(".", 1)[-1]
            add(
                "URL_SUSPICIOUS_TLD",
                "domain",
                "TLD deserves additional scrutiny",
                "LOW",
                f"TLD: .{tld}",
                "This TLD can be associated with higher-risk registrations and should be evaluated with other signals. A TLD alone does not establish maliciousness.",
                "Use an independently known organization address rather than trusting the TLD by itself.",
            )
        if features.uses_shortener:
            add(
                "URL_SHORTENER",
                "destination",
                "Known URL shortener domain",
                "MEDIUM",
                f"Shortener hostname: {features.hostname}",
                "A shortened URL hides the final destination and therefore deserves additional scrutiny.",
                "Do not expand or open it automatically; obtain the full destination through a trusted source.",
            )
        if features.has_unusual_port:
            add(
                "URL_UNUSUAL_PORT",
                "port",
                "Unusual explicit port",
                "MEDIUM",
                f"Port: {features.port}",
                "The URL explicitly uses a port outside the common web-port set. This is an anomaly worth reviewing but does not prove phishing.",
                "Verify why the service uses this port before connecting to it.",
            )
        if features.has_percent_encoding:
            add(
                "URL_PERCENT_ENCODING",
                "obfuscation",
                "Percent-encoded URL content",
                "LOW",
                f"Encoded sequences: {features.percent_encoding_count}",
                "Percent encoding is valid in URLs, but encoded content can make a destination or path harder to inspect.",
                "Review encoded portions as text and avoid decoding content into executable form.",
            )
        if features.has_repeated_percent_encoding or features.has_long_encoded_sequence:
            add(
                "URL_EXCESSIVE_ENCODING",
                "obfuscation",
                "Excessive percent encoding",
                "MEDIUM",
                f"Encoded sequences: {features.percent_encoding_count}",
                "Repeated or long runs of percent-encoded bytes can obscure the meaning of a URL component.",
                "Treat the link as suspicious until its intended destination is confirmed independently.",
            )
        if (
            features.has_backslash
            or features.repeated_separator_count >= EXCESSIVE_REPEATED_SEPARATOR_THRESHOLD
            or features.suspicious_punctuation_count >= EXCESSIVE_PUNCTUATION_THRESHOLD
        ):
            add(
                "URL_SUSPICIOUS_CHARACTERS",
                "syntax",
                "Unusual URL punctuation or separators",
                "MEDIUM",
                f"Punctuation count: {features.suspicious_punctuation_count}; repeated separators: {features.repeated_separator_count}",
                "Unusual punctuation, backslashes, or repeated separators can make a URL difficult to parse consistently and may support visual obfuscation.",
                "Do not rely on the rendered appearance; verify the complete string through a trusted source.",
            )
        if features.path_depth > EXCESSIVE_PATH_DEPTH_THRESHOLD:
            add(
                "URL_EXCESSIVE_PATH_DEPTH",
                "path",
                "Deep URL path",
                "LOW",
                f"Non-empty path segments: {features.path_depth}",
                f"The path contains more than {EXCESSIVE_PATH_DEPTH_THRESHOLD} non-empty segments, which can make a destination harder to review.",
                "Inspect the full path and be cautious if it is combined with account, login, or verification language.",
            )
        if features.has_punycode:
            add(
                "URL_PUNYCODE",
                "domain",
                "Punycode hostname label",
                "MEDIUM",
                "A hostname label begins with xn--.",
                "Internationalized domain names can sometimes be abused for visual impersonation. Punycode by itself does not mean the domain is malicious.",
                "Use a known-good organization address or verify the domain through an independent channel.",
            )
        for match in features.brand_like_matches:
            add(
                "URL_BRAND_LIKE_STRUCTURE",
                "domain_structure",
                "Brand-like word with unusual structure",
                "MEDIUM",
                f"Matched '{match['keyword']}' in {match['location']}",
                "A brand-like word appears alongside an unusual hostname structure. This is only a conservative impersonation signal and does not establish ownership or maliciousness.",
                "Use an independently known organization address instead of trusting a familiar word in the link.",
            )
        for match in features.suspicious_keyword_matches:
            add(
                "URL_SUSPICIOUS_KEYWORD",
                "keyword",
                "Sensitive-action keyword in URL",
                "LOW",
                f"Matched '{match['keyword']}' in {match['location']}",
                f"The URL contains the keyword '{match['keyword']}' in its {match['location']}. Such terms can occur in legitimate workflows but are also common in credential, payment, or verification lures.",
                "Do not infer legitimacy from the wording; navigate through a trusted bookmark or independently known address instead.",
            )

        return indicators

    def _failure(self, original_url: str, error: str) -> URLAnalysisResult:
        return URLAnalysisResult(
            success=False,
            original_url=original_url,
            normalized_url="",
            features=None,
            indicators=tuple(),
            error=error,
            analysis_metadata={
                "analyzer": "url",
                "rule_version": self.rule_version,
                "network_access": False,
            },
        )


def analyze_url(submitted_url: str) -> URLAnalysisResult:
    """Convenience function for future scan workflows and direct callers."""

    return URLAnalyzer().analyze(submitted_url)
