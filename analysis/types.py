"""Framework-independent contracts returned by the local analyzers."""

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class IndicatorResult:
    """A signal shaped to match the future Indicator database model."""

    code: str
    category: str
    title: str
    severity: str
    points: int
    evidence: str
    explanation: str
    recommendation: str
    sort_order: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class URLFeatures:
    """Deterministic technical features derived from a URL string."""

    scheme: str
    hostname: str
    domain: str
    subdomain: str
    port: int | None
    path: str
    query: str
    fragment: str
    url_length: int
    hostname_length: int
    path_length: int
    hostname_label_count: int
    subdomain_count: int
    query_parameter_count: int
    path_depth: int
    uses_ip: bool
    ip_version: int | None
    uses_https: bool
    uses_http: bool
    has_at_symbol: bool
    has_authentication_syntax: bool
    has_punycode: bool
    has_percent_encoding: bool
    percent_encoding_count: int
    has_repeated_percent_encoding: bool
    has_long_encoded_sequence: bool
    has_backslash: bool
    repeated_separator_count: int
    suspicious_punctuation_count: int
    has_suspicious_tld: bool
    uses_shortener: bool
    has_explicit_port: bool
    has_unusual_port: bool
    suspicious_keyword_matches: tuple[dict[str, str], ...] = field(default_factory=tuple)
    brand_like_matches: tuple[dict[str, str], ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["suspicious_keyword_matches"] = list(self.suspicious_keyword_matches)
        data["brand_like_matches"] = list(self.brand_like_matches)
        return data


@dataclass(frozen=True)
class AttachmentInfo:
    """Text-only metadata about an email attachment."""

    filename: str
    extension: str
    content_type: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EmailFeatures:
    """Deterministic metadata extracted from an email without storing payloads."""

    sender: str
    sender_domain: str
    sender_display_name: str
    recipient: str
    reply_to: str
    subject: str
    date: str
    body_length: int
    has_plain_text: bool
    has_html: bool
    is_multipart: bool
    attachment_count: int
    extracted_url_count: int
    header_count: int
    malformed_parts: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["malformed_parts"] = list(self.malformed_parts)
        return data


@dataclass(frozen=True)
class EmailAnalysisResult:
    """The email analyzer contract; it intentionally has no final score/verdict."""

    success: bool
    features: EmailFeatures | None
    indicators: tuple[IndicatorResult, ...] = field(default_factory=tuple)
    extracted_urls: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    attachments: tuple[AttachmentInfo, ...] = field(default_factory=tuple)
    error: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "features": self.features.to_dict() if self.features else {},
            "indicators": [indicator.to_dict() for indicator in self.indicators],
            "extracted_urls": [dict(item) for item in self.extracted_urls],
            "attachments": [attachment.to_dict() for attachment in self.attachments],
            "error": self.error,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class ScoreBreakdownItem:
    """One deduplicated contribution to a final risk score."""

    code: str
    title: str
    severity: str
    points: int
    applied_points: int
    evidence: str
    occurrence_count: int = 1

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RiskAnalysisResult:
    """Immutable centralized risk-engine output."""

    success: bool
    score: int | None
    risk_level: str
    verdict: str
    indicators: tuple[IndicatorResult, ...] = field(default_factory=tuple)
    score_breakdown: tuple[ScoreBreakdownItem, ...] = field(default_factory=tuple)
    summary: str = ""
    recommendations: tuple[str, ...] = field(default_factory=tuple)
    rule_version: str = ""
    error: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "score": self.score,
            "risk_level": self.risk_level,
            "verdict": self.verdict,
            "indicators": [indicator.to_dict() for indicator in self.indicators],
            "score_breakdown": [item.to_dict() for item in self.score_breakdown],
            "summary": self.summary,
            "recommendations": list(self.recommendations),
            "rule_version": self.rule_version,
            "error": self.error,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class URLAnalysisResult:
    """The analyzer contract. It deliberately contains no score or verdict."""

    success: bool
    original_url: str
    normalized_url: str
    features: URLFeatures | None
    indicators: tuple[IndicatorResult, ...] = field(default_factory=tuple)
    error: str = ""
    analysis_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "original_url": self.original_url,
            "normalized_url": self.normalized_url,
            "features": self.features.to_dict() if self.features else {},
            "indicators": [indicator.to_dict() for indicator in self.indicators],
            "error": self.error,
            "analysis_metadata": dict(self.analysis_metadata),
        }
