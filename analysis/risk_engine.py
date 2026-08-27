"""Centralized, deterministic, explainable risk scoring.

The risk engine consumes already-generated local indicators. It has no Django,
network, filesystem, content-execution, or analyzer-side effects.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .constants import (
    CONTEXTUAL_INDICATOR_CAPS,
    RECOMMENDATION_BY_CATEGORY,
    RECOMMENDATION_BY_CODE,
    RISK_LEVEL_THRESHOLDS,
    RISK_MAXIMUM_SCORE,
    RISK_MINIMUM_SCORE,
    RISK_RULE_VERSION,
    RISK_VERDICTS,
    RISK_WEIGHTS,
)
from .types import IndicatorResult, RiskAnalysisResult, ScoreBreakdownItem


@dataclass(frozen=True)
class _NormalizedIndicator:
    indicator: IndicatorResult
    configured_points: int
    occurrence_count: int


class RiskEngine:
    """Score structured URL/email indicators without external dependencies."""

    rule_version = RISK_RULE_VERSION

    def evaluate(
        self,
        indicators: Iterable[IndicatorResult | Mapping[str, Any]] | None,
        *,
        analysis_success: bool = True,
        analysis_error: str = "",
    ) -> RiskAnalysisResult:
        """Return a score result or a clear failure result.

        Indicator codes are deduplicated once by default. The generic
        ``EMAIL_CONTAINS_SUSPICIOUS_URL`` marker is capped and contributes no
        additional points when detailed ``URL_*`` indicators are present.
        """

        if not analysis_success:
            return self._failure(analysis_error or "The source analysis failed.")
        if indicators is None:
            return self._failure("Indicators are required for risk evaluation.")

        try:
            normalized = self._normalize_indicators(indicators)
        except (TypeError, ValueError) as exc:
            return self._failure(f"Invalid indicator data: {exc}")

        has_detailed_url_signal = any(
            item.indicator.code.startswith("URL_") for item in normalized
        )
        breakdown: list[ScoreBreakdownItem] = []
        applied_total = 0
        for item in normalized:
            code = item.indicator.code
            applied_points = item.configured_points
            if code in CONTEXTUAL_INDICATOR_CAPS:
                if has_detailed_url_signal:
                    applied_points = 0
                else:
                    applied_points = min(
                        applied_points, CONTEXTUAL_INDICATOR_CAPS[code]
                    )
            applied_points = max(applied_points, 0)
            applied_total += applied_points
            breakdown.append(
                ScoreBreakdownItem(
                    code=code,
                    title=item.indicator.title,
                    severity=item.indicator.severity,
                    points=item.configured_points,
                    applied_points=applied_points,
                    evidence=item.indicator.evidence,
                    occurrence_count=item.occurrence_count,
                )
            )

        score = self._clamp(applied_total)
        risk_level = self._risk_level_for(score)
        verdict = RISK_VERDICTS[risk_level]
        summary = self._summary(score, risk_level, normalized)
        recommendations = self._recommendations(normalized)
        return RiskAnalysisResult(
            success=True,
            score=score,
            risk_level=risk_level,
            verdict=verdict,
            indicators=tuple(item.indicator for item in normalized),
            score_breakdown=tuple(breakdown),
            summary=summary,
            recommendations=tuple(recommendations),
            rule_version=self.rule_version,
            metadata={
                "deduplication": "one contribution per unique indicator code",
                "nested_url_handling": "detailed URL indicators are primary; contextual email marker is capped or metadata-only",
                "score_minimum": RISK_MINIMUM_SCORE,
                "score_maximum": RISK_MAXIMUM_SCORE,
                "network_access": False,
            },
        )

    def _normalize_indicators(
        self, indicators: Iterable[IndicatorResult | Mapping[str, Any]]
    ) -> list[_NormalizedIndicator]:
        grouped: dict[str, _NormalizedIndicator] = {}
        for raw_indicator in indicators:
            indicator = self._coerce_indicator(raw_indicator)
            configured_points = RISK_WEIGHTS.get(indicator.code, indicator.points)
            if configured_points < 0:
                raise ValueError(f"points must not be negative for {indicator.code}")
            if indicator.code in grouped:
                existing = grouped[indicator.code]
                grouped[indicator.code] = _NormalizedIndicator(
                    indicator=existing.indicator,
                    configured_points=existing.configured_points,
                    occurrence_count=existing.occurrence_count + 1,
                )
            else:
                grouped[indicator.code] = _NormalizedIndicator(
                    indicator=indicator,
                    configured_points=int(configured_points),
                    occurrence_count=1,
                )
        return list(grouped.values())

    @staticmethod
    def _coerce_indicator(
        raw_indicator: IndicatorResult | Mapping[str, Any],
    ) -> IndicatorResult:
        if isinstance(raw_indicator, IndicatorResult):
            indicator = raw_indicator
        elif isinstance(raw_indicator, Mapping):
            required = {
                "code",
                "category",
                "title",
                "severity",
                "points",
                "evidence",
                "explanation",
                "recommendation",
                "sort_order",
            }
            missing = sorted(required.difference(raw_indicator.keys()))
            if missing:
                raise ValueError(f"missing fields: {', '.join(missing)}")
            try:
                indicator = IndicatorResult(
                    code=str(raw_indicator["code"]),
                    category=str(raw_indicator["category"]),
                    title=str(raw_indicator["title"]),
                    severity=str(raw_indicator["severity"]),
                    points=int(raw_indicator["points"]),
                    evidence=str(raw_indicator["evidence"]),
                    explanation=str(raw_indicator["explanation"]),
                    recommendation=str(raw_indicator["recommendation"]),
                    sort_order=int(raw_indicator["sort_order"]),
                )
            except (TypeError, ValueError) as exc:
                raise ValueError(f"fields have invalid types: {exc}") from exc
        else:
            raise TypeError("each indicator must be IndicatorResult or a mapping")

        if not indicator.code.strip():
            raise ValueError("indicator code must not be empty")
        if indicator.points < 0:
            raise ValueError(f"points must not be negative for {indicator.code}")
        return indicator

    @staticmethod
    def _clamp(value: int) -> int:
        return max(RISK_MINIMUM_SCORE, min(RISK_MAXIMUM_SCORE, int(value)))

    @staticmethod
    def _risk_level_for(score: int) -> str:
        for minimum, maximum, risk_level in RISK_LEVEL_THRESHOLDS:
            if minimum <= score <= maximum:
                return risk_level
        raise ValueError(f"No risk level configured for score {score}")

    @staticmethod
    def _summary(
        score: int, risk_level: str, indicators: list[_NormalizedIndicator]
    ) -> str:
        if not indicators:
            return "No significant phishing indicators were detected by the configured rules. This does not guarantee safety."
        titles = [item.indicator.title for item in indicators[:3]]
        joined_titles = ", ".join(titles)
        if risk_level in {"HIGH", "CRITICAL"}:
            return "Multiple high-risk indicators were detected. Treat this content as potentially phishing and verify it through an independent channel."
        if risk_level == "MEDIUM":
            return f"Several suspicious indicators were detected, including {joined_titles}. Review the evidence before acting."
        return f"Limited review indicators were detected, including {joined_titles}. Verify sensitive requests independently."

    @staticmethod
    def _recommendations(
        indicators: list[_NormalizedIndicator],
    ) -> list[str]:
        recommendations: list[str] = []
        seen: set[str] = set()
        for item in indicators:
            indicator = item.indicator
            recommendation = RECOMMENDATION_BY_CODE.get(indicator.code)
            if not recommendation:
                recommendation = RECOMMENDATION_BY_CATEGORY.get(indicator.category)
            if not recommendation:
                recommendation = indicator.recommendation.strip()
            if not recommendation:
                recommendation = "Review the evidence and verify the context independently."
            if recommendation not in seen:
                seen.add(recommendation)
                recommendations.append(recommendation)
        return recommendations

    def _failure(self, error: str) -> RiskAnalysisResult:
        return RiskAnalysisResult(
            success=False,
            score=None,
            risk_level="",
            verdict="",
            indicators=tuple(),
            score_breakdown=tuple(),
            summary="",
            recommendations=tuple(),
            rule_version=self.rule_version,
            error=error,
            metadata={
                "network_access": False,
                "score_minimum": RISK_MINIMUM_SCORE,
                "score_maximum": RISK_MAXIMUM_SCORE,
            },
        )


def evaluate_risk(
    indicators: Iterable[IndicatorResult | Mapping[str, Any]] | None,
    *,
    analysis_success: bool = True,
    analysis_error: str = "",
) -> RiskAnalysisResult:
    """Convenience function for future scan workflows and direct callers."""

    return RiskEngine().evaluate(
        indicators,
        analysis_success=analysis_success,
        analysis_error=analysis_error,
    )
