import unittest

from analysis.risk_engine import RiskEngine, evaluate_risk
from analysis.types import IndicatorResult


class RiskEngineTests(unittest.TestCase):
    def setUp(self):
        self.engine = RiskEngine()

    @staticmethod
    def indicator(code="CUSTOM", points=0, category="test", recommendation=""):
        return IndicatorResult(
            code=code,
            category=category,
            title=f"{code} indicator",
            severity="LOW",
            points=points,
            evidence=f"Evidence for {code}",
            explanation=f"Explanation for {code}",
            recommendation=recommendation,
            sort_order=1,
        )

    def test_no_indicators_returns_cautious_safe_result(self):
        result = self.engine.evaluate([])
        self.assertTrue(result.success)
        self.assertEqual(result.score, 0)
        self.assertEqual(result.risk_level, "VERY_LOW")
        self.assertIn("Safe", result.verdict)
        self.assertIn("does not guarantee safety", result.summary)
        self.assertEqual(result.score_breakdown, ())
        self.assertEqual(result.recommendations, ())

    def test_one_low_risk_indicator(self):
        result = self.engine.evaluate([self.indicator(points=25)])
        self.assertEqual(result.score, 25)
        self.assertEqual(result.risk_level, "LOW")

    def test_one_high_risk_indicator(self):
        result = self.engine.evaluate([self.indicator(points=60)])
        self.assertEqual(result.score, 60)
        self.assertEqual(result.risk_level, "HIGH")

    def test_multiple_indicators_are_added(self):
        result = self.engine.evaluate([
            self.indicator(code="FIRST", points=10),
            self.indicator(code="SECOND", points=20),
        ])
        self.assertEqual(result.score, 30)
        self.assertEqual(len(result.score_breakdown), 2)

    def test_score_is_clamped_above_100(self):
        result = self.engine.evaluate([
            self.indicator(code="FIRST", points=75),
            self.indicator(code="SECOND", points=75),
        ])
        self.assertEqual(result.score, 100)

    def test_score_cannot_be_negative(self):
        result = self.engine.evaluate([])
        self.assertGreaterEqual(result.score, 0)

    def test_exact_score_boundaries(self):
        boundaries = {
            19: "VERY_LOW",
            20: "LOW",
            39: "LOW",
            40: "MEDIUM",
            59: "MEDIUM",
            60: "HIGH",
            79: "HIGH",
            80: "CRITICAL",
            100: "CRITICAL",
        }
        for score, expected_level in boundaries.items():
            with self.subTest(score=score):
                result = self.engine.evaluate([self.indicator(points=score)])
                self.assertEqual(result.score, score)
                self.assertEqual(result.risk_level, expected_level)

    def test_duplicate_indicator_code_contributes_once_and_counts_occurrences(self):
        result = self.engine.evaluate([
            self.indicator(code="DUPLICATE", points=25),
            self.indicator(code="DUPLICATE", points=25),
        ])
        self.assertEqual(result.score, 25)
        self.assertEqual(len(result.score_breakdown), 1)
        self.assertEqual(result.score_breakdown[0].occurrence_count, 2)

    def test_distinct_indicator_codes_contribute_independently(self):
        result = self.engine.evaluate([
            self.indicator(code="RULE_A", points=15),
            self.indicator(code="RULE_B", points=15),
        ])
        self.assertEqual(result.score, 30)
        self.assertEqual(len(result.indicators), 2)

    def test_accepts_compatible_dictionaries(self):
        result = evaluate_risk([self.indicator(code="MAPPING", points=20).to_dict()])
        self.assertEqual(result.score, 20)
        self.assertTrue(result.success)

    def test_invalid_indicator_mapping_returns_failure(self):
        result = self.engine.evaluate([{"code": "MISSING_FIELDS"}])
        self.assertFalse(result.success)
        self.assertIsNone(result.score)
        self.assertEqual(result.risk_level, "")
        self.assertIn("missing fields", result.error)

    def test_negative_indicator_points_returns_failure(self):
        result = self.engine.evaluate([self.indicator(points=-1)])
        self.assertFalse(result.success)
        self.assertIsNone(result.score)
        self.assertIn("must not be negative", result.error)

    def test_failed_analyzer_result_does_not_receive_normal_score(self):
        result = self.engine.evaluate([], analysis_success=False, analysis_error="URL parsing failed")
        self.assertFalse(result.success)
        self.assertIsNone(result.score)
        self.assertEqual(result.score_breakdown, ())
        self.assertEqual(result.error, "URL parsing failed")

    def test_breakdown_contains_required_transparent_fields(self):
        result = self.engine.evaluate([self.indicator(code="BREAKDOWN", points=12)])
        breakdown = result.score_breakdown[0]
        self.assertEqual(breakdown.code, "BREAKDOWN")
        self.assertEqual(breakdown.points, 12)
        self.assertEqual(breakdown.applied_points, 12)
        self.assertEqual(breakdown.evidence, "Evidence for BREAKDOWN")

    def test_url_indicator_uses_centralized_weight(self):
        result = self.engine.evaluate([self.indicator(code="URL_IP_ADDRESS", points=1)])
        self.assertEqual(result.score, 25)
        self.assertEqual(result.score_breakdown[0].points, 25)

    def test_email_indicator_uses_centralized_weight(self):
        result = self.engine.evaluate([self.indicator(code="EMAIL_CREDENTIAL_REQUEST", points=1)])
        self.assertEqual(result.score, 25)

    def test_nested_email_url_marker_is_suppressed_when_detail_exists(self):
        result = self.engine.evaluate([
            self.indicator(code="EMAIL_CONTAINS_SUSPICIOUS_URL", points=20, category="link"),
            self.indicator(code="URL_IP_ADDRESS", points=1, category="hostname"),
        ])
        self.assertEqual(result.score, 25)
        contextual = next(item for item in result.score_breakdown if item.code == "EMAIL_CONTAINS_SUSPICIOUS_URL")
        self.assertEqual(contextual.applied_points, 0)

    def test_nested_email_url_marker_has_small_cap_without_detail(self):
        result = self.engine.evaluate([
            self.indicator(code="EMAIL_CONTAINS_SUSPICIOUS_URL", points=20, category="link"),
        ])
        self.assertEqual(result.score, 5)
        self.assertEqual(result.score_breakdown[0].applied_points, 5)

    def test_recommendations_are_deduplicated(self):
        result = self.engine.evaluate([
            self.indicator(code="EMAIL_PASSWORD_REQUEST", points=25),
            self.indicator(code="EMAIL_PASSWORD_REQUEST", points=25),
            self.indicator(code="EMAIL_CREDENTIAL_REQUEST", points=25),
        ])
        self.assertEqual(len(result.recommendations), 2)
        self.assertEqual(len(set(result.recommendations)), 2)

    def test_category_and_indicator_recommendation_fallbacks_work(self):
        result = self.engine.evaluate([
            self.indicator(code="CUSTOM_LINK", points=5, category="link", recommendation="Original link advice"),
            self.indicator(code="CUSTOM_OTHER", points=5, category="other", recommendation="Original custom advice"),
        ])
        self.assertIn("Avoid opening suspicious links", result.recommendations[0])
        self.assertIn("Original custom advice", result.recommendations[1])

    def test_summary_changes_with_risk_level(self):
        low = self.engine.evaluate([self.indicator(points=20)])
        high = self.engine.evaluate([self.indicator(points=80)])
        self.assertIn("Limited review indicators", low.summary)
        self.assertIn("Multiple high-risk indicators", high.summary)

    def test_scenario_normal_url_has_very_low_risk(self):
        result = self.engine.evaluate([])
        self.assertEqual((result.score, result.risk_level), (0, "VERY_LOW"))

    def test_scenario_http_plus_keyword_is_higher_than_normal(self):
        normal = self.engine.evaluate([])
        scenario = self.engine.evaluate([
            self.indicator(code="URL_HTTP", points=1, category="transport"),
            self.indicator(code="URL_SUSPICIOUS_KEYWORD", points=1, category="keyword"),
        ])
        self.assertGreater(scenario.score, normal.score)
        self.assertEqual(scenario.score, 20)

    def test_scenario_multiple_url_signals_reaches_high_risk_band(self):
        result = self.engine.evaluate([
            self.indicator(code="URL_IP_ADDRESS", points=1),
            self.indicator(code="URL_HTTP", points=1),
            self.indicator(code="URL_SUSPICIOUS_KEYWORD", points=1),
            self.indicator(code="URL_UNUSUAL_PORT", points=1),
            self.indicator(code="URL_AT_SYMBOL", points=1),
            self.indicator(code="URL_SUSPICIOUS_TLD", points=1),
        ])
        self.assertEqual(result.score, 85)
        self.assertEqual(result.risk_level, "CRITICAL")

    def test_scenario_normal_email_has_very_low_risk(self):
        result = self.engine.evaluate([])
        self.assertEqual(result.risk_level, "VERY_LOW")

    def test_scenario_urgent_credential_request_and_suspicious_url_is_high(self):
        result = self.engine.evaluate([
            self.indicator(code="EMAIL_URGENCY_LANGUAGE", points=1),
            self.indicator(code="EMAIL_CREDENTIAL_REQUEST", points=1),
            self.indicator(code="EMAIL_CONTAINS_SUSPICIOUS_URL", points=1, category="link"),
            self.indicator(code="URL_IP_ADDRESS", points=1, category="hostname"),
        ])
        self.assertEqual(result.score, 60)
        self.assertEqual(result.risk_level, "HIGH")

    def test_scenario_attachment_payment_reply_to_reaches_high_band(self):
        result = self.engine.evaluate([
            self.indicator(code="EMAIL_RISKY_ATTACHMENT", points=1, category="attachment"),
            self.indicator(code="EMAIL_PAYMENT_REQUEST", points=1, category="body"),
            self.indicator(code="EMAIL_REPLY_TO_MISMATCH", points=1, category="reply_to"),
            self.indicator(code="EMAIL_FINANCIAL_REQUEST", points=1, category="body"),
        ])
        self.assertEqual(result.score, 70)
        self.assertEqual(result.risk_level, "HIGH")

    def test_same_indicators_produce_identical_output(self):
        indicators = [
            self.indicator(code="URL_HTTP", points=1),
            self.indicator(code="EMAIL_URGENCY_LANGUAGE", points=1),
            self.indicator(code="EMAIL_PASSWORD_REQUEST", points=1),
        ]
        first = self.engine.evaluate(indicators).to_dict()
        second = self.engine.evaluate(indicators).to_dict()
        self.assertEqual(first, second)
        self.assertEqual(first["rule_version"], "risk-v1")

    def test_result_contract_is_immutable(self):
        result = self.engine.evaluate([])
        with self.assertRaises(Exception):
            result.score = 10


if __name__ == "__main__":
    unittest.main()
