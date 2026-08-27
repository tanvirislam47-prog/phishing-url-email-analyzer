import os
import socket
import subprocess
import urllib.request
from unittest.mock import patch

from django.test import SimpleTestCase

from analysis.constants import (
    MAX_ATTACHMENT_NAMES_LENGTH,
    MAX_EMAIL_ATTACHMENTS,
    MAX_EMAIL_BODY_LENGTH,
    MAX_EXTRACTED_EMAIL_URLS,
    MAX_RAW_EMAIL_LENGTH,
    MAX_URL_LENGTH,
)
from analysis.email_analyzer import analyze_email
from analysis.risk_engine import evaluate_risk
from analysis.text_features import extract_html_text
from analysis.types import IndicatorResult
from analysis.url_analyzer import analyze_url


class PhaseEightAdversarialAnalyzerTests(SimpleTestCase):
    def test_url_adversarial_inputs_are_local_deterministic_and_bounded(self):
        values = [
            "",
            "   ",
            "javascript:alert(1)",
            "file://localhost/etc/passwd",
            "http://127.0.0.1:8080/login",
            "http://[::1]/verify",
            "https://例え.テスト/ログイン?next=%2Faccount#section",
            "https://xn--e1afmkfd.xn--p1ai/account",
            "https://example.com/a//b///c?x=1&&y=2#frag",
            "https://user:pass@example.com/login",
        ]
        for value in values:
            with self.subTest(value=value):
                first = analyze_url(value)
                second = analyze_url(value)
                self.assertEqual(first.to_dict(), second.to_dict())
                self.assertFalse(first.analysis_metadata["network_access"])
                self.assertLessEqual(len(first.original_url), MAX_URL_LENGTH)

    def test_oversized_url_fails_before_unbounded_processing(self):
        result = analyze_url("https://example.com/" + "a" * MAX_URL_LENGTH)
        self.assertFalse(result.success)
        self.assertLessEqual(len(result.original_url), MAX_URL_LENGTH)
        self.assertIn("maximum supported length", result.error)

    def test_oversized_email_inputs_fail_safely(self):
        raw_result = analyze_email("From: sender@example.com\n\n" + "x" * MAX_RAW_EMAIL_LENGTH)
        structured_result = analyze_email(
            sender="sender@example.com",
            body="x" * (MAX_EMAIL_BODY_LENGTH + 1),
        )
        attachment_result = analyze_email(
            sender="sender@example.com",
            attachment_names="x" * (MAX_ATTACHMENT_NAMES_LENGTH + 1),
        )
        self.assertFalse(raw_result.success)
        self.assertFalse(structured_result.success)
        self.assertFalse(attachment_result.success)
        self.assertNotIn("Traceback", raw_result.error)

    def test_malformed_and_hostile_email_text_remains_inert(self):
        raw_email = (
            "From: <not-an-address>\n"
            "Reply-To: <script>alert(1)</script>\n"
            "Subject: <img src=x onerror=alert(1)>\n"
            "Content-Type: text/html; charset=utf-8\n\n"
            "<p>Visible message</p><script>alert(2)</script>"
        )
        result = analyze_email(raw_email)
        self.assertTrue(result.success)
        self.assertEqual(result.metadata["network_access"], False)
        self.assertLessEqual(len(result.indicators), 80)
        self.assertNotIn("<script>alert(2)</script>", extract_html_text("<p>Visible</p><script>alert(2)</script>"))

    def test_html_script_and_style_content_is_not_visible_text(self):
        html = '<div>Review now</div><script>alert(1)</script><style>body{display:none}</style>'
        visible = extract_html_text(html)
        self.assertEqual(visible, "Review now")
        self.assertNotIn("alert", visible)
        self.assertNotIn("display", visible)

    def test_many_nested_urls_and_attachments_are_bounded_and_deduplicated(self):
        repeated_urls = " ".join(
            f"https://example{i}.invalid/login" for i in range(MAX_EXTRACTED_EMAIL_URLS + 10)
        )
        attachment_names = ",".join(
            f"attachment-{i}.pdf" for i in range(MAX_EMAIL_ATTACHMENTS + 10)
        )
        result = analyze_email(
            sender="sender@example.com",
            body=repeated_urls,
            attachment_names=attachment_names,
        )
        self.assertTrue(result.success)
        self.assertLessEqual(len(result.extracted_urls), MAX_EXTRACTED_EMAIL_URLS)
        self.assertLessEqual(len(result.attachments), MAX_EMAIL_ATTACHMENTS)
        self.assertEqual(len({item["url"] for item in result.extracted_urls}), len(result.extracted_urls))

    def test_duplicate_nested_url_is_analyzed_once(self):
        url = "https://example.invalid/login"
        result = analyze_email(sender="sender@example.com", body=f"{url} {url}")
        self.assertTrue(result.success)
        self.assertEqual(result.features.extracted_url_count, 1)
        self.assertEqual(len(result.extracted_urls), 1)

    def test_network_calls_are_blocked_for_normal_and_suspicious_inputs(self):
        with patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS called")), patch.object(
            socket, "gethostbyname", side_effect=AssertionError("DNS called")
        ), patch.object(socket, "socket", side_effect=AssertionError("socket called")), patch.object(
            urllib.request, "urlopen", side_effect=AssertionError("HTTP called")
        ):
            results = [
                analyze_url("https://example.com"),
                analyze_url("http://127.0.0.1:8080/login"),
                analyze_email(sender="sender@example.com", body="A normal message"),
                analyze_email(sender="sender@example.com", body="Click https://bit.ly/login now"),
            ]
        self.assertTrue(all(result.success for result in results))

    def test_analyzers_do_not_open_files_or_execute_processes(self):
        with patch("builtins.open", side_effect=AssertionError("file opened")) as open_mock, patch.object(
            os, "open", side_effect=AssertionError("file opened")
        ) as os_open_mock, patch.object(
            subprocess, "run", side_effect=AssertionError("process executed")
        ) as run_mock, patch.object(
            subprocess, "Popen", side_effect=AssertionError("process executed")
        ) as popen_mock, patch.object(
            os, "system", side_effect=AssertionError("process executed")
        ) as system_mock:
            url_result = analyze_url("https://example.com/report")
            email_result = analyze_email(
                sender="sender@example.com",
                body="Please review https://example.com/report",
                attachment_names="invoice.exe",
            )
        self.assertTrue(url_result.success)
        self.assertTrue(email_result.success)
        open_mock.assert_not_called()
        os_open_mock.assert_not_called()
        run_mock.assert_not_called()
        popen_mock.assert_not_called()
        system_mock.assert_not_called()

    def test_indicator_duplicates_do_not_double_count(self):
        indicator = IndicatorResult(
            code="CUSTOM_DUPLICATE",
            category="test",
            title="Duplicate test signal",
            severity="LOW",
            points=35,
            evidence="test",
            explanation="test",
            recommendation="test",
            sort_order=1,
        )
        result = evaluate_risk([indicator, indicator])
        self.assertTrue(result.success)
        self.assertEqual(result.score, 35)
        self.assertEqual(result.score_breakdown[0].occurrence_count, 2)

    def test_risk_thresholds_are_exact_at_all_boundaries(self):
        expected = {
            0: "VERY_LOW",
            1: "VERY_LOW",
            19: "VERY_LOW",
            20: "LOW",
            39: "LOW",
            40: "MEDIUM",
            59: "MEDIUM",
            60: "HIGH",
            79: "HIGH",
            80: "CRITICAL",
            99: "CRITICAL",
            100: "CRITICAL",
        }
        for score, level in expected.items():
            with self.subTest(score=score):
                indicator = IndicatorResult(
                    code=f"CUSTOM_SCORE_{score}",
                    category="test",
                    title="Boundary signal",
                    severity="LOW",
                    points=score,
                    evidence="test",
                    explanation="test",
                    recommendation="test",
                    sort_order=1,
                )
                result = evaluate_risk([indicator])
                self.assertEqual(result.score, score)
                self.assertEqual(result.risk_level, level)
                self.assertGreaterEqual(result.score, 0)
                self.assertLessEqual(result.score, 100)

    def test_long_indicator_evidence_is_bounded_by_analyzer_contract(self):
        result = analyze_email(
            sender="sender@example.com",
            body="password " + "x" * 10000,
        )
        self.assertTrue(result.success)
        self.assertTrue(all(len(indicator.evidence) <= 240 for indicator in result.indicators))
