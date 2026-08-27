import socket
import urllib.request
from unittest.mock import patch

from django.test import Client, TestCase
from django.urls import reverse

from analysis.email_analyzer import analyze_email
from analysis.risk_engine import evaluate_risk
from analysis.types import URLAnalysisResult
from analysis.url_analyzer import analyze_url
from scans.models import EmailScan, Indicator, Scan, ScanStatus, ScanType, URLScan
from scans.services import analyze_email_scan, analyze_url_scan


class PhaseSixWorkflowServiceTests(TestCase):
    def test_url_submission_creates_scan_and_urlscan(self):
        scan = analyze_url_scan("https://example.com/account/verify")
        self.assertEqual(Scan.objects.count(), 1)
        self.assertEqual(URLScan.objects.count(), 1)
        self.assertEqual(scan.scan_type, ScanType.URL)
        self.assertEqual(scan.status, ScanStatus.COMPLETED)
        self.assertEqual(scan.url_scan.scan, scan)

    def test_url_analyzer_and_risk_engine_are_called(self):
        with patch("scans.services.analyze_url", wraps=analyze_url) as url_mock, patch(
            "scans.services.evaluate_risk", wraps=evaluate_risk
        ) as risk_mock:
            scan = analyze_url_scan("http://192.0.2.10/login")
        url_mock.assert_called_once_with("http://192.0.2.10/login")
        risk_mock.assert_called_once()
        self.assertEqual(scan.status, ScanStatus.COMPLETED)

    def test_url_result_fields_are_persisted_from_risk_engine(self):
        scan = analyze_url_scan("http://192.0.2.10/login")
        self.assertIsNotNone(scan.score)
        self.assertEqual(scan.risk_level, "MEDIUM")
        self.assertIn("Potentially suspicious", scan.verdict)
        self.assertGreaterEqual(scan.analysis_duration_ms, 0)
        self.assertEqual(Indicator.objects.filter(scan=scan).count(), len(scan.indicators.all()))
        self.assertTrue(scan.input_hash)

    def test_url_input_hash_is_based_on_normalized_input(self):
        scan = analyze_url_scan("  HTTPS://EXAMPLE.COM/path  ")
        self.assertEqual(len(scan.input_hash), 64)
        self.assertEqual(scan.url_scan.original_url, "HTTPS://EXAMPLE.COM/path")
        self.assertEqual(scan.input_hash, __import__("hashlib").sha256(scan.url_scan.normalized_url.encode()).hexdigest())

    def test_email_submission_creates_scan_and_emailscan(self):
        scan = analyze_email_scan(
            sender="sender@example.com",
            reply_to="sender@example.com",
            subject="Monthly notice",
            body="Your monthly report is ready.",
            attachment_names="report.pdf",
        )
        self.assertEqual(Scan.objects.count(), 1)
        self.assertEqual(EmailScan.objects.count(), 1)
        self.assertEqual(scan.scan_type, ScanType.EMAIL)
        self.assertEqual(scan.status, ScanStatus.COMPLETED)
        self.assertEqual(scan.email_scan.attachment_count, 1)
        self.assertEqual(scan.email_scan.extracted_url_count, 0)

    def test_email_analyzer_and_nested_url_analysis_are_reused(self):
        with patch("scans.services.analyze_email", wraps=analyze_email) as email_mock, patch(
            "scans.services.evaluate_risk", wraps=evaluate_risk
        ) as risk_mock:
            scan = analyze_email_scan(
                sender="sender@example.com",
                subject="Verify",
                body="Open http://192.0.2.10/login",
            )
        email_mock.assert_called_once()
        risk_mock.assert_called_once()
        self.assertEqual(scan.email_scan.extracted_url_count, 1)
        self.assertTrue(Indicator.objects.filter(scan=scan, code="URL_IP_ADDRESS").exists())
        self.assertTrue(Indicator.objects.filter(scan=scan, code="EMAIL_CONTAINS_SUSPICIOUS_URL").exists())

    def test_email_result_fields_and_indicators_are_persisted(self):
        scan = analyze_email_scan(
            sender="security@example.com",
            reply_to="help@different.example",
            subject="Urgent action required",
            body="Act now and enter your password and OTP.",
            attachment_names="invoice.exe",
        )
        self.assertEqual(scan.status, ScanStatus.COMPLETED)
        self.assertEqual(scan.rule_version, "risk-v1")
        self.assertGreaterEqual(scan.analysis_duration_ms, 0)
        codes = set(scan.indicators.values_list("code", flat=True))
        self.assertIn("EMAIL_REPLY_TO_MISMATCH", codes)
        self.assertIn("EMAIL_PASSWORD_REQUEST", codes)
        self.assertIn("EMAIL_OTP_REQUEST", codes)
        self.assertIn("EMAIL_RISKY_ATTACHMENT", codes)

    def test_analyzer_failure_creates_failed_url_scan(self):
        failed = URLAnalysisResult(
            success=False,
            original_url="https://example.com",
            normalized_url="https://example.com",
            features=None,
            error="Malformed URL",
            analysis_metadata={"network_access": False},
        )
        with patch("scans.services.analyze_url", return_value=failed):
            scan = analyze_url_scan("https://example.com")
        self.assertEqual(scan.status, ScanStatus.FAILED)
        self.assertIsNone(scan.score)
        self.assertEqual(scan.risk_level, "")
        self.assertEqual(scan.verdict, "")
        self.assertTrue(scan.error_message)
        self.assertTrue(URLScan.objects.filter(scan=scan).exists())

    def test_unexpected_exception_creates_failed_email_scan_without_traceback(self):
        with patch("scans.services.analyze_email", side_effect=RuntimeError("database password: secret")):
            scan = analyze_email_scan(sender="sender@example.com", body="Body")
        self.assertEqual(scan.status, ScanStatus.FAILED)
        self.assertEqual(scan.score, None)
        self.assertNotIn("database password", scan.error_message)
        self.assertNotIn("secret", scan.error_message)
        self.assertFalse(EmailScan.objects.filter(scan=scan).exists())

    def test_indicator_database_failure_rolls_back_detail_records_and_marks_scan_failed(self):
        with patch("scans.services.Indicator.objects.bulk_create", side_effect=RuntimeError("write failed")):
            scan = analyze_url_scan("https://example.com")
        self.assertEqual(scan.status, ScanStatus.FAILED)
        self.assertFalse(URLScan.objects.filter(scan=scan).exists())
        self.assertFalse(Indicator.objects.filter(scan=scan).exists())
        self.assertEqual(Scan.objects.count(), 1)

    def test_workflow_has_no_network_access(self):
        with patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS called")), patch.object(
            socket, "gethostbyname", side_effect=AssertionError("DNS called")
        ), patch.object(socket, "socket", side_effect=AssertionError("socket called")), patch.object(
            urllib.request, "urlopen", side_effect=AssertionError("HTTP called")
        ):
            url_scan = analyze_url_scan("http://192.0.2.10/login")
            email_scan = analyze_email_scan(
                sender="sender@example.com",
                body="Please review http://192.0.2.10/login",
            )
        self.assertEqual(url_scan.status, ScanStatus.COMPLETED)
        self.assertEqual(email_scan.status, ScanStatus.COMPLETED)


class PhaseSixWorkflowViewTests(TestCase):
    def test_valid_url_post_redirects_to_result(self):
        response = self.client.post(reverse("scans:url"), {"url": "https://example.com"})
        scan = Scan.objects.get()
        self.assertRedirects(response, reverse("scans:result-detail", kwargs={"scan_id": scan.pk}))

    def test_valid_email_post_redirects_to_result(self):
        response = self.client.post(
            reverse("scans:email"),
            {"sender": "sender@example.com", "body": "A normal message."},
        )
        scan = Scan.objects.get()
        self.assertRedirects(response, reverse("scans:result-detail", kwargs={"scan_id": scan.pk}))

    def test_post_requires_csrf(self):
        client = Client(enforce_csrf_checks=True)
        response = client.post(reverse("scans:url"), {"url": "https://example.com"})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(Scan.objects.exists())

    def test_get_result_does_not_call_analyzer(self):
        self.client.post(reverse("scans:url"), {"url": "https://example.com"})
        scan = Scan.objects.get()
        with patch("scans.views.analyze_url_scan", side_effect=AssertionError("analysis rerun")):
            response = self.client.get(reverse("scans:result-detail", kwargs={"scan_id": scan.pk}))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, str(scan.score))

    def test_result_page_escapes_persisted_evidence(self):
        scan = analyze_email_scan(sender="sender@example.com", body="Message")
        Indicator.objects.create(
            scan=scan,
            code="CUSTOM_XSS",
            category="test",
            title="<script>alert(1)</script>",
            severity="LOW",
            points=1,
            evidence="<script>alert(2)</script>",
            explanation="<b>not trusted</b>",
            recommendation="Review safely",
            sort_order=999,
        )
        response = self.client.get(reverse("scans:result-detail", kwargs={"scan_id": scan.pk}))
        self.assertNotContains(response, "<script>alert(1)</script>")
        self.assertContains(response, "&lt;script&gt;alert(1)&lt;/script&gt;")
