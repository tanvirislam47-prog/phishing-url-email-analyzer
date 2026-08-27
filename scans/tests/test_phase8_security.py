from unittest.mock import patch

from django.db import IntegrityError, connection, transaction
from django.test import Client, TestCase
from django.test.utils import CaptureQueriesContext
from django.urls import reverse

from analysis.types import RiskAnalysisResult, URLAnalysisResult
from scans.models import EmailScan, Indicator, RiskLevel, Scan, ScanStatus, ScanType, URLScan
from scans.services import analyze_email_scan, analyze_url_scan, create_pending_scan


class PhaseEightSecurityViewTests(TestCase):
    def test_xss_payloads_are_escaped_in_url_email_and_indicator_output(self):
        url_scan = analyze_url_scan("https://example.com/<script>alert(1)</script>")
        email_scan = analyze_email_scan(
            sender="<script>alert(2)</script>",
            reply_to='<img src=x onerror=alert(3)>',
            subject="<script>alert(4)</script>",
            body="Review this message safely.",
        )
        Indicator.objects.create(
            scan=email_scan,
            code="CUSTOM_XSS_PHASE8",
            category="test",
            title="<script>alert(5)</script>",
            severity="LOW",
            points=1,
            evidence='<img src=x onerror=alert(6)>',
            explanation="<b>Untrusted explanation</b>",
            recommendation="Review safely",
            sort_order=999,
        )
        for scan_id, payload in (
            (url_scan.pk, "&lt;script&gt;alert(1)&lt;/script&gt;"),
            (email_scan.pk, "&lt;script&gt;alert(4)&lt;/script&gt;"),
        ):
            with self.subTest(scan_id=scan_id):
                response = self.client.get(reverse("scans:result-detail", kwargs={"scan_id": scan_id}))
                self.assertEqual(response.status_code, 200)
                self.assertNotContains(response, "<script>alert(")
                self.assertContains(response, payload)
        response = self.client.get(reverse("scans:result-detail", kwargs={"scan_id": email_scan.pk}))
        self.assertNotContains(response, "<img src=x onerror=alert")
        self.assertContains(response, "&lt;img src=x onerror=alert(6)&gt;")

    def test_failed_result_never_exposes_persisted_internal_error(self):
        scan = Scan.objects.create(
            scan_type=ScanType.URL,
            status=ScanStatus.FAILED,
            error_message="database password: super-secret /srv/app/private.py",
        )
        URLScan.objects.create(scan=scan, original_url="https://example.com")
        response = self.client.get(reverse("scans:result-detail", kwargs={"scan_id": scan.pk}))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "super-secret")
        self.assertNotContains(response, "/srv/app/private.py")
        self.assertContains(response, "No internal error details are available")

    def test_sql_injection_and_invalid_history_filters_are_safe(self):
        Scan.objects.create(scan_type=ScanType.URL, status=ScanStatus.COMPLETED, score=10, risk_level=RiskLevel.VERY_LOW)
        for query in ("'", '"', "' OR '1'='1", '" OR "1"="1', ";", "--"):
            with self.subTest(query=query):
                response = self.client.get(reverse("scans:history"), {"q": query})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.context["history_total"], 0)
        response = self.client.get(
            reverse("scans:history"),
            {"type": "DROP", "risk": "UNKNOWN", "status": "SELECT", "q": "<script>alert(1)</script>"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["history_total"], 0)
        self.assertNotContains(response, "<script>alert(1)</script>")
        self.assertContains(response, "&lt;script&gt;alert(1)&lt;/script&gt;")

    def test_result_id_and_path_variants_return_safe_404s(self):
        paths = [
            "/scans/result/0/",
            "/scans/result/-1/",
            "/scans/result/999999999999/",
            "/scans/result/not-a-number/",
            "/scans/result/1/extra/",
        ]
        branded_404_paths = {"/scans/result/0/", "/scans/result/999999999999/"}
        for path in paths:
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 404)
                self.assertNotContains(response, "Traceback", status_code=404)
                self.assertNotContains(response, "django.views", status_code=404)
                if path in branded_404_paths:
                    self.assertContains(response, "No database details were exposed", status_code=404)

    def test_analyzer_get_routes_are_read_only(self):
        self.client.get(reverse("scans:url"))
        self.client.get(reverse("scans:email"))
        self.client.get(reverse("scans:result"))
        self.client.get(reverse("scans:history"))
        self.client.get(reverse("dashboard:index"))
        self.assertFalse(Scan.objects.exists())

    def test_post_without_csrf_is_rejected(self):
        client = Client(enforce_csrf_checks=True)
        response = client.post(reverse("scans:url"), {"url": "https://example.com"})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(Scan.objects.exists())

    def test_security_headers_are_present(self):
        response = self.client.get(reverse("core:home"))
        self.assertEqual(response["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response["X-Frame-Options"], "DENY")
        self.assertEqual(response["Referrer-Policy"], "same-origin")
        self.assertNotContains(response, "fonts.googleapis.com")
        self.assertNotContains(response, "fonts.gstatic.com")

    def test_invalid_pagination_values_return_normal_responses(self):
        for index in range(31):
            Scan.objects.create(
                scan_type=ScanType.URL,
                status=ScanStatus.COMPLETED,
                score=index,
                risk_level=RiskLevel.LOW,
            )
        for page in ("abc", "-2", "0", "999999"):
            with self.subTest(page=page):
                response = self.client.get(reverse("scans:history"), {"page": page, "status": "completed"})
                self.assertEqual(response.status_code, 200)
                self.assertIn("Page", response.content.decode())
        response = self.client.get(reverse("scans:history"), {"page": 2, "status": "completed"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["page_obj"].number, 2)
        self.assertContains(response, "status=completed&amp;page=1")


class PhaseEightWorkflowIntegrityTests(TestCase):
    def test_email_detail_creation_failure_leaves_no_orphan_and_marks_scan_failed(self):
        with patch("scans.services.EmailScan.objects.create", side_effect=RuntimeError("write failed")):
            scan = analyze_email_scan(sender="sender@example.com", body="Message")
        self.assertEqual(scan.status, ScanStatus.FAILED)
        self.assertFalse(EmailScan.objects.filter(scan=scan).exists())
        self.assertEqual(Scan.objects.count(), 1)
        self.assertEqual(scan.error_message, "The local analysis could not be completed. Please review the submitted content and try again.")

    def test_risk_engine_failure_persists_consistent_failed_state(self):
        failed_result = RiskAnalysisResult(
            success=False,
            score=None,
            risk_level="",
            verdict="",
            error="internal risk details",
            rule_version="risk-v1",
        )
        with patch("scans.services.evaluate_risk", return_value=failed_result):
            scan = analyze_url_scan("https://example.com/login")
        self.assertEqual(scan.status, ScanStatus.FAILED)
        self.assertIsNone(scan.score)
        self.assertEqual(scan.risk_level, "")
        self.assertEqual(scan.verdict, "")
        self.assertTrue(URLScan.objects.filter(scan=scan).exists())
        self.assertFalse(Indicator.objects.filter(scan=scan).exists())
        self.assertNotIn("internal risk details", scan.error_message)

    def test_indicator_persistence_failure_rolls_back_email_detail(self):
        with patch("scans.services.Indicator.objects.bulk_create", side_effect=RuntimeError("write failed")):
            scan = analyze_email_scan(sender="sender@example.com", body="Review this message")
        self.assertEqual(scan.status, ScanStatus.FAILED)
        self.assertFalse(EmailScan.objects.filter(scan=scan).exists())
        self.assertFalse(Indicator.objects.filter(scan=scan).exists())
        self.assertEqual(Scan.objects.count(), 1)

    def test_score_database_constraint_rejects_out_of_range_values(self):
        for score in (-1, 101):
            with self.subTest(score=score):
                with self.assertRaises(IntegrityError):
                    with transaction.atomic():
                        Scan.objects.create(
                            scan_type=ScanType.URL,
                            status=ScanStatus.COMPLETED,
                            score=score,
                            risk_level=RiskLevel.LOW,
                        )
        self.assertFalse(Scan.objects.exists())

    def test_service_scores_remain_within_persisted_bounds(self):
        scans = [
            analyze_url_scan("https://example.com"),
            analyze_url_scan("http://127.0.0.1:8080/login"),
            analyze_email_scan(sender="sender@example.com", body="Please verify your account immediately."),
        ]
        for scan in scans:
            with self.subTest(scan=scan.pk):
                self.assertEqual(scan.status, ScanStatus.COMPLETED)
                self.assertGreaterEqual(scan.score, 0)
                self.assertLessEqual(scan.score, 100)
                self.assertIn(scan.risk_level, {level.value for level in RiskLevel})

    def test_runtime_network_safety_is_preserved_through_workflows(self):
        import socket
        import urllib.request

        with patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS called")), patch.object(
            socket, "gethostbyname", side_effect=AssertionError("DNS called")
        ), patch.object(socket, "socket", side_effect=AssertionError("socket called")), patch.object(
            urllib.request, "urlopen", side_effect=AssertionError("HTTP called")
        ):
            url_scan = analyze_url_scan("http://192.0.2.10/login")
            email_scan = analyze_email_scan(
                sender="sender@example.com",
                body="Click https://bit.ly/login now",
                attachment_names="invoice.exe",
            )
        self.assertEqual(url_scan.status, ScanStatus.COMPLETED)
        self.assertEqual(email_scan.status, ScanStatus.COMPLETED)

    def test_workflow_uses_bounded_database_queries_for_result_reads(self):
        scan = analyze_email_scan(sender="sender@example.com", body="A normal message")
        with CaptureQueriesContext(connection) as queries:
            response = self.client.get(reverse("scans:result-detail", kwargs={"scan_id": scan.pk}))
        self.assertEqual(response.status_code, 200)
        self.assertLessEqual(len(queries), 8)

    def test_persist_scan_result_rejects_failed_risk_result(self):
        scan = create_pending_scan(ScanType.URL)
        failed_result = RiskAnalysisResult(success=False, score=None, risk_level="", verdict="")
        with self.assertRaises(ValueError):
            from scans.services import persist_scan_result

            persist_scan_result(scan, failed_result, duration_ms=1)
        scan.refresh_from_db()
        self.assertEqual(scan.status, ScanStatus.PENDING)
