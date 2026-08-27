from django.test import TestCase
from django.urls import reverse

from scans.models import Indicator, Scan, ScanStatus, ScanType


class PhaseSixViewTests(TestCase):
    def test_navigation_pages_render(self):
        for name in (
            "core:home",
            "core:about",
            "scans:url",
            "scans:email",
            "scans:result",
            "scans:history",
            "dashboard:index",
        ):
            response = self.client.get(reverse(name))
            self.assertEqual(response.status_code, 200, name)

    def test_valid_url_post_redirects_to_persisted_result(self):
        response = self.client.post(
            reverse("scans:url"),
            {"url": "https://example.com/account/verify"},
        )
        scan = Scan.objects.get()
        self.assertRedirects(response, reverse("scans:result-detail", kwargs={"scan_id": scan.pk}))
        self.assertEqual(scan.scan_type, ScanType.URL)
        self.assertEqual(scan.status, ScanStatus.COMPLETED)
        self.assertIsNotNone(scan.score)
        self.assertTrue(scan.url_scan.normalized_url)

    def test_valid_email_post_redirects_to_persisted_result(self):
        response = self.client.post(
            reverse("scans:email"),
            {
                "sender": "sender@example.com",
                "reply_to": "reply@example.com",
                "subject": "Please review",
                "body": "Message body",
                "attachment_names": "notice.pdf",
            },
        )
        scan = Scan.objects.get()
        self.assertRedirects(response, reverse("scans:result-detail", kwargs={"scan_id": scan.pk}))
        self.assertEqual(scan.scan_type, ScanType.EMAIL)
        self.assertEqual(scan.status, ScanStatus.COMPLETED)
        self.assertIsNotNone(scan.score)
        self.assertEqual(scan.email_scan.attachment_count, 1)

    def test_invalid_url_post_does_not_create_scan(self):
        response = self.client.post(reverse("scans:url"), {"url": "not a url"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Include a scheme and hostname")
        self.assertFalse(Scan.objects.exists())

    def test_empty_email_post_does_not_create_scan(self):
        response = self.client.post(reverse("scans:email"), {})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Enter at least one email field")
        self.assertFalse(Scan.objects.exists())

    def test_forms_include_csrf_protection(self):
        self.assertContains(self.client.get(reverse("scans:url")), "csrfmiddlewaretoken")
        self.assertContains(self.client.get(reverse("scans:email")), "csrfmiddlewaretoken")

    def test_get_does_not_create_a_scan(self):
        self.client.get(reverse("scans:url"))
        self.client.get(reverse("scans:email"))
        self.assertFalse(Scan.objects.exists())

    def test_result_page_renders_persisted_url_data(self):
        self.client.post(reverse("scans:url"), {"url": "http://192.0.2.10/login"})
        scan = Scan.objects.get()
        response = self.client.get(reverse("scans:result-detail", kwargs={"scan_id": scan.pk}))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, str(scan.score))
        self.assertContains(response, "IP address")
        self.assertEqual(Indicator.objects.filter(scan=scan).count(), scan.indicators.count())

    def test_result_get_does_not_rerun_analysis(self):
        self.client.post(reverse("scans:url"), {"url": "https://example.com"})
        scan = Scan.objects.get()
        original_score = scan.score
        original_count = scan.indicators.count()
        response = self.client.get(reverse("scans:result-detail", kwargs={"scan_id": scan.pk}))
        self.assertEqual(response.status_code, 200)
        scan.refresh_from_db()
        self.assertEqual(scan.score, original_score)
        self.assertEqual(scan.indicators.count(), original_count)

    def test_nonexistent_result_is_404(self):
        response = self.client.get(reverse("scans:result-detail", kwargs={"scan_id": 99999}))
        self.assertEqual(response.status_code, 404)

    def test_dashboard_remains_honest_phase_six_boundary(self):
        response = self.client.get(reverse("dashboard:index"))
        self.assertContains(response, "Total scans")
        self.assertContains(response, ">0<")
        self.assertContains(response, "No analyses recorded")
