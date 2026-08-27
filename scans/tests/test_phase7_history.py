from datetime import timedelta

from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils import timezone

from scans.models import RiskLevel, Scan, ScanStatus, ScanType, URLScan, EmailScan


class HistoryFixtureMixin:
    def make_url_scan(self, *, score=20, risk=RiskLevel.LOW, status=ScanStatus.COMPLETED, hostname="example.com", verdict="Review the context"):
        scan = Scan.objects.create(
            scan_type=ScanType.URL,
            status=status,
            score=score if status == ScanStatus.COMPLETED else None,
            risk_level=risk if status == ScanStatus.COMPLETED else "",
            verdict=verdict if status == ScanStatus.COMPLETED else "",
            error_message="internal database path should never render" if status == ScanStatus.FAILED else "",
        )
        URLScan.objects.create(scan=scan, original_url=f"https://{hostname}/path", normalized_url=f"https://{hostname}/path", scheme="https", hostname=hostname, path="/path")
        return scan

    def make_email_scan(self, *, score=45, risk=RiskLevel.MEDIUM, status=ScanStatus.COMPLETED, sender="sender@example.com", subject="Review notice"):
        scan = Scan.objects.create(
            scan_type=ScanType.EMAIL,
            status=status,
            score=score if status == ScanStatus.COMPLETED else None,
            risk_level=risk if status == ScanStatus.COMPLETED else "",
            verdict="Review the context" if status == ScanStatus.COMPLETED else "",
            error_message="internal email exception should never render" if status == ScanStatus.FAILED else "",
        )
        EmailScan.objects.create(scan=scan, sender=sender, sender_domain=sender.split("@")[-1], subject=subject)
        return scan


class HistoryViewTests(HistoryFixtureMixin, TestCase):
    def test_empty_history_is_honest_and_actionable(self):
        response = self.client.get(reverse("scans:history"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "No scans yet.")
        self.assertContains(response, "Run a URL or email analysis")
        self.assertContains(response, "Analyze a URL")
        self.assertContains(response, "Analyze an email")

    def test_history_orders_newest_first(self):
        older = self.make_url_scan(hostname="older.example")
        newer = self.make_email_scan(sender="newer@example.com")
        older.created_at = timezone.now() - timedelta(days=1)
        older.save(update_fields=["created_at"])
        newer.created_at = timezone.now()
        newer.save(update_fields=["created_at"])
        response = self.client.get(reverse("scans:history"))
        self.assertEqual(response.context["page_obj"].object_list[0].pk, newer.pk)
        self.assertLess(response.content.find(f"#{newer.pk}".encode()), response.content.find(f"#{older.pk}".encode()))

    def test_url_and_email_filters(self):
        url_scan = self.make_url_scan()
        email_scan = self.make_email_scan()
        url_response = self.client.get(reverse("scans:history"), {"type": "url"})
        email_response = self.client.get(reverse("scans:history"), {"type": "email"})
        self.assertEqual(list(url_response.context["page_obj"].object_list), [url_scan])
        self.assertEqual(list(email_response.context["page_obj"].object_list), [email_scan])

    def test_risk_and_status_filters(self):
        low = self.make_url_scan(risk=RiskLevel.LOW)
        critical = self.make_url_scan(score=90, risk=RiskLevel.CRITICAL)
        failed = self.make_email_scan(status=ScanStatus.FAILED)
        risk_response = self.client.get(reverse("scans:history"), {"risk": "critical"})
        status_response = self.client.get(reverse("scans:history"), {"status": "failed"})
        self.assertEqual(list(risk_response.context["page_obj"].object_list), [critical])
        self.assertEqual(list(status_response.context["page_obj"].object_list), [failed])
        self.assertNotIn(low.pk, [scan.pk for scan in risk_response.context["page_obj"].object_list])

    def test_search_matches_scan_id_hostname_sender_and_subject(self):
        url_scan = self.make_url_scan(hostname="billing.example.test")
        email_scan = self.make_email_scan(sender="alerts@payments.example", subject="Invoice verification")
        self.assertEqual(self.client.get(reverse("scans:history"), {"q": str(url_scan.pk)}).context["history_total"], 1)
        self.assertEqual(self.client.get(reverse("scans:history"), {"q": "billing.example"}).context["history_total"], 1)
        self.assertEqual(self.client.get(reverse("scans:history"), {"q": "alerts@payments"}).context["history_total"], 1)
        self.assertEqual(self.client.get(reverse("scans:history"), {"q": "Invoice verification"}).context["history_total"], 1)

    def test_pagination_and_filter_preservation(self):
        for index in range(31):
            self.make_url_scan(hostname=f"host{index}.example")
        response = self.client.get(reverse("scans:history"), {"type": "url", "risk": "low"})
        self.assertEqual(response.context["page_obj"].paginator.per_page, 15)
        self.assertEqual(response.context["page_obj"].paginator.num_pages, 3)
        self.assertContains(response, "Page 1 of 3")
        self.assertContains(response, "type=url&amp;risk=low&amp;page=2")
        next_response = self.client.get(reverse("scans:history"), {"type": "url", "risk": "low", "page": 2})
        self.assertEqual(next_response.context["page_obj"].number, 2)
        self.assertContains(next_response, "type=url&amp;risk=low&amp;page=3")

    def test_result_action_uses_existing_stable_result_route(self):
        scan = self.make_url_scan()
        response = self.client.get(reverse("scans:history"))
        self.assertContains(response, reverse("scans:result-detail", kwargs={"scan_id": scan.pk}))
        self.assertContains(response, "View result")

    def test_failed_scans_are_visible_without_internal_error(self):
        failed = self.make_email_scan(status=ScanStatus.FAILED)
        response = self.client.get(reverse("scans:history"))
        self.assertContains(response, f"#{failed.pk}")
        self.assertContains(response, "Failed")
        self.assertContains(response, "Analysis unavailable")
        self.assertNotContains(response, "internal email exception")

    def test_history_get_does_not_create_scans(self):
        self.client.get(reverse("scans:history"), {"type": "url", "risk": "critical", "status": "failed", "q": "example"})
        self.assertFalse(Scan.objects.exists())

    def test_history_uses_bounded_query_count(self):
        for index in range(5):
            self.make_url_scan(hostname=f"host{index}.example")
            self.make_email_scan(sender=f"sender{index}@example.com")
        with CaptureQueriesContext(connection) as queries:
            response = self.client.get(reverse("scans:history"))
        self.assertEqual(response.status_code, 200)
        self.assertLessEqual(len(queries), 3)
