from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.urls import reverse

from scans.models import RiskLevel, Scan, ScanStatus, ScanType, URLScan, EmailScan


class DashboardViewTests(TestCase):
    def test_zero_state_dashboard_is_honest_and_safe(self):
        response = self.client.get(reverse("dashboard:index"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Total scans")
        self.assertContains(response, ">0<")
        self.assertContains(response, "Nothing to review yet.")
        self.assertContains(response, "Score statistics will appear after the first completed analysis.")

    def test_dashboard_aggregates_real_scan_counts(self):
        Scan.objects.create(scan_type=ScanType.URL, status=ScanStatus.COMPLETED, score=10, risk_level=RiskLevel.VERY_LOW)
        Scan.objects.create(scan_type=ScanType.URL, status=ScanStatus.FAILED)
        Scan.objects.create(scan_type=ScanType.EMAIL, status=ScanStatus.COMPLETED, score=85, risk_level=RiskLevel.CRITICAL)
        response = self.client.get(reverse("dashboard:index"))
        self.assertEqual(response.context["aggregate"]["total"], 3)
        self.assertEqual(response.context["aggregate"]["url"], 2)
        self.assertEqual(response.context["aggregate"]["email"], 1)
        self.assertEqual(response.context["aggregate"]["completed"], 2)
        self.assertEqual(response.context["aggregate"]["failed"], 1)
        self.assertContains(response, ">3<")
        self.assertContains(response, ">2<")
        self.assertContains(response, ">1<")

    def test_dashboard_calculates_real_score_statistics(self):
        Scan.objects.create(scan_type=ScanType.URL, status=ScanStatus.COMPLETED, score=20, risk_level=RiskLevel.LOW)
        Scan.objects.create(scan_type=ScanType.URL, status=ScanStatus.COMPLETED, score=60, risk_level=RiskLevel.HIGH)
        Scan.objects.create(scan_type=ScanType.EMAIL, status=ScanStatus.COMPLETED, score=40, risk_level=RiskLevel.MEDIUM)
        response = self.client.get(reverse("dashboard:index"))
        self.assertEqual(response.context["score_stats"]["average"], 40)
        self.assertEqual(response.context["score_stats"]["highest"], 60)
        self.assertEqual(response.context["score_stats"]["lowest"], 20)
        self.assertContains(response, ">40<")
        self.assertContains(response, ">60<")
        self.assertContains(response, ">20<")

    def test_dashboard_risk_distribution_matches_database(self):
        Scan.objects.create(scan_type=ScanType.URL, status=ScanStatus.COMPLETED, score=10, risk_level=RiskLevel.VERY_LOW)
        Scan.objects.create(scan_type=ScanType.URL, status=ScanStatus.COMPLETED, score=15, risk_level=RiskLevel.VERY_LOW)
        Scan.objects.create(scan_type=ScanType.EMAIL, status=ScanStatus.COMPLETED, score=95, risk_level=RiskLevel.CRITICAL)
        response = self.client.get(reverse("dashboard:index"))
        dist = {item["key"]: item["count"] for item in response.context["risk_distribution"]}
        self.assertEqual(dist[RiskLevel.VERY_LOW], 2)
        self.assertEqual(dist[RiskLevel.CRITICAL], 1)
        self.assertEqual(dist[RiskLevel.MEDIUM], 0)

    def test_dashboard_recent_activity_shows_latest_scans(self):
        for i in range(10):
            Scan.objects.create(scan_type=ScanType.URL, status=ScanStatus.COMPLETED, score=i, risk_level=RiskLevel.LOW)
        response = self.client.get(reverse("dashboard:index"))
        self.assertEqual(len(response.context["recent_scans"]), 8)
        self.assertEqual(response.context["recent_scans"][0].score, 9)

    def test_dashboard_metric_links_to_filtered_history(self):
        response = self.client.get(reverse("dashboard:index"))
        self.assertContains(response, reverse("scans:history") + "?type=url")
        self.assertContains(response, reverse("scans:history") + "?status=failed")
        self.assertContains(response, reverse("scans:history") + "?risk=high")
        self.assertContains(response, reverse("scans:history") + "?risk=critical")
        metric_by_label = {metric["label"]: metric for metric in response.context["metrics"]}
        self.assertEqual(metric_by_label["Safe / low"]["query"], "")
        self.assertEqual(metric_by_label["High risk"]["query"], "?risk=high")
        self.assertEqual(metric_by_label["Critical risk"]["query"], "?risk=critical")

    def test_dashboard_uses_bounded_aggregate_queries(self):
        for index in range(20):
            Scan.objects.create(scan_type=ScanType.URL, status=ScanStatus.COMPLETED, score=index, risk_level=RiskLevel.LOW)
        with CaptureQueriesContext(connection) as queries:
            response = self.client.get(reverse("dashboard:index"))
        self.assertEqual(response.status_code, 200)
        self.assertLessEqual(len(queries), 5)

    def test_dashboard_get_does_not_create_scans(self):
        self.client.get(reverse("dashboard:index"))
        self.assertFalse(Scan.objects.exists())
