from datetime import timedelta

from django.contrib import admin
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone

from scans.models import (
    EmailScan,
    Indicator,
    IndicatorSeverity,
    RiskLevel,
    Scan,
    ScanStatus,
    ScanType,
    URLScan,
)
from scans.services import create_pending_scan


class ScanModelTests(TestCase):
    def test_scan_creation(self):
        scan = Scan.objects.create(scan_type=ScanType.URL)
        self.assertEqual(scan.scan_type, ScanType.URL)
        self.assertEqual(scan.status, ScanStatus.PENDING)
        self.assertEqual(scan.rule_version, "v1")
        self.assertIsNone(scan.score)

    def test_pending_scan_service_creates_only_persistence_record(self):
        scan = create_pending_scan(ScanType.EMAIL, input_hash="a" * 64)
        self.assertEqual(scan.status, ScanStatus.PENDING)
        self.assertEqual(scan.input_hash, "a" * 64)
        self.assertIsNone(scan.score)
        self.assertEqual(EmailScan.objects.count(), 0)

    def test_url_scan_relationship(self):
        scan = Scan.objects.create(scan_type=ScanType.URL)
        url_scan = URLScan.objects.create(
            scan=scan,
            original_url="https://example.com/path",
            normalized_url="https://example.com/path",
            scheme="https",
            hostname="example.com",
            path="/path",
        )
        self.assertIs(scan.url_scan, url_scan)
        self.assertIs(url_scan.scan, scan)

    def test_email_scan_relationship(self):
        scan = Scan.objects.create(scan_type=ScanType.EMAIL)
        email_scan = EmailScan.objects.create(
            scan=scan,
            sender="sender@example.com",
            sender_domain="example.com",
            subject="Notice",
        )
        self.assertIs(scan.email_scan, email_scan)
        self.assertIs(email_scan.scan, scan)

    def test_indicator_relationship(self):
        scan = Scan.objects.create(scan_type=ScanType.URL)
        indicator = Indicator.objects.create(
            scan=scan,
            code="URL_IP_HOSTNAME",
            category="hostname",
            title="IP address hostname",
            severity=IndicatorSeverity.MEDIUM,
            explanation="The hostname is represented as an IP address.",
        )
        self.assertIn(indicator, scan.indicators.all())
        self.assertIs(indicator.scan, scan)

    def test_valid_score(self):
        scan = Scan(scan_type=ScanType.URL, score=100)
        scan.full_clean()
        scan.save()
        self.assertEqual(scan.score, 100)

    def test_invalid_score_is_rejected_by_validation_and_database(self):
        invalid_scan = Scan(scan_type=ScanType.URL, score=101)
        with self.assertRaises(ValidationError):
            invalid_scan.full_clean()
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                Scan.objects.create(scan_type=ScanType.URL, score=101)

    def test_scan_type_choices(self):
        scan = Scan(scan_type="OTHER")
        with self.assertRaises(ValidationError):
            scan.full_clean()

    def test_status_choices(self):
        scan = Scan(scan_type=ScanType.URL, status="OTHER")
        with self.assertRaises(ValidationError):
            scan.full_clean()

    def test_risk_level_choices(self):
        scan = Scan(scan_type=ScanType.URL, risk_level="OTHER")
        with self.assertRaises(ValidationError):
            scan.full_clean()

    def test_indicator_severity_choices(self):
        scan = Scan.objects.create(scan_type=ScanType.URL)
        indicator = Indicator(
            scan=scan,
            code="TEST",
            category="test",
            title="Test signal",
            severity="OTHER",
            explanation="Test explanation.",
        )
        with self.assertRaises(ValidationError):
            indicator.full_clean()

    def test_timestamps_are_recorded(self):
        before = timezone.now() - timedelta(seconds=1)
        scan = Scan.objects.create(scan_type=ScanType.URL)
        after = timezone.now() + timedelta(seconds=1)
        self.assertGreaterEqual(scan.created_at, before)
        self.assertLessEqual(scan.created_at, after)
        self.assertIsNotNone(scan.updated_at)

    def test_indicator_ordering(self):
        scan = Scan.objects.create(scan_type=ScanType.URL)
        later = Indicator.objects.create(
            scan=scan,
            code="SECOND",
            category="test",
            title="Second",
            severity=IndicatorSeverity.LOW,
            explanation="Second indicator.",
            sort_order=20,
        )
        first = Indicator.objects.create(
            scan=scan,
            code="FIRST",
            category="test",
            title="First",
            severity=IndicatorSeverity.HIGH,
            explanation="First indicator.",
            sort_order=10,
        )
        self.assertEqual(list(scan.indicators.all()), [first, later])

    def test_nullable_optional_fields(self):
        url_scan = URLScan.objects.create(
            scan=Scan.objects.create(scan_type=ScanType.URL),
            original_url="https://example.com",
        )
        email_scan = EmailScan.objects.create(
            scan=Scan.objects.create(scan_type=ScanType.EMAIL)
        )
        self.assertIsNone(url_scan.port)
        self.assertEqual(email_scan.raw_email, "")
        self.assertEqual(email_scan.attachment_names, "")

    def test_multiple_indicators_can_be_stored(self):
        scan = Scan.objects.create(scan_type=ScanType.EMAIL)
        for number in range(3):
            Indicator.objects.create(
                scan=scan,
                code=f"SIGNAL_{number}",
                category="social_engineering",
                title=f"Signal {number}",
                severity=IndicatorSeverity.MEDIUM,
                points=number + 1,
                explanation="Stored for later rendering.",
            )
        self.assertEqual(scan.indicators.count(), 3)

    def test_database_constraints_reject_invalid_scan_type(self):
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                Scan.objects.create(scan_type="OTHER")

    def test_string_representations(self):
        scan = Scan.objects.create(scan_type=ScanType.URL)
        url_scan = URLScan.objects.create(scan=scan, original_url="https://example.com")
        email_scan = EmailScan.objects.create(scan=Scan.objects.create(scan_type=ScanType.EMAIL))
        indicator = Indicator.objects.create(
            scan=scan,
            code="URL_TEST",
            category="test",
            title="Test indicator",
            severity=IndicatorSeverity.INFORMATIONAL,
            explanation="Test explanation.",
        )
        self.assertEqual(str(scan), "URL scan #1")
        self.assertIn("URL details for", str(url_scan))
        self.assertIn("Email details for", str(email_scan))
        self.assertEqual(str(indicator), "URL_TEST: Test indicator")

    def test_historical_scan_loads_from_database_without_analysis(self):
        scan = Scan.objects.create(
            scan_type=ScanType.URL,
            status=ScanStatus.COMPLETED,
            score=42,
            risk_level=RiskLevel.MEDIUM,
            verdict="Historical result",
            rule_version="v1",
        )
        URLScan.objects.create(scan=scan, original_url="https://example.com/archive")
        Indicator.objects.create(
            scan=scan,
            code="HISTORICAL_SIGNAL",
            category="test",
            title="Persisted signal",
            severity=IndicatorSeverity.LOW,
            explanation="Persisted explanation.",
            recommendation="Persisted recommendation.",
        )

        loaded = Scan.objects.get(pk=scan.pk)
        self.assertEqual(loaded.score, 42)
        self.assertEqual(loaded.url_scan.original_url, "https://example.com/archive")
        self.assertEqual(loaded.indicators.get().code, "HISTORICAL_SIGNAL")


class AdminRegistrationTests(TestCase):
    def test_phase_two_models_are_registered(self):
        for model in (Scan, URLScan, EmailScan, Indicator):
            self.assertIn(model, admin.site._registry)
