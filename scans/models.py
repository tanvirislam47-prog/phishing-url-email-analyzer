"""Persistence models for URL and email scan results.

The models in this module store submitted values and future analysis output.
They contain no network access, analyzer calls, or save hooks that inspect
submitted URLs.
"""

from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.db.models import Q


class ScanType(models.TextChoices):
    URL = "URL", "URL"
    EMAIL = "EMAIL", "Email"


class ScanStatus(models.TextChoices):
    PENDING = "PENDING", "Pending"
    COMPLETED = "COMPLETED", "Completed"
    FAILED = "FAILED", "Failed"


class RiskLevel(models.TextChoices):
    VERY_LOW = "VERY_LOW", "Very Low"
    LOW = "LOW", "Low"
    MEDIUM = "MEDIUM", "Medium"
    HIGH = "HIGH", "High"
    CRITICAL = "CRITICAL", "Critical"


class IndicatorSeverity(models.TextChoices):
    INFORMATIONAL = "INFORMATIONAL", "Informational"
    LOW = "LOW", "Low"
    MEDIUM = "MEDIUM", "Medium"
    HIGH = "HIGH", "High"
    CRITICAL = "CRITICAL", "Critical"


class Scan(models.Model):
    """Common metadata and persisted result summary for one scan."""

    scan_type = models.CharField(max_length=10, choices=ScanType.choices, db_index=True)
    status = models.CharField(
        max_length=12,
        choices=ScanStatus.choices,
        default=ScanStatus.PENDING,
        db_index=True,
    )
    score = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
    )
    risk_level = models.CharField(
        max_length=12,
        choices=RiskLevel.choices,
        blank=True,
        default="",
        db_index=True,
    )
    verdict = models.CharField(max_length=500, blank=True, default="")
    rule_version = models.CharField(max_length=32, default="v1")
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)
    input_hash = models.CharField(max_length=64, blank=True, default="", db_index=True)
    analysis_duration_ms = models.PositiveIntegerField(null=True, blank=True)
    error_message = models.TextField(blank=True, default="")

    class Meta:
        ordering = ["-created_at", "-pk"]
        constraints = [
            models.CheckConstraint(
                condition=Q(scan_type__in=[choice.value for choice in ScanType]),
                name="scan_type_valid",
            ),
            models.CheckConstraint(
                condition=Q(status__in=[choice.value for choice in ScanStatus]),
                name="scan_status_valid",
            ),
            models.CheckConstraint(
                condition=Q(risk_level="")
                | Q(risk_level__in=[choice.value for choice in RiskLevel]),
                name="scan_risk_level_valid_or_empty",
            ),
            models.CheckConstraint(
                condition=Q(score__isnull=True)
                | (Q(score__gte=0) & Q(score__lte=100)),
                name="scan_score_0_100_or_null",
            ),
        ]

    def __str__(self):
        identifier = self.pk or "unsaved"
        return f"{self.get_scan_type_display()} scan #{identifier}"


class URLScan(models.Model):
    """URL input and parsed components stored as data, never fetched."""

    scan = models.OneToOneField(Scan, on_delete=models.CASCADE, related_name="url_scan")
    original_url = models.CharField(max_length=2048)
    normalized_url = models.CharField(max_length=2048, blank=True, default="")
    scheme = models.CharField(max_length=32, blank=True, default="")
    hostname = models.CharField(max_length=253, blank=True, default="")
    port = models.PositiveIntegerField(null=True, blank=True)
    path = models.CharField(max_length=2048, blank=True, default="")
    query = models.TextField(max_length=4096, blank=True, default="")
    fragment = models.TextField(max_length=2048, blank=True, default="")

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=Q(port__isnull=True)
                | (Q(port__gte=1) & Q(port__lte=65535)),
                name="url_scan_port_valid_or_null",
            )
        ]

    def __str__(self):
        return f"URL details for {self.scan}"


class EmailScan(models.Model):
    """Structured email input stored with bounded text-only fields."""

    scan = models.OneToOneField(Scan, on_delete=models.CASCADE, related_name="email_scan")
    sender = models.CharField(max_length=320, blank=True, default="")
    sender_domain = models.CharField(max_length=253, blank=True, default="")
    reply_to = models.CharField(max_length=320, blank=True, default="")
    subject = models.CharField(max_length=500, blank=True, default="")
    body = models.TextField(max_length=30000, blank=True, default="")
    attachment_names = models.TextField(max_length=2000, blank=True, default="")
    raw_email = models.TextField(max_length=50000, blank=True, default="")

    def __str__(self):
        return f"Email details for {self.scan}"


class Indicator(models.Model):
    """One explainable signal detected during a scan."""

    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="indicators")
    code = models.CharField(max_length=64)
    category = models.CharField(max_length=64)
    title = models.CharField(max_length=200)
    severity = models.CharField(max_length=13, choices=IndicatorSeverity.choices)
    points = models.SmallIntegerField(
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
    )
    evidence = models.TextField(max_length=1000, blank=True, default="")
    explanation = models.TextField(max_length=2000)
    recommendation = models.TextField(max_length=2000, blank=True, default="")
    sort_order = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["sort_order", "created_at", "pk"]
        indexes = [models.Index(fields=["scan", "sort_order"])]
        constraints = [
            models.CheckConstraint(
                condition=Q(severity__in=[choice.value for choice in IndicatorSeverity]),
                name="indicator_severity_valid",
            ),
            models.CheckConstraint(
                condition=Q(points__gte=0) & Q(points__lte=100),
                name="indicator_points_0_100",
            ),
        ]

    def __str__(self):
        return f"{self.code}: {self.title}"
