from django.contrib import admin

from .models import EmailScan, Indicator, Scan, URLScan


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "scan_type",
        "status",
        "score",
        "risk_level",
        "rule_version",
        "created_at",
    )
    list_filter = ("scan_type", "status", "risk_level", "created_at")
    search_fields = ("verdict", "rule_version", "input_hash")
    readonly_fields = ("created_at", "updated_at")
    date_hierarchy = "created_at"


@admin.register(URLScan)
class URLScanAdmin(admin.ModelAdmin):
    list_display = ("id", "scan", "scheme", "hostname", "port")
    list_filter = ("scheme",)
    search_fields = ("original_url", "normalized_url", "hostname")


@admin.register(EmailScan)
class EmailScanAdmin(admin.ModelAdmin):
    list_display = ("id", "scan", "sender", "sender_domain", "reply_to", "subject")
    list_filter = ("sender_domain",)
    search_fields = ("sender", "sender_domain", "reply_to", "subject")
    exclude = ("body", "raw_email", "attachment_names")


@admin.register(Indicator)
class IndicatorAdmin(admin.ModelAdmin):
    list_display = ("id", "scan", "code", "category", "severity", "points", "sort_order")
    list_filter = ("category", "severity")
    search_fields = ("code", "title", "category", "evidence", "explanation")
    readonly_fields = ("created_at",)
