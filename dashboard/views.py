from django.db.models import Avg, Count, Max, Min, Q
from django.shortcuts import render

from scans.models import RiskLevel, Scan, ScanStatus, ScanType


def index(request):
    """Render database-backed aggregate statistics for all local scans."""

    scans = Scan.objects.all()
    aggregate = scans.aggregate(
        total=Count("id"),
        url=Count("id", filter=Q(scan_type=ScanType.URL)),
        email=Count("id", filter=Q(scan_type=ScanType.EMAIL)),
        completed=Count("id", filter=Q(status=ScanStatus.COMPLETED)),
        failed=Count("id", filter=Q(status=ScanStatus.FAILED)),
        safe_low=Count(
            "id",
            filter=Q(
                status=ScanStatus.COMPLETED,
                risk_level__in=[RiskLevel.VERY_LOW, RiskLevel.LOW],
            ),
        ),
        high=Count(
            "id",
            filter=Q(status=ScanStatus.COMPLETED, risk_level=RiskLevel.HIGH),
        ),
        critical=Count(
            "id",
            filter=Q(status=ScanStatus.COMPLETED, risk_level=RiskLevel.CRITICAL),
        ),
    )
    score_stats = scans.filter(status=ScanStatus.COMPLETED).aggregate(
        average=Avg("score"),
        highest=Max("score"),
        lowest=Min("score"),
    )
    distribution_rows = scans.values("risk_level").annotate(count=Count("id"))
    distribution_by_level = {row["risk_level"]: row["count"] for row in distribution_rows}
    completed_count = aggregate["completed"] or 0
    risk_distribution = [
        {
            "key": level.value,
            "label": level.label,
            "count": distribution_by_level.get(level.value, 0),
            "percentage": round((distribution_by_level.get(level.value, 0) / completed_count) * 100) if completed_count else 0,
        }
        for level in RiskLevel
    ]
    average = score_stats["average"]
    metrics = [
        {
            "label": "Total scans",
            "value": aggregate["total"] or 0,
            "detail": "All local database records",
            "href": "scans:history",
            "query": "",
        },
        {
            "label": "URL scans",
            "value": aggregate["url"] or 0,
            "detail": "Persisted URL analyses",
            "href": "scans:history",
            "query": "?type=url",
        },
        {
            "label": "Email scans",
            "value": aggregate["email"] or 0,
            "detail": "Persisted email analyses",
            "href": "scans:history",
            "query": "?type=email",
        },
        {
            "label": "Completed",
            "value": aggregate["completed"] or 0,
            "detail": "Analysis results available",
            "href": "scans:history",
            "query": "?status=completed",
        },
        {
            "label": "Failed",
            "value": aggregate["failed"] or 0,
            "detail": "Needs no internal details",
            "href": "scans:history",
            "query": "?status=failed",
        },
        {
            "label": "Safe / low",
            "value": aggregate["safe_low"] or 0,
            "detail": "Very low and low risk; review history",
            "href": "scans:history",
            "query": "",
        },
        {
            "label": "High risk",
            "value": aggregate["high"] or 0,
            "detail": "Completed high-risk results",
            "href": "scans:history",
            "query": "?risk=high",
        },
        {
            "label": "Critical risk",
            "value": aggregate["critical"] or 0,
            "detail": "Completed critical results",
            "href": "scans:history",
            "query": "?risk=critical",
        },
    ]
    return render(
        request,
        "dashboard/index.html",
        {
            "metrics": metrics,
            "aggregate": aggregate,
            "score_stats": score_stats,
            "average_score_display": round(average) if average is not None else "—",
            "risk_distribution": risk_distribution,
            "recent_scans": scans.order_by("-created_at", "-pk")[:8],
            "has_scans": bool(aggregate["total"]),
            "has_completed": bool(completed_count),
            "risk_levels": RiskLevel,
        },
    )
