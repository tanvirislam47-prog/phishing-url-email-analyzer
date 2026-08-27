"""Django orchestration for the local scan workflow.

Analyzers and the RiskEngine remain framework-independent. This module is the
boundary that creates persistence records, coordinates those pure services,
and stores their structured output. No function here performs network access.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from time import perf_counter
from typing import Any

from django.db import transaction
from django.utils import timezone

from analysis.email_analyzer import analyze_email
from analysis.risk_engine import evaluate_risk
from analysis.types import IndicatorResult, RiskAnalysisResult, URLAnalysisResult
from analysis.url_analyzer import analyze_url

from .models import EmailScan, Indicator, Scan, ScanStatus, ScanType, URLScan

_SAFE_FAILURE_MESSAGE = "The local analysis could not be completed. Please review the submitted content and try again."


def create_pending_scan(scan_type: str, *, input_hash: str = "") -> Scan:
    """Create an empty pending scan record for a later workflow step."""

    return Scan.objects.create(
        scan_type=scan_type,
        status=ScanStatus.PENDING,
        input_hash=input_hash,
    )


def analyze_url_scan(url: str) -> Scan:
    """Analyze and persist one URL submission, then return its saved Scan."""

    started = perf_counter()
    submitted = url.strip()
    scan = create_pending_scan(ScanType.URL, input_hash=_sha256_text(submitted))
    try:
        with transaction.atomic():
            analysis = analyze_url(submitted)
            url_details = _url_details_from_result(scan, submitted, analysis)
            url_details.save()
            if not analysis.success:
                _mark_failed(scan, _duration_ms(started), _SAFE_FAILURE_MESSAGE, analysis_metadata=analysis.analysis_metadata)
                return _refresh_scan(scan)

            if analysis.normalized_url:
                scan.input_hash = _sha256_text(analysis.normalized_url)
                scan.save(update_fields=["input_hash", "updated_at"])
            risk = evaluate_risk(analysis.indicators)
            if not risk.success:
                _mark_failed(scan, _duration_ms(started), _SAFE_FAILURE_MESSAGE, risk_result=risk)
                return _refresh_scan(scan)
            _complete_scan(scan, risk, _duration_ms(started))
            _persist_indicators(scan, risk)
        return _refresh_scan(scan)
    except Exception:
        _mark_failed_after_rollback(scan, _duration_ms(started))
        return _refresh_scan(scan)


def analyze_email_scan(
    *,
    sender: str = "",
    reply_to: str = "",
    subject: str = "",
    body: str = "",
    attachment_names: str = "",
) -> Scan:
    """Analyze and persist one structured email submission."""

    started = perf_counter()
    payload = {
        "sender": sender,
        "reply_to": reply_to,
        "subject": subject,
        "body": body,
        "attachment_names": attachment_names,
    }
    scan = create_pending_scan(ScanType.EMAIL, input_hash=_sha256_json(payload))
    try:
        with transaction.atomic():
            email_details = EmailScan.objects.create(
                scan=scan,
                sender=sender,
                reply_to=reply_to,
                subject=subject,
                body=body,
                attachment_names=attachment_names,
            )
            analysis = analyze_email(**payload)
            if not analysis.success:
                _mark_failed(scan, _duration_ms(started), _SAFE_FAILURE_MESSAGE)
                return _refresh_scan(scan)

            email_details.sender = analysis.features.sender
            email_details.sender_domain = analysis.features.sender_domain
            email_details.reply_to = analysis.features.reply_to
            email_details.subject = analysis.features.subject
            email_details.extracted_url_count = len(analysis.extracted_urls)
            email_details.attachment_count = len(analysis.attachments)
            email_details.save()

            indicators = list(analysis.indicators)
            for nested_url in analysis.extracted_urls:
                indicators.extend(
                    _indicator_from_dict(item) for item in nested_url.get("indicators", [])
                )
            risk = evaluate_risk(indicators)
            if not risk.success:
                _mark_failed(scan, _duration_ms(started), _SAFE_FAILURE_MESSAGE, risk_result=risk)
                return _refresh_scan(scan)
            _complete_scan(scan, risk, _duration_ms(started))
            _persist_indicators(scan, risk)
        return _refresh_scan(scan)
    except Exception:
        _mark_failed_after_rollback(scan, _duration_ms(started))
        return _refresh_scan(scan)


def persist_scan_result(scan: Scan, risk_result: RiskAnalysisResult, *, duration_ms: int) -> Scan:
    """Persist a successful RiskEngine result for a scan already in a transaction."""

    if not risk_result.success or risk_result.score is None:
        raise ValueError("Only successful risk results can be persisted as completed.")
    _complete_scan(scan, risk_result, max(duration_ms, 0))
    _persist_indicators(scan, risk_result)
    return scan


def _url_details_from_result(
    scan: Scan, submitted: str, analysis: URLAnalysisResult
) -> URLScan:
    features = analysis.features
    return URLScan(
        scan=scan,
        original_url=submitted,
        normalized_url=analysis.normalized_url,
        scheme=features.scheme if features else "",
        hostname=features.hostname if features else "",
        port=features.port if features else None,
        path=features.path if features else "",
        query=features.query if features else "",
        fragment=features.fragment if features else "",
    )


def _complete_scan(scan: Scan, risk_result: RiskAnalysisResult, duration_ms: int) -> None:
    scan.status = ScanStatus.COMPLETED
    scan.score = risk_result.score
    scan.risk_level = risk_result.risk_level
    scan.verdict = risk_result.verdict
    scan.rule_version = risk_result.rule_version
    scan.analysis_duration_ms = max(duration_ms, 0)
    scan.error_message = ""
    scan.updated_at = timezone.now()
    scan.save(
        update_fields=[
            "status",
            "score",
            "risk_level",
            "verdict",
            "rule_version",
            "analysis_duration_ms",
            "error_message",
            "updated_at",
        ]
    )


def _persist_indicators(scan: Scan, risk_result: RiskAnalysisResult) -> None:
    breakdown_by_code = {item.code: item for item in risk_result.score_breakdown}
    records = []
    for position, indicator in enumerate(risk_result.indicators, start=1):
        breakdown = breakdown_by_code.get(indicator.code)
        records.append(
            Indicator(
                scan=scan,
                code=indicator.code,
                category=indicator.category,
                title=indicator.title,
                severity=indicator.severity,
                # Persist the applied contribution so the stored record agrees
                # with the final score, including a nested contextual signal
                # that was correctly suppressed to zero.
                points=breakdown.applied_points if breakdown else 0,
                evidence=indicator.evidence,
                explanation=indicator.explanation,
                recommendation=indicator.recommendation,
                sort_order=position,
            )
        )
    Indicator.objects.bulk_create(records)


def _mark_failed(
    scan: Scan,
    duration_ms: int,
    message: str,
    *,
    analysis_metadata: dict[str, Any] | None = None,
    risk_result: RiskAnalysisResult | None = None,
) -> None:
    scan.status = ScanStatus.FAILED
    scan.score = None
    scan.risk_level = ""
    scan.verdict = ""
    scan.rule_version = risk_result.rule_version if risk_result else scan.rule_version
    scan.analysis_duration_ms = max(duration_ms, 0)
    scan.error_message = message
    scan.updated_at = timezone.now()
    scan.save(
        update_fields=[
            "status",
            "score",
            "risk_level",
            "verdict",
            "rule_version",
            "analysis_duration_ms",
            "error_message",
            "updated_at",
        ]
    )


def _mark_failed_after_rollback(scan: Scan, duration_ms: int) -> None:
    """Persist a safe FAILED state after an inner atomic block rolled back."""

    Scan.objects.filter(pk=scan.pk).update(
        status=ScanStatus.FAILED,
        score=None,
        risk_level="",
        verdict="",
        analysis_duration_ms=max(duration_ms, 0),
        error_message=_SAFE_FAILURE_MESSAGE,
        updated_at=timezone.now(),
    )


def persisted_result_context(scan: Scan) -> dict[str, Any]:
    """Build display-only data from persisted fields without rerunning analysis."""

    indicators = list(scan.indicators.all())
    if not indicators:
        summary = "No significant phishing indicators were detected by the configured rules. This does not guarantee safety."
    elif scan.risk_level in {"HIGH", "CRITICAL"}:
        summary = "Multiple high-risk indicators were detected. Treat this content as potentially phishing and verify it through an independent channel."
    elif scan.risk_level == "MEDIUM":
        titles = ", ".join(indicator.title for indicator in indicators[:3])
        summary = f"Several suspicious indicators were detected, including {titles}. Review the evidence before acting."
    else:
        titles = ", ".join(indicator.title for indicator in indicators[:3])
        summary = f"Limited review indicators were detected, including {titles}. Verify sensitive requests independently."

    recommendations = []
    seen = set()
    for indicator in indicators:
        recommendation = indicator.recommendation.strip()
        if recommendation and recommendation not in seen:
            seen.add(recommendation)
            recommendations.append(recommendation)

    context: dict[str, Any] = {
        "risk_summary": summary,
        "recommendations": recommendations,
    }
    if scan.scan_type == ScanType.URL:
        url_scan = scan.url_scan
        context.update(
            {
                "url_domain": _domain_from_hostname(url_scan.hostname),
                "url_subdomain": _subdomain_from_hostname(url_scan.hostname),
                "query_presence": "Present" if url_scan.query else "None",
                "fragment_presence": "Present" if url_scan.fragment else "None",
            }
        )
    return context


def _domain_from_hostname(hostname: str) -> str:
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass
    labels = [label for label in hostname.split(".") if label]
    if len(labels) <= 2:
        return hostname
    return ".".join(labels[-2:])


def _subdomain_from_hostname(hostname: str) -> str:
    try:
        ipaddress.ip_address(hostname)
        return ""
    except ValueError:
        pass
    labels = [label for label in hostname.split(".") if label]
    if len(labels) <= 2:
        return ""
    return ".".join(labels[:-2])


def _refresh_scan(scan: Scan) -> Scan:
    return Scan.objects.get(pk=scan.pk)


def _duration_ms(started: float) -> int:
    return max(int(round((perf_counter() - started) * 1000)), 0)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_json(value: dict[str, str]) -> str:
    canonical = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return _sha256_text(canonical)


def _indicator_from_dict(value: dict[str, Any]) -> IndicatorResult:
    return IndicatorResult(
        code=str(value["code"]),
        category=str(value["category"]),
        title=str(value["title"]),
        severity=str(value["severity"]),
        points=int(value["points"]),
        evidence=str(value["evidence"]),
        explanation=str(value["explanation"]),
        recommendation=str(value["recommendation"]),
        sort_order=int(value["sort_order"]),
    )


__all__ = [
    "analyze_email_scan",
    "analyze_url_scan",
    "create_pending_scan",
    "persist_scan_result",
]
