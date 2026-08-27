from urllib.parse import urlencode

from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Q
from django.shortcuts import redirect, render

from .forms import EmailScanForm, URLScanForm
from .models import RiskLevel, Scan, ScanStatus, ScanType
from .services import analyze_email_scan, analyze_url_scan, persisted_result_context


_ERROR_MESSAGE = "The scan could not be completed. No internal details were exposed."
HISTORY_PAGE_SIZE = 15


def url_form(request):
    if request.method == "POST":
        form = URLScanForm(request.POST)
        if form.is_valid():
            try:
                scan = analyze_url_scan(form.cleaned_data["url"])
            except Exception:
                messages.error(request, _ERROR_MESSAGE)
                return redirect("scans:url")
            return redirect("scans:result-detail", scan_id=scan.pk)
    else:
        form = URLScanForm()
    return render(request, "scans/url_form.html", {"form": form})


def email_form(request):
    if request.method == "POST":
        form = EmailScanForm(request.POST)
        if form.is_valid():
            try:
                scan = analyze_email_scan(**form.cleaned_data)
            except Exception:
                messages.error(request, _ERROR_MESSAGE)
                return redirect("scans:email")
            return redirect("scans:result-detail", scan_id=scan.pk)
    else:
        form = EmailScanForm()
    return render(request, "scans/email_form.html", {"form": form})


def result_landing(request):
    """Compatibility landing page; completed scans use the ID-based route."""

    return render(request, "scans/result.html", {"scan": None})


def result_detail(request, scan_id: int):
    scan = (
        Scan.objects.select_related("url_scan", "email_scan")
        .prefetch_related("indicators")
        .filter(pk=scan_id)
        .first()
    )
    if scan is None:
        return render(request, "scans/not_found.html", status=404)
    context = {"scan": scan}
    context.update(persisted_result_context(scan))
    return render(request, "scans/result.html", context)


def history(request):
    """Render all local database scans with safe GET-only filters and pagination."""

    selected_type = request.GET.get("type", "").strip().lower()
    selected_risk = request.GET.get("risk", "").strip().upper()
    selected_status = request.GET.get("status", "").strip().upper()
    search = request.GET.get("q", "").strip()[:100]

    scans = Scan.objects.select_related("url_scan", "email_scan").order_by("-created_at", "-pk")
    if selected_type in {"url", "email"}:
        scans = scans.filter(scan_type=selected_type.upper())
    else:
        selected_type = ""
    if selected_risk in {choice.value for choice in RiskLevel}:
        scans = scans.filter(risk_level=selected_risk)
    else:
        selected_risk = ""
    if selected_status in {ScanStatus.COMPLETED, ScanStatus.FAILED}:
        scans = scans.filter(status=selected_status)
    else:
        selected_status = ""
    if search:
        search_query = Q()
        if search.isdigit():
            search_query |= Q(pk=int(search))
        search_query |= Q(url_scan__hostname__icontains=search)
        search_query |= Q(url_scan__original_url__icontains=search)
        search_query |= Q(email_scan__sender__icontains=search)
        search_query |= Q(email_scan__sender_domain__icontains=search)
        search_query |= Q(email_scan__reply_to__icontains=search)
        search_query |= Q(email_scan__subject__icontains=search)
        scans = scans.filter(search_query).distinct()

    paginator = Paginator(scans, HISTORY_PAGE_SIZE)
    page_obj = paginator.get_page(request.GET.get("page", 1))
    query_string = urlencode(
        {
            key: value
            for key, value in request.GET.items()
            if key != "page" and value
        }
    )
    return render(
        request,
        "scans/history.html",
        {
            "page_obj": page_obj,
            "selected_type": selected_type,
            "selected_risk": selected_risk.lower(),
            "selected_status": selected_status.lower(),
            "search": search,
            "query_string": query_string,
            "history_total": paginator.count,
            "risk_levels": RiskLevel,
        },
    )
