from django.contrib import messages
from django.shortcuts import redirect, render

from .forms import EmailScanForm, URLScanForm
from .models import Scan
from .services import analyze_email_scan, analyze_url_scan, persisted_result_context


_ERROR_MESSAGE = "The scan could not be completed. No internal details were exposed."


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
    return render(request, "scans/history.html")
