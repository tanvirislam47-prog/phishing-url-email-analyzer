from django.contrib import messages
from django.shortcuts import redirect, render

from .forms import EmailScanForm, URLScanForm


def url_form(request):
    if request.method == "POST":
        form = URLScanForm(request.POST)
        if form.is_valid():
            messages.info(
                request,
                "Phase 1 is UI-only. No URL analysis was performed and the submitted address was not opened.",
            )
            return redirect("scans:url")
    else:
        form = URLScanForm()
    return render(request, "scans/url_form.html", {"form": form})


def email_form(request):
    if request.method == "POST":
        form = EmailScanForm(request.POST)
        if form.is_valid():
            messages.info(
                request,
                "Phase 1 is UI-only. No email analysis was performed and no scan was saved.",
            )
            return redirect("scans:email")
    else:
        form = EmailScanForm()
    return render(request, "scans/email_form.html", {"form": form})


def result_placeholder(request):
    return render(request, "scans/result.html")


def history(request):
    return render(request, "scans/history.html")
