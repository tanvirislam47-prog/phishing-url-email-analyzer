from django.shortcuts import render


def index(request):
    context = {
        "metrics": [
            {"label": "Total scans", "value": "0", "detail": "No analyses recorded"},
            {"label": "URL scans", "value": "0", "detail": "Available in a later phase"},
            {"label": "Email scans", "value": "0", "detail": "Available in a later phase"},
            {"label": "Safe / low risk", "value": "0", "detail": "No results yet"},
            {"label": "Suspicious", "value": "0", "detail": "No results yet"},
            {"label": "High / critical", "value": "0", "detail": "No results yet"},
        ]
    }
    return render(request, "dashboard/index.html", context)
