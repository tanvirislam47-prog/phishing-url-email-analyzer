from django.urls import path

from . import views


app_name = "scans"

urlpatterns = [
    path("url/", views.url_form, name="url"),
    path("email/", views.email_form, name="email"),
    path("result/", views.result_landing, name="result"),
    path("result/<int:scan_id>/", views.result_detail, name="result-detail"),
    path("history/", views.history, name="history"),
]
