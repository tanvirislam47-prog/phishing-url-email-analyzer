from django.urls import path

from . import views


app_name = "scans"

urlpatterns = [
    path("url/", views.url_form, name="url"),
    path("email/", views.email_form, name="email"),
    path("result/", views.result_placeholder, name="result"),
    path("history/", views.history, name="history"),
]
