"""Root URL configuration for the analyzer."""

from django.contrib import admin
from django.urls import include, path


urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("core.urls")),
    path("scans/", include("scans.urls")),
    path("dashboard/", include("dashboard.urls")),
]
