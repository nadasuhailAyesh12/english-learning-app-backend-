"""
URL configuration for English Learning App Backend.
"""

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

urlpatterns = [
    # Admin interface
    path('admin/', admin.site.urls),

    # API documentation
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),

    # Authentication
    path('api/auth/', include('rest_framework_simplejwt.urls')),
    path('accounts/', include('allauth.urls')),

    # API endpoints
    path('api/v1/', include('apps.users.urls')),
    path('api/v1/', include('apps.courses.urls')),
    path('api/v1/', include('apps.lessons.urls')),
    path('api/v1/', include('apps.exercises.urls')),
    path('api/v1/', include('apps.progress.urls')),
    path('api/v1/', include('apps.analytics.urls')),
]

# Serve static and media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)