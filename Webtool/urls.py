from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView
from django.contrib.auth.views import LogoutView  
from django.conf.urls.static import static
from django.conf import settings


urlpatterns = [
    path('admin/', admin.site.urls),
    path('authentication/', include('authentication.urls')),
    path("auth/", include('social_django.urls', namespace="social")),
    path('logout/', LogoutView.as_view(), name='logout'),  
    path('', RedirectView.as_view(url='/authentication/')),  
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
