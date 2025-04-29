from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView
from django.contrib.auth.views import LogoutView  # 👈 import this

urlpatterns = [
    path('admin/', admin.site.urls),
    path('authentication/', include('authentication.urls')),
    path("auth/", include('social_django.urls', namespace="social")),
    path('logout/', LogoutView.as_view(), name='logout'),  # 👈 add this
    path('', RedirectView.as_view(url='/authentication/')),  # 👈 Add this line
]
