# jwt_auth/urls.py

from django.contrib import admin
from django.urls import path
from authentication.views import CustomTokenObtainPairView, CustomTokenRefreshView, RegisterView
from authentication.views import receive_tags

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    path('api/register/', RegisterView.as_view(), name='register'),
    path('api/receive-tags/', receive_tags, name='receive-tags'),

]
