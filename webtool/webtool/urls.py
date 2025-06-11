# jwt_auth/urls.py

from django.contrib import admin
from django.urls import path
from authentication.views import CustomTokenObtainPairView, CustomTokenRefreshView, RegisterView
from authentication.views import receive_tags
from authentication.views import pub_key
from authentication.views import keysign
urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    path('api/register/', RegisterView.as_view(), name='register'),
    path('api/receive-tags/', receive_tags, name='receive-tags'),
    path('api/pub-key/', pub_key, name='pub-key'),
    path('api/keysign', keysign, name='key-sign')
]
