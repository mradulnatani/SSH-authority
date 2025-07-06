# jwt_auth/urls.py

from django.contrib import admin
from django.urls import path
from authentication.views import CustomTokenObtainPairView, CustomTokenRefreshView, RegisterView
from authentication.views import receive_tags
from authentication.views import pub_key
from authentication.views import keysign
from authentication.views import get_user
from django.views.generic import TemplateView
from authentication.views import get_all_certs
from authentication.views import logout_view
from authentication.views import get_groups

urlpatterns = [
    path('', TemplateView.as_view(template_name="index.html")),  
    path('admin/', admin.site.urls),
    path('api/token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    path('api/register/', RegisterView.as_view(), name='register'),
    path('api/receive-tags/', receive_tags, name='receive-tags'),
    path('api/pub-key/', pub_key, name='pub-key'),
    path('api/keysign/', keysign, name='key-sign'),
    path('api/get-user/', get_user, name='get-user'),
    path("api/certificates/", get_all_certs, name="certs"),
    path("api/logout/", logout_view, name="logout"),
    path("api/groups/", get_groups, name="get-groups"),




    #Templates
    path('login/', TemplateView.as_view(template_name="login.html"), name='login'),
    path('register/', TemplateView.as_view(template_name="register.html"), name='register-page'),
    path('dashboard/', TemplateView.as_view(template_name="dashboard.html"), name='dashboard'),
    path('home/', TemplateView.as_view(template_name="index.html")),
    path('profile/', TemplateView.as_view(template_name="profile.html")),
    path('certificates/', TemplateView.as_view(template_name="certificates.html")),

]
