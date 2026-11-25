from django.contrib import admin
from django.urls import path
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.generic import TemplateView

from authentication.views import (
    AdminRegisterView,
    AdminTokenObtainPairView,
    CustomTokenObtainPairView,
    CustomTokenRefreshView,
    RegisterView,
    get_activity_logs,
    get_all_certs,
    get_group_ips,
    get_groups,
    get_registration_groups,
    get_user,
    healthz,
    keysign,
    logout_view,
    pub_key,
    receive_tags,
    revoke_cert,
)


def csrf_template(template_name: str):
    return ensure_csrf_cookie(TemplateView.as_view(template_name=template_name))


urlpatterns = [
    path("", csrf_template("index.html")),
    path("admin/", admin.site.urls),
    path("api/healthz/", healthz, name="healthz"),
    path("api/token/", CustomTokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("api/token/refresh/", CustomTokenRefreshView.as_view(), name="token_refresh"),
    path("api/register/", RegisterView.as_view(), name="register"),
    path("api/receive-tags/", receive_tags, name="receive-tags"),
    path("api/pub-key/", pub_key, name="pub-key"),
    path("api/keysign/", keysign, name="key-sign"),
    path("api/get-user/", get_user, name="get-user"),
    path("api/certificates/", get_all_certs, name="certs"),
    path("api/certificates/<uuid:cert_id>/revoke/", revoke_cert, name="revoke-cert"),
    path("api/revoke-cert/", revoke_cert, name="revoke-cert-legacy"),
    path("api/activity-logs/", get_activity_logs, name="activity-logs"),
    path("api/logout/", logout_view, name="logout"),
    path("api/groups/", get_groups, name="get-groups"),
    path("api/registration-groups/", get_registration_groups, name="get-registration-groups"),
    path("api/admin/register/", AdminRegisterView.as_view(), name="admin-register"),
    path("api/admin/login/", AdminTokenObtainPairView.as_view(), name="admin-login"),
    path("api/group-ips/", get_group_ips, name="get-group-ips"),
    # Templates
    path("login/", csrf_template("login.html"), name="login"),
    path("register/", csrf_template("register.html"), name="register-page"),
    path("dashboard/", csrf_template("dashboard.html"), name="dashboard"),
    path("home/", csrf_template("index.html")),
    path("profile/", csrf_template("profile.html")),
    path("certificates/", csrf_template("certificates.html")),
]
