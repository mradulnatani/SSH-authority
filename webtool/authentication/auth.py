"""JWT authentication supporting Authorization Bearer headers and CSRF-protected HttpOnly cookies."""

from django.conf import settings
from django.middleware.csrf import CsrfViewMiddleware
from rest_framework import exceptions
from rest_framework_simplejwt.authentication import JWTAuthentication


class _DummyResponse:
    pass


def enforce_csrf(request) -> None:
    """Run Django's CSRF check for cookie-authenticated requests."""
    check = CsrfViewMiddleware(lambda req: _DummyResponse())
    check.process_request(request)
    reason = check.process_view(request, None, (), {})
    if reason:
        raise exceptions.PermissionDenied(f"CSRF Failed: {reason}")


class CookieOrHeaderJWTAuthentication(JWTAuthentication):
    """Authenticate via Authorization Bearer header or HttpOnly access_token cookie."""

    def authenticate(self, request):
        header = self.get_header(request)
        if header is not None:
            raw_token = self.get_raw_token(header)
            if raw_token is None:
                return None
            validated_token = self.get_validated_token(raw_token)
            return self.get_user(validated_token), validated_token

        raw_cookie_token = request.COOKIES.get(settings.JWT_ACCESS_COOKIE_NAME)
        if not raw_cookie_token:
            return None

        enforce_csrf(request)
        validated_token = self.get_validated_token(raw_cookie_token)
        return self.get_user(validated_token), validated_token
