import hmac
import ipaddress
import logging
import time

from django.conf import settings
from django.db import connection, transaction
from django.http import HttpResponse, JsonResponse
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from .models import ActivityLog, Certificate, CustomUser, Group, GroupIP, PublicKey
from .serializers import CustomTokenObtainPairSerializer, UserSerializer
from .signing import (
    CASigningError,
    check_ca_signer_health,
    parse_validity_timedelta,
    request_certificate_signature,
)
from .ssh_utils import SSHValidationError, validate_principal, validate_ssh_public_key

logger = logging.getLogger(__name__)


class AuthRateThrottle(ScopedRateThrottle):
    scope = "auth"


class SigningRateThrottle(ScopedRateThrottle):
    scope = "signing"


def log_activity(user, event: str, metadata: dict | None = None) -> None:
    ActivityLog.objects.create(user=user, event=event, metadata=metadata or {})


def _set_auth_cookies(response: Response, access: str | None, refresh: str | None) -> None:
    if access:
        response.set_cookie(
            key=settings.JWT_ACCESS_COOKIE_NAME,
            value=access,
            max_age=int(settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"].total_seconds()),
            httponly=True,
            secure=settings.JWT_COOKIE_SECURE,
            samesite="Lax",
            path="/",
        )
    if refresh:
        response.set_cookie(
            key=settings.JWT_REFRESH_COOKIE_NAME,
            value=refresh,
            max_age=int(settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"].total_seconds()),
            httponly=True,
            secure=settings.JWT_COOKIE_SECURE,
            samesite="Lax",
            path="/",
        )


def _clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(settings.JWT_ACCESS_COOKIE_NAME, path="/", samesite="Lax")
    response.delete_cookie(settings.JWT_REFRESH_COOKIE_NAME, path="/", samesite="Lax")


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer
    throttle_classes = [AuthRateThrottle]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as exc:
            raise InvalidToken(exc.args[0]) from exc

        data = serializer.validated_data
        response = Response(data, status=status.HTTP_200_OK)
        _set_auth_cookies(response, data.get("access"), data.get("refresh"))
        return response


class AdminTokenObtainPairView(CustomTokenObtainPairView):
    def post(self, request, *args, **kwargs):
        data = request.data.copy() if hasattr(request.data, "copy") else dict(request.data)
        data["group"] = "ubuntu"
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        validated = serializer.validated_data
        response = Response(validated, status=status.HTTP_200_OK)
        _set_auth_cookies(response, validated.get("access"), validated.get("refresh"))
        return response


class CustomTokenRefreshView(TokenRefreshView):
    throttle_classes = [AuthRateThrottle]

    def post(self, request, *args, **kwargs):
        data = request.data.copy() if hasattr(request.data, "copy") else dict(request.data)
        if not data.get("refresh"):
            cookie_refresh = request.COOKIES.get(settings.JWT_REFRESH_COOKIE_NAME)
            if cookie_refresh:
                data["refresh"] = cookie_refresh

        serializer = self.get_serializer(data=data)
        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as exc:
            raise InvalidToken(exc.args[0]) from exc

        validated = serializer.validated_data
        response = Response(validated, status=status.HTTP_200_OK)
        _set_auth_cookies(response, validated.get("access"), validated.get("refresh"))
        return response


class AdminRegisterView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [AuthRateThrottle]

    def post(self, request):
        if not settings.ADMIN_BOOTSTRAP_TOKEN:
            return Response(
                {"error": "Admin bootstrap registration is disabled (ADMIN_BOOTSTRAP_TOKEN not set)."},
                status=status.HTTP_403_FORBIDDEN,
            )

        provided_token = (
            request.headers.get("X-Bootstrap-Token")
            or request.data.get("bootstrap_token")
            or ""
        )
        if not hmac.compare_digest(str(provided_token), settings.ADMIN_BOOTSTRAP_TOKEN):
            return Response({"error": "Invalid bootstrap token."}, status=status.HTTP_403_FORBIDDEN)

        if CustomUser.objects.filter(group__name="ubuntu").exists():
            return Response({"error": "Admin user already exists."}, status=status.HTTP_403_FORBIDDEN)

        data = request.data.copy() if hasattr(request.data, "copy") else dict(request.data)
        data["group"] = "ubuntu"

        serializer = UserSerializer(data=data, context={"is_admin_registration": True})
        if serializer.is_valid():
            user = serializer.save()
            log_activity(user, "admin_registered", {"group": "ubuntu"})
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RegisterView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [AuthRateThrottle]

    def post(self, request):
        if not settings.ALLOW_SELF_REGISTRATION:
            return Response(
                {"error": "Self-registration is disabled. Contact an administrator."},
                status=status.HTTP_403_FORBIDDEN,
            )

        if settings.REGISTRATION_INVITE_CODE:
            invite = str(request.data.get("invite_code", ""))
            if not hmac.compare_digest(invite, settings.REGISTRATION_INVITE_CODE):
                return Response({"error": "Valid invite code is required."}, status=status.HTTP_403_FORBIDDEN)

        serializer = UserSerializer(data=request.data, context={"is_admin_registration": False})
        if serializer.is_valid():
            user = serializer.save()
            log_activity(user, "user_registered", {"group": user.group.name})
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
@permission_classes([AllowAny])
def receive_tags(request):
    if not settings.TAG_SYNC_TOKEN:
        return Response(
            {"error": "Tag sync endpoint is disabled (TAG_SYNC_TOKEN not configured)."},
            status=status.HTTP_403_FORBIDDEN,
        )

    provided_token = request.headers.get("X-Service-Token", "")
    if not hmac.compare_digest(str(provided_token), settings.TAG_SYNC_TOKEN):
        return Response({"error": "Invalid service token."}, status=status.HTTP_401_UNAUTHORIZED)

    tags = request.data.get("tags", [])
    public_ip = str(request.data.get("public_ip", "")).strip()

    if not isinstance(tags, list) or not public_ip:
        return Response({"error": "Invalid format for tags or missing IP."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        ipaddress.ip_address(public_ip)
    except ValueError:
        return Response({"error": "Invalid public_ip address."}, status=status.HTTP_400_BAD_REQUEST)

    created_groups = []
    processed_tags = []

    for raw_tag in tags:
        if not isinstance(raw_tag, str):
            return Response({"error": "Each tag must be a string."}, status=status.HTTP_400_BAD_REQUEST)
        tag = raw_tag.strip()
        if not tag:
            continue
        try:
            validate_principal(tag)
        except SSHValidationError as exc:
            return Response({"error": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        group, created = Group.objects.get_or_create(name=tag, defaults={"server_tags": tag})
        if created:
            created_groups.append(group.name)

        GroupIP.objects.get_or_create(
            group_name=tag,
            public_ip=public_ip,
            defaults={"group": group},
        )
        processed_tags.append(tag)

    logger.info("Processed %d tags for IP %s", len(processed_tags), public_ip)
    return Response(
        {
            "message": "Tags and IP processed successfully",
            "created_groups": created_groups,
            "received_tags": processed_tags,
            "saved_ip": public_ip,
        },
        status=status.HTTP_200_OK,
    )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_group_ips(request):
    user_group = getattr(request.user, "group", None)
    if not user_group:
        return Response({"error": "User group not found."}, status=status.HTTP_400_BAD_REQUEST)

    group_ips = GroupIP.objects.filter(group_name=user_group.name).values_list("public_ip", flat=True)
    return Response({"group": user_group.name, "ips": list(group_ips)})


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def pub_key(request):
    raw_key = request.data.get("key")
    try:
        parsed = validate_ssh_public_key(raw_key)
    except SSHValidationError as exc:
        return Response({"error": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

    key_obj = PublicKey.objects.create(
        user=request.user,
        key_data=parsed.normalized_key,
        key_type=parsed.key_type,
        fingerprint=parsed.fingerprint_sha256,
    )
    log_activity(
        request.user,
        "public_key_uploaded",
        {"key_id": key_obj.id, "key_type": parsed.key_type, "fingerprint": parsed.fingerprint_sha256},
    )
    return Response(
        {
            "message": "Public key uploaded successfully.",
            "key_type": parsed.key_type,
            "fingerprint": parsed.fingerprint_sha256,
        },
        status=status.HTTP_201_CREATED,
    )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
@throttle_classes([SigningRateThrottle])
def keysign(request):
    return sign_key_with_ca(request)


def sign_key_with_ca(request):
    now = timezone.now()
    validity = settings.SSH_CERT_VALIDITY

    try:
        validity_delta = parse_validity_timedelta(validity)
    except CASigningError as exc:
        return Response({"error": str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    with transaction.atomic():
        existing_cert = Certificate.objects.filter(
            user=request.user,
            revoked=False,
            valid_until__gt=now,
        ).first()
        if existing_cert:
            return Response(
                {"error": "You already have a valid certificate. Revoke it or wait for expiration."},
                status=status.HTTP_403_FORBIDDEN,
            )

        public_key_obj = (
            PublicKey.objects.select_for_update()
            .filter(user=request.user, signed=False)
            .order_by("-uploaded_at")
            .first()
        )
        if not public_key_obj:
            return Response(
                {"error": "No unsigned public key found for this user."},
                status=status.HTTP_404_NOT_FOUND,
            )

        try:
            parsed_key = validate_ssh_public_key(public_key_obj.key_data)
        except SSHValidationError as exc:
            return Response({"error": f"Stored key failed validation: {exc}"}, status=status.HTTP_400_BAD_REQUEST)

        user_groups = list(request.user.custom_groups.all())
        if not user_groups and request.user.group:
            user_groups = [request.user.group]
        if not user_groups:
            return Response({"error": "No group associated with this user."}, status=status.HTTP_403_FORBIDDEN)

        primary_group = request.user.group or user_groups[0]
        try:
            principals = [validate_principal(g.name) for g in user_groups]
        except SSHValidationError as exc:
            return Response({"error": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        serial = int(time.time() * 1000)
        try:
            sign_result = request_certificate_signature(
                public_key=parsed_key.normalized_key,
                identity=request.user.email,
                principals=principals,
                validity=validity,
                serial=serial,
            )
        except CASigningError as exc:
            logger.error("CA signing failed for user %s: %s", request.user.email, exc)
            return Response({"error": "Certificate signing failed."}, status=status.HTTP_502_BAD_GATEWAY)

        issued_at = timezone.now()
        valid_until = sign_result.get("valid_until_dt") or (issued_at + validity_delta)
        cert_serial = sign_result.get("serial") or serial
        signed_cert = sign_result["certificate"]

        public_key_obj.signed = True
        public_key_obj.save(update_fields=["signed"])

        cert = Certificate.objects.create(
            user=request.user,
            public_key=public_key_obj,
            group=primary_group,
            serial=cert_serial,
            principals=",".join(principals),
            valid_until=valid_until,
            cert_data=signed_cert,
        )
        log_activity(
            request.user,
            "certificate_issued",
            {
                "cert_id": str(cert.id),
                "serial": cert_serial,
                "principals": principals,
                "valid_until": valid_until.isoformat(),
                "fingerprint": parsed_key.fingerprint_sha256,
            },
        )

    return HttpResponse(signed_cert, content_type="text/plain")


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_user(request):
    user = request.user
    group_name = user.group.name if user.group else "N/A"
    return JsonResponse(
        {
            "email": user.email or "N/A",
            "full_name": user.username or "N/A",
            "group": group_name,
            "role": group_name,
            "is_admin": bool(user.is_admin_user or user.is_superuser),
            "date_joined": user.date_joined.isoformat(),
        }
    )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_all_certs(request):
    certs = Certificate.objects.filter(user=request.user).select_related("group").order_by("-issued_at")
    data = [
        {
            "id": str(cert.id),
            "cert": cert.cert_data,
            "issued_at": cert.issued_at.isoformat(),
            "valid_until": cert.valid_until.isoformat(),
            "group": cert.group.name if cert.group else "N/A",
            "principals": cert.principals,
            "serial": cert.serial,
            "revoked": cert.revoked,
            "revoked_at": cert.revoked_at.isoformat() if cert.revoked_at else None,
        }
        for cert in certs
    ]
    return JsonResponse({"certificates": data})


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def logout_view(request):
    refresh_token = request.data.get("refresh") or request.COOKIES.get(settings.JWT_REFRESH_COOKIE_NAME)
    if refresh_token:
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
        except Exception:
            pass

    log_activity(request.user, "user_logged_out")
    response = Response({"message": "Logged out successfully"}, status=status.HTTP_200_OK)
    _clear_auth_cookies(response)
    return response


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def revoke_cert(request, cert_id=None):
    target_id = cert_id or request.data.get("cert_id")
    if not target_id:
        return Response({"error": "cert_id is required."}, status=status.HTTP_400_BAD_REQUEST)

    cert = Certificate.objects.filter(id=target_id, user=request.user).first()
    if not cert:
        return Response({"error": "Certificate not found."}, status=status.HTTP_404_NOT_FOUND)

    if cert.revoked:
        return Response({"message": "Certificate is already revoked."}, status=status.HTTP_200_OK)

    cert.revoked = True
    cert.revoked_at = timezone.now()
    cert.save(update_fields=["revoked", "revoked_at"])
    log_activity(request.user, "certificate_revoked", {"cert_id": str(cert.id), "serial": cert.serial})
    return Response({"message": "Certificate revoked", "cert_id": str(cert.id)})


@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def get_groups(request):
    if request.method == "POST":
        if not (request.user.is_admin_user or request.user.is_superuser):
            return Response(
                {"error": "Only administrators can create groups."},
                status=status.HTTP_403_FORBIDDEN,
            )
        name = str(request.data.get("name", "")).strip()
        server_tags = str(request.data.get("server_tags", name)).strip() or name
        try:
            validate_principal(name)
        except SSHValidationError as exc:
            return Response({"error": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        group, created = Group.objects.get_or_create(
            name=name,
            defaults={"server_tags": server_tags},
        )
        if not created:
            return Response({"error": f"Group '{name}' already exists."}, status=status.HTTP_409_CONFLICT)

        log_activity(request.user, "group_created", {"group": group.name, "server_tags": group.server_tags})
        return Response(
            {"message": "Group created successfully.", "name": group.name, "server_tags": group.server_tags},
            status=status.HTTP_201_CREATED,
        )

    groups = Group.objects.all().order_by("name").values_list("name", flat=True)
    return JsonResponse(list(groups), safe=False)


@api_view(["GET"])
@permission_classes([AllowAny])
def get_registration_groups(request):
    if not settings.ALLOW_SELF_REGISTRATION:
        return Response({"error": "Self-registration is disabled."}, status=status.HTTP_403_FORBIDDEN)
    groups = Group.objects.exclude(name="ubuntu").order_by("name").values_list("name", flat=True)
    return JsonResponse(list(groups), safe=False)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_activity_logs(request):
    logs = ActivityLog.objects.filter(user=request.user).order_by("-timestamp")[:50]
    return JsonResponse(
        {
            "logs": [
                {
                    "event": log.event,
                    "timestamp": log.timestamp.isoformat(),
                    "metadata": log.metadata,
                }
                for log in logs
            ]
        }
    )


@api_view(["GET"])
@permission_classes([AllowAny])
def healthz(request):
    db_ok = False
    try:
        connection.ensure_connection()
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        db_ok = True
    except Exception as exc:
        logger.error("Database healthcheck failed: %s", exc)

    ca_ok = check_ca_signer_health()
    overall = db_ok and ca_ok
    return JsonResponse(
        {
            "status": "ok" if overall else "degraded",
            "database": "ok" if db_ok else "error",
            "ca_signer": "ok" if ca_ok else "error",
        },
        status=200 if overall else 503,
    )
