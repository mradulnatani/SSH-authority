
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from .serializers import CustomTokenObtainPairSerializer, UserSerializer
from rest_framework.decorators import api_view,permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from .models import Group
from .models import PublicKey
from .models import GroupIP
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view
from django.utils.decorators import method_decorator
# import docker
# import requests
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from .models import PublicKey
from .models import Group
from .models import Certificate
from datetime import timedelta
from django.utils import timezone
import subprocess
import tempfile
import os
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from authentication.models import ActivityLog  
from .models import CustomUser

pem_path = os.path.expanduser("~/Downloads/formradul.pem")
command = f"ssh -i {pem_path} ubuntu@54.159.193.62"


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer
  
@method_decorator(csrf_exempt, name='dispatch')
class AdminRegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        if CustomUser.objects.filter(group__name='ubuntu').exists():
            return Response({'error': 'Admin user already exists.'}, status=status.HTTP_403_FORBIDDEN)

        # Force group = ubuntu regardless of what the request sends
        data = request.data.copy()
        data['group'] = 'ubuntu'

        serializer = UserSerializer(data=data)
        if serializer.is_valid():
            user = serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AdminTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        # Force the group in request to be "ubuntu"
        request.data._mutable = True
        request.data["group"] = "ubuntu"
        request.data._mutable = False
        return super().post(request, *args, **kwargs)

class CustomTokenRefreshView(TokenRefreshView):
    pass

@method_decorator(csrf_exempt, name='dispatch')
class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            if user:
                json = serializer.data
                return Response(json, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@csrf_exempt
@api_view(['POST'])
def receive_tags(request):
    print("Raw request data:", request.data)
    tags = request.data.get('tags', [])
    public_ip = request.data.get('public_ip')

    if not isinstance(tags, list) or not public_ip:
        return Response({"error": "Invalid format for tags or missing IP"}, status=status.HTTP_400_BAD_REQUEST)

    created_groups = []

    for tag in tags:
        tag = tag.strip()
        if not tag:
            continue

        group, created = Group.objects.get_or_create(
            name=tag,
            defaults={'server_tags': tag}
        )
        if created:
            created_groups.append(group.name)

        GroupIP.objects.get_or_create(
            group_name=tag,
            public_ip=public_ip
        )

    return Response({
        "message": "Tags and IP processed successfully",
        "created_groups": created_groups,
        "received_tags": tags,
        "saved_ip": public_ip
    }, status=status.HTTP_200_OK)



@csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_group_ips(request):
    user_group = getattr(request.user, 'group', None)
    if not user_group:
        return Response({"error": "User group not found"}, status=400)

    group_ips = GroupIP.objects.filter(group_name=user_group.name).values_list('public_ip', flat=True)

    return Response({
        "group": user_group.name,
        "ips": list(group_ips)
    })

@csrf_exempt
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def pub_key(request):
    print("Raw request data:", request.data)
    
    key_data = request.data.get('key')

    if not key_data:
        return Response({'error': 'Public key is required.'}, status=status.HTTP_400_BAD_REQUEST)

    # saves the key to the DB
    PublicKey.objects.create(user=request.user, key_data=key_data)

    return Response({'message': 'Public key uploaded successfully.'}, status=status.HTTP_201_CREATED)


@csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def keysign(request):
    return sign_key_on_remote_ca(request)
    # try:
    #     public_key_obj = PublicKey.objects.filter(user=request.user, signed=False).latest('uploaded_at')
    #     public_key = public_key_obj.key_data
    #     user_groups = request.user.custom_groups.all()
        
    #     if not user_groups.exists():
    #         return Response({'error': 'No group associated with this user'}, status=status.HTTP_403_FORBIDDEN)

    #     group = user_groups.first()
    #     roles = list(user_groups.values_list('name', flat=True))
    #     username = request.user.username

    #     # Step 1: Write public key to temp file
    #     with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
    #         f.write(public_key)
    #         pub_path = f.name

    #     # Step 2: Copy public key to container
    #     container_path = f"/tmp/{os.path.basename(pub_path)}"
    #     subprocess.run(["docker", "cp", pub_path, f"certificate-authority:{container_path}"], check=True)

    #     # Step 3: Execute signing script in container
    #     subprocess.run([
    #         "docker", "exec", "certificate-authority", "bash", "-c",
    #         f"/usr/local/bin/sign.sh {container_path} {username} \"{','.join(roles)}\""
    #     ], check=True)

    #     # Step 4: Copy signed cert back to host
    #     cert_path_host = pub_path + "-cert.pub"
    #     cert_path_container = container_path + "-cert.pub"
    #     subprocess.run(["docker", "cp", f"certificate-authority:{cert_path_container}", cert_path_host], check=True)

    #     # Step 5: Read signed cert
    #     with open(cert_path_host) as f:
    #         signed_cert = f.read()

    #     # Step 6: Cleanup
    #     os.remove(pub_path)
    #     os.remove(cert_path_host)

    #     # Step 7: Mark public key signed & save certificate
    #     public_key_obj.signed = True
    #     public_key_obj.save()

    #     issued_at = timezone.now()
    #     valid_until = issued_at + timedelta(days=7)

    #     Certificate.objects.create(
    #         user=request.user,
    #         public_key=public_key_obj,
    #         group=group,
    #         issued_at=issued_at,
    #         valid_until=valid_until,
    #         cert_data=signed_cert
    #     )

    #     return HttpResponse(signed_cert, content_type="text/plain")

    # except PublicKey.DoesNotExist:
    #     return Response({'error': 'No unsigned public key found for this user.'}, status=status.HTTP_404_NOT_FOUND)

    # except subprocess.CalledProcessError as e:
    #     return Response({'error': 'Signing process failed', 'details': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
@csrf_exempt  
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_user(request):
    user = request.user

    return JsonResponse({
        "email": user.email or "N/A",
        "full_name": f"{user.username}" or "N/A",
        "group": user.group.name if user.group else "N/A",
        "role": user.group.name,  # Add this field to model if needed
        "date_joined": user.date_joined.strftime("%Y-%m-%d %H:%M:%S")
    })


def sign_key_on_remote_ca(request):
    try:
         # Check if user already has a valid (non-expired) certificate
        existing_cert = Certificate.objects.filter(
            user=request.user,
            valid_until__gt=timezone.now()
        ).first()

        if existing_cert:
            return Response({
                'error': 'You already have a valid certificate. You can request a new one after it expires.'
            }, status=status.HTTP_403_FORBIDDEN)
        REMOTE_USER = "ubuntu"
        REMOTE_HOST = "54.159.193.62"
        REMOTE_CONTAINER = "certificate-authority"
        SSH_KEY_PATH = os.path.expanduser("~/Downloads/formradul.pem")

        public_key_obj = PublicKey.objects.filter(user=request.user, signed=False).latest('uploaded_at')
        public_key = public_key_obj.key_data

        user_groups = request.user.custom_groups.all()
        if not user_groups.exists():
            return Response({'error': 'No group associated with this user'}, status=status.HTTP_403_FORBIDDEN)

        group = user_groups.first()
        roles = list(user_groups.values_list('name', flat=True))
        username = request.user.username

        with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
            f.write(public_key)
            pub_path = f.name

        filename = os.path.basename(pub_path)
        remote_tmp_path = f"/tmp/{filename}"
        remote_cert_path = f"{remote_tmp_path}-cert.pub"
        local_cert_path = f"{pub_path}-cert.pub"
        roles_str = ",".join(roles)

        subprocess.run([
            "scp", "-i", SSH_KEY_PATH, pub_path,
            f"{REMOTE_USER}@{REMOTE_HOST}:{remote_tmp_path}"
        ], check=True)

        remote_command = (
            f"sudo docker cp {remote_tmp_path} {REMOTE_CONTAINER}:{remote_tmp_path} && "
            f"sudo docker exec {REMOTE_CONTAINER} bash -c "
            f"'/usr/local/bin/sign.sh {remote_tmp_path} {username} \"{roles_str}\"' && "
            f"sudo docker cp {REMOTE_CONTAINER}:{remote_tmp_path}-cert.pub {remote_cert_path}"
        )


        subprocess.run([
            "ssh", "-i", SSH_KEY_PATH,
            f"{REMOTE_USER}@{REMOTE_HOST}",
            remote_command
        ], check=True)

        subprocess.run([
            "scp", "-i", SSH_KEY_PATH,
            f"{REMOTE_USER}@{REMOTE_HOST}:{remote_cert_path}", local_cert_path
        ], check=True)

        with open(local_cert_path) as cert_file:
            signed_cert = cert_file.read()

        os.remove(pub_path)
        os.remove(local_cert_path)

        public_key_obj.signed = True
        public_key_obj.save()

        issued_at = timezone.now()
        valid_until = issued_at + timedelta(days=7)

        Certificate.objects.create(
            user=request.user,
            public_key=public_key_obj,
            group=group,
            issued_at=issued_at,
            valid_until=valid_until,
            cert_data=signed_cert
        )

        return HttpResponse(signed_cert, content_type="text/plain")

    except PublicKey.DoesNotExist:
        return Response({'error': 'No unsigned public key found for this user.'}, status=status.HTTP_404_NOT_FOUND)

    except subprocess.CalledProcessError as e:
        return Response({'error': 'Remote signing process failed', 'details': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@csrf_exempt
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_all_certs(request):
    user = request.user
    certs = Certificate.objects.filter(user=user).order_by("-issued_at")
    data = []
    for cert in certs:
        data.append({
            "cert": cert.cert_data,  # <--- corrected from content to cert_data
            "issued_at": cert.issued_at.isoformat(),
            "valid_until": cert.valid_until.isoformat(),
            "group": cert.group.name if cert.group else "N/A"
        })
    return JsonResponse({"certificates": data})

@csrf_exempt
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    try:
        refresh_token = request.data.get("refresh")
        token = RefreshToken(refresh_token)
        token.blacklist()
        return Response({"message": "Logged out successfully"}, status=status.HTTP_205_RESET_CONTENT)
    except Exception as e:
        return Response({"error": "Invalid token or already logged out"}, status=status.HTTP_400_BAD_REQUEST)
    
def log_activity(user, action, metadata=None):
    ActivityLog.objects.create(user=user, action=action, metadata=metadata or {})


@csrf_exempt
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def revoke_cert(request):
    cert_id = request.data.get("cert_id")
    cert = Certificate.objects.filter(id=cert_id, user=request.user).first()
    if not cert:
        return Response({"error": "Certificate not found"}, status=404)
    
    cert.revoked = True
    cert.revoked_at = timezone.now()
    cert.save()
    log_activity(request.user, "revoked certificate", {"cert_id": cert_id})
    return Response({"message": "Certificate revoked"})

def get_groups(request):
    groups = Group.objects.all().values_list('name', flat=True)
    return JsonResponse(list(groups), safe=False)

# @api_view(["GET"])
# @permission_classes([IsAuthenticated])
# def get_activity_logs(request):
#     logs = ActivityLog.objects.filter(user=request.user).order_by('-timestamp')[:20]
#     return JsonResponse({
#         "logs": [
#             {"action": log.action, "timestamp": log.timestamp.isoformat(), "metadata": log.metadata}
#             for log in logs
#         ]
#     })

# @api_view(["GET"])
# @permission_classes([IsAuthenticated])
# def certs_per_day(request):
#     from django.db.models.functions import TruncDate
#     from django.db.models import Count

#     data = (
#         Certificate.objects
#         .filter(user=request.user)
#         .annotate(date=TruncDate('issued_at'))
#         .values('date')
#         .annotate(count=Count('id'))
#         .order_by('date')
#     )

#     return JsonResponse({"history": list(data)})

# authentication/views.py


# @csrf_exempt
# @api_view(['GET'])
# @permission_classes([IsAuthenticated])
# def get_group_ips(request):
#     group = request.user.group  # or request.user.custom_group.name if your field differs
#     ips = GroupIP.objects.filter(group_name=group).values_list('public_ip', flat=True)
#     return Response({"ips": list(ips)})

