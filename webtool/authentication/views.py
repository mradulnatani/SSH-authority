
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
import docker
import requests
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from .models import PublicKey
from .models import Group
from .models import Certificate
from datetime import timedelta
from django.utils import timezone

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

class CustomTokenRefreshView(TokenRefreshView):
    pass

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


@api_view(['POST'])
def receive_tags(request):
    print("Raw request data:", request.data)
    tags = request.data.get('tags', [])
    print("Extracted tags:", tags)
    tags = request.data.get('tags', [])
    if not isinstance(tags, list):
        return Response({"error": "Invalid format for tags"}, status=status.HTTP_400_BAD_REQUEST)

    created_groups = []
    for tag in tags:
        group, created = Group.objects.get_or_create(name=tag, defaults={'server_tags': tag})
        if created:
            created_groups.append(group.name)

    return Response({
        "message": "Tags processed",
        "created_groups": created_groups,
        "received_tags": tags
    }, status=status.HTTP_200_OK)


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



@api_view(['GET'])
@permission_classes([IsAuthenticated])
def keysign(request):
    try:
        public_key_obj = PublicKey.objects.filter(user=request.user, signed=False).latest('created_at')
        public_key = public_key_obj.key_data
        user_groups = request.user.custom_groups.all()
        if not user_groups.exists():
            return Response({'error': 'No group associated with this user'}, status=status.HTTP_403_FORBIDDEN)
        
        group = user_groups.first()  # Assuming one group per user; adjust if multiple

        roles = list(user_groups.values_list('name', flat=True))

        payload = {
            "username": request.user.username,
            "email": request.user.email,
            "public_key": public_key,
            "roles": roles
        }

        # Call signing container
        response = requests.post(
            "http://localhost:8000/sign",
            json=payload,
            headers={"Content-Type": "application/json"}
        )

        if response.status_code == 200:
            signed_cert = response.text

            # Mark public key as signed
            public_key_obj.signed = True
            public_key_obj.save()

            # Define certificate validity (e.g., 1 week)
            issued_at = timezone.now()
            valid_until = issued_at + timedelta(days=7)

            # Save certificate
            Certificate.objects.create(
                user=request.user,
                public_key=public_key_obj,
                group=group,
                issued_at=issued_at,
                valid_until=valid_until,
                cert_data=signed_cert
            )

            return HttpResponse(signed_cert, content_type="text/plain")

        else:
            return Response(
                {"error": "Signing service failed", "details": response.text},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    except PublicKey.DoesNotExist:
        return Response({'error': 'No unsigned public key found for this user.'}, status=status.HTTP_404_NOT_FOUND)

    except requests.exceptions.RequestException as e:
        return Response({'error': 'Could not contact signing container', 'details': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

