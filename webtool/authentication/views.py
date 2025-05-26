
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from .serializers import CustomTokenObtainPairSerializer, UserSerializer
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .models import Group


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