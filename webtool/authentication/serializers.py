from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from .models import CustomUser, Group
from .ssh_utils import SSHValidationError, validate_principal


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    group = serializers.CharField(write_only=True, required=False, allow_blank=True)

    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")
        group_name = (attrs.get("group") or "").strip()

        if not email or not password:
            raise serializers.ValidationError("Email and password are required.")

        user = authenticate(email=email, password=password)
        if not user:
            raise serializers.ValidationError("No active account found with the given credentials.")

        if not user.group:
            raise serializers.ValidationError("User has no assigned group.")

        if group_name and user.group.name != group_name:
            raise serializers.ValidationError("User does not belong to the provided group.")

        resolved_group = user.group.name
        refresh = self.get_token(user)

        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "email": user.email,
            "group": resolved_group,
        }

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token["email"] = user.email
        token["group"] = user.group.name if user.group else None
        return token


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    group = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ("email", "username", "password", "group")

    def validate_username(self, value):
        cleaned = value.strip()
        try:
            validate_principal(cleaned)
        except SSHValidationError as exc:
            raise serializers.ValidationError(str(exc))
        return cleaned

    def validate_password(self, value):
        try:
            validate_password(value)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(list(exc.messages))
        return value

    def create(self, validated_data):
        email = validated_data["email"].strip().lower()
        username = validated_data["username"]
        password = validated_data["password"]
        group_name = validated_data["group"].strip()
        is_admin_registration = self.context.get("is_admin_registration", False)

        try:
            group = Group.objects.get(name=group_name)
        except Group.DoesNotExist:
            raise serializers.ValidationError({"group": "Group not found with the given name."})

        if group.name == "ubuntu" and not is_admin_registration:
            raise serializers.ValidationError({"group": "Cannot register into the admin group via this endpoint."})

        if group.name == "ubuntu" and CustomUser.objects.filter(group__name="ubuntu").exists():
            raise serializers.ValidationError({"group": "Only one user can belong to the ubuntu group (admin)."})

        user = CustomUser(email=email, username=username, group=group)
        user.set_password(password)
        if group.name == "ubuntu":
            user.is_admin_user = True

        user.save()
        return user
