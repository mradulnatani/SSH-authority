from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework import serializers
from .models import CustomUser
from rest_framework_simplejwt.exceptions import AuthenticationFailed
from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import CustomUser
from django.core.validators import validate_email
from django.core.exceptions import ValidationError as DjangoValidationError

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        # Add custom claims
        token['email'] = user.email
        token['group'] = user.group  # add group to token claims
        return token

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ('email', 'username', 'password', 'group')  # added group here

    def create(self, validated_data):
        user = CustomUser(
            email=validated_data['email'],
            username=validated_data['username'],
            group = validated_data.get('group')
        )
        user.set_password(validated_data['password'])  # hash the password
        user.save()
        return user


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    group = serializers.CharField(write_only=True)  # Add group as a required field

    from rest_framework import serializers
from django.contrib.auth import authenticate

def validate(self, attrs):
    email = attrs.get('email')
    password = attrs.get('password')
    group = attrs.get('group')

    if not email:
        raise serializers.ValidationError("Email is required")

    data = super().validate(attrs)  # call parent's validate first

    user = authenticate(email=email, password=password)
    if not user:
        raise serializers.ValidationError('No active account found with the given credentials')

    # Check group attribute safely
    user_group_name = getattr(user.group, 'name', None)
    if user_group_name != group:
        raise serializers.ValidationError('User does not belong to the provided group')

    refresh = self.get_token(user)
    data['refresh'] = str(refresh)
    data['access'] = str(refresh.access_token)
    data['email'] = user.email
    data['group'] = user_group_name

    return data

