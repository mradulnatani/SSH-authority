from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework import serializers
from .models import CustomUser
from rest_framework_simplejwt.exceptions import AuthenticationFailed
from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import CustomUser
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
            group=validated_data.get('group', '')  # safely get group or default empty string
        )
        user.set_password(validated_data['password'])  # hash the password
        user.save()
        return user


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    group = serializers.CharField(write_only=True)  # Add group as a required field

    def validate(self, attrs):
        # Extract email, password, and group from incoming data
        email = attrs.get('email')
        password = attrs.get('password')
        group = attrs.get('group')

        # First, authenticate the user by email and password
        user = authenticate(email=email, password=password)
        if not user:
            raise serializers.ValidationError('No active account found with the given credentials')

        # Now check if the user's group matches the provided group
        if user.group != group:
            raise serializers.ValidationError('User does not belong to the provided group')

        # If everything is OK, call super to get tokens
        data = super().validate(attrs)

        # Add custom claims in token payload
        refresh = self.get_token(user)
        data['refresh'] = str(refresh)
        data['access'] = str(refresh.access_token)
        data['email'] = user.email
        data['group'] = user.group

        return data