from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import CustomUser, Group


from django.contrib.auth import authenticate
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework import serializers
from .models import Group

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    group = serializers.CharField(write_only=True)

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        group_name = attrs.get('group')  # Expecting group name (string)

        if not email or not password or not group_name:
            raise serializers.ValidationError("Email, password, and group are required")

        user = authenticate(email=email, password=password)
        if not user:
            raise serializers.ValidationError("No active account found with the given credentials")

        # Check if group name matches
        if not user.group or user.group.name != group_name:
            raise serializers.ValidationError("User does not belong to the provided group")

        # All checks passed — generate token
        refresh = self.get_token(user)

        data = super().validate(attrs)
        data['refresh'] = str(refresh)
        data['access'] = str(refresh.access_token)
        data['email'] = user.email
        data['group'] = group_name

        return data
    

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['email'] = user.email
        token['group'] = user.group.name if user.group else None
        return token



class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ('email', 'username', 'password', 'group')

    def create(self, validated_data):
        email = validated_data['email']
        username = validated_data['username']
        password = validated_data['password']
        group = validated_data['group']  
        user = CustomUser(email=email, username=username)
        user.set_password(password)  
        user.group = group  
        user.save()

        user.custom_groups.add(group) 

        return user
