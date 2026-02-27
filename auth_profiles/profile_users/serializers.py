from typing import Any, Dict, Optional
from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.models import AbstractUser
from rest_framework.request import Request

from .models import User


class UserSerializer(serializers.ModelSerializer):
    full_name = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields: tuple = ('id', 'email', 'first_name', 'last_name',
                         'patronymic', 'full_name', 'is_active',
                         'created_at', 'role')
        read_only_fields: tuple = ('id', 'is_active', 'created_at')

    def get_full_name(self, obj: User) -> str:
        return obj.get_full_name()


class UserCreateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        style={'input_type': 'password'}
    )

    password2 = serializers.CharField(
        write_only=True,
        style={'input_type': 'password'},
        label='Подтверждение пароля'
    )

    class Meta:
        model = User
        fields: tuple = ('email', 'first_name', 'last_name',
                         'patronymic', 'password', 'password2', 'role')

    def validate(self, data: Dict[str, Any]) -> Dict[str, Any]:
        if data['password'] != data['password2']:
            raise serializers.ValidationError(
                {'password': 'Пароли не совпадают'}
            )
        return data

    def validate_email(self, value: str) -> str:
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError(
                'Пользователь с таким email уже существует'
            )
        return value

    def create(self, validated_data: Dict[str, Any]) -> User:
        validated_data.pop('password2')
        password: str = validated_data.pop('password')
        user_data: Dict[str, Any] = {
            'email': validated_data['email'],
            'password': password,
            'first_name': validated_data.get('first_name', ''),
            'last_name': validated_data.get('last_name', ''),
            'patronymic': validated_data.get('patronymic', '')
        }
        user: User = User.objects.create_user(**user_data)
        return user


class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields: tuple = ('first_name', 'last_name', 'patronymic', 'role')

    def update(self, instance: User, validated_data: Dict[str, Any]) -> User:
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(style={'input_type': 'password'})

    def validate(self, data: Dict[str, Any]) -> Dict[str, Any]:
        email: Optional[str] = data.get('email')
        password: Optional[str] = data.get('password')

        if email and password:
            user: Optional[AbstractUser] = authenticate(
                request=self.context.get('request'),
                username=email,
                password=password
            )
            if not user:
                raise serializers.ValidationError('Неверный email или пароль')

            if not user.is_active:
                raise serializers.ValidationError('Профиль был удален')

            data['user'] = user
        else:
            raise serializers.ValidationError('Введите email и пароль')
        return data


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(style={'input_type': 'password'})
    new_password = serializers.CharField(style={'input_type': 'password'})
    new_password2 = serializers.CharField(
        style={'input_type': 'password'},
        label='Подтверждение пароля'
    )

    def validate(self, data: Dict[str, Any]) -> Dict[str, Any]:
        if data['new_password'] != data['new_password2']:
            raise serializers.ValidationError(
                {'new_password': 'Пароли не совпадают'}
            )
        return data

    def validate_old_password(self, value: str) -> str:
        user: User = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError('Неверный текущий пароль')
        return value


class UserRoleSerializer(serializers.Serializer):
    role = serializers.ChoiceField(choices=User.STATUS)

    def validate_role(self, value: str) -> str:
        request: Optional[Request] = self.context.get('request')
        if request and request.user.role == 'moderator' and value == 'admin':
            raise serializers.ValidationError(
                'Модератор не может назначить роль администратора'
            )
        return value
