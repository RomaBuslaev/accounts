from typing import Any, Type
from django.contrib.auth import login, logout
from rest_framework import status, generics
from rest_framework.authentication import SessionAuthentication
from rest_framework.exceptions import NotAuthenticated
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView


from profile_users.models import User
from profile_users.permissions import IsOwnerOrAdmin
from profile_users.serializers import (
    ChangePasswordSerializer, LoginSerializer, UserSerializer,
    UserCreateSerializer, UserUpdateSerializer)


class RegisterView(generics.CreateAPIView):
    queryset: User = User.objects.all()
    serializer_class: Type[UserCreateSerializer] = UserCreateSerializer
    permission_classes: tuple = (AllowAny,)

    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        serializer: UserCreateSerializer = self.get_serializer(
            data=request.data)
        serializer.is_valid(raise_exception=True)
        user: User = serializer.save()
        return Response({
            'user': UserSerializer(user).data,
            'message': 'Регистрация успешна'},
            status=status.HTTP_201_CREATED
        )


class LoginView(APIView):
    permission_classes: tuple = (AllowAny,)
    authentication_classes: tuple = (SessionAuthentication,)

    def post(self, request: Request) -> Response:
        serializer: LoginSerializer = LoginSerializer(
            data=request.data,
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        user: User = serializer.validated_data['user']
        login(request, user)
        return Response({
            'user': UserSerializer(user).data,
            'message': 'Вход выполнен успешно'
        })


class LogoutView(APIView):
    permission_classes: tuple = (IsAuthenticated,)

    def post(self, request: Request) -> Response:
        logout(request)
        return Response(
            {'message': 'Выход выполнен успешно'},
            status=status.HTTP_200_OK)


class ProfileView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class: Type[UserSerializer] = UserSerializer
    permission_classes: tuple = (IsAuthenticated,)

    def get_object(self) -> User:
        if not self.request.user.is_authenticated:
            raise NotAuthenticated('Требуется аутентификация')
        return self.request.user

    def get_permissions(self) -> list:
        if self.request.method == 'DELETE':
            return [IsOwnerOrAdmin()]
        return [IsAuthenticated()]

    def update(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        partial: bool = kwargs.pop('partial', False)
        instance: User = self.get_object()
        if not (instance == request.user or request.user.is_admin):
            return Response(
                {'error': 'Доступ запрещен'},
                status=status.HTTP_403_FORBIDDEN
            )
        serializer: UserUpdateSerializer = UserUpdateSerializer(
            instance,
            data=request.data,
            partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data)

    def destroy(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        user: User = self.get_object()
        if not (user == request.user or request.user.is_admin):
            return Response(
                {'error': 'Доступ запрещен'},
                status=status.HTTP_403_FORBIDDEN
            )

        if user.is_superuser and not request.user.is_superuser:
            return Response(
                {'error': 'Доступ запрещен'},
                status=status.HTTP_403_FORBIDDEN)
        user.user_delete()
        user.save()
        logout(request)

        return Response(
            {'message': 'Аккаунт успешно удален'},
            status=status.HTTP_200_OK)


class ChangePasswordView(APIView):
    permission_classes: tuple = (IsAuthenticated,)

    def post(self, request: Request) -> Response:
        serializer: ChangePasswordSerializer = ChangePasswordSerializer(
            data=request.data,
            context={'request': request}
        )

        serializer.is_valid(raise_exception=True)
        request.user.set_password(serializer.validated_data['new_password'])
        request.user.save()

        return Response(
            {'message': 'Пароль успешно изменен'},
            status=status.HTTP_200_OK)
