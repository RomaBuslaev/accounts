from datetime import datetime
from typing import List, Optional, Type

from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.permissions import BasePermission

from profile_users.models import User
from profile_users.permissions import IsAdmin, IsModerator
from profile_users.serializers import UserRoleSerializer, UserSerializer


class UserViewSet(viewsets.ModelViewSet):
    queryset: User = User.objects.filter(is_active=True)
    serializer_class: Type[UserSerializer] = UserSerializer

    def get_permissions(self) -> List[BasePermission]:
        if self.action in ['list', 'retrieve']:
            permission_classes: List[Type[BasePermission]] = [IsModerator]
        else:
            permission_classes = [IsAdmin]
        return [permission() for permission in permission_classes]

    def get_queryset(self) -> User:
        return User.objects.filter(is_active=True)

    @action(detail=True, methods=['put'], permission_classes=[IsAdmin])
    def change_role(
        self,
        request: Request,
        pk: Optional[int] = None
    ) -> Response:

        user: User = self.get_object()
        serializer: UserRoleSerializer = UserRoleSerializer(data=request.data)

        if serializer.is_valid():
            new_role: str = serializer.validated_data['role']
            if user.is_superuser and new_role != 'admin':
                return Response(
                    {'error': 'Нельзя изменить роль суперпользователя'},
                    status=status.HTTP_403_FORBIDDEN
                )

            user.role = new_role
            user.save()
            return Response(UserSerializer(user).data)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['post'], permission_classes=[IsAdmin])
    def deactivate(
        self,
        request: Request,
        pk: Optional[int] = None
    ) -> Response:

        user: User = self.get_object()

        if user.is_superuser:
            return Response(
                {'error': 'Нельзя деактивировать суперпользователя'},
                status=status.HTTP_403_FORBIDDEN
            )
        user.is_active = False
        user.deleted_at = datetime.now()
        user.save()
        return Response({'message': 'Пользователь деактивирован'})
