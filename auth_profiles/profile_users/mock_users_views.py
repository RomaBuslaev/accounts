# mock_auth_views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.authentication import SessionAuthentication
from django.contrib.auth import login, logout
from types import SimpleNamespace


MOCK_USERS = [
    {
        'id': 1,
        'email': 'admin@example.com',
        'first_name': 'Admin',
        'last_name': 'System',
        'role': 'admin',
        'is_active': True,
        'is_superuser': True,
    },
    {
        'id': 2,
        'email': 'moderator@example.com',
        'first_name': 'Moder',
        'last_name': 'Ator',
        'role': 'moderator',
        'is_active': True,
        'is_superuser': False,
    },
    {
        'id': 3,
        'email': 'user@example.com',
        'first_name': 'Иван',
        'last_name': 'Петров',
        'role': 'user',
        'is_active': True,
        'is_superuser': False,
    },
    {
        'id': 4,
        'email': 'inactive@example.com',
        'first_name': 'Неактивный',
        'last_name': 'Пользователь',
        'role': 'user',
        'is_active': False,
        'is_superuser': False,
    }
]


class MockLoginView(APIView):
    permission_classes = (AllowAny,)
    authentication_classes = (SessionAuthentication,)

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        mock_user = None
        for user in MOCK_USERS:
            if user['email'] == email and password == 'password123':
                mock_user = user
                break

        if not mock_user:
            return Response(
                {'error': 'Неверный email или пароль'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        if not mock_user['is_active']:
            return Response(
                {'error': 'Аккаунт деактивирован'},
                status=status.HTTP_403_FORBIDDEN
            )

        mock_user_obj = SimpleNamespace(
            id=mock_user['id'],
            email=mock_user['email'],
            first_name=mock_user['first_name'],
            last_name=mock_user['last_name'],
            role=mock_user['role'],
            is_authenticated=True,
            is_active=mock_user['is_active'],
            is_superuser=mock_user['is_superuser'],
            is_admin=mock_user['role'] == 'admin' or mock_user['is_superuser'],
            is_moderator=mock_user['role'] in ['admin', 'moderator'] or mock_user['is_superuser'],
        )

        login(request, mock_user_obj)
        
        return Response({
            'user': {
                'id': mock_user['id'],
                'email': mock_user['email'],
                'first_name': mock_user['first_name'],
                'last_name': mock_user['last_name'],
                'role': mock_user['role'],
            },
            'message': 'Вход выполнен успешно'
        })


class MockProfileDeleteView(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (SessionAuthentication,)

    def delete(self, request, user_id=None):
        if not request.user.is_authenticated:
            return Response(
                {'error': 'Требуется аутентификация'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        if user_id is None:
            target_user_id = request.user.id
        else:
            target_user_id = int(user_id)

        target_user = None
        for user in MOCK_USERS:
            if user['id'] == target_user_id:
                target_user = user
                break

        if not target_user:
            return Response(
                {'error': 'Пользователь не найден'},
                status=status.HTTP_404_NOT_FOUND
            )

        is_owner = request.user.id == target_user_id
        is_admin = request.user.is_admin

        if not is_owner and not is_admin:
            return Response(
                {
                    'error': 'Доступ запрещен',
                    'details': 'Вы можете удалить только свой профиль',
                    'your_id': request.user.id,
                    'target_id': target_user_id,
                    'your_role': request.user.role
                },
                status=status.HTTP_403_FORBIDDEN
            )

        if target_user['is_superuser'] and not request.user.is_superuser:
            return Response(
                {
                    'error': 'Доступ запрещен',
                    'details': 'Нельзя удалить суперпользователя'
                },
                status=status.HTTP_403_FORBIDDEN
            )

        target_user['is_active'] = False

        if is_owner:
            logout(request)
            message = 'Ваш аккаунт успешно удален'
        else:
            message = f'Пользователь {target_user["email"]} успешно удален администратором'

        return Response(
            {
                'message': message,
                'deleted_user': {
                    'id': target_user['id'],
                    'email': target_user['email'],
                    'role': target_user['role']
                }
            },
            status=status.HTTP_200_OK
        )


class MockProfileView(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (SessionAuthentication,)

    def get(self, request):
        if not request.user.is_authenticated:
            return Response(
                {'error': 'Требуется аутентификация'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        user_data = None
        for user in MOCK_USERS:
            if user['id'] == request.user.id:
                user_data = user
                break

        return Response({
            'user': user_data,
            'permissions': {
                'is_admin': request.user.is_admin,
                'is_moderator': request.user.is_moderator,
                'can_delete_own_profile': True,
                'can_delete_others': request.user.is_admin
            }
        })


class MockLogoutView(APIView):

    permission_classes = (IsAuthenticated,)
    authentication_classes = (SessionAuthentication,)

    def post(self, request):
        if not request.user.is_authenticated:
            return Response(
                {'error': 'Требуется аутентификация'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        logout(request)
        return Response(
            {'message': 'Выход выполнен успешно'},
            status=status.HTTP_200_OK
        )
