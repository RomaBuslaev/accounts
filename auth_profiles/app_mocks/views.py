from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny

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

    permission_classes = (AllowAny,)

    def delete(self, request, user_id=None):
        auth_email = request.headers.get('X-Auth-Email')

        if not auth_email:
            return Response(
                {'error': 'Требуется аутентификация'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        current_user = None
        for user in MOCK_USERS:
            if user['email'] == auth_email:
                current_user = user
                break

        if not current_user:
            return Response(
                {'error': 'Пользователь не найден'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        if not current_user['is_active']:
            return Response(
                {'error': 'Аккаунт деактивирован'},
                status=status.HTTP_403_FORBIDDEN
            )

        if user_id is None:
            target_user_id = current_user['id']
        else:
            target_user_id = int(user_id)

        target_user = None
        target_index = -1
        for i, user in enumerate(MOCK_USERS):
            if user['id'] == target_user_id:
                target_user = user
                target_index = i
                break

        if not target_user:
            return Response(
                {'error': 'Пользователь не найден'},
                status=status.HTTP_404_NOT_FOUND
            )

        is_owner = current_user['id'] == target_user_id
        is_admin = current_user['role'] == (
            'admin' or current_user['is_superuser'])

        if not is_owner and not is_admin:
            return Response(
                {
                    'error': 'Доступ запрещен',
                    'details': 'Вы можете удалить только свой профиль',
                    'your_email': current_user['email'],
                    'your_role': current_user['role'],
                    'target_email': target_user['email'],
                    'target_role': target_user['role']
                },
                status=status.HTTP_403_FORBIDDEN
            )

        if target_user['is_superuser'] and not current_user['is_superuser']:
            return Response(
                {
                    'error': 'Доступ запрещен',
                    'details': 'Нельзя удалить суперпользователя'
                },
                status=status.HTTP_403_FORBIDDEN
            )

        MOCK_USERS[target_index]['is_active'] = False

        message = f'Пользователь {target_user["email"]} успешно удален'
        if is_owner:
            message = 'Ваш аккаунт успешно удален'

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
    permission_classes = (AllowAny,)

    def get(self, request):
        auth_email = request.headers.get('X-Auth-Email')

        if not auth_email:
            return Response(
                {'error': 'Требуется аутентификация'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        user_data = None
        for user in MOCK_USERS:
            if user['email'] == auth_email:
                user_data = user
                break

        if not user_data:
            return Response(
                {'error': 'Пользователь не найден'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        if not user_data['is_active']:
            return Response(
                {'error': 'Аккаунт деактивирован'},
                status=status.HTTP_403_FORBIDDEN
            )

        return Response({'user': user_data})


class MockLogoutView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        return Response(
            {'message': 'Выход выполнен успешно'},
            status=status.HTTP_200_OK
        )
