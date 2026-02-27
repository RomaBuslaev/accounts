from django.urls import include, path
from rest_framework.routers import DefaultRouter

from profile_users.views import (
    RegisterView, LoginView, LogoutView, ProfileView, ChangePasswordView)
from profile_users.views_admin import UserViewSet

router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')

urlpatterns = [
    path('auth/register/', RegisterView.as_view(), name='register'),
    path('auth/login/', LoginView.as_view(), name='login'),
    path('auth/logout/', LogoutView.as_view(), name='logout'),
    path('profile/', ProfileView.as_view(), name='profile'),
    path('set_password/', ChangePasswordView.as_view(), name='set_password'),
    path('', include(router.urls)),
]
