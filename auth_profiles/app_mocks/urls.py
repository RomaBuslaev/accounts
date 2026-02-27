from django.urls import path
from app_mocks.views import (
    MockLoginView,
    MockLogoutView,
    MockProfileView,
    MockProfileDeleteView,
)

urlpatterns = [
    path('mock/login/', MockLoginView.as_view(), name='mock_login'),
    path('mock/logout/', MockLogoutView.as_view(), name='mock_logout'),
    path('mock/profile/', MockProfileView.as_view(), name='mock_profile'),
    path('mock/profile/delete/', MockProfileDeleteView.as_view(),
         name='mock_profile_delete'),
    path('mock/profile/<int:user_id>/delete/', MockProfileDeleteView.as_view(),
         name='mock_profile_delete_by_id'),
]
