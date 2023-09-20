from django.urls import path
from .views import UserDetailAPI,RegisterUserAPIView,LoginAPIView, LogoutAPIView, UserDetailAPI
urlpatterns = [
  path('register',RegisterUserAPIView.as_view()),
  path('login', LoginAPIView.as_view()),
  path('logout', LogoutAPIView.as_view()),
  path('user', UserDetailAPI.as_view(), name='get-user'),
]