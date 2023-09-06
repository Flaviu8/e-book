from django.urls import path
from .views import UserDetailAPI,RegisterUserAPIView,LoginAPIView
urlpatterns = [
  path("get-details",UserDetailAPI.as_view()),
  path('register',RegisterUserAPIView.as_view()),
  path('login', LoginAPIView.as_view()),
]