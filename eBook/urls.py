from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('api.urls')),
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),  # Obtain token
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),  # Refresh token
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),  # Verify token
]
